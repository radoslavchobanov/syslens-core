use crate::{
    Result,
    ai::{self, Action, ChatRequest},
    client::HostClient,
    config::{self, Config},
    state::Store,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use syslens_protocol::{Envelope, EventPage};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub store: Arc<Mutex<Store>>,
    waiting: Arc<Semaphore>,
    inference: Arc<Semaphore>,
}

fn evidence_tool_content(evidence: &Value, facts: Option<&ai::RootStorageFacts>) -> String {
    let mut content = json!({
        "kind": "syslens_evidence_data",
        "evidence": evidence,
    });
    if let Some(facts) = facts {
        let canonical: Value = serde_json::from_str(&ai::canonical_storage_facts(facts))
            .expect("canonical storage facts must remain valid JSON");
        content["canonical_storage_facts"] = canonical;
    }
    serde_json::to_string(&content).expect("evidence tool content is serializable")
}

impl App {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        if !config.enabled {
            return Err("gateway is disabled".into());
        }
        let store = Store::open(&config.database)?;
        store.cleanup(config.session_retention_days, config.event_retention_days)?;
        Ok(Self {
            waiting: Arc::new(Semaphore::new(config.queue_limit + 1)),
            inference: Arc::new(Semaphore::new(1)),
            config: Arc::new(config),
            store: Arc::new(Mutex::new(store)),
        })
    }
    fn db(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.store
            .lock()
            .map_err(|_| "gateway state unavailable".into())
    }
    pub async fn host<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Envelope<T>> {
        let h = self.config.hosts.get(name).ok_or("unknown target host")?;
        let client = HostClient::new(h, self.config.host_timeout_seconds)?;
        let result = client.request(path, body).await?;
        self.db()?.identity(name, &result)?;
        Ok(result)
    }
    pub async fn evidence(&self, name: &str, action: Action) -> Result<Value> {
        match action {
            Action::Memory(r) => Ok(serde_json::to_value(
                self.host::<Value>(
                    name,
                    "/v1/evidence/memory",
                    Some(&serde_json::to_value(r).unwrap()),
                )
                .await?,
            )
            .unwrap()),
            Action::Storage(r) => Ok(serde_json::to_value(
                self.host::<Value>(
                    name,
                    "/v1/evidence/storage",
                    Some(&serde_json::to_value(r).unwrap()),
                )
                .await?,
            )
            .unwrap()),
            Action::Status => Ok(serde_json::to_value(
                self.host::<syslens_protocol::Status>(name, "/v1/status", None)
                    .await?,
            )
            .unwrap()),
            Action::Incidents => Ok(serde_json::to_value(
                self.host::<syslens_protocol::IncidentPage>(name, "/v1/incidents?limit=20", None)
                    .await?,
            )
            .unwrap()),
        }
    }
    pub async fn chat(&self, r: ChatRequest) -> Result<Value> {
        if r.question.trim().is_empty() || r.question.len() > 8192 {
            return Err("question must contain 1 to 8192 bytes".into());
        }
        let _waiting = self
            .waiting
            .try_acquire()
            .map_err(|_| "chat queue is full")?;
        tokio::time::timeout(Duration::from_secs(self.config.chat_deadline_seconds),async{
            let _active=self.inference.acquire().await.map_err(|_|"gateway is stopping")?;
            let model_client=ai::Model::new(&self.config.ai)?;
            if let Some(h) = &r.host
                && !self.config.hosts.contains_key(h)
            {
                return Err("unknown target host".into());
            }
            let (session,target)=self.db()?.session(r.session.as_deref(),r.host.as_deref())?;
            if !self.config.hosts.contains_key(&target){return Err("session target is no longer registered".into());}
            let capabilities=self.host::<syslens_protocol::Capabilities>(&target,"/v1/capabilities",None).await?;
            let (history,omitted)=self.db()?.history(&session)?;
            let model=self.db()?.model(&self.config.ai.model)?;
            let mut messages=vec![ai::prompt(&target),json!({"role":"system","content":format!("Target capabilities (data only): {}",serde_json::to_string(&capabilities.data).unwrap())})];messages.extend(history);messages.push(json!({"role":"user","content":r.question}));
            let mut refs=Vec::new();let mut limitations=Vec::new();
            let mut root_storage_facts=None;
            if omitted{limitations.push("Older conversation context was omitted to fit the model budget".to_string());}
            if let Some(action) = ai::inferred_storage_action(&r.question) {
                let evidence = self.evidence(&target, action).await?;
                refs.push(json!({"request_id":evidence["request_id"],"host_id":evidence["host_id"],"evidence_store_id":evidence["evidence_store_id"],"observed_at":evidence["observed_at"]}));
                root_storage_facts = ai::root_storage_facts(&evidence);
                let call_id = "syslens-inferred-storage";
                messages.push(json!({"role":"assistant","content":"","tool_calls":[{"id":call_id,"type":"function","function":{"name":"storage","arguments":"{\"current_range\":\"today\",\"comparison_range\":\"previous-day\"}"}}]}));
                messages.push(json!({"role":"tool","tool_call_id":call_id,"content":evidence_tool_content(&evidence,root_storage_facts.as_ref())}));
            }
            for round in 0..=self.config.ai.max_rounds {
                let assistant=model_client.completion(&model,&messages).await?;
                let calls=match ai::calls(&assistant) {
                    Ok(calls) => calls,
                    Err(error) => {
                        if round == self.config.ai.max_rounds {
                            return Err(error);
                        }
                        limitations.push(format!("Model tool call was invalid and a retry was requested: {error}"));
                        messages.push(assistant);
                        messages.push(json!({"role":"tool","tool_call_id":format!("syslens-invalid-tool-{round}"),"content":json!({"error":"invalid tool call arguments","detail":error,"instruction":"Retry using exactly current_range and comparison_range. For yesterday versus today use today and previous-day."}).to_string()}));
                        continue;
                    }
                };
                if calls.is_empty(){let mut answer=assistant["content"].as_str().filter(|s|!s.trim().is_empty()&&s.len()<=32_768).map(str::to_owned);
                    if answer.is_none() {
                        answer = root_storage_facts.as_ref().map(ai::deterministic_storage_summary);
                    }
                    let mut answer=answer.ok_or("AI returned no bounded answer")?;
                    if let Some(facts)=root_storage_facts.as_ref()
                        && let Some(fallback)=ai::grounded_storage_fallback(&answer,facts)
                    {
                        limitations.push("The model answer contradicted authoritative root storage evidence; a deterministic fallback was returned".into());
                        answer=fallback;
                    }
                    if let Some(facts) = root_storage_facts.as_ref()
                        && !answer.contains("Authoritative storage evidence")
                    {
                        answer = format!("{}\n\nModel analysis:\n{}", ai::deterministic_storage_summary(facts), answer);
                    }
                    if refs.is_empty(){limitations.push("No successful host evidence supports this answer".into());}
                    let response=json!({"session":session,"target":target,"model":model,"answer":answer,"evidence_refs":refs,"limitations":limitations});self.db()?.save(&session,&r.question,&response)?;return Ok(response);
                }
                if round==self.config.ai.max_rounds||calls.len()>self.config.ai.max_calls{return Err("AI evidence action limit reached".into());}
                messages.push(assistant);
                for call in calls {
                    let id = call.id;
                    let action = match call.action {
                        Ok(action) => action,
                        Err(error) => {
                            limitations.push(format!("Model tool arguments were invalid; a retry was requested: {error}"));
                            messages.push(json!({"role":"tool","tool_call_id":id,"content":json!({"error":"invalid tool arguments","detail":error,"instruction":"Retry with valid typed evidence arguments."}).to_string()}));
                            continue;
                        }
                    };
                    let is_storage=matches!(&action,Action::Storage(_));
                    let supported=match &action{Action::Memory(_)=>capabilities.data.resources.iter().any(|s|s=="memory"),Action::Storage(_)=>capabilities.data.resources.iter().any(|s|s=="storage"),_=>true};
                    if !supported{return Err("AI requested a resource unavailable on this target".into());}
                    let mut facts_for_message=None;
                    let evidence=match self.evidence(&target,action).await {Ok(e)=>{let reference=json!({"request_id":e["request_id"],"host_id":e["host_id"],"evidence_store_id":e["evidence_store_id"],"observed_at":e["observed_at"]});refs.push(reference);if is_storage {facts_for_message=ai::root_storage_facts(&e);}
                        if e.to_string().len()>12_000{limitations.push("Evidence exceeded model context budget; full result is available through deterministic diagnosis".into());json!({"status":"insufficient_evidence","limitation":"Evidence omitted because it exceeds model context budget","request_id":e["request_id"]})}else{e}},Err(error)=>{limitations.push(error.clone());json!({"error":error})}};
                    if let Some(facts) = facts_for_message.as_ref() {
                        root_storage_facts = Some(facts.clone());
                    }
                    // Keep canonical measurements in the tool-data message. A
                    // host-controlled path, status, or limitation must never
                    // be promoted to a system instruction.
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": id,
                        "content": evidence_tool_content(&evidence, facts_for_message.as_ref()),
                    }));
                }
            } Err("AI action limit reached".into())
        }).await.map_err(|_|"chat deadline exceeded")?
    }
    pub async fn operation(&self, op: &str, body: Value) -> Result<Value> {
        match op {
            "hosts" => {
                let db = self.db()?;
                let mut hosts = Vec::new();
                for name in self.config.hosts.keys() {
                    let error: Option<String> = db
                        .conn
                        .query_row("SELECT error FROM host_state WHERE name=?", [name], |r| {
                            r.get(0)
                        })
                        .unwrap_or(None);
                    hosts.push(json!({"name":name,"error":error}));
                }
                Ok(json!({"hosts":hosts}))
            }
            "host-status" => {
                let r: HostRequest = parse(body)?;
                self.evidence(&r.host, Action::Status).await
            }
            "host-enroll" => {
                let r: HostRequest = parse(body)?;
                let h = self
                    .config
                    .hosts
                    .get(&r.host)
                    .ok_or("unknown target host")?;
                let evidence: Envelope<syslens_protocol::Capabilities> =
                    HostClient::new(h, self.config.host_timeout_seconds)?
                        .request("/v1/capabilities", None)
                        .await?;
                self.db()?.reenroll(&r.host, &evidence)?;
                Ok(
                    json!({"host":r.host,"host_id":evidence.host_id,"evidence_store_id":evidence.evidence_store_id}),
                )
            }
            "chat" => self.chat(parse(body)?).await,
            "diagnose" => {
                let r: DiagnoseRequest = parse(body)?;
                let args = if r.current_start.is_some()
                    || r.current_end.is_some()
                    || r.comparison_start.is_some()
                    || r.comparison_end.is_some()
                {
                    json!({
                        "current_start": r.current_start,
                        "current_end": r.current_end,
                        "comparison_start": r.comparison_start,
                        "comparison_end": r.comparison_end,
                    })
                } else {
                    serde_json::to_value(ai::window(&r.since, &r.compare)?).unwrap()
                };
                let a = ai::action(&r.resource, args)?;
                self.evidence(&r.host, a).await
            }
            "sessions" => {
                let r: SessionRequest = parse(body)?;
                self.db()?.sessions(r.id.as_deref())
            }
            "incidents" => {
                let r: EventRequest = parse(body)?;
                self.db()?.events(r.after)
            }
            "models" => ai::Model::new(&self.config.ai)?.models().await,
            "model-set" => {
                let r: ModelRequest = parse(body)?;
                self.db()?.set_model(&r.model)?;
                Ok(json!({"model":r.model}))
            }
            "health" => Ok(json!({"status":"ready"})),
            _ => Err("unsupported gateway operation".into()),
        }
    }
    pub async fn poll_host(&self, name: &str) -> Result<()> {
        for _ in 0..4 {
            let cursor = self.db()?.cursor(name)?;
            let result: Result<Envelope<EventPage>> = self
                .host(name, &format!("/v1/events?after={cursor}&limit=100"), None)
                .await;
            let page = match result {
                Ok(page) => page,
                Err(error) => {
                    if let Some(floor) = error
                        .strip_prefix("history gap; replay floor: ")
                        .and_then(|s| s.parse::<i64>().ok())
                    {
                        // Confirm identities before accepting a recovery cursor from an error envelope.
                        self.host::<syslens_protocol::Capabilities>(name, "/v1/capabilities", None)
                            .await?;
                        self.db()?.history_gap(name, floor)?;
                        continue;
                    }
                    return Err(error);
                }
            };
            let more = page.data.has_more;
            self.db()?.ingest(name, &page)?;
            if !more {
                break;
            }
        }
        Ok(())
    }
    async fn poll(self, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.poll_seconds));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut failures: BTreeMap<String, (u32, std::time::Instant)> = BTreeMap::new();
        loop {
            tokio::select! {_ = stop.changed()=>break,_ = interval.tick()=>{let mut tasks=tokio::task::JoinSet::new();let permits=Arc::new(Semaphore::new(4));for name in self.config.hosts.keys(){if failures.get(name).is_some_and(|(_,next)|*next>std::time::Instant::now()){continue;}let name=name.clone();let app=self.clone();let p=permits.clone();tasks.spawn(async move{let _permit=p.acquire_owned().await;let result=app.poll_host(&name).await;(name,result)});}while let Some(result)=tasks.join_next().await{if let Ok((name,result))=result{match result{Ok(())=>{failures.remove(&name);},Err(e)=>{let count=failures.get(&name).map(|v|v.0).unwrap_or(0).saturating_add(1).min(6);failures.insert(name.clone(),(count,std::time::Instant::now()+Duration::from_secs((self.config.poll_seconds*(1<<count)).min(1800))));if let Ok(db)=self.db(){let _=db.host_error(&name,&e);}}}}}if let Ok(db)=self.db(){let _=db.cleanup(self.config.session_retention_days,self.config.event_retention_days);}}}
        }
    }
}
fn parse<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| "invalid gateway request".into())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRequest {
    host: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnoseRequest {
    host: String,
    resource: String,
    since: String,
    compare: String,
    #[serde(default)]
    current_start: Option<String>,
    #[serde(default)]
    current_end: Option<String>,
    #[serde(default)]
    comparison_start: Option<String>,
    #[serde(default)]
    comparison_end: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct SessionRequest {
    id: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct EventRequest {
    after: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRequest {
    model: String,
}
fn response(result: Result<Value>) -> axum::response::Response {
    let request = crate::id();
    match result{Ok(data)=>(StatusCode::OK,Json(json!({"version":1,"request_id":request,"data":data}))).into_response(),Err(error)=>(StatusCode::BAD_REQUEST,Json(json!({"version":1,"request_id":request,"error":{"code":"request_failed","message":error}}))).into_response()}
}
async fn command(
    State(app): State<App>,
    axum::extract::Path(op): axum::extract::Path<String>,
    payload: std::result::Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> axum::response::Response {
    let result = match payload {
        Ok(Json(body)) => app.operation(&op, body).await,
        Err(_) => Err("invalid gateway request".into()),
    };
    response(result)
}
async fn hosts(State(app): State<App>) -> axum::response::Response {
    response(app.operation("hosts", json!({})).await)
}
async fn events_post(
    State(app): State<App>,
    payload: std::result::Result<Json<EventRequest>, axum::extract::rejection::JsonRejection>,
) -> axum::response::Response {
    response(match payload {
        Ok(Json(r)) => app.operation("incidents", json!({"after":r.after})).await,
        Err(_) => Err("invalid event cursor".into()),
    })
}
async fn events(
    State(app): State<App>,
    query: std::result::Result<Query<EventRequest>, axum::extract::rejection::QueryRejection>,
) -> axum::response::Response {
    response(match query {
        Ok(Query(r)) => app.operation("incidents", json!({"after":r.after})).await,
        Err(_) => Err("invalid event cursor".into()),
    })
}
fn router(app: App) -> Router {
    Router::new()
        .route("/v1/{op}", post(command))
        .route("/v1/hosts", get(hosts).post(hosts))
        .route("/v1/incidents", get(events).post(events_post))
        .fallback(|| async { response(Err("unsupported gateway operation".into())) })
        .method_not_allowed_fallback(|| async {
            response(Err("unsupported gateway method".into()))
        })
        .layer(DefaultBodyLimit::max(32_768))
        .with_state(app)
}
pub fn peer_allowed(uid: u32) -> bool {
    uid == unsafe { libc::geteuid() }
}
struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub async fn run(config: Config) -> Result<()> {
    if !config.enabled {
        return Err("gateway is disabled; explicitly enable configuration before starting".into());
    }
    config.validate()?;
    let directory = config.socket.parent().ok_or("invalid socket location")?;
    config::private_dir(directory)?;
    let lock_path = directory.join("gateway.lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|_| "cannot open daemon lock")?;
    config::private(&lock_path, false)?;
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("gateway daemon already owns the socket".into());
    }
    if config.socket.exists() {
        let m =
            fs::symlink_metadata(&config.socket).map_err(|_| "cannot inspect gateway socket")?;
        if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } {
            return Err("socket path is occupied".into());
        }
        fs::remove_file(&config.socket).map_err(|_| "cannot remove stale socket")?;
    }
    let listener = UnixListener::bind(&config.socket).map_err(|_| "cannot bind gateway socket")?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot secure gateway socket")?;
    let _socket = SocketGuard(config.socket.clone());
    let app = App::new(config)?;
    let routes = router(app.clone());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let poll = tokio::spawn(app.poll(stop_rx));
    let mut connections = tokio::task::JoinSet::new();
    let limit = Arc::new(Semaphore::new(32));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "cannot install shutdown signal")?;
    loop {
        tokio::select! {_ = tokio::signal::ctrl_c()=>break,_ = terminate.recv()=>break,Some(_) = connections.join_next(),if !connections.is_empty()=>{},accepted = listener.accept()=>{let(stream,_)=accepted.map_err(|_|"gateway socket failed")?;if !stream.peer_cred().map(|c|peer_allowed(c.uid())).unwrap_or(false){continue;}let Ok(permit)=limit.clone().try_acquire_owned()else{continue;};let service=hyper_util::service::TowerToHyperService::new(routes.clone());connections.spawn(async move{let _permit=permit;let connection=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream),service);let _=tokio::time::timeout(Duration::from_secs(610),connection).await;});}}
    }
    let _ = stop_tx.send(true);
    poll.abort();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let _ = poll.await;
    Ok(())
}
pub async fn request(socket: &Path, op: &str, body: Value) -> Result<Value> {
    let parent = socket.parent().ok_or("invalid socket path")?;
    config::private(parent, true)?;
    let m = fs::symlink_metadata(socket).map_err(|_| "gateway is unavailable; start its daemon")?;
    if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0
    {
        return Err("gateway socket is not owner-only".into());
    }
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|_| "gateway is unavailable")?;
    if !stream
        .peer_cred()
        .map(|c| peer_allowed(c.uid()))
        .unwrap_or(false)
    {
        return Err("gateway peer is unauthorized".into());
    }
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| "gateway connection failed")?;
    let task = tokio::spawn(connection);
    let result = async {
        let request = hyper::Request::builder()
            .method("POST")
            .uri(format!("/v1/{op}"))
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|_| "invalid gateway request")?;
        let mut response = sender
            .send_request(request)
            .await
            .map_err(|_| "gateway request failed")?
            .into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = response.frame().await {
            let frame = frame.map_err(|_| "gateway response failed")?;
            if let Ok(data) = frame.into_data() {
                if bytes.len() + data.len() > crate::MAX_BODY {
                    return Err("gateway response exceeds limit".into());
                }
                bytes.extend_from_slice(&data);
            }
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid gateway response")?;
        if v["version"] != 1 {
            return Err("unsupported gateway protocol".into());
        }
        if let Some(message) = v["error"]["message"].as_str() {
            return Err(message.to_string());
        }
        v.get("data")
            .cloned()
            .ok_or("gateway response has no data".into())
    }
    .await;
    task.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_owner_can_use_socket() {
        assert!(peer_allowed(unsafe { libc::geteuid() }));
        assert!(!peer_allowed(unsafe { libc::geteuid() }.wrapping_add(1)));
    }
    #[tokio::test]
    async fn disabled_gateway_does_not_create_state() {
        let d = tempfile::tempdir().unwrap();
        let c = Config {
            database: d.path().join("missing/state.db"),
            socket: d.path().join("missing/gw.sock"),
            ..Config::default()
        };
        assert!(run(c).await.is_err());
        assert!(!d.path().join("missing").exists());
    }
}
