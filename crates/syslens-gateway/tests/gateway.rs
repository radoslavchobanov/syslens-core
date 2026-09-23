use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};
use syslens_gateway::{
    ai::ChatRequest,
    client::HostClient,
    config::{self, Config, Host},
    daemon::App,
};

struct Fixture {
    dir: tempfile::TempDir,
    host: Host,
    gap_floor: Arc<AtomicI64>,
    storage_calls: Arc<AtomicI64>,
    oversized_storage: Arc<AtomicI64>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn fixture() -> Fixture {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["test-ca".into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let server = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let client_key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["gateway".into()])
        .unwrap()
        .signed_by(&client_key, &ca, &ca_key)
        .unwrap();
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    config::write_new(&ca_path, ca.pem().as_bytes()).unwrap();
    config::write_new(&cert_path, cert.pem().as_bytes()).unwrap();
    config::write_new(&key_path, client_key.serialize_pem().as_bytes()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let gap_floor = Arc::new(AtomicI64::new(0));
    let events_floor = gap_floor.clone();
    let storage_calls = Arc::new(AtomicI64::new(0));
    let storage_count = storage_calls.clone();
    let oversized_storage = Arc::new(AtomicI64::new(0));
    let oversized_storage_response = oversized_storage.clone();
    let router=Router::new().route("/v1/capabilities",get(||async{Json(envelope(json!({"timezone":"UTC","resources":["memory","storage"],"earliest_observation":null,"latest_observation":null})))}))
        .route("/v1/status",get(||async{Json(envelope(json!({"recording":"active","samples":10,"latest_observation":null,"freshness_seconds":0})))}))
        .route("/v1/events",get(move|Query(query):Query<BTreeMap<String,String>>|{let floor=events_floor.clone();async move{let after=query.get("after").and_then(|v|v.parse::<i64>().ok()).unwrap_or(0);let replay=floor.load(Ordering::Relaxed);if replay>after{(StatusCode::CONFLICT,Json(json!({"version":1,"request_id":"request","error":{"code":"history_gap","message":"notification history gap"},"replay_floor":replay}))).into_response()}else{Json(envelope(json!({"events":[],"next_cursor":after,"has_more":false}))).into_response()}}}))
        .route("/v1/evidence/memory",post(|Json(body):Json<Value>|async move{assert!(body["window"].is_object());Json(envelope(json!({"status":"insufficient evidence","limitations":["No comparison history yet"]})))}))
        .route("/v1/evidence/storage",post(move|Json(body):Json<Value>|{let calls=storage_count.clone();let oversized=oversized_storage_response.clone();async move{
            calls.fetch_add(1,Ordering::Relaxed);
            assert_eq!(body["window"]["relative"]["unit"],"today");
            assert_eq!(body["window"]["comparison"],"previous-day");
            let mut data = json!({
                "current":{"start_utc":"2026-09-16T00:00:00Z","end_utc":"2026-09-16T12:00:00Z"},
                "comparison":{"start_utc":"2026-09-15T00:00:00Z","end_utc":"2026-09-15T12:00:00Z"},
                "mounts":[{"mount_id":"root","mount_point":"/","current_used_bytes":1100i64,"comparison_used_bytes":1000i64,"used_bytes_change":100i64}],
                "directories":[],
                "current_directory_snapshot":[],
                "path_attribution_status":"unavailable",
                "limitations":["No comparable historical directory scan"]
            });
            if oversized.load(Ordering::Relaxed) != 0 {
                data["limitations"] = json!(vec!["bounded evidence padding ".repeat(128); 16]);
                if oversized.load(Ordering::Relaxed) == 2 {
                    data["mounts"] = json!([]);
                }
            }
            Json(envelope(data))
        }}));
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let app = router.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let service = hyper_util::service::TowerToHyperService::new(app);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                }
            });
        }
    });
    Fixture {
        dir,
        host: Host {
            url: format!("https://localhost:{port}"),
            ca: ca_path,
            client_cert: cert_path,
            client_key: key_path,
            host_id: Some("host".into()),
            evidence_store_id: Some("store".into()),
        },
        gap_floor,
        storage_calls,
        oversized_storage,
        task,
    }
}
fn envelope(data: Value) -> Value {
    json!({"version":1,"request_id":"request","host_id":"host","evidence_store_id":"store","observed_at":chrono::Utc::now(),"responded_at":chrono::Utc::now(),"data":data})
}
fn app_config(f: &Fixture) -> Config {
    let mut c = Config {
        enabled: true,
        database: f.dir.path().join("state/gateway.db"),
        socket: f.dir.path().join("run/gateway.sock"),
        ..Config::default()
    };
    c.hosts.insert("pi".into(), f.host.clone());
    c
}

#[tokio::test]
async fn mtls_enforces_client_trust_and_host_identity() {
    let f = fixture().await;
    let client = HostClient::new(&f.host, 2).unwrap();
    let status = client
        .request::<syslens_protocol::Status>("/v1/status", None)
        .await
        .unwrap();
    assert_eq!(status.data.samples, 10);
    let mut wrong = f.host.clone();
    wrong.host_id = Some("another-host".into());
    assert!(
        HostClient::new(&wrong, 2)
            .unwrap()
            .request::<Value>("/v1/status", None)
            .await
            .unwrap_err()
            .contains("identity mismatch")
    );
    let public = syslens_gateway::client::tls_client(Some(&f.host.ca), None, None, 2).unwrap();
    assert!(
        public
            .get(format!("{}/v1/status", f.host.url))
            .send()
            .await
            .is_err()
    );
    let other = fixture().await;
    let mut untrusted = f.host.clone();
    untrusted.ca = other.host.ca.clone();
    let error = HostClient::new(&untrusted, 2)
        .unwrap()
        .request::<Value>("/v1/status", None)
        .await
        .unwrap_err();
    assert_eq!(error, "host connection failed");
    assert!(!error.contains("localhost"));
}
#[tokio::test]
async fn tool_loop_uses_selected_host_and_sessions_resume() {
    let f = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router=Router::new().route("/v1/chat/completions",post(|Json(body):Json<Value>|async move{
        let messages=body["messages"].as_array().unwrap();assert_eq!(body["model"],"test-model");
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["think"], false);
        let tool=messages.last().unwrap()["role"]=="tool";
        if tool {assert!(messages.last().unwrap()["content"].as_str().unwrap().contains("insufficient evidence"));Json(json!({"choices":[{"message":{"role":"assistant","content":"There is insufficient comparison history."}}]}))}
        else {Json(json!({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"memory","arguments":"{\"window\":{\"relative\":{\"value\":1,\"unit\":\"today\"}}}"}}]}}]}))}
    }));
    let model = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut config = app_config(&f);
    config.ai.enabled = true;
    config.ai.allow_insecure_http = true;
    config.ai.endpoint_url = format!("http://{address}/v1/chat/completions");
    config.ai.model = "test-model".into();
    let app = App::new(config).unwrap();
    let result = app
        .chat(ChatRequest {
            question: "Why is memory higher?".into(),
            host: Some("pi".into()),
            session: None,
        })
        .await
        .unwrap();
    assert_eq!(result["target"], "pi");
    assert_eq!(result["evidence_refs"].as_array().unwrap().len(), 1);
    let id = result["session"].as_str().unwrap().to_string();
    let followup = app
        .chat(ChatRequest {
            question: "What is missing?".into(),
            host: None,
            session: Some(id.clone()),
        })
        .await
        .unwrap();
    assert_eq!(followup["session"], id);
    model.abort();
    let failed = app
        .chat(ChatRequest {
            question: "why?".into(),
            host: None,
            session: Some(id),
        })
        .await
        .unwrap_err();
    assert_eq!(failed, "AI endpoint is unavailable");
    assert_eq!(
        app.operation("host-status", json!({"host":"pi"}))
            .await
            .unwrap()["data"]["samples"],
        10
    );
    app.poll_host("pi").await.unwrap();
}

#[tokio::test]
async fn contradictory_storage_model_output_falls_back_to_deterministic_answer() {
    let f = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let model_calls = Arc::new(AtomicI64::new(0));
    let calls = model_calls.clone();
    let router = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                assert!(body["tools"].is_null());
                assert!(body["tool_choice"].is_null());
                Json(json!({"choices":[{"message":{"role":"assistant","content":"The root filesystem decreased by 100 bytes."}}]}))
            }
        }),
    );
    let model = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut config = app_config(&f);
    config.ai.enabled = true;
    config.ai.allow_insecure_http = true;
    config.ai.endpoint_url = format!("http://{address}/v1/chat/completions");
    config.ai.model = "test-model".into();
    let app = App::new(config).unwrap();

    let result = app
        .chat(ChatRequest {
            question: "Why did storage increase from yesterday to today?".into(),
            host: Some("pi".into()),
            session: None,
        })
        .await
        .unwrap();

    assert_eq!(model_calls.load(Ordering::Relaxed), 1);
    assert_eq!(f.storage_calls.load(Ordering::Relaxed), 1);
    assert!(
        result["answer"]
            .as_str()
            .unwrap()
            .contains("increased by 100 bytes")
    );
    assert!(
        !result["answer"]
            .as_str()
            .unwrap()
            .contains("Model analysis:")
    );
    assert!(
        result["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value
                    .as_str()
                    .is_some_and(|text| text.contains("contradicted authoritative measurements"))
            })
    );
    model.abort();
}

#[tokio::test]
async fn model_failure_after_storage_prefetch_returns_and_saves_grounded_answer() {
    let f = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"temporarily unavailable"})),
            )
        }),
    );
    let model = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut config = app_config(&f);
    config.ai.enabled = true;
    config.ai.allow_insecure_http = true;
    config.ai.endpoint_url = format!("http://{address}/v1/chat/completions");
    config.ai.model = "test-model".into();
    let app = App::new(config).unwrap();

    let result = app
        .chat(ChatRequest {
            question: "Why did storage increase from yesterday to today?".into(),
            host: Some("pi".into()),
            session: None,
        })
        .await
        .unwrap();

    assert_eq!(f.storage_calls.load(Ordering::Relaxed), 1);
    assert_eq!(result["evidence_refs"].as_array().unwrap().len(), 1);
    assert!(
        result["answer"]
            .as_str()
            .unwrap()
            .contains("increased by 100 bytes")
    );
    assert!(
        result["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value.as_str().is_some_and(|text| {
                    text.contains("bounded storage model failed")
                        && text.contains("deterministic storage answer")
                })
            })
    );
    let saved = app
        .operation(
            "sessions",
            json!({"id":result["session"].as_str().unwrap()}),
        )
        .await
        .unwrap();
    let stored_response: Value =
        serde_json::from_str(saved["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(stored_response["answer"], result["answer"]);
    model.abort();
}

#[tokio::test]
async fn inferred_storage_uses_bounded_facts_only_model_request() {
    let f = fixture().await;
    f.oversized_storage.store(1, Ordering::Relaxed);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let model_calls = Arc::new(AtomicI64::new(0));
    let calls = model_calls.clone();
    let router = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                assert!(body["tools"].is_null());
                assert!(body["tool_choice"].is_null());
                assert_eq!(body["temperature"], 0);
                assert_eq!(body["max_tokens"], 256);
                assert_eq!(body["think"], false);
                assert!(body.to_string().len() < 32_768);
                let messages = body["messages"].as_array().unwrap();
                assert_eq!(messages.len(), 2);
                assert_eq!(messages[0]["role"], "system");
                assert_eq!(messages[1]["role"], "user");
                let content = messages[1]["content"].as_str().unwrap();
                assert!(content.contains("Why did storage increase from yesterday to today?"));
                assert!(content.contains("root_used_bytes_change"));
                Json(json!({"choices":[{"message":{"role":"assistant","content":"The bounded storage facts show the root filesystem increased; the evidence does not establish a more specific cause."}}]}))
            }
        }),
    );
    let model = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut config = app_config(&f);
    config.ai.enabled = true;
    config.ai.allow_insecure_http = true;
    config.ai.endpoint_url = format!("http://{address}/v1/chat/completions");
    config.ai.model = "test-model".into();
    let app = App::new(config).unwrap();

    let result = app
        .chat(ChatRequest {
            question: "Why did storage increase from yesterday to today?".into(),
            host: Some("pi".into()),
            session: None,
        })
        .await
        .unwrap();

    assert_eq!(model_calls.load(Ordering::Relaxed), 1);
    assert_eq!(f.storage_calls.load(Ordering::Relaxed), 1);
    assert_eq!(result["evidence_refs"].as_array().unwrap().len(), 1);
    assert!(
        result["answer"]
            .as_str()
            .unwrap()
            .contains("increased by 100 bytes")
    );
    assert!(
        result["answer"]
            .as_str()
            .unwrap()
            .contains("Model analysis:")
    );

    let saved = app
        .operation(
            "sessions",
            json!({"id":result["session"].as_str().unwrap()}),
        )
        .await
        .unwrap();
    let stored_response: Value =
        serde_json::from_str(saved["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(stored_response["answer"], result["answer"]);
    assert_eq!(stored_response["evidence_refs"], result["evidence_refs"]);
    model.abort();
}

#[tokio::test]
async fn oversized_storage_without_root_facts_skips_model_and_persists_limitation() {
    let f = fixture().await;
    f.oversized_storage.store(2, Ordering::Relaxed);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let model_calls = Arc::new(AtomicI64::new(0));
    let calls = model_calls.clone();
    let router = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                Json(json!({"choices":[{"message":{"role":"assistant","content":"unexpected model call"}}]}))
            }
        }),
    );
    let model = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut config = app_config(&f);
    config.ai.enabled = true;
    config.ai.allow_insecure_http = true;
    config.ai.endpoint_url = format!("http://{address}/v1/chat/completions");
    config.ai.model = "test-model".into();
    let app = App::new(config).unwrap();

    let result = app
        .chat(ChatRequest {
            question: "Why did storage increase from yesterday to today?".into(),
            host: Some("pi".into()),
            session: None,
        })
        .await
        .unwrap();

    assert_eq!(model_calls.load(Ordering::Relaxed), 0);
    assert_eq!(result["evidence_refs"].as_array().unwrap().len(), 1);
    assert!(
        result["answer"]
            .as_str()
            .unwrap()
            .contains("usable root-mount facts were unavailable")
    );
    assert!(
        result["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value.as_str().is_some_and(|text| {
                    text.contains("bounded storage model was not called")
                        && text.contains("Authoritative root-mount facts were unavailable")
                        && text.contains("Full evidence remains available")
                })
            })
    );

    let saved = app
        .operation(
            "sessions",
            json!({"id":result["session"].as_str().unwrap()}),
        )
        .await
        .unwrap();
    let stored_response: Value =
        serde_json::from_str(saved["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(stored_response["answer"], result["answer"]);
    assert_eq!(stored_response["evidence_refs"], result["evidence_refs"]);
    model.abort();
}

#[tokio::test]
async fn event_poll_recovers_from_a_host_replay_floor() {
    let f = fixture().await;
    f.gap_floor.store(5, Ordering::Relaxed);
    let app = App::new(app_config(&f)).unwrap();
    app.poll_host("pi").await.unwrap();
    let store = app.store.lock().unwrap();
    assert_eq!(store.cursor("pi").unwrap(), 5);
    let events = store.events(0).unwrap();
    assert_eq!(events["events"].as_array().unwrap().len(), 1);
    assert_eq!(events["events"][0]["event"]["kind"], "history_gap");
}
#[tokio::test]
async fn unix_socket_client_and_api_are_independent_of_ha() {
    let f = fixture().await;
    let c = app_config(&f);
    let socket = c.socket.clone();
    let server = tokio::spawn(syslens_gateway::daemon::run(c));
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let hosts = syslens_gateway::daemon::request(&socket, "hosts", json!({}))
        .await
        .unwrap();
    assert_eq!(hosts["hosts"][0]["name"], "pi");
    let status = syslens_gateway::daemon::request(&socket, "host-status", json!({"host":"pi"}))
        .await
        .unwrap();
    assert_eq!(status["data"]["samples"], 10);
    let metadata = fs::metadata(&socket).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let failed = syslens_gateway::daemon::request(
        &socket,
        "chat",
        json!({"question":"why?","host":"pi","session":null}),
    )
    .await
    .unwrap_err();
    assert!(failed.contains("AI is disabled"));
    server.abort();
    let _ = server.await;
}
