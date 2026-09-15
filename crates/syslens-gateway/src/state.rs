use crate::{Result, config};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use syslens_protocol::Envelope;

pub struct Store {
    pub conn: Connection,
    path: PathBuf,
    _lock: fs::File,
}
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        config::private_dir(path.parent().ok_or("invalid state location")?)?;
        let lock_path = sidecar(path, ".lock");
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|_| "cannot open state lock")?;
        config::private(&lock_path, false)?;
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("gateway state already has an owner".into());
        }
        if !path.exists() {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| "cannot create gateway state")?;
        }
        config::private(path, false)?;
        for suffix in ["-wal", "-shm"] {
            let p = sidecar(path, suffix);
            if p.exists() {
                config::private(&p, false)?;
            }
        }
        let conn = Connection::open(path).map_err(|_| "cannot open gateway state")?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db_error)?;
        if version > 1 {
            return Err("gateway database was created by a newer version".into());
        }
        conn.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(db_error)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,host TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS exchanges(id INTEGER PRIMARY KEY,session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,question TEXT NOT NULL,answer TEXT NOT NULL,created INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS exchange_session ON exchanges(session,id); CREATE TABLE IF NOT EXISTS host_state(name TEXT PRIMARY KEY,host_id TEXT,store_id TEXT,cursor INTEGER NOT NULL DEFAULT 0,error TEXT,updated INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,host TEXT NOT NULL,host_id TEXT NOT NULL,store_id TEXT NOT NULL,cursor INTEGER NOT NULL,event TEXT NOT NULL,received INTEGER NOT NULL,UNIQUE(host_id,store_id,cursor)); CREATE INDEX IF NOT EXISTS event_retention ON events(received); CREATE TABLE IF NOT EXISTS gaps(id INTEGER PRIMARY KEY,host TEXT NOT NULL,reason TEXT NOT NULL,created INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);").map_err(db_error)?;
        let s = Self {
            conn,
            path: path.into(),
            _lock: lock,
        };
        s.conn
            .pragma_update(None, "user_version", 1)
            .map_err(db_error)?;
        s.secure()?;
        Ok(s)
    }
    fn secure(&self) -> Result<()> {
        for suffix in ["", "-wal", "-shm"] {
            let p = sidecar(&self.path, suffix);
            if p.exists() {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600))
                    .map_err(|_| "cannot secure gateway state")?;
            }
        }
        Ok(())
    }
    pub fn session(&self, session: Option<&str>, host: Option<&str>) -> Result<(String, String)> {
        if let Some(id) = session {
            let stale: bool = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM settings WHERE key=?)",
                    [format!("stale_session:{id}")],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if stale {
                return Err("session target was re-enrolled; start a new session".into());
            }
            let target: String = self
                .conn
                .query_row("SELECT host FROM sessions WHERE id=?", [id], |r| r.get(0))
                .optional()
                .map_err(db_error)?
                .ok_or("session not found")?;
            if host.is_some_and(|h| h != target) {
                return Err("session target cannot change".into());
            }
            return Ok((id.into(), target));
        }
        let host = host.ok_or("host is required for a new session")?;
        let id = crate::id();
        let now = chrono::Utc::now().timestamp();
        self.conn
            .execute(
                "INSERT INTO sessions VALUES(?,?,?,?)",
                params![id, host, now, now],
            )
            .map_err(db_error)?;
        Ok((id, host.into()))
    }
    pub fn history(&self, id: &str) -> Result<(Vec<Value>, bool)> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT question,answer FROM exchanges WHERE session=? ORDER BY id DESC LIMIT 9",
            )
            .map_err(db_error)?;
        let rows = stmt
            .query_map([id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(db_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_error)?;
        let mut result = Vec::new();
        let mut size = 0;
        let mut omitted = rows.len() > 8;
        for (q, a) in rows.into_iter().take(8) {
            if size + q.len() + a.len() > 24_000 {
                omitted = true;
                break;
            }
            size += q.len() + a.len();
            result.push((q, a));
        }
        result.reverse();
        Ok((
            result
                .into_iter()
                .flat_map(|(q, a)| {
                    [
                        json!({"role":"user","content":q}),
                        json!({"role":"assistant","content":a}),
                    ]
                })
                .collect(),
            omitted,
        ))
    }
    pub fn save(&mut self, id: &str, q: &str, answer: &Value) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let tx = self.conn.transaction().map_err(db_error)?;
        tx.execute(
            "INSERT INTO exchanges(session,question,answer,created) VALUES(?,?,?,?)",
            params![id, q, answer.to_string(), now],
        )
        .map_err(db_error)?;
        tx.execute("UPDATE sessions SET updated=? WHERE id=?", params![now, id])
            .map_err(db_error)?;
        tx.commit().map_err(db_error)
    }
    pub fn sessions(&self, id: Option<&str>) -> Result<Value> {
        if let Some(id) = id {
            let target: Option<String> = self
                .conn
                .query_row("SELECT host FROM sessions WHERE id=?", [id], |r| r.get(0))
                .optional()
                .map_err(db_error)?;
            let (messages, omitted) = self.history(id)?;
            return Ok(
                json!({"id":id,"host":target.ok_or("session not found")?,"messages":messages,"older_context_omitted":omitted}),
            );
        }
        let mut s = self
            .conn
            .prepare("SELECT id,host,updated FROM sessions ORDER BY updated DESC LIMIT 100")
            .map_err(db_error)?;
        let items=s.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"host":r.get::<_,String>(1)?,"updated":r.get::<_,i64>(2)?}))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        Ok(json!({"sessions":items}))
    }
    pub fn identity<T>(&self, name: &str, e: &Envelope<T>) -> Result<()> {
        let existing: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT host_id,store_id FROM host_state WHERE name=? AND host_id IS NOT NULL",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        if existing.is_some_and(|(h, s)| h != e.host_id || s != e.evidence_store_id) {
            return Err("host identity changed; re-enrollment required".into());
        }
        self.conn.execute("INSERT INTO host_state(name,host_id,store_id) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET host_id=excluded.host_id,store_id=excluded.store_id",params![name,e.host_id,e.evidence_store_id]).map_err(db_error)?;
        Ok(())
    }
    pub fn cursor(&self, name: &str) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT cursor FROM host_state WHERE name=?", [name], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_error)?
            .unwrap_or(0))
    }
    pub fn ingest(&mut self, name: &str, e: &Envelope<syslens_protocol::EventPage>) -> Result<()> {
        self.identity(name, e)?;
        let old = self.cursor(name)?;
        let mut last = 0;
        if e.data.events.len() > 256 {
            return Err("invalid event page".into());
        }
        for event in &e.data.events {
            let c = event["cursor"].as_i64().ok_or("invalid event cursor")?;
            if c <= last {
                return Err("non-monotonic event page".into());
            }
            last = c;
        }
        if (e.data.events.is_empty() && e.data.next_cursor != old)
            || (!e.data.events.is_empty() && e.data.next_cursor != last)
            || (e.data.has_more && last <= old)
        {
            return Err("invalid event page cursor".into());
        }
        let now = chrono::Utc::now().timestamp();
        let tx = self.conn.transaction().map_err(db_error)?;
        for event in &e.data.events {
            tx.execute("INSERT OR IGNORE INTO events(host,host_id,store_id,cursor,event,received) VALUES(?,?,?,?,?,?)",params![name,e.host_id,e.evidence_store_id,event["cursor"].as_i64(),event.to_string(),now]).map_err(db_error)?;
        }
        tx.execute(
            "UPDATE host_state SET cursor=?,error=NULL,updated=? WHERE name=?",
            params![last.max(old), now, name],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)
    }
    pub fn host_error(&self, name: &str, error: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute("INSERT INTO host_state(name,error,updated) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET error=excluded.error,updated=excluded.updated",params![name,error,now]).map_err(db_error)?;
        Ok(())
    }
    pub fn history_gap(&mut self, name: &str, floor: i64) -> Result<()> {
        let old = self.cursor(name)?;
        if floor <= old {
            return Err("invalid history gap floor".into());
        }
        let now = chrono::Utc::now().timestamp();
        let tx = self.conn.transaction().map_err(db_error)?;
        tx.execute(
            "INSERT INTO gaps(host,reason,created) VALUES(?,?,?)",
            params![
                name,
                format!("source history gap from cursor {old} through {floor}"),
                now
            ],
        )
        .map_err(db_error)?;
        let (host_id, store_id): (String, String) = tx
            .query_row(
                "SELECT host_id,store_id FROM host_state WHERE name=?",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_error)?;
        tx.execute("INSERT OR IGNORE INTO events(host,host_id,store_id,cursor,event,received) VALUES(?,?,?,?,?,?)",params![name,host_id,format!("gap:{store_id}"),floor,json!({"kind":"history_gap","previous_cursor":old,"replay_floor":floor,"created_at":now}).to_string(),now]).map_err(db_error)?;
        tx.execute(
            "UPDATE host_state SET cursor=? WHERE name=?",
            params![floor, name],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)
    }
    pub fn reenroll<T>(&mut self, name: &str, e: &Envelope<T>) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let tx = self.conn.transaction().map_err(db_error)?;
        tx.execute("INSERT INTO settings(key,value) SELECT 'stale_session:'||id,'true' FROM sessions WHERE host=? ON CONFLICT(key) DO NOTHING",[name]).map_err(db_error)?;
        tx.execute("INSERT INTO gaps(host,reason,created) VALUES(?,'host explicitly re-enrolled; prior evidence continuity ended',?)",params![name,now]).map_err(db_error)?;
        tx.execute("INSERT INTO host_state(name,host_id,store_id,cursor,error,updated) VALUES(?,?,?,0,NULL,?) ON CONFLICT(name) DO UPDATE SET host_id=excluded.host_id,store_id=excluded.store_id,cursor=0,error=NULL,updated=excluded.updated",params![name,e.host_id,e.evidence_store_id,now]).map_err(db_error)?;
        tx.commit().map_err(db_error)
    }
    pub fn events(&self, after: i64) -> Result<Value> {
        if after < 0 {
            return Err("invalid cursor".into());
        }
        let mut s = self
            .conn
            .prepare("SELECT id,host,event,received FROM events WHERE id>? ORDER BY id LIMIT 101")
            .map_err(db_error)?;
        let mut items=s.query_map([after],|r|Ok(json!({"cursor":r.get::<_,i64>(0)?,"host":r.get::<_,String>(1)?,"event":serde_json::from_str::<Value>(&r.get::<_,String>(2)?).unwrap_or(Value::Null),"received_at":r.get::<_,i64>(3)?}))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        let mut has_more = items.len() > 100;
        items.truncate(100);
        let mut bytes = 0;
        let count = items
            .iter()
            .take_while(|item| {
                bytes += item.to_string().len();
                bytes < 180_000
            })
            .count();
        if count == 0 && !items.is_empty() {
            return Err("stored event exceeds response limit".into());
        }
        has_more |= count < items.len();
        items.truncate(count);
        let next = items
            .last()
            .and_then(|v| v["cursor"].as_i64())
            .unwrap_or(after);
        let mut gaps = self
            .conn
            .prepare("SELECT host,reason,created FROM gaps ORDER BY id DESC LIMIT 20")
            .map_err(db_error)?;
        let gaps=gaps.query_map([],|r|Ok(json!({"host":r.get::<_,String>(0)?,"reason":r.get::<_,String>(1)?,"created_at":r.get::<_,i64>(2)?}))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        let floor: i64 = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key='replay_floor'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(db_error)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok(
            json!({"events":items,"next_cursor":next.max(floor),"has_more":has_more,"history_gap":after<floor,"replay_floor":floor,"source_gaps":gaps}),
        )
    }
    pub fn model(&self, default: &str) -> Result<String> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key='model'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_error)?
            .unwrap_or(default.into()))
    }
    pub fn set_model(&self, model: &str) -> Result<()> {
        if model.is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
            return Err("invalid model name".into());
        }
        self.conn.execute("INSERT INTO settings VALUES('model',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[model]).map_err(db_error)?;
        Ok(())
    }
    pub fn cleanup(&self, sessions: u32, events: u32) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let expired: Option<i64> = self
            .conn
            .query_row(
                "SELECT max(id) FROM events WHERE received<?",
                [now - i64::from(events) * 86400],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if let Some(floor) = expired {
            self.conn.execute("INSERT INTO settings VALUES('replay_floor',?) ON CONFLICT(key) DO UPDATE SET value=CAST(max(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",[floor.to_string()]).map_err(db_error)?;
        }
        self.conn
            .execute(
                "DELETE FROM sessions WHERE updated<?",
                [now - i64::from(sessions) * 86400],
            )
            .map_err(db_error)?;
        self.conn
            .execute(
                "DELETE FROM events WHERE received<?",
                [now - i64::from(events) * 86400],
            )
            .map_err(db_error)?;
        self.conn
            .execute(
                "DELETE FROM gaps WHERE created<?",
                [now - i64::from(events) * 86400],
            )
            .map_err(db_error)?;
        Ok(())
    }
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
fn db_error(_: rusqlite::Error) -> String {
    "gateway state operation failed".into()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn page(cursor: i64) -> Envelope<syslens_protocol::EventPage> {
        Envelope {
            version: 1,
            request_id: "request".into(),
            host_id: "host".into(),
            evidence_store_id: "store".into(),
            observed_at: chrono::Utc::now(),
            responded_at: chrono::Utc::now(),
            data: syslens_protocol::EventPage {
                events: vec![json!({"cursor":cursor,"created_at":10,"kind":"opened"})],
                next_cursor: cursor,
                has_more: false,
            },
        }
    }
    #[test]
    fn event_replay_is_idempotent_survives_restart_and_detects_replacement() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = d.path().join("events.sqlite");
        let mut s = Store::open(&path).unwrap();
        s.ingest("pi", &page(1)).unwrap();
        s.ingest("pi", &page(1)).unwrap();
        assert_eq!(s.events(0).unwrap()["events"].as_array().unwrap().len(), 1);
        drop(s);
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.cursor("pi").unwrap(), 1);
        let mut wrong = page(2);
        wrong.evidence_store_id = "replacement".into();
        assert!(s.ingest("pi", &wrong).is_err());
        assert_eq!(s.cursor("pi").unwrap(), 1);
        s.history_gap("pi", 5).unwrap();
        assert_eq!(s.cursor("pi").unwrap(), 5);
        s.ingest("pi", &page(6)).unwrap();
        assert_eq!(s.events(0).unwrap()["events"].as_array().unwrap().len(), 3);
    }
    #[test]
    fn retention_never_reuses_central_cursors() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut s = Store::open(&d.path().join("state.db")).unwrap();
        s.ingest("pi", &page(1)).unwrap();
        s.conn.execute("UPDATE events SET received=0", []).unwrap();
        s.cleanup(30, 185).unwrap();
        assert_eq!(s.events(0).unwrap()["history_gap"], true);
        s.ingest("pi", &page(2)).unwrap();
        assert_eq!(s.events(1).unwrap()["events"][0]["cursor"], 2);
    }
    #[test]
    fn state_has_one_writer_and_private_sidecars() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = d.path().join("custom.db");
        let _s = Store::open(&p).unwrap();
        assert!(Store::open(&p).is_err());
        for suffix in ["", "-wal", "-shm"] {
            config::private(&sidecar(&p, suffix), false).unwrap();
        }
    }
    #[test]
    fn reenrollment_invalidates_old_session() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut s = Store::open(&d.path().join("s.db")).unwrap();
        let (id, _) = s.session(None, Some("pi")).unwrap();
        s.ingest("pi", &page(1)).unwrap();
        s.reenroll("pi", &page(1)).unwrap();
        assert!(s.session(Some(&id), None).is_err());
    }
    #[test]
    fn sessions_resume_target_and_retention() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut s = Store::open(&d.path().join("state.db")).unwrap();
        let (id, _) = s.session(None, Some("pi")).unwrap();
        assert!(s.session(Some(&id), Some("pc")).is_err());
        s.save(&id, "why?", &json!({"answer":"evidence"})).unwrap();
        drop(s);
        let s = Store::open(&d.path().join("state.db")).unwrap();
        assert_eq!(s.history(&id).unwrap().0.len(), 2);
        s.conn.execute("UPDATE sessions SET updated=0", []).unwrap();
        s.cleanup(30, 185).unwrap();
        assert!(s.session(Some(&id), None).is_err());
    }
}
