use std::{collections::{BTreeSet, HashMap}, sync::{Arc, Mutex}, time::Duration};
use tokio::time::Instant;
use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};
use crate::protocol::{MAX_MESSAGE_BYTES, SUBPROTOCOL};

/// Shared client-side WebSocket limits for upstream control and data connects.
pub fn websocket_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE_BYTES),
        max_frame_size: Some(MAX_MESSAGE_BYTES),
        ..Default::default()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub call_timeout: Duration,
    pub ping_interval: Duration,
    pub idle_timeout: Duration,
}

/// Result of one upstream control RPC. Rex puts success data in `response.payload` and
/// failures in a sibling top-level `response.error` (`{code,message,status}`) with no
/// payload. Both shapes must reach the agent unchanged in kind.
#[derive(Clone, Debug)]
pub struct UpstreamReply {
    pub payload: Value,
    pub error: Option<Value>,
}

impl UpstreamReply {
    pub fn is_frame_error(&self) -> bool { self.error.as_ref().is_some_and(|e| !e.is_null()) }
    pub fn payload_has_error(&self) -> bool { self.payload.get("error").is_some() }
    /// True for Rex frame-level errors and payload-level `{"error":…}` (used by tests / some
    /// upstreams). Transport failures are `Err` from [`ControlClient::call`], not this.
    pub fn is_application_error(&self) -> bool { self.is_frame_error() || self.payload_has_error() }
}

#[derive(Clone, Debug)]
pub struct UpstreamEvent { pub upstream: String, pub event: Value }

/// Synthetic broadcast frame type the actor emits after it re-subscribed a reconnected
/// upstream control socket (events in the gap were not delivered).
pub const RESUBSCRIBED_EVENT_TYPE: &str = "gateway.upstream_resubscribed";

/// Effect a successful control RPC has on the shared upstream connection's event
/// subscription. Rex subscriptions are additive per connection: `session.attach` /
/// `session.bootstrap` add one session (or every event for `event_scope` `all`),
/// `session.attach_all` adds every session (`session`) or every event (`all`), and
/// `session.detach` removes only an explicit per-session attach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionEffect {
    Attach { session: String, all: bool },
    /// `session.bootstrap` without `session_id`: Rex picks the session (`view.session_id`).
    BootstrapDefault { all: bool },
    AttachAll { all: bool },
    Detach { session: String },
}

impl SubscriptionEffect {
    /// Classifies a request as Rex would see it (session ids already de-namespaced).
    pub fn classify(method: &str, payload: &Value) -> Option<Self> {
        let scope_all = || match payload.get("event_scope").and_then(Value::as_str) {
            Some("all") => Some(true),
            Some("session") => Some(false),
            _ => None,
        };
        let session = || payload.get("session_id").and_then(Value::as_str).map(str::to_owned);
        match method {
            "session.attach" => Some(Self::Attach { session: session()?, all: scope_all()? }),
            "session.bootstrap" => Some(match session() {
                Some(session) => Self::Attach { session, all: scope_all()? },
                None => Self::BootstrapDefault { all: scope_all()? },
            }),
            "session.attach_all" => Some(Self::AttachAll { all: scope_all()? }),
            "session.detach" => Some(Self::Detach { session: session()? }),
            _ => None,
        }
    }

    /// Final effect once the successful response is known (fills the session Rex picked for
    /// a session-less bootstrap from `view.session_id`).
    pub fn resolve(&self, response: &Value) -> Option<Self> {
        match self {
            Self::BootstrapDefault { all } => match response.pointer("/view/session_id").and_then(Value::as_str) {
                Some(session) => Some(Self::Attach { session: session.to_owned(), all: *all }),
                None if *all => Some(Self::AttachAll { all: true }),
                None => None,
            },
            other => Some(other.clone()),
        }
    }
}

/// Union of event subscriptions that succeeded on one upstream control socket. Replayed after
/// a reconnect because Rex forgets them when the socket closes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subscriptions { pub all: bool, pub all_sessions: bool, pub sessions: BTreeSet<String> }

impl Subscriptions {
    pub fn is_empty(&self) -> bool { !self.all && !self.all_sessions && self.sessions.is_empty() }
    pub fn apply(&mut self, effect: &SubscriptionEffect) {
        match effect {
            SubscriptionEffect::Attach { session, all } => { self.sessions.insert(session.clone()); self.all |= *all; }
            SubscriptionEffect::BootstrapDefault { all } => { self.all |= *all; }
            SubscriptionEffect::AttachAll { all } => { if *all { self.all = true } else { self.all_sessions = true } }
            SubscriptionEffect::Detach { session } => { self.sessions.remove(session); }
        }
    }
    /// Requests that rebuild this subscription set on a fresh socket.
    pub fn replay(&self) -> Vec<(&'static str, Value)> {
        let mut calls = Vec::new();
        if self.all { calls.push(("session.attach_all", json!({"event_scope":"all"}))); }
        else if self.all_sessions { calls.push(("session.attach_all", json!({"event_scope":"session"}))); }
        for session in &self.sessions {
            calls.push(("session.attach", json!({"session_id":session,"event_scope":"session"})));
        }
        calls
    }
}

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
struct Command { id: String, method: String, payload: Value, reply: oneshot::Sender<Result<UpstreamReply>> }

/// Reconnect backoff after a failed connect: 200 ms doubling up to 5 s.
const BACKOFF_BASE: Duration = Duration::from_millis(200);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

fn backoff_delay(failures: u32) -> Duration {
    BACKOFF_BASE.saturating_mul(1u32 << failures.saturating_sub(1).min(8)).min(BACKOFF_MAX)
}

/// Lazily connecting, self-reconnecting control connection to one upstream Rex server.
///
/// Creating a client never touches the network and never fails: the actor task opens the
/// WebSocket when the first call arrives (and again after any socket loss). Failed connects
/// back off exponentially so a dead upstream is not hammered, and fail fast meanwhile.
#[derive(Clone)]
pub struct ControlClient { tx: mpsc::Sender<Command>, call_timeout: Duration, replay_filter: Arc<std::sync::Mutex<Option<ReplayFilter>>> }

/// Narrows the subscription set replayed after a reconnect (upstream id, recorded set).
pub type ReplayFilter = Arc<dyn Fn(&str, &mut Subscriptions) + Send + Sync>;

impl ControlClient {
    /// `call_timeout` bounds every call and each (re)connect attempt of this upstream.
    pub fn new(id: String, url: String, options: Options, events: broadcast::Sender<UpstreamEvent>) -> Self {
        let call_timeout = options.call_timeout;
        let upstream = id;
        let (tx, rx) = mpsc::channel(64);
        let replay_filter = Arc::new(std::sync::Mutex::new(None));
        tokio::spawn(Self::actor(url, options, events, upstream, rx, replay_filter.clone()));
        Self { tx, call_timeout, replay_filter }
    }
    /// Install the filter applied to the recorded subscriptions before each reconnect replay.
    /// The first one installed wins.
    pub fn set_replay_filter(&self, filter: ReplayFilter) {
        let mut guard = self.replay_filter.lock().expect("replay filter");
        if guard.is_none() { *guard = Some(filter); }
    }
    pub async fn call(&self, method: &str, payload: Value) -> Result<UpstreamReply> {
        self.call_timeout(method, payload, self.call_timeout).await
    }
    pub async fn call_timeout(&self, method: &str, payload: Value, timeout: Duration) -> Result<UpstreamReply> {
        let (reply,rx) = oneshot::channel();
        let send = self.tx.send(Command { id: uuid::Uuid::new_v4().to_string(), method:method.to_owned(), payload, reply });
        // The actor may be stuck connecting; never let a full queue outlast the caller's timeout.
        tokio::time::timeout(timeout, send).await.context("upstream request timeout")?.map_err(|_| anyhow!("control client stopped"))?;
        // Errors the actor reports (connect failure, socket closed, ...) pass through unchanged.
        tokio::time::timeout(timeout,rx).await.context("upstream request timeout")?.map_err(|_| anyhow!("upstream response lost"))?
    }
    async fn actor(url:String, options:Options, events:broadcast::Sender<UpstreamEvent>, upstream:String, mut rx:mpsc::Receiver<Command>, replay_filter:Arc<std::sync::Mutex<Option<ReplayFilter>>>) {
        let call_timeout = options.call_timeout;
        let mut socket:Option<Socket>=None;
        // Each in-flight RPC keeps its inserted Instant so we can fail hung ones even when
        // the socket stays alive on ping/pong alone (caller timeout already closed the oneshot).
        let mut pending:HashMap<String,PendingReply>=HashMap::new();
        let mut failures=0u32; let mut retry_at:Option<Instant>=None; let mut last_error=String::new();
        let mut pings=tokio::time::interval_at(Instant::now()+options.ping_interval, options.ping_interval); pings.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut idle=tokio::time::interval(std::cmp::max(options.idle_timeout / 5, Duration::from_millis(1))); idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_activity=Instant::now();
        // Successful subscriptions on this upstream, replayed after every reconnect.
        let mut subscriptions=Subscriptions::default();
        let mut ever_connected=false;
        loop {
            tokio::select! {
                _=pings.tick(), if socket.is_some()=> {
                    // Opportunistic reap: drop caller-timed-out slots and fail age-exceeded ones.
                    reap_pending(&mut pending, call_timeout);
                    if let Some(s)=socket.as_mut() {
                        if s.send(Message::Ping(Vec::new())).await.is_err() { socket=None; }
                    }
                }
                _=idle.tick(), if socket.is_some()=> {
                    reap_pending(&mut pending, call_timeout);
                    if last_activity.elapsed() < options.idle_timeout { continue; }
                    let _=socket.as_mut().unwrap().send(Message::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame { code:1001.into(), reason:"idle timeout".into() }))).await;
                    socket=None;
                    for (_,pending) in pending.drain() { let _=pending.reply.send(Err(anyhow!("upstream idle timeout"))); }
                }
                command=rx.recv()=> {
                    let Some(cmd)=command else { break };
                    last_activity=Instant::now();
                    if socket.is_none() {
                        if let Some(at)=retry_at.filter(|at|Instant::now()<*at) {
                            let wait=at.saturating_duration_since(Instant::now()).as_millis();
                            let _=cmd.reply.send(Err(anyhow!("upstream unavailable (retry in {wait} ms): {last_error}")));
                            continue;
                        }
                        let opened=match tokio::time::timeout(call_timeout,open_socket(&url)).await {
                            Ok(result)=>result,
                            Err(_)=>Err(anyhow!("upstream connect timed out after {} ms",call_timeout.as_millis())),
                        };
                        match opened {
                            Ok(mut opened)=>{
                                last_activity=Instant::now(); failures=0; retry_at=None; last_error.clear();
                                // Drop what no agent holds any more (Rex cannot undo attach_all / scope all).
                                let filter=replay_filter.lock().expect("replay filter").clone();
                                if let Some(filter)=filter { filter(&upstream,&mut subscriptions); }
                                if ever_connected && !subscriptions.is_empty() {
                                    // Rex dropped this socket's subscriptions with the old socket.
                                    let mut replayed=true;
                                    for (method,payload) in subscriptions.replay() {
                                        let frame=json!({"type":"request","id":format!("resubscribe-{}",uuid::Uuid::new_v4()),"method":method,"payload":payload}).to_string();
                                        let sent=tokio::time::timeout(call_timeout,opened.send(Message::Text(frame))).await;
                                        if !matches!(sent,Ok(Ok(()))) { replayed=false; break; }
                                    }
                                    if replayed {
                                        let _=events.send(UpstreamEvent { upstream:upstream.clone(), event:json!({"type":RESUBSCRIBED_EVENT_TYPE}) });
                                    } else {
                                        tracing::warn!(upstream=%upstream,"re-subscribe after reconnect failed");
                                    }
                                }
                                ever_connected=true;
                                socket=Some(opened);
                            }
                            Err(e)=>{
                                failures=failures.saturating_add(1); retry_at=Some(Instant::now()+backoff_delay(failures)); last_error=format!("{e:#}");
                                let _=cmd.reply.send(Err(e)); continue;
                            }
                        }
                    }
                    let frame=json!({"type":"request","id":cmd.id,"method":cmd.method,"payload":cmd.payload}).to_string();
                    // Calls that timed out on the caller side must not accumulate forever.
                    reap_pending(&mut pending, call_timeout);
                    let id=cmd.id.clone();
                    let effect=SubscriptionEffect::classify(&cmd.method,&cmd.payload);
                    pending.insert(cmd.id, PendingReply { inserted: Instant::now(), reply: cmd.reply, effect });
                    let sent=match tokio::time::timeout(call_timeout,socket.as_mut().unwrap().send(Message::Text(frame))).await {
                        Ok(result)=>result.map_err(anyhow::Error::from),
                        Err(_)=>Err(anyhow!("upstream send timed out")),
                    };
                    if let Err(e)=sent {
                        if let Some(p)=pending.remove(&id) { let _=p.reply.send(Err(e)); }
                        socket=None;
                        for (_,p) in pending.drain() { let _=p.reply.send(Err(anyhow!("upstream socket closed"))); }
                    }
                }
                incoming=async { socket.as_mut().unwrap().next().await }, if socket.is_some()=> {
                    match incoming {
                        // Keepalive only: ping/pong must not refresh application-idle.
                        Some(Ok(Message::Pong(_)))=> {}
                        Some(Ok(Message::Text(text)))=> {
                            last_activity=Instant::now();
                            let Ok(message)=serde_json::from_str::<Value>(&text) else { continue };
                            match message["type"].as_str() {
                                Some("response")=> {
                                    if let Some(p)=message["id"].as_str().and_then(|id|pending.remove(id)) {
                                        let error = message.get("error").cloned().filter(|e| !e.is_null());
                                        let payload = message.get("payload").cloned().unwrap_or(Value::Null);
                                        if let Some(effect)=p.effect.as_ref().filter(|_| error.is_none() && payload.get("error").is_none()).and_then(|e| e.resolve(&payload)) {
                                            subscriptions.apply(&effect);
                                        }
                                        let _=p.reply.send(Ok(UpstreamReply { payload, error }));
                                    }
                                }
                                Some("event")=> { let _=events.send(UpstreamEvent { upstream:upstream.clone(), event:message }); }
                                _=>{}
                            }
                        }
                        Some(Ok(Message::Ping(_)))=> {
                            if let Some(s)=socket.as_mut() { let _=s.send(Message::Pong(Vec::new())).await; }
                        }
                        Some(Ok(Message::Close(_)))|None|Some(Err(_))=> {
                            socket=None;
                            for (_,p) in pending.drain() { let _=p.reply.send(Err(anyhow!("upstream socket closed"))); }
                        }
                        _=>{}
                    }
                }
            }
        }
    }
}

struct PendingReply {
    inserted: Instant,
    reply: oneshot::Sender<Result<UpstreamReply>>,
    effect: Option<SubscriptionEffect>,
}

/// Drop slots whose caller already timed out, and fail any still-open slot older than
/// `call_timeout`. Keeps the pending map from growing when an upstream accepts a request
/// but never answers while the socket stays alive on keepalive alone.
fn reap_pending(pending: &mut HashMap<String, PendingReply>, call_timeout: Duration) {
    let now = Instant::now();
    let mut expired = Vec::new();
    pending.retain(|id, entry| {
        if entry.reply.is_closed() {
            return false;
        }
        if now.saturating_duration_since(entry.inserted) >= call_timeout {
            expired.push(id.clone());
            return true; // remove after send below (need ownership of Sender)
        }
        true
    });
    for id in expired {
        if let Some(entry) = pending.remove(&id) {
            let _ = entry.reply.send(Err(anyhow!("upstream response timed out")));
        }
    }
}

async fn open_socket(url:&str)->Result<Socket> {
    let url=format!("{}/api/control",url.trim_end_matches('/'));
    let url=url.strip_prefix("http://").map(|rest|format!("ws://{rest}")).or_else(||url.strip_prefix("https://").map(|rest|format!("wss://{rest}"))).unwrap_or(url);
    let mut request=url.as_str().into_client_request()?;
    request.headers_mut().insert("sec-websocket-protocol",HeaderValue::from_static(SUBPROTOCOL));
    let (mut socket,response)=connect_async_with_config(request, Some(websocket_config()), false).await.context("upstream WebSocket connect")?;
    if response.headers().get("sec-websocket-protocol").and_then(|v|v.to_str().ok())!=Some(SUBPROTOCOL) { bail!("upstream did not select {SUBPROTOCOL}"); }
    socket.send(Message::Text(json!({"type":"hello"}).to_string())).await?;
    while let Some(frame)=socket.next().await {
        if let Message::Text(text)=frame? {
            let value:Value=serde_json::from_str(&text)?;
            if value["type"]=="welcome" { return Ok(socket); }
        }
    }
    bail!("upstream closed before welcome")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mock_upstream(ping_count: tokio::sync::mpsc::Sender<usize>) -> String {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream,_)=listener.accept().await.unwrap();
            let mut socket=tokio_tungstenite::accept_hdr_async(stream, |_: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| { response.headers_mut().insert("sec-websocket-protocol", SUBPROTOCOL.parse().unwrap()); Ok(response) }).await.unwrap();
            socket.next().await;
            socket.send(Message::Text(json!({"type":"welcome"}).to_string())).await.unwrap();
            let mut pings=0usize;
            while let Some(Ok(frame))=socket.next().await {
                match frame {
                    Message::Text(text)=> { let request:Value=serde_json::from_str(&text).unwrap();
                        socket.send(Message::Text(json!({"type":"event","seq":4,"payload":{"session_id":"session:test"}}).to_string())).await.unwrap();
                        socket.send(Message::Text(json!({"type":"response","id":request["id"],"payload":{"ok":true}}).to_string())).await.unwrap();
                    }
                    Message::Ping(_)=> { pings+=1; let _=ping_count.send(pings).await; socket.send(Message::Pong(Vec::new())).await.unwrap(); }
                    _=>{}
                }
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn forwards_events_and_keeps_correlation_separate() {
        let (tx,_rx)=tokio::sync::mpsc::channel(1);
        let url=mock_upstream(tx).await;
        let (events,mut received)=broadcast::channel(4);
        let client=ControlClient::new("local".into(),url,Options { call_timeout:Duration::from_secs(1), ping_interval:Duration::from_secs(10), idle_timeout:Duration::from_secs(30) },events);
        assert_eq!(client.call("session.list",json!({})).await.unwrap().payload,json!({"ok":true}));
        let event=received.recv().await.unwrap();
        assert_eq!(event.upstream,"local");
        assert_eq!(event.event["payload"]["session_id"],"session:test");
    }

    async fn mock_upstream_frame_error() -> String {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream,_)=listener.accept().await.unwrap();
            let mut socket=tokio_tungstenite::accept_hdr_async(stream, |_: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| { response.headers_mut().insert("sec-websocket-protocol", SUBPROTOCOL.parse().unwrap()); Ok(response) }).await.unwrap();
            socket.next().await;
            socket.send(Message::Text(json!({"type":"welcome"}).to_string())).await.unwrap();
            while let Some(Ok(frame))=socket.next().await {
                if let Message::Text(text)=frame {
                    let request:Value=serde_json::from_str(&text).unwrap();
                    socket.send(Message::Text(json!({"type":"response","id":request["id"],"error":{"code":"method_not_found","message":"nope","status":404}}).to_string())).await.unwrap();
                }
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn preserves_rex_frame_level_errors() {
        let url=mock_upstream_frame_error().await;
        let (events,_)=broadcast::channel(4);
        let client=ControlClient::new("local".into(),url,Options { call_timeout:Duration::from_secs(1), ping_interval:Duration::from_secs(10), idle_timeout:Duration::from_secs(30) },events);
        let reply=client.call("no.such",json!({})).await.unwrap();
        assert!(reply.payload.is_null(), "{reply:?}");
        assert_eq!(reply.error, Some(json!({"code":"method_not_found","message":"nope","status":404})));
        assert!(reply.is_application_error());
    }

    #[test]
    fn websocket_config_caps_message_and_frame_at_1_mib() {
        let cfg = websocket_config();
        assert_eq!(cfg.max_message_size, Some(MAX_MESSAGE_BYTES));
        assert_eq!(cfg.max_frame_size, Some(MAX_MESSAGE_BYTES));
        assert_eq!(MAX_MESSAGE_BYTES, 1_048_576);
    }

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        let ms: Vec<u128> = (1..=8).map(|n| backoff_delay(n).as_millis()).collect();
        assert_eq!(ms, [200, 400, 800, 1600, 3200, 5000, 5000, 5000]);
        assert_eq!(backoff_delay(u32::MAX), BACKOFF_MAX);
        assert_eq!(backoff_delay(0), BACKOFF_BASE);
    }

    async fn mock_upstream_never_responds() -> String {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream,_)=listener.accept().await.unwrap();
            let mut socket=tokio_tungstenite::accept_hdr_async(stream, |_: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| { response.headers_mut().insert("sec-websocket-protocol", SUBPROTOCOL.parse().unwrap()); Ok(response) }).await.unwrap();
            socket.next().await;
            socket.send(Message::Text(json!({"type":"welcome"}).to_string())).await.unwrap();
            // Accept requests and answer only with Pong so the socket stays "active".
            while let Some(Ok(frame))=socket.next().await {
                match frame {
                    Message::Ping(_)=> { let _=socket.send(Message::Pong(Vec::new())).await; }
                    Message::Text(_)=> { /* swallow; never respond */ }
                    _=>{}
                }
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn reaps_hung_pending_when_upstream_never_responds() {
        let url=mock_upstream_never_responds().await;
        let (events,_)=broadcast::channel(4);
        let client=ControlClient::new(
            "silent".into(),
            url,
            Options {
                call_timeout: Duration::from_millis(150),
                ping_interval: Duration::from_millis(40),
                idle_timeout: Duration::from_secs(30),
            },
            events,
        );
        let err = client.call("session.list", json!({})).await.expect_err("must time out");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("upstream request timeout") || msg.contains("upstream response timed out") || msg.contains("upstream response lost"),
            "unexpected error: {msg}"
        );
        // Give the actor a ping/idle tick so closed oneshots are reaped without tearing the socket.
        tokio::time::sleep(Duration::from_millis(120)).await;
        // A second call against the same silent-but-alive upstream must still time out cleanly:
        // hung-pending reap must not leave the actor wedged.
        let err2 = client.call("session.list", json!({})).await.expect_err("second call also times out");
        let msg2 = format!("{err2:#}");
        assert!(
            msg2.contains("upstream request timeout") || msg2.contains("upstream response timed out") || msg2.contains("upstream response lost"),
            "unexpected error: {msg2}"
        );
    }

    async fn mock_upstream_ping_only() -> String {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream,_)=listener.accept().await.unwrap();
            let mut socket=tokio_tungstenite::accept_hdr_async(stream, |_: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| { response.headers_mut().insert("sec-websocket-protocol", SUBPROTOCOL.parse().unwrap()); Ok(response) }).await.unwrap();
            socket.next().await;
            socket.send(Message::Text(json!({"type":"welcome"}).to_string())).await.unwrap();
            // Keep the socket alive on ping/pong alone; never emit application text.
            while let Some(Ok(frame))=socket.next().await {
                match frame {
                    Message::Ping(_)=> { let _=socket.send(Message::Pong(Vec::new())).await; }
                    Message::Pong(_)=> {}
                    Message::Text(_)=> { /* swallow RPC; no response/event */ }
                    _=>{}
                }
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn application_idle_closes_despite_ping_pong() {
        let url=mock_upstream_ping_only().await;
        let (events,_)=broadcast::channel(4);
        let client=ControlClient::new(
            "keepalive-only".into(),
            url,
            Options {
                // call_timeout longer than idle so the pending oneshot survives until idle close.
                call_timeout: Duration::from_millis(800),
                ping_interval: Duration::from_millis(40),
                idle_timeout: Duration::from_millis(150),
            },
            events,
        );
        let err = client.call("session.list", json!({})).await.expect_err("must idle-close");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("upstream idle timeout"),
            "expected application-idle close while ping/pong kept flowing, got: {msg}"
        );
    }

    #[test]
    fn reap_pending_drops_closed_and_ages_out_open() {
        let (tx_closed, rx_closed) = oneshot::channel::<Result<UpstreamReply>>();
        drop(rx_closed); // caller already gone
        let (tx_open, _rx_open) = oneshot::channel::<Result<UpstreamReply>>();
        let old = Instant::now() - Duration::from_secs(10);
        let mut pending = HashMap::from([
            ("closed".into(), PendingReply { inserted: Instant::now(), reply: tx_closed, effect: None }),
            ("aged".into(), PendingReply { inserted: old, reply: tx_open, effect: None }),
        ]);
        reap_pending(&mut pending, Duration::from_secs(1));
        assert!(pending.is_empty(), "closed and aged entries must be removed");
    }

    #[test]
    fn classifies_and_replays_subscriptions() {
        let c = SubscriptionEffect::classify;
        assert_eq!(c("session.attach", &json!({"session_id":"session:a","event_scope":"session"})), Some(SubscriptionEffect::Attach { session: "session:a".into(), all: false }));
        assert_eq!(c("session.bootstrap", &json!({"session_id":"session:a","event_scope":"all"})), Some(SubscriptionEffect::Attach { session: "session:a".into(), all: true }));
        assert_eq!(c("session.bootstrap", &json!({"event_scope":"session"})), Some(SubscriptionEffect::BootstrapDefault { all: false }));
        assert_eq!(c("session.attach", &json!({"session_id":"session:a"})), None, "no event_scope: Rex rejects, nothing to track");
        assert_eq!(c("session.attach_all", &json!({"event_scope":"bogus"})), None);
        assert_eq!(c("session.detach", &json!({"session_id":"session:a"})), Some(SubscriptionEffect::Detach { session: "session:a".into() }));
        assert_eq!(c("session.list", &json!({})), None);
        assert_eq!(SubscriptionEffect::BootstrapDefault { all: false }.resolve(&json!({"view":{"session_id":"session:p"}})), Some(SubscriptionEffect::Attach { session: "session:p".into(), all: false }));
        let mut subs = Subscriptions::default();
        assert!(subs.is_empty() && subs.replay().is_empty());
        subs.apply(&SubscriptionEffect::Attach { session: "session:a".into(), all: false });
        subs.apply(&SubscriptionEffect::Attach { session: "session:b".into(), all: false });
        subs.apply(&SubscriptionEffect::Detach { session: "session:b".into() });
        subs.apply(&SubscriptionEffect::AttachAll { all: false });
        assert_eq!(subs.replay(), vec![
            ("session.attach_all", json!({"event_scope":"session"})),
            ("session.attach", json!({"session_id":"session:a","event_scope":"session"})),
        ]);
        subs.apply(&SubscriptionEffect::AttachAll { all: true });
        assert_eq!(subs.replay()[0], ("session.attach_all", json!({"event_scope":"all"})));
    }

    /// Every connection reports its requests; `test.drop` closes the socket without answering
    /// and attaching `session:bad` gets a Rex frame error.
    async fn mock_upstream_recording(seen: tokio::sync::mpsc::UnboundedSender<(usize, String, Value)>) -> String {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut connection=0usize;
            loop {
                let Ok((stream,_))=listener.accept().await else { return };
                connection+=1;
                let seen=seen.clone();
                let conn=connection;
                tokio::spawn(async move {
                    let mut socket=tokio_tungstenite::accept_hdr_async(stream, |_: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| { response.headers_mut().insert("sec-websocket-protocol", SUBPROTOCOL.parse().unwrap()); Ok(response) }).await.unwrap();
                    while let Some(Ok(Message::Text(text)))=socket.next().await {
                        let message:Value=serde_json::from_str(&text).unwrap();
                        match message["type"].as_str() {
                            Some("hello")=>{ socket.send(Message::Text(json!({"type":"welcome"}).to_string())).await.unwrap(); }
                            Some("request")=>{
                                let method=message["method"].as_str().unwrap().to_owned();
                                let _=seen.send((conn, method.clone(), message["payload"].clone()));
                                if method=="test.drop" { return; }
                                let reply=if message["payload"]["session_id"]=="session:bad" {
                                    json!({"type":"response","id":message["id"],"error":{"code":"session_not_found","message":"nope","status":404}})
                                } else {
                                    json!({"type":"response","id":message["id"],"payload":{}})
                                };
                                socket.send(Message::Text(reply.to_string())).await.unwrap();
                            }
                            _=>{}
                        }
                    }
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn replays_successful_subscriptions_after_reconnect_and_announces_it() {
        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let url = mock_upstream_recording(seen_tx).await;
        let (events, mut events_rx) = broadcast::channel(16);
        let options = Options { call_timeout: Duration::from_millis(500), ping_interval: Duration::from_secs(20), idle_timeout: Duration::from_secs(120) };
        let client = ControlClient::new("up".into(), url, options, events);
        client.call("session.attach", json!({"session_id":"session:a","event_scope":"session"})).await.unwrap();
        let rejected = client.call("session.attach", json!({"session_id":"session:bad","event_scope":"session"})).await.unwrap();
        assert!(rejected.is_frame_error());
        assert!(client.call("test.drop", json!({})).await.is_err(), "socket closed without reply");
        client.call("server.version", json!({})).await.unwrap();
        let mut second = Vec::new();
        while let Ok(Some((conn, method, payload))) = tokio::time::timeout(Duration::from_millis(200), seen.recv()).await {
            if conn == 2 { second.push((method, payload)); }
        }
        assert_eq!(second, vec![
            ("session.attach".to_owned(), json!({"session_id":"session:a","event_scope":"session"})),
            ("server.version".to_owned(), json!({})),
        ], "only the successful attach is replayed, before the new call");
        let notice = events_rx.try_recv().expect("resubscribe notice");
        assert_eq!((notice.upstream.as_str(), &notice.event), ("up", &json!({"type":RESUBSCRIBED_EVENT_TYPE})));
    }

    #[tokio::test]
    async fn replay_filter_drops_subscriptions_nobody_holds() {
        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let url = mock_upstream_recording(seen_tx).await;
        let (events, _events_rx) = broadcast::channel(16);
        let options = Options { call_timeout: Duration::from_millis(500), ping_interval: Duration::from_secs(20), idle_timeout: Duration::from_secs(120) };
        let client = ControlClient::new("up".into(), url, options, events);
        // Stale: scope all and session:b are no longer held; session:a and attach_all session are.
        client.set_replay_filter(Arc::new(|upstream: &str, subs: &mut Subscriptions| {
            assert_eq!(upstream, "up");
            subs.all = false;
            subs.sessions.retain(|s| s == "session:a");
        }));
        client.set_replay_filter(Arc::new(|_: &str, subs: &mut Subscriptions| *subs = Subscriptions::default()));
        client.call("session.attach_all", json!({"event_scope":"all"})).await.unwrap();
        client.call("session.attach_all", json!({"event_scope":"session"})).await.unwrap();
        client.call("session.attach", json!({"session_id":"session:a","event_scope":"session"})).await.unwrap();
        client.call("session.attach", json!({"session_id":"session:b","event_scope":"session"})).await.unwrap();
        assert!(client.call("test.drop", json!({})).await.is_err());
        client.call("server.version", json!({})).await.unwrap();
        let mut second = Vec::new();
        while let Ok(Some((conn, method, payload))) = tokio::time::timeout(Duration::from_millis(200), seen.recv()).await {
            if conn == 2 { second.push((method, payload)); }
        }
        assert_eq!(second, vec![
            ("session.attach_all".to_owned(), json!({"event_scope":"session"})),
            ("session.attach".to_owned(), json!({"session_id":"session:a","event_scope":"session"})),
            ("server.version".to_owned(), json!({})),
        ], "first filter wins; stale all and session:b are not replayed");
    }
}


/// Shared, mutable registry of lazy upstream control clients (Manual + discovered).
#[derive(Clone, Default)]
pub struct ClientMap { inner: Arc<Mutex<HashMap<String, Arc<ControlClient>>>> }

impl ClientMap {
    pub fn new() -> Self { Self::default() }
    pub fn insert(&self, id: String, client: Arc<ControlClient>) { self.inner.lock().expect("clients").insert(id, client); }
    pub fn get(&self, id: &str) -> Option<Arc<ControlClient>> { self.inner.lock().expect("clients").get(id).cloned() }
    pub fn remove(&self, id: &str) -> Option<Arc<ControlClient>> { self.inner.lock().expect("clients").remove(id) }
    pub fn contains(&self, id: &str) -> bool { self.inner.lock().expect("clients").contains_key(id) }
    pub fn snapshot(&self) -> HashMap<String, Arc<ControlClient>> { self.inner.lock().expect("clients").clone() }
}
