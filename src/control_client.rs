use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};
use tokio::time::Instant;
use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, http::HeaderValue, Message}, MaybeTlsStream, WebSocketStream};
use crate::protocol::SUBPROTOCOL;

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
pub struct ControlClient { tx: mpsc::Sender<Command>, call_timeout: Duration }

impl ControlClient {
    /// `call_timeout` bounds every call and each (re)connect attempt of this upstream.
    pub fn new(id: String, url: String, options: Options, events: broadcast::Sender<UpstreamEvent>) -> Self {
        let call_timeout = options.call_timeout;
        let upstream = id;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(Self::actor(url, options, events, upstream, rx));
        Self { tx, call_timeout }
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
    async fn actor(url:String, options:Options, events:broadcast::Sender<UpstreamEvent>, upstream:String, mut rx:mpsc::Receiver<Command>) {
        let call_timeout = options.call_timeout;
        let mut socket:Option<Socket>=None; let mut pending:HashMap<String,oneshot::Sender<Result<UpstreamReply>>>=HashMap::new();
        let mut failures=0u32; let mut retry_at:Option<Instant>=None; let mut last_error=String::new();
        let mut pings=tokio::time::interval_at(Instant::now()+options.ping_interval, options.ping_interval); pings.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut idle=tokio::time::interval(std::cmp::max(options.idle_timeout / 5, Duration::from_millis(1))); idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_activity=Instant::now();
        loop {
            tokio::select! {
                _=pings.tick(), if socket.is_some()=> {
                    if let Some(s)=socket.as_mut() {
                        if s.send(Message::Ping(Vec::new())).await.is_err() { socket=None; }
                    }
                }
                _=idle.tick(), if socket.is_some()=> {
                    if last_activity.elapsed() < options.idle_timeout { continue; }
                    let _=socket.as_mut().unwrap().send(Message::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame { code:1001.into(), reason:"idle timeout".into() }))).await;
                    socket=None;
                    for (_,reply) in pending.drain() { let _=reply.send(Err(anyhow!("upstream idle timeout"))); }
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
                            Ok(opened)=>{ last_activity=Instant::now(); socket=Some(opened); failures=0; retry_at=None; last_error.clear(); }
                            Err(e)=>{
                                failures=failures.saturating_add(1); retry_at=Some(Instant::now()+backoff_delay(failures)); last_error=format!("{e:#}");
                                let _=cmd.reply.send(Err(e)); continue;
                            }
                        }
                    }
                    let frame=json!({"type":"request","id":cmd.id,"method":cmd.method,"payload":cmd.payload}).to_string();
                    // Calls that timed out on the caller side must not accumulate forever.
                    pending.retain(|_,reply|!reply.is_closed());
                    let id=cmd.id.clone(); pending.insert(cmd.id,cmd.reply);
                    let sent=match tokio::time::timeout(call_timeout,socket.as_mut().unwrap().send(Message::Text(frame))).await {
                        Ok(result)=>result.map_err(anyhow::Error::from),
                        Err(_)=>Err(anyhow!("upstream send timed out")),
                    };
                    if let Err(e)=sent {
                        if let Some(reply)=pending.remove(&id) { let _=reply.send(Err(e)); }
                        socket=None;
                        for (_,reply) in pending.drain() { let _=reply.send(Err(anyhow!("upstream socket closed"))); }
                    }
                }
                incoming=async { socket.as_mut().unwrap().next().await }, if socket.is_some()=> {
                    match incoming {
                        Some(Ok(Message::Pong(_)))=> { last_activity=Instant::now(); }
                        Some(Ok(Message::Text(text)))=> {
                            last_activity=Instant::now();
                            let Ok(message)=serde_json::from_str::<Value>(&text) else { continue };
                            match message["type"].as_str() {
                                Some("response")=> {
                                    if let Some(reply)=message["id"].as_str().and_then(|id|pending.remove(id)) {
                                        let error = message.get("error").cloned().filter(|e| !e.is_null());
                                        let payload = message.get("payload").cloned().unwrap_or(Value::Null);
                                        let _=reply.send(Ok(UpstreamReply { payload, error }));
                                    }
                                }
                                Some("event")=> { let _=events.send(UpstreamEvent { upstream:upstream.clone(), event:message }); }
                                _=>{}
                            }
                        }
                        Some(Ok(Message::Ping(_)))=> {
                            last_activity=Instant::now();
                            if let Some(s)=socket.as_mut() { let _=s.send(Message::Pong(Vec::new())).await; }
                        }
                        Some(Ok(Message::Close(_)))|None|Some(Err(_))=> {
                            socket=None;
                            for (_,reply) in pending.drain() { let _=reply.send(Err(anyhow!("upstream socket closed"))); }
                        }
                        _=>{}
                    }
                }
            }
        }
    }
}
async fn open_socket(url:&str)->Result<Socket> {
    let url=format!("{}/api/control",url.trim_end_matches('/'));
    let url=url.strip_prefix("http://").map(|rest|format!("ws://{rest}")).or_else(||url.strip_prefix("https://").map(|rest|format!("wss://{rest}"))).unwrap_or(url);
    let mut request=url.as_str().into_client_request()?;
    request.headers_mut().insert("sec-websocket-protocol",HeaderValue::from_static(SUBPROTOCOL));
    let (mut socket,response)=connect_async(request).await.context("upstream WebSocket connect")?;
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
    fn backoff_grows_exponentially_and_is_capped() {
        let ms: Vec<u128> = (1..=8).map(|n| backoff_delay(n).as_millis()).collect();
        assert_eq!(ms, [200, 400, 800, 1600, 3200, 5000, 5000, 5000]);
        assert_eq!(backoff_delay(u32::MAX), BACKOFF_MAX);
        assert_eq!(backoff_delay(0), BACKOFF_BASE);
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
