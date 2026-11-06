use std::{collections::HashMap, time::Duration};
use tokio::time::Instant;
use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, http::HeaderValue, Message}, MaybeTlsStream, WebSocketStream};
use crate::protocol::SUBPROTOCOL;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
struct Command { id: String, method: String, payload: Value, reply: oneshot::Sender<Result<Value>> }

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
    pub fn new(url: String, call_timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(Self::actor(url, call_timeout, rx));
        Self { tx, call_timeout }
    }
    pub async fn call(&self, method: &str, payload: Value) -> Result<Value> {
        self.call_timeout(method, payload, self.call_timeout).await
    }
    pub async fn call_timeout(&self, method: &str, payload: Value, timeout: Duration) -> Result<Value> {
        let (reply,rx) = oneshot::channel();
        let send = self.tx.send(Command { id: uuid::Uuid::new_v4().to_string(), method:method.to_owned(), payload, reply });
        // The actor may be stuck connecting; never let a full queue outlast the caller's timeout.
        tokio::time::timeout(timeout, send).await.context("upstream request timeout")?.map_err(|_| anyhow!("control client stopped"))?;
        // Errors the actor reports (connect failure, socket closed, ...) pass through unchanged.
        tokio::time::timeout(timeout,rx).await.context("upstream request timeout")?.map_err(|_| anyhow!("upstream response lost"))?
    }
    async fn actor(url:String, call_timeout:Duration, mut rx:mpsc::Receiver<Command>) {
        let mut socket:Option<Socket>=None; let mut pending:HashMap<String,oneshot::Sender<Result<Value>>>=HashMap::new();
        let mut failures=0u32; let mut retry_at:Option<Instant>=None; let mut last_error=String::new();
        loop {
            tokio::select! {
                command=rx.recv()=> {
                    let Some(cmd)=command else { break };
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
                            Ok(opened)=>{ socket=Some(opened); failures=0; retry_at=None; last_error.clear(); }
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
                        Some(Ok(Message::Text(text)))=> {
                            let Ok(message)=serde_json::from_str::<Value>(&text) else { continue };
                            if message["type"]=="response" {
                                if let Some(reply)=message["id"].as_str().and_then(|id|pending.remove(id)) { let _=reply.send(Ok(message["payload"].clone())); }
                            }
                            // Events and unmatched responses do not belong to a request oneshot.
                        }
                        Some(Ok(Message::Ping(bytes)))=> { if let Some(s)=socket.as_mut() { let _=s.send(Message::Pong(bytes)).await; } }
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

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        let ms: Vec<u128> = (1..=8).map(|n| backoff_delay(n).as_millis()).collect();
        assert_eq!(ms, [200, 400, 800, 1600, 3200, 5000, 5000, 5000]);
        assert_eq!(backoff_delay(u32::MAX), BACKOFF_MAX);
        assert_eq!(backoff_delay(0), BACKOFF_BASE);
    }
}
