use std::{collections::HashMap, time::Duration};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, http::HeaderValue, Message}, MaybeTlsStream, WebSocketStream};
use crate::protocol::SUBPROTOCOL;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
struct Command { id: String, method: String, payload: Value, reply: oneshot::Sender<Result<Value>> }
#[derive(Clone)]
pub struct ControlClient { tx: mpsc::Sender<Command> }

impl ControlClient {
    pub async fn connect(url: String) -> Result<Self> {
        let (tx, rx) = mpsc::channel(64);
        // Connect before returning so a bad URL fails startup. The same task stays socket owner.
        let socket = open_socket(&url).await?;
        tokio::spawn(Self::actor(url, socket, rx));
        Ok(Self { tx })
    }
    pub async fn call(&self, method: &str, payload: Value) -> Result<Value> {
        self.call_timeout(method,payload,Duration::from_secs(10)).await
    }
    pub async fn call_timeout(&self, method: &str, payload: Value, timeout: Duration) -> Result<Value> {
        let (reply,rx) = oneshot::channel();
        self.tx.send(Command { id: uuid::Uuid::new_v4().to_string(), method:method.to_owned(), payload, reply }).await.map_err(|_| anyhow!("control client stopped"))?;
        tokio::time::timeout(timeout,rx).await.context("upstream request timeout")??.map_err(|e| anyhow!("upstream response lost: {e}"))
    }
    async fn open_if_needed(url:&str, socket:&mut Option<Socket>) -> Result<()> {
        if socket.is_none() { *socket = Some(open_socket(url).await?); } Ok(())
    }
    async fn actor(url:String, initial:Socket, mut rx:mpsc::Receiver<Command>) {
        let mut socket=Some(initial); let mut pending:HashMap<String,oneshot::Sender<Result<Value>>>=HashMap::new();
        loop {
            tokio::select! {
                command=rx.recv()=> {
                    let Some(cmd)=command else { break };
                    if let Err(e)=Self::open_if_needed(&url,&mut socket).await { let _=cmd.reply.send(Err(e)); continue; }
                    let frame=json!({"type":"request","id":cmd.id,"method":cmd.method,"payload":cmd.payload}).to_string();
                    let id=cmd.id.clone(); pending.insert(cmd.id,cmd.reply);
                    if let Err(e)=socket.as_mut().unwrap().send(Message::Text(frame)).await {
                        if let Some(reply)=pending.remove(&id) { let _=reply.send(Err(e.into())); }
                        socket=None;
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
