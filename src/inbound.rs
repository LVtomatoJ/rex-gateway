use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use anyhow::Result;
use axum::{extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State}, http::{header, HeaderMap, StatusCode}, response::Response, routing::get, Router};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use crate::{auth::{Authenticator, self}, control_client::ControlClient, pool::UpstreamPool, protocol::{translate_session_id, SUBPROTOCOL}};

type Clients = Arc<HashMap<String,Arc<ControlClient>>>;
#[derive(Clone)]
struct AppState { pool:UpstreamPool, clients:Clients, tokens:Arc<HashMap<String,Vec<String>>> }

pub async fn serve(listen:SocketAddr,pool:UpstreamPool,clients:HashMap<String,Arc<ControlClient>>,tokens:Arc<HashMap<String,Vec<String>>>)->Result<()> {
    let state=AppState{pool,clients:Arc::new(clients),tokens};
    let router=Router::new().route("/api/control",get(upgrade)).with_state(state);
    let listener=tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen,"gateway listening");
    axum::serve(listener,router).await?; Ok(())
}
async fn upgrade(ws:WebSocketUpgrade,headers:HeaderMap,State(state):State<AppState>)->Result<Response,StatusCode> {
    if headers.get(header::SEC_WEBSOCKET_PROTOCOL).and_then(|v|v.to_str().ok()).map(|v|v.split(',').any(|p|p.trim()==SUBPROTOCOL))!=Some(true) { return Err(StatusCode::BAD_REQUEST); }
    let Some(acl)=headers.get(header::AUTHORIZATION).and_then(|v|v.to_str().ok()).and_then(|h|Authenticator::new((*state.tokens).clone()).acl(Some(h))) else { return Err(StatusCode::UNAUTHORIZED); };
    Ok(ws.protocols([SUBPROTOCOL]).on_upgrade(move|socket|serve_agent(socket,state,acl)))
}
async fn serve_agent(mut socket:WebSocket,state:AppState,acl:Vec<String>) {
    match socket.recv().await {
        Some(Ok(Message::Text(text))) if serde_json::from_str::<Value>(&text).ok().and_then(|v|v.get("type").and_then(Value::as_str).map(str::to_owned))==Some("hello".into())=>{},
        _=>{let _=socket.send(Message::Close(None)).await;return},
    }
    let welcome=json!({"type":"welcome","protocol":SUBPROTOCOL,"limits":{"max_message_bytes":1048576},"client":{"id":format!("client:{}",uuid::Uuid::new_v4()),"reconnect_token":uuid::Uuid::new_v4().to_string()},"api_server_revision":11});
    if socket.send(Message::Text(welcome.to_string())).await.is_err(){return}
    let socket=Arc::new(Mutex::new(socket));
    let mut seq: u64=0;
    loop {
        let request={let mut guard=socket.lock().await;let Ok(Some(Ok(Message::Text(text))))=tokio::time::timeout(std::time::Duration::from_secs(60),guard.recv()).await else{break};text};
        let message:Value=match serde_json::from_str(&request){Ok(v)=>v,Err(_)=>continue};
        let id=message["id"].clone();
        if message["type"]!="request" { continue; }
        let method=message["method"].as_str().unwrap_or_default().to_owned();
        let payload=message["payload"].clone();
        let response=handle(&state,&acl,&method,payload).await.unwrap_or_else(|e|json!({"error":e.to_string()}));
        seq+=1;
        let response=json!({"type":"response","id":id,"seq":seq,"payload":response});
        if socket.lock().await.send(Message::Text(response.to_string())).await.is_err(){break}
    }
}
async fn handle(state:&AppState,acl:&[String],method:&str,mut payload:Value)->Result<Value,String> {
    let online=state.pool.list_allowed_online(acl).await;
    if method=="session.list" {
        let mut sessions=Vec::new();
        for upstream in online {
            let client=state.clients.get(&upstream.id).ok_or("upstream client missing")?;
            let mut result=client.call(method,json!({})).await.map_err(|e|e.to_string())?;
            for session in result["sessions"].as_array_mut().ok_or("upstream session.list omitted sessions")? {
                if translate_session_id(session,&upstream.id,true) {sessions.push(session.take());}
            }
        }
        return Ok(json!({"sessions":sessions}));
    }
    let owner=match payload.get("session_id").and_then(Value::as_str).and_then(crate::protocol::unwrap_session_id) {
        Some((upstream,_))=>upstream.to_owned(),
        None=>payload.get("host").and_then(Value::as_str).map(str::to_owned).or_else(||method.strip_prefix("session.").filter(|_|method=="session.create").and_then(|_|online.first().map(|u|u.id.clone()))).or_else(||online.first().map(|u|u.id.clone())).ok_or("no allowed online upstream")?
    };
    if !auth::Authenticator::permits(acl,&owner) || !online.iter().any(|u|u.id==owner) { return Err(format!("upstream {owner} is not allowed and online")); }
    if payload.get("session_id").is_some() && !translate_session_id(&mut payload,&owner,false) { return Err("invalid or mismatched namespaced session_id".into()); }
    if let Some(object)=payload.as_object_mut(){object.remove("host");}
    let mut response=state.clients.get(&owner).ok_or("upstream client missing")?.call(method,payload).await.map_err(|e|e.to_string())?;
    // Session create methods in revision 11 return the id directly or alongside session metadata.
    if let Some(object)=response.as_object_mut() { for value in object.values_mut() { translate_session_id(value,&owner,true); } }
    if method=="session.create" || method=="session.bootstrap" { translate_session_id(&mut response,&owner,true); }
    Ok(response)
}
