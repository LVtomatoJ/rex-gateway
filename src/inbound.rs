use std::{borrow::Cow, collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, client::IntoClientRequest, http::HeaderValue},
};

use crate::{
    auth::{self, Authenticator},
    control_client::ControlClient,
    data::{decode_hello, TicketMap},
    metrics::{Gauge, Metrics},
    pool::UpstreamPool,
    status,
    protocol::{translate_session_id, SUBPROTOCOL},
};

const DATA_SUBPROTOCOL: &str = "rex.data.terminal.v1";
type Clients = Arc<HashMap<String, Arc<ControlClient>>>;

#[derive(Clone)]
struct AppState {
    pool: UpstreamPool,
    clients: Clients,
    tokens: Arc<HashMap<String, Vec<String>>>,
    tickets: TicketMap,
    metrics: Arc<Metrics>,
}

pub async fn serve(
    listen: SocketAddr,
    pool: UpstreamPool,
    clients: HashMap<String, Arc<ControlClient>>,
    tokens: Arc<HashMap<String, Vec<String>>>,
    tickets: TicketMap,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let state = AppState { pool, clients: Arc::new(clients), tokens, tickets, metrics };
    let router = router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "gateway listening");
    axum::serve(listener, router).await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/control", get(control_upgrade))
        .route("/api/data", get(data_upgrade))
        .route("/status", get(status_handler))
        .with_state(state)
}

/// `GET /status`: bearer-authenticated JSON snapshot, filtered by the token's ACL.
async fn status_handler(headers: HeaderMap, State(state): State<AppState>) -> Response {
    let bearer = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    let Some(acl) = Authenticator::new((*state.tokens).clone()).acl(bearer) else {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")]).into_response();
    };
    let upstreams = state.pool.list_allowed(&acl).await;
    let body = status::build(&upstreams, state.tickets.pending(), state.metrics.snapshot(), std::time::Instant::now());
    Json(body).into_response()
}

fn authenticate(headers: &HeaderMap, state: &AppState, protocol: &str) -> Result<(Vec<String>, String), StatusCode> {
    let selected = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|p| p.trim() == protocol)) == Some(true);
    if !selected { return Err(StatusCode::BAD_REQUEST); }
    let bearer = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let acl = Authenticator::new((*state.tokens).clone()).acl(Some(bearer)).ok_or(StatusCode::UNAUTHORIZED)?;
    Ok((acl, bearer.to_owned()))
}

async fn control_upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    let (acl, owner) = authenticate(&headers, &state, SUBPROTOCOL)?;
    Ok(ws.protocols([SUBPROTOCOL]).on_upgrade(move |socket| serve_agent(socket, state, acl, owner)))
}

async fn serve_agent(mut socket: WebSocket, state: AppState, acl: Vec<String>, owner: String) {
    let _active = state.metrics.track(Gauge::Control);
    match socket.recv().await {
        Some(Ok(Message::Text(text)))
            if serde_json::from_str::<Value>(&text).ok()
                .and_then(|v| v.get("type").and_then(Value::as_str).map(str::to_owned))
                == Some("hello".into()) => {}
        _ => {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    }
    let welcome = json!({"type":"welcome","protocol":SUBPROTOCOL,"limits":{"max_message_bytes":1048576},"client":{"id":format!("client:{}",uuid::Uuid::new_v4()),"reconnect_token":uuid::Uuid::new_v4().to_string()},"api_server_revision":11});
    if socket.send(Message::Text(welcome.to_string())).await.is_err() { return; }
    let socket = Arc::new(Mutex::new(socket));
    let mut seq = 0;
    loop {
        let request = {
            let mut guard = socket.lock().await;
            let Ok(Some(Ok(Message::Text(text)))) = tokio::time::timeout(Duration::from_secs(60), guard.recv()).await else { break };
            text
        };
        let message: Value = match serde_json::from_str(&request) { Ok(v) => v, Err(_) => continue };
        let id = message["id"].clone();
        if message["type"] != "request" { continue; }
        let method = message["method"].as_str().unwrap_or_default().to_owned();
        let response = handle(&state, &acl, &owner, &method, message["payload"].clone()).await
            .unwrap_or_else(|e| json!({"error":e.to_string()}));
        seq += 1;
        let response = json!({"type":"response","id":id,"seq":seq,"payload":response});
        if socket.lock().await.send(Message::Text(response.to_string())).await.is_err() { break; }
    }
}

async fn handle(state: &AppState, acl: &[String], owner: &str, method: &str, mut payload: Value) -> Result<Value, String> {
    let online = state.pool.list_allowed_online(acl).await;
    if method == "session.list" {
        let mut sessions = Vec::new();
        for upstream in online {
            let client = state.clients.get(&upstream.id).ok_or("upstream client missing")?;
            let mut result = client.call(method, json!({})).await.map_err(|e| e.to_string())?;
            for session in result["sessions"].as_array_mut().ok_or("upstream session.list omitted sessions")? {
                if translate_session_id(session, &upstream.id, true) { sessions.push(session.take()); }
            }
        }
        return Ok(json!({"sessions":sessions}));
    }
    let owner_upstream = match payload.get("session_id").and_then(Value::as_str).and_then(crate::protocol::unwrap_session_id) {
        Some((upstream, _)) => upstream.to_owned(),
        None => payload.get("host").and_then(Value::as_str).map(str::to_owned)
            .or_else(|| method.strip_prefix("session.").filter(|_| method == "session.create").and_then(|_| online.first().map(|u| u.id.clone())))
            .or_else(|| online.first().map(|u| u.id.clone())).ok_or("no allowed online upstream")?,
    };
    if !auth::Authenticator::permits(acl, &owner_upstream) || !online.iter().any(|u| u.id == owner_upstream) {
        return Err(format!("upstream {owner_upstream} is not allowed and online"));
    }
    if payload.get("session_id").is_some() && !translate_session_id(&mut payload, &owner_upstream, false) {
        return Err("invalid or mismatched namespaced session_id".into());
    }
    if let Some(object) = payload.as_object_mut() { object.remove("host"); }
    let mut response = state.clients.get(&owner_upstream).ok_or("upstream client missing")?
        .call(method, payload).await.map_err(|e| e.to_string())?;
    if method == "data.connect" {
        let upstream_ticket = response.get("ticket").and_then(Value::as_str).ok_or("upstream data.connect omitted ticket")?;
        response["ticket"] = Value::String(state.tickets.insert(&owner_upstream, upstream_ticket, owner));
    }
    if let Some(object) = response.as_object_mut() {
        for value in object.values_mut() { translate_session_id(value, &owner_upstream, true); }
    }
    if method == "session.create" || method == "session.bootstrap" { translate_session_id(&mut response, &owner_upstream, true); }
    Ok(response)
}

async fn data_upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    let (_, owner) = authenticate(&headers, &state, DATA_SUBPROTOCOL)?;
    Ok(ws.protocols([DATA_SUBPROTOCOL]).on_upgrade(move |socket| proxy_data(socket, state, owner)))
}

async fn proxy_data(mut agent: WebSocket, state: AppState, owner: String) {
    let Some(Ok(Message::Binary(hello))) = agent.recv().await else {
        let _ = agent.send(Message::Binary(vec![0x82, 0x05].into())).await;
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1002, reason: Cow::Borrowed("malformed HELLO") }))).await;
        return;
    };
    let Some(external) = decode_hello(&hello) else {
        let _ = agent.send(Message::Binary(vec![0x82, 0x05].into())).await;
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1002, reason: Cow::Borrowed("malformed HELLO") }))).await;
        return;
    };
    let Some(ticket) = state.tickets.take(&external, &owner) else {
        let _ = agent.send(Message::Binary(vec![0x82, 0x01].into())).await;
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1008, reason: Cow::Borrowed("bad or used ticket") }))).await;
        return;
    };
    let Some(upstream) = state.pool.get(&ticket.upstream).await else {
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1011, reason: Cow::Borrowed("upstream unavailable") }))).await;
        return;
    };
    let url = format!("{}/api/data", upstream.url.trim_end_matches('/'));
    let url = url.strip_prefix("http://").map(|u| format!("ws://{u}"))
        .or_else(|| url.strip_prefix("https://").map(|u| format!("wss://{u}"))).unwrap_or(url);
    let mut request = match url.as_str().into_client_request().context("upstream data URL") {
        Ok(request) => request,
        Err(error) => { tracing::warn!(%error, "invalid upstream data URL"); return; }
    };
    request.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(DATA_SUBPROTOCOL));
    let mut upstream_socket = match connect_async(request).await {
        Ok((socket, _)) => socket,
        Err(error) => {
            tracing::warn!(%error, "upstream data connection failed");
            let _ = agent.send(Message::Close(Some(CloseFrame { code: 1011, reason: Cow::Borrowed("upstream connection failed") }))).await;
            return;
        }
    };
    let mut upstream_hello = vec![1];
    upstream_hello.extend(match base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &ticket.upstream_ticket) {
        Ok(bytes) => bytes,
        Err(_) => { let _ = agent.send(Message::Close(Some(CloseFrame { code: 1011, reason: Cow::Borrowed("invalid upstream ticket") }))).await; return; }
    });
    if upstream_socket.send(tungstenite::Message::Binary(upstream_hello.into())).await.is_err() { return; }

    let _active = state.metrics.track(Gauge::Data);
    let (mut upstream_sink, mut upstream_stream) = upstream_socket.split();
    let (mut agent_sink, mut agent_stream) = agent.split();
    loop {
        tokio::select! {
            incoming = agent_stream.next() => match incoming {
                Some(Ok(Message::Binary(bytes))) => if upstream_sink.send(tungstenite::Message::Binary(bytes)).await.is_err() { break; },
                Some(Ok(Message::Text(text))) => if upstream_sink.send(tungstenite::Message::Text(text.as_str().into())).await.is_err() { break; },
                Some(Ok(Message::Ping(bytes))) => if upstream_sink.send(tungstenite::Message::Ping(bytes)).await.is_err() { break; },
                Some(Ok(Message::Pong(bytes))) => if upstream_sink.send(tungstenite::Message::Pong(bytes)).await.is_err() { break; },
                Some(Ok(Message::Close(frame))) => {
                    let _ = upstream_sink.send(tungstenite::Message::Close(frame.map(to_upstream_close))).await;
                    break;
                }
                Some(Err(_)) | None => break,
            },
            outgoing = upstream_stream.next() => match outgoing {
                Some(Ok(tungstenite::Message::Binary(bytes))) => if agent_sink.send(Message::Binary(bytes)).await.is_err() { break; },
                Some(Ok(tungstenite::Message::Text(text))) => if agent_sink.send(Message::Text(text.as_str().into())).await.is_err() { break; },
                Some(Ok(tungstenite::Message::Ping(bytes))) => if agent_sink.send(Message::Ping(bytes)).await.is_err() { break; },
                Some(Ok(tungstenite::Message::Pong(bytes))) => if agent_sink.send(Message::Pong(bytes)).await.is_err() { break; },
                Some(Ok(tungstenite::Message::Close(frame))) => {
                    let _ = agent_sink.send(Message::Close(frame.map(to_agent_close))).await;
                    break;
                }
                Some(Ok(tungstenite::Message::Frame(_))) => {}
                Some(Err(_)) | None => break,
            }
        }
    }
}

fn to_upstream_close(frame: CloseFrame) -> tungstenite::protocol::CloseFrame {
    tungstenite::protocol::CloseFrame { code: frame.code.into(), reason: frame.reason.to_string().into() }
}

fn to_agent_close(frame: tungstenite::protocol::CloseFrame) -> CloseFrame {
    CloseFrame { code: frame.code.into(), reason: Cow::Owned(frame.reason.to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{Source, UpstreamState};
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_gateway() -> (SocketAddr, AppState) {
        let pool = UpstreamPool::new();
        pool.upsert("a", "http://a:1", Source::Manual).await;
        pool.upsert("b", "http://b:2", Source::Manual).await;
        pool.mark("a", UpstreamState::Online, Some(7), 1).await;
        pool.mark_failure("b", "refused".into()).await;
        let metrics = Metrics::new();
        let tokens = Arc::new(HashMap::from([
            ("all".to_owned(), vec!["*".to_owned()]),
            ("onlyb".to_owned(), vec!["b".to_owned()]),
        ]));
        let tickets = TicketMap::new(Duration::from_secs(30), 16, metrics.clone());
        let state = AppState { pool, clients: Arc::new(HashMap::new()), tokens, tickets, metrics };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr, state)
    }

    async fn get_status(addr: SocketAddr, auth: Option<&str>) -> (u16, String) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = auth.map(|a| format!("Authorization: {a}\r\n")).unwrap_or_default();
        stream.write_all(format!("GET /status HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let code = raw.split_whitespace().nth(1).unwrap().parse().unwrap();
        (code, raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned())
    }

    #[tokio::test]
    async fn status_requires_bearer_and_filters_by_acl() {
        let (addr, state) = spawn_gateway().await;
        assert_eq!(get_status(addr, None).await.0, 401);
        assert_eq!(get_status(addr, Some("Bearer nope")).await.0, 401);
        assert_eq!(get_status(addr, Some("all")).await.0, 401, "scheme required");

        state.tickets.insert("a", "t", "all");
        let _control = state.metrics.track(Gauge::Control);
        let (code, body) = get_status(addr, Some("Bearer all")).await;
        assert_eq!(code, 200);
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["upstreams"].as_array().unwrap().len(), 2);
        assert_eq!(json["upstreams"][0]["state"], "Online");
        assert_eq!(json["upstreams"][1]["last_error"], "refused");
        assert_eq!(json["counters"]["pending_tickets"], 1);
        assert_eq!(json["counters"]["tickets_issued"], 1);
        assert_eq!(json["counters"]["active_control_connections"], 1);

        let (code, body) = get_status(addr, Some("Bearer onlyb")).await;
        assert_eq!(code, 200);
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["upstreams"].as_array().unwrap().len(), 1);
        assert_eq!(json["upstreams"][0]["id"], "b");
    }
}
