use std::{borrow::Cow, net::SocketAddr, sync::Arc, time::Duration};

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
use tokio::sync::broadcast;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, client::IntoClientRequest, http::HeaderValue},
};

use crate::{
    auth::{self, Authenticator},
    pool::{UpstreamState, TagPreferences},
    control_client::{ClientMap, UpstreamEvent, UpstreamReply},
    data::{decode_hello, TicketMap},
    discovery::DiscoveryHealth,
    metrics::{Gauge, Metrics, OwnerLimiter},
    pool::UpstreamPool,
    status,
    sessions::{SessionStore, FORGOTTEN_ERROR},
    protocol::{namespace_and_record, translate_session_id, SUBPROTOCOL},
};

const DATA_SUBPROTOCOL: &str = "rex.data.terminal.v1";
/// Matches the control-plane welcome `limits.max_message_bytes` (and Rex itself).
const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// What the agent control response frame carries after a successful `handle`.
/// Gateway-originated failures stay `Err(String)` → `payload: {"error":…}` for
/// backward compatibility. Rex frame-level errors (`response.error`) are forwarded
/// as [`AgentReply::FrameError`] so agents see the same shape as talking to Rex.
enum AgentReply {
    Payload(Value),
    FrameError(Value),
}

fn reply_from_upstream(reply: UpstreamReply) -> AgentReply {
    if let Some(error) = reply.error.filter(|e| !e.is_null()) {
        AgentReply::FrameError(error)
    } else {
        AgentReply::Payload(reply.payload)
    }
}

#[derive(Clone)]
struct AppState {
    pool: UpstreamPool,
    clients: ClientMap,
    auth: Arc<Authenticator>,
    tickets: TicketMap,
    sessions: SessionStore,
    metrics: Arc<Metrics>,
    data_limiter: OwnerLimiter,
    control_limiter: OwnerLimiter,
    options: Options,
    events: broadcast::Sender<UpstreamEvent>,
    discovery: DiscoveryHealth,
}

/// Tunables of the inbound server.
#[derive(Clone, Copy)]
pub struct Options {
    /// Bounds the agent's data-plane HELLO read and the connect to the upstream data socket.
    pub data_connect_timeout: Duration,
    pub ping_interval: Duration,
    pub idle_timeout: Duration,
    pub max_data_streams: usize,
    pub max_data_streams_per_token: usize,
    pub max_control_connections: usize,
    pub max_control_connections_per_token: usize,
    pub create_reservation_ttl: Duration,
}

pub async fn serve(
    listen: SocketAddr,
    pool: UpstreamPool,
    clients: ClientMap,
    auth: Arc<Authenticator>,
    tickets: TicketMap,
    sessions: SessionStore,
    metrics: Arc<Metrics>,
    options: Options,
    events: broadcast::Sender<UpstreamEvent>,
    discovery: DiscoveryHealth,
) -> Result<()> {
    let state = AppState { pool, clients, auth, tickets, sessions, metrics, data_limiter: OwnerLimiter::new(), control_limiter: OwnerLimiter::new(), options, events, discovery };
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
    let Some(acl) = state.auth.acl(bearer) else {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")]).into_response();
    };
    let now = std::time::Instant::now();
    let upstreams = state.pool.list_allowed(&acl).await;
    let body = status::build(
        &upstreams,
        state.tickets.pending(),
        state.metrics.snapshot(),
        state.discovery.snapshot(now),
        now,
    );
    Json(body).into_response()
}

fn authenticate(headers: &HeaderMap, state: &AppState, protocol: &str) -> Result<(Vec<String>, String), StatusCode> {
    let selected = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|p| p.trim() == protocol)) == Some(true);
    if !selected { return Err(StatusCode::BAD_REQUEST); }
    let bearer = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let identity = state.auth.identify(Some(bearer)).ok_or(StatusCode::UNAUTHORIZED)?;
    let acl = identity.acl;
    Ok((acl, bearer.to_owned()))
}

async fn control_upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    let (acl, owner) = authenticate(&headers, &state, SUBPROTOCOL)?;
    Ok(ws.protocols([SUBPROTOCOL]).max_message_size(MAX_MESSAGE_BYTES).on_upgrade(move |socket| serve_agent(socket, state, acl, owner)))
}

async fn serve_agent(mut socket: WebSocket, state: AppState, acl: Vec<String>, owner: String) {
    // Reserve control slots before hello/welcome so a rejected agent never sees a fake welcome.
    let Some(_owner_slot) = state.control_limiter.try_acquire(&owner, state.options.max_control_connections_per_token) else {
        let _ = socket.send(Message::Close(Some(CloseFrame { code: 1013, reason: Cow::Borrowed("per-token control connection limit") }))).await;
        return;
    };
    let Some(_active) = state.metrics.try_track(Gauge::Control, state.options.max_control_connections) else {
        let _ = socket.send(Message::Close(Some(CloseFrame { code: 1013, reason: Cow::Borrowed("gateway control connection limit") }))).await;
        return;
    };
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
    let welcome = json!({"type":"welcome","protocol":SUBPROTOCOL,"limits":{"max_message_bytes":MAX_MESSAGE_BYTES},"client":{"id":format!("client:{}",uuid::Uuid::new_v4()),"reconnect_token":uuid::Uuid::new_v4().to_string()},"api_server_revision":19});
    if socket.send(Message::Text(welcome.to_string())).await.is_err() { return; }
    let (mut sink, mut stream) = socket.split();
    let mut events = state.events.subscribe();
    let mut seq = 0;
    // Delay the first ping so hello/welcome and early RPCs are not raced by keepalive.
    let mut pings = tokio::time::interval_at(tokio::time::Instant::now() + state.options.ping_interval, state.options.ping_interval);
    pings.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut idle = tokio::time::interval(std::cmp::max(state.options.idle_timeout / 5, Duration::from_millis(1)));
    idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_activity = std::time::Instant::now();
    loop {
        tokio::select! {
            incoming=stream.next()=> {
                match incoming {
                    Some(Ok(Message::Text(text)))=> {
                        last_activity=std::time::Instant::now();
                        let message: Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => continue };
                        if message["type"] != "request" { continue; }
                        let id = message["id"].clone();
                        let method = message["method"].as_str().unwrap_or_default().to_owned();
                        let response = match handle(&state, &acl, &owner, &method, message["payload"].clone()).await {
                            Ok(AgentReply::Payload(payload)) => json!({"type":"response","id":id,"seq":seq+1,"payload":payload}),
                            Ok(AgentReply::FrameError(error)) => json!({"type":"response","id":id,"seq":seq+1,"error":error}),
                            Err(e) => json!({"type":"response","id":id,"seq":seq+1,"payload":{"error":e.to_string()}}),
                        };
                        seq += 1;
                        if sink.send(Message::Text(response.to_string())).await.is_err() { break; }
                    }
                    // Keepalive only: axum/tungstenite auto-answer pings. Pong must not
                    // count as application activity or idle agents are never reaped.
                    Some(Ok(Message::Ping(_)))|Some(Ok(Message::Pong(_)))=> {}
                    Some(Ok(Message::Close(_)))|Some(Err(_))|None=>break,
                    _=>{}
                }
            }
            event=events.recv()=> {
                let event=match event { Ok(event)=>event, Err(broadcast::error::RecvError::Lagged(n))=>{ tracing::warn!(n,"agent event receiver lagged"); continue }, Err(_)=>break };
                if event.event.get("type").and_then(Value::as_str) != Some("event") { continue; }
                if !auth::Authenticator::permits(&acl,&event.upstream) { continue; }
                // Namespace once, then record from the wrapped payload. Re-running
                // namespace_and_record on an already-wrapped payload double-prefixes
                // session ids (so recording fails) and re-issues orphan tickets.
                let mut payload = event.event.get("payload").cloned().unwrap_or(Value::Null);
                namespace_and_record(&mut payload, &event.upstream, &state.tickets, &owner, &state.sessions);
                seq += 1;
                let framed = json!({"type":"event","seq":seq,"payload":payload});
                if sink.send(Message::Text(framed.to_string())).await.is_err() { break; }
            }
            _=pings.tick()=>if sink.send(Message::Ping(Vec::new())).await.is_err() { break; },
            _=idle.tick()=>if last_activity.elapsed()>=state.options.idle_timeout {
                let _=sink.send(Message::Close(Some(CloseFrame { code:1001, reason:Cow::Borrowed("idle timeout") }))).await;
                let _=sink.close().await;
                break;
            }
        }
    }
}

async fn handle(state: &AppState, acl: &[String], owner: &str, method: &str, mut payload: Value) -> Result<AgentReply, String> {
    let external_session=payload.get("session_id").and_then(Value::as_str).map(str::to_owned);
    if method == "session.list" { return list_sessions(state, acl, owner, &state.sessions).await.map(AgentReply::Payload); }
    if method == "session.forget" {
        let external=payload.get("session_id").and_then(Value::as_str).ok_or("session.forget requires session_id")?;
        let (upstream,_)=crate::protocol::unwrap_session_id(external).ok_or("invalid namespaced session_id")?;
        if !auth::Authenticator::permits(acl,upstream){return Err(format!("upstream {upstream} is not allowed"));}
        return Ok(AgentReply::Payload(json!({"forgotten":state.sessions.forget(external)?,"session_id":external})));
    }
    if let Some(external)=payload.get("session_id").and_then(Value::as_str) {
        if crate::protocol::unwrap_session_id(external).is_some(){state.sessions.resolve(external)?;state.sessions.touch(external);}
    }
    let defaults = state.auth.identify(Some(owner)).unwrap_or(crate::auth::Identity {
        acl: acl.to_vec(), prefer_tags: Vec::new(), avoid_tags: Vec::new(), prefer_hosts: Vec::new(), avoid_hosts: Vec::new(),
    });
    let prefs = if method == "session.create" {
        TagPreferences {
            prefer: string_list(&payload, "prefer_tags").unwrap_or(defaults.prefer_tags),
            avoid: string_list(&payload, "avoid_tags").unwrap_or(defaults.avoid_tags),
            prefer_hosts: string_list(&payload, "prefer_hosts").unwrap_or(defaults.prefer_hosts),
            avoid_hosts: string_list(&payload, "avoid_hosts").unwrap_or(defaults.avoid_hosts),
        }
    } else { TagPreferences::default() };
    let owner_upstream = match payload.get("session_id").and_then(Value::as_str).and_then(crate::protocol::unwrap_session_id) {
        Some((upstream, _)) => upstream.to_owned(),
        None => match payload.get("host").and_then(Value::as_str).map(str::to_owned) {
            Some(host) => host,
            None => {
                if method != "session.create" {
                    // Hostless non-create (e.g. server.version): Manual/Online default with
                    // transport-error failover across candidates (same policy as create).
                    return hostless_with_failover(state, acl, owner, method, payload).await;
                } else {
                    return create_with_failover(state, acl, owner, prefs, payload).await;
                }
            }
        },
    };
    if !auth::Authenticator::permits(acl, &owner_upstream) {
        return Err(format!("upstream {owner_upstream} is not allowed"));
    }
    let Some(upstream) = state.pool.get(&owner_upstream).await else {
        return Err(format!("upstream {owner_upstream} is unknown"));
    };
    if !upstream.state.is_routable() {
        return Err(format!("upstream {owner_upstream} is {}; the owning upstream is unavailable, remove/recreate this session", upstream.state.as_str()));
    }
    if payload.get("session_id").is_some() && !translate_session_id(&mut payload, &owner_upstream, false) {
        return Err("invalid or mismatched namespaced session_id".into());
    }
    if let Some(object) = payload.as_object_mut() {
        object.remove("host"); object.remove("prefer_tags"); object.remove("avoid_tags");
        object.remove("prefer_hosts"); object.remove("avoid_hosts");
    }
    let reply = state.clients.get(&owner_upstream).ok_or("upstream client missing")?
        .call(method, payload).await.map_err(|e| e.to_string())?;
    if reply.is_frame_error() {
        // Do not decorate failed bootstrap / invent "omitted ticket" over a real Rex error.
        return Ok(reply_from_upstream(reply));
    }
    let mut response = reply.payload;
    if method == "session.create" {
        // Hard-pin create (no reservation). Hostless create returns earlier via create_with_failover.
        if response.get("error").is_some() { return Ok(AgentReply::Payload(response)); }
    }
    if method == "session.bootstrap" {
        response["upstream"] = json!({"id":upstream.id,"tags":upstream.tags,"description":upstream.description,"state":upstream.state.as_str(),"latency_ms":upstream.latency_ms,"session_count":upstream.session_count});
        response["upstreams"] = Value::Array(state.pool.list_allowed(acl).await.into_iter().map(|u| json!({"id":u.id,"tags":u.tags,"description":u.description,"state":u.state.as_str(),"latency_ms":u.latency_ms,"session_count":u.session_count,"reserved_session_count":u.reserved_sessions,"effective_session_count":u.session_count+u.reserved_sessions})).collect::<Vec<_>>());
    }
    if method == "data.connect" && response.get("ticket").and_then(Value::as_str).is_none() {
        return Err("upstream data.connect omitted ticket".into());
    }
    namespace_and_record(&mut response, &owner_upstream, &state.tickets, owner, &state.sessions);
    if method=="data.connect" {if let (Some(ticket),Some(id))=(response.get("ticket").and_then(Value::as_str),external_session.as_deref()){state.tickets.bind_session(ticket,id);}}
    Ok(AgentReply::Payload(response))
}

/// Fans `session.list` out to every allowed upstream concurrently (each bounded by the upstream
/// call timeout). Upstreams that are not routable (`Online`/`Degraded`) or that fail are skipped
/// and reported through the additive `partial` / `failed_upstreams` / `upstream_errors` fields;
/// if every allowed upstream fails, the request fails. This matches create/RPC routing, which
/// already treats Degraded as usable.

/// Hostless `session.create`: try candidates in score order. Transport failures (timeout,
/// connect, missing client, socket closed, "retry in …") drop the reservation, optionally
/// mark the upstream failed, and retry the next candidate under the same TagPreferences
/// while excluding already-tried host ids for this request only. Application-level
/// `{"error":…}` responses and hard `host` pins do not failover (pin stays single-shot
/// in [`handle`]).
async fn create_with_failover(
    state: &AppState,
    acl: &[String],
    owner: &str,
    prefs: TagPreferences,
    mut payload: Value,
) -> Result<AgentReply, String> {
    if let Some(object) = payload.as_object_mut() {
        object.remove("host");
        object.remove("prefer_tags");
        object.remove("avoid_tags");
        object.remove("prefer_hosts");
        object.remove("avoid_hosts");
    }
    let mut tried: Vec<(String, String)> = Vec::new();
    loop {
        let exclude: Vec<String> = tried.iter().map(|(id, _)| id.clone()).collect();
        let (upstream, reserved) = match state
            .pool
            .reserve_for_create_excluding(acl, &prefs, state.options.create_reservation_ttl, &exclude)
            .await
        {
            Ok(pair) => pair,
            Err(e) if tried.is_empty() => return Err(e),
            Err(_) => {
                state.metrics.create_failover_exhausted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let detail = tried
                    .iter()
                    .map(|(id, err)| format!("{id}: {err}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(format!("session.create failed on all candidates: {detail}"));
            }
        };
        let id = upstream.id.clone();
        let call = match state.clients.get(&id) {
            Some(client) => client.call("session.create", payload.clone()).await.map_err(|e| e.to_string()),
            None => Err("upstream client missing".into()),
        };
        match call {
            Ok(reply) if reply.is_application_error() => {
                // Application error (frame-level or payload-level): do not failover.
                drop(reserved);
                return Ok(reply_from_upstream(reply));
            }
            Ok(reply) => {
                reserved.finish();
                let mut response = reply.payload;
                namespace_and_record(&mut response, &id, &state.tickets, owner, &state.sessions);
                return Ok(AgentReply::Payload(response));
            }
            Err(err) => {
                drop(reserved);
                let _ = state.pool.mark_failure(&id, err.clone()).await;
                tried.push((id, err));
                state.metrics.create_transport_failovers.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// Hostless non-create RPCs (`server.version`, …): try `pick_default` candidates in order.
/// Transport failures mark the upstream and retry the next candidate (already-tried ids are
/// excluded for this request only). Application-level `{"error":…}` responses and hard `host`
/// pins do not failover (pin stays single-shot in [`handle`]).
async fn hostless_with_failover(
    state: &AppState,
    acl: &[String],
    owner: &str,
    method: &str,
    mut payload: Value,
) -> Result<AgentReply, String> {
    if let Some(object) = payload.as_object_mut() {
        object.remove("host");
        object.remove("prefer_tags");
        object.remove("avoid_tags");
        object.remove("prefer_hosts");
        object.remove("avoid_hosts");
    }
    let mut tried: Vec<(String, String)> = Vec::new();
    loop {
        let exclude: Vec<String> = tried.iter().map(|(id, _)| id.clone()).collect();
        let picked = if exclude.is_empty() {
            state.pool.pick_default(acl).await
        } else {
            state.pool.pick_default_excluding(acl, &exclude).await
        };
        let Some(upstream) = picked else {
            if tried.is_empty() {
                return Err("no routable upstream".into());
            }
            state.metrics.hostless_failover_exhausted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let detail = tried
                .iter()
                .map(|(id, err)| format!("{id}: {err}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("{method} failed on all candidates: {detail}"));
        };
        let id = upstream.id.clone();
        let call = match state.clients.get(&id) {
            Some(client) => client.call(method, payload.clone()).await.map_err(|e| e.to_string()),
            None => Err("upstream client missing".into()),
        };
        match call {
            Ok(reply) if reply.is_application_error() => {
                // Application error: do not failover (parity with session.create).
                return Ok(reply_from_upstream(reply));
            }
            Ok(reply) => {
                let mut response = reply.payload;
                namespace_and_record(&mut response, &id, &state.tickets, owner, &state.sessions);
                return Ok(AgentReply::Payload(response));
            }
            Err(err) => {
                let _ = state.pool.mark_failure(&id, err.clone()).await;
                tried.push((id, err));
                state.metrics.hostless_transport_failovers.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

fn string_list(payload: &Value, field: &str) -> Option<Vec<String>> {
    payload.get(field).and_then(Value::as_array).map(|values| values.iter().filter_map(Value::as_str).map(str::to_owned).collect())
}

async fn list_sessions(state: &AppState, acl: &[String], owner: &str, store: &SessionStore) -> Result<Value, String> {
    let allowed = state.pool.list_allowed(acl).await;
    let results = futures_util::future::join_all(allowed.iter().map(|upstream| async move {
        if !upstream.state.is_routable() {
            return (upstream.id.as_str(), Err(format!("upstream is {}", upstream.state.as_str())));
        }
        let Some(client) = state.clients.get(&upstream.id) else { return (upstream.id.as_str(), Err("upstream client missing".to_owned())) };
        let result = client.call("session.list", json!({})).await.map_err(|e| format!("{e:#}")).and_then(|reply| {
            if let Some(error) = reply.error.as_ref().filter(|e| !e.is_null()) {
                let message = error.get("message").and_then(Value::as_str).unwrap_or("upstream frame error");
                return Err(format!("session.list frame error: {message}"));
            }
            match reply.payload {
                Value::Object(mut object) => match object.remove("sessions") {
                    Some(Value::Array(sessions)) => Ok(sessions),
                    _ => Err("upstream session.list omitted sessions".to_owned()),
                },
                _ => Err("upstream session.list omitted sessions".to_owned()),
            }
        });
        (upstream.id.as_str(), result)
    })).await;
    let mut sessions = Vec::new();
    let mut errors = serde_json::Map::new();
    for (id, result) in results {
        match result {
            Ok(items) => for mut session in items {
                // Require a bare upstream session_id; then recursively wrap nested
                // session/ticket fields the same way responses and events do.
                let Some(raw) = session.get("session_id").and_then(Value::as_str) else { continue };
                if !raw.starts_with("session:") { continue; }
                namespace_and_record(&mut session, id, &state.tickets, owner, store);
                sessions.push(session);
            },
            Err(error) => { tracing::warn!(upstream = id, %error, "session.list skipped upstream"); errors.insert(id.to_owned(), Value::String(error)); }
        }
    }
    if !allowed.is_empty() && errors.len() == allowed.len() {
        let detail: Vec<String> = errors.iter().map(|(id, e)| format!("{id}: {}", e.as_str().unwrap_or_default())).collect();
        return Err(format!("all upstreams failed: {}", detail.join("; ")));
    }
    let mut response = json!({"sessions": sessions});
    if !errors.is_empty() {
        response["partial"] = Value::Bool(true);
        response["failed_upstreams"] = Value::Array(errors.keys().cloned().map(Value::String).collect());
        response["upstream_errors"] = Value::Object(errors);
    }
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
    let hello = match tokio::time::timeout(state.options.data_connect_timeout, agent.recv()).await {
        Ok(Some(Ok(Message::Binary(hello)))) => hello,
        Err(_) => {
            // Idle socket that never sent HELLO: REJECT (malformed/missing HELLO) and close.
            let _ = agent.send(Message::Binary(vec![0x82, 0x05].into())).await;
            let _ = agent.send(Message::Close(Some(CloseFrame { code: 1008, reason: Cow::Borrowed("HELLO timeout") }))).await;
            return;
        }
        _ => {
            let _ = agent.send(Message::Binary(vec![0x82, 0x05].into())).await;
            let _ = agent.send(Message::Close(Some(CloseFrame { code: 1002, reason: Cow::Borrowed("malformed HELLO") }))).await;
            return;
        }
    };
    let Some(external) = decode_hello(&hello) else {
        let _ = agent.send(Message::Binary(vec![0x82, 0x05].into())).await;
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1002, reason: Cow::Borrowed("malformed HELLO") }))).await;
        return;
    };
    // Reserve stream slots before consuming the ticket so a capacity miss does not burn it.
    let Some(_owner_slot) = state.data_limiter.try_acquire(&owner, state.options.max_data_streams_per_token) else {
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1013, reason: Cow::Borrowed("per-token data stream limit") }))).await;
        return;
    };
    let Some(_global_slot) = state.metrics.try_track(Gauge::Data, state.options.max_data_streams) else {
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1013, reason: Cow::Borrowed("gateway data stream limit") }))).await;
        return;
    };
    // Lookup of a ticket attached to a forgotten session still leads to a clear refusal.
    // The gateway keeps the ticket's owning upstream private; stale tickets cannot be replayed.
    let Some(ticket) = state.tickets.take(&external, &owner) else {
        let _ = agent.send(Message::Binary(vec![0x82, 0x01].into())).await;
        let _ = agent.send(Message::Close(Some(CloseFrame { code: 1008, reason: Cow::Borrowed("bad or used ticket") }))).await;
        return;
    };
    if let Some(id)=ticket.session_id.as_deref(){
        if state.sessions.resolve(id).is_err(){let _=agent.send(Message::Close(Some(CloseFrame{code:1008,reason:Cow::Borrowed(FORGOTTEN_ERROR)}))).await;return;}
        state.sessions.touch(id);
    }
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
    let mut upstream_socket = match tokio::time::timeout(state.options.data_connect_timeout, connect_async(request)).await {
        Ok(Ok((socket, _))) => socket,
        Err(_) => {
            tracing::warn!(upstream = %ticket.upstream, "upstream data connection timed out");
            let _ = agent.send(Message::Close(Some(CloseFrame { code: 1011, reason: Cow::Borrowed("upstream connect timeout") }))).await;
            return;
        }
        Ok(Err(error)) => {
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

    let (mut upstream_sink, mut upstream_stream) = upstream_socket.split();
    let (mut agent_sink, mut agent_stream) = agent.split();
    let mut pings=tokio::time::interval_at(tokio::time::Instant::now() + state.options.ping_interval, state.options.ping_interval);
    pings.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut idle=tokio::time::interval(std::cmp::max(state.options.idle_timeout / 5, Duration::from_millis(1)));
    idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_activity=std::time::Instant::now();
    loop {
        tokio::select! {
            incoming = agent_stream.next() => match incoming {
                Some(Ok(Message::Binary(bytes))) => {
                    last_activity=std::time::Instant::now();
                    if let Some(id)=ticket.session_id.as_deref(){state.sessions.touch(id);}
                    if upstream_sink.send(tungstenite::Message::Binary(bytes)).await.is_err() { break; }
                }
                Some(Ok(Message::Text(text))) => {
                    last_activity=std::time::Instant::now();
                    if upstream_sink.send(tungstenite::Message::Text(text.as_str().into())).await.is_err() { break; }
                }
                Some(Ok(Message::Ping(bytes))) => if upstream_sink.send(tungstenite::Message::Ping(bytes)).await.is_err() { break; },
                Some(Ok(Message::Pong(bytes))) => if upstream_sink.send(tungstenite::Message::Pong(bytes)).await.is_err() { break; },
                Some(Ok(Message::Close(frame))) => {
                    let _ = upstream_sink.send(tungstenite::Message::Close(frame.map(to_upstream_close))).await;
                    break;
                }
                Some(Err(_)) | None => {
                    // Agent dropped without a Close frame: tell the upstream so Rex can
                    // release the terminal attach instead of waiting for idle timeout.
                    close_upstream_peer_closed(&mut upstream_sink).await;
                    break;
                }
            },
            outgoing = upstream_stream.next() => match outgoing {
                Some(Ok(tungstenite::Message::Binary(bytes))) => {
                    last_activity=std::time::Instant::now();
                    if let Some(id)=ticket.session_id.as_deref(){state.sessions.touch(id);}
                    if agent_sink.send(Message::Binary(bytes)).await.is_err() {
                        close_upstream_peer_closed(&mut upstream_sink).await;
                        break;
                    }
                }
                Some(Ok(tungstenite::Message::Text(text))) => {
                    last_activity=std::time::Instant::now();
                    if agent_sink.send(Message::Text(text.as_str().into())).await.is_err() {
                        close_upstream_peer_closed(&mut upstream_sink).await;
                        break;
                    }
                }
                Some(Ok(tungstenite::Message::Ping(bytes))) => {
                    if agent_sink.send(Message::Ping(bytes)).await.is_err() {
                        close_upstream_peer_closed(&mut upstream_sink).await;
                        break;
                    }
                }
                Some(Ok(tungstenite::Message::Pong(bytes))) => {
                    if agent_sink.send(Message::Pong(bytes)).await.is_err() {
                        close_upstream_peer_closed(&mut upstream_sink).await;
                        break;
                    }
                }
                Some(Ok(tungstenite::Message::Close(frame))) => {
                    let _ = agent_sink.send(Message::Close(frame.map(to_agent_close))).await;
                    break;
                }
                Some(Ok(tungstenite::Message::Frame(_))) => {}
                Some(Err(_)) | None => {
                    let reason = match state.pool.get(&ticket.upstream).await {
                        Some(u) if u.state == UpstreamState::Offline => "upstream offline",
                        _ => "upstream closed",
                    };
                    let _ = agent_sink.send(Message::Close(Some(CloseFrame { code: 1011, reason: Cow::Borrowed(reason) }))).await;
                    break;
                }
            },
            _=pings.tick()=> {
                if agent_sink.send(Message::Ping(Vec::new())).await.is_err() {
                    close_upstream_peer_closed(&mut upstream_sink).await;
                    break;
                }
                if upstream_sink.send(tungstenite::Message::Ping(Vec::new())).await.is_err() {
                    let _ = agent_sink.send(Message::Close(Some(CloseFrame { code: 1011, reason: Cow::Borrowed("upstream closed") }))).await;
                    break;
                }
            }
            _=idle.tick()=>if last_activity.elapsed()>=state.options.idle_timeout {
                let _=agent_sink.send(Message::Close(Some(CloseFrame { code:1001,reason:Cow::Borrowed("idle timeout") }))).await;
                let _=upstream_sink.send(tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame { code:1001.into(),reason:"idle timeout".into() }))).await;
                let _=agent_sink.close().await;
                let _=upstream_sink.close().await;
                break;
            }
        }
    }
}

/// Notify the upstream data socket that the agent disappeared without a Close frame.
async fn close_upstream_peer_closed(
    upstream_sink: &mut (impl SinkExt<tungstenite::Message> + Unpin),
) {
    let _ = upstream_sink
        .send(tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
            code: 1001.into(),
            reason: "peer closed".into(),
        })))
        .await;
    let _ = upstream_sink.close().await;
}

fn to_upstream_close(frame: CloseFrame) -> tungstenite::protocol::CloseFrame {
    tungstenite::protocol::CloseFrame { code: frame.code.into(), reason: frame.reason.to_string().into() }
}

fn to_agent_close(frame: tungstenite::protocol::CloseFrame) -> CloseFrame {
    CloseFrame { code: frame.code.into(), reason: Cow::Owned(frame.reason.to_string()) }
}

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
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
        let auth = Arc::new(Authenticator::new(HashMap::from([
            ("all".to_owned(), vec!["*".to_owned()]),
            ("onlyb".to_owned(), vec!["b".to_owned()]),
        ])));
        let tickets = TicketMap::new(Duration::from_secs(30), 16, metrics.clone());
        let state = AppState { pool, clients: ClientMap::new(), auth, tickets, sessions: SessionStore::open(tempfile::tempdir().unwrap().path().join("sessions.json"),Duration::from_secs(86400),16384).unwrap(), metrics, data_limiter: OwnerLimiter::new(), control_limiter: OwnerLimiter::new(), options: Options { data_connect_timeout: Duration::from_secs(5), ping_interval: Duration::from_secs(20), idle_timeout: Duration::from_secs(120), max_data_streams: 128, max_data_streams_per_token: 32, max_control_connections: 128, max_control_connections_per_token: 32, create_reservation_ttl: Duration::from_secs(5) }, events: broadcast::channel(8).0, discovery: DiscoveryHealth::disabled() };
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
        assert_eq!(json["counters"]["create_transport_failovers"], 0);
        assert_eq!(json["counters"]["hostless_transport_failovers"], 0);
        assert_eq!(json["counters"]["create_failover_exhausted"], 0);
        assert_eq!(json["counters"]["hostless_failover_exhausted"], 0);
        assert_eq!(json["discovery"]["enabled"], false);
        assert_eq!(json["discovery"]["mode"], "none");
        assert_eq!(json["discovery"]["refresh_count"], 0);

        let (code, body) = get_status(addr, Some("Bearer onlyb")).await;
        assert_eq!(code, 200);
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["upstreams"].as_array().unwrap().len(), 1);
        assert_eq!(json["upstreams"][0]["id"], "b");
    }
}
