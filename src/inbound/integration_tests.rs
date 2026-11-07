//! End-to-end tests: fake Rex control servers <-> real `ControlClient`/pool/probe <-> the real
//! gateway router <-> a real WebSocket agent client, all over loopback sockets.
use super::*;
use std::collections::HashMap;
use crate::{
    control_client::{ClientMap, ControlClient},
    pool::{Source, UpstreamState},
    probe,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_hdr_async, connect_async,
    tungstenite::handshake::server::{ErrorResponse, Request, Response},
    MaybeTlsStream, WebSocketStream,
};

type Agent = WebSocketStream<MaybeTlsStream<TcpStream>>;
const SECRET: &str = "Bearer it-secret";

fn tmo(ms: u64) -> Duration { Duration::from_millis(ms) }

/// Fake Rex control server: speaks hello/welcome and answers `session.list` (and anything else
/// with an empty object). A `hung` server completes the handshake but never answers requests.
async fn spawn_fake_rex_on(listener: TcpListener, sessions: Vec<Value>, hung: bool) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let sessions = sessions.clone();
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(mut socket) = accept_hdr_async(stream, callback).await else { return };
                while let Some(Ok(frame)) = socket.next().await {
                    let tungstenite::Message::Text(text) = frame else { continue };
                    let message: Value = serde_json::from_str(&text).unwrap();
                    match message["type"].as_str() {
                        Some("hello") => { let _ = socket.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await; }
                        Some("request") if !hung => {
                            let payload = if message["method"] == "session.list" || message["method"] == "session.attach_all" {
                                json!({"sessions": sessions})
                            } else if message["method"] == "session.create" {
                                json!({"session_id":"session:created"})
                            } else {
                                json!({"ok": true})
                            };
                            let reply = json!({"type":"response","id":message["id"],"payload":payload});
                            let _ = socket.send(tungstenite::Message::Text(reply.to_string())).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
}

async fn spawn_fake_rex(sessions: Vec<Value>, hung: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    spawn_fake_rex_on(listener, sessions, hung).await;
    url
}

/// Fake Rex that sleeps `delay` before answering `delay_method`. Request handling is concurrent
/// (per-request tasks + write lock) so a slow method does not block other methods on the same socket.
async fn spawn_fake_rex_delayed(delay_method: &str, delay: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let delay_method = delay_method.to_owned();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let delay_method = delay_method.clone();
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(socket) = accept_hdr_async(stream, callback).await else { return };
                let (sink, mut stream) = socket.split();
                let sink = std::sync::Arc::new(tokio::sync::Mutex::new(sink));
                while let Some(Ok(frame)) = stream.next().await {
                    let tungstenite::Message::Text(text) = frame else { continue };
                    let message: Value = serde_json::from_str(&text).unwrap();
                    match message["type"].as_str() {
                        Some("hello") => {
                            let mut sink = sink.lock().await;
                            let _ = sink.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await;
                        }
                        Some("request") => {
                            let sink = sink.clone();
                            let delay_method = delay_method.clone();
                            tokio::spawn(async move {
                                let method = message["method"].as_str().unwrap_or_default().to_owned();
                                if method == delay_method {
                                    tokio::time::sleep(delay).await;
                                }
                                let payload = if method == "session.list" {
                                    json!({"sessions": []})
                                } else if method == delay_method {
                                    json!({"slow": true})
                                } else {
                                    json!({"ok": true})
                                };
                                let reply = json!({"type":"response","id":message["id"],"payload":payload});
                                let mut sink = sink.lock().await;
                                let _ = sink.send(tungstenite::Message::Text(reply.to_string())).await;
                            });
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    url
}

/// A loopback URL nothing listens on.
async fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

/// Fake Rex that answers session.create with an application-level `{"error":…}` payload.
async fn spawn_fake_rex_create_app_error(error: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let error = error.to_owned();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let error = error.clone();
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(mut socket) = accept_hdr_async(stream, callback).await else { return };
                while let Some(Ok(frame)) = socket.next().await {
                    let tungstenite::Message::Text(text) = frame else { continue };
                    let message: Value = serde_json::from_str(&text).unwrap();
                    match message["type"].as_str() {
                        Some("hello") => { let _ = socket.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await; }
                        Some("request") => {
                            let payload = if message["method"] == "session.list" {
                                json!({"sessions": []})
                            } else if message["method"] == "session.create" {
                                json!({"error": error})
                            } else {
                                json!({"ok": true})
                            };
                            let reply = json!({"type":"response","id":message["id"],"payload":payload});
                            let _ = socket.send(tungstenite::Message::Text(reply.to_string())).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    url
}


/// Fake Rex that answers `method` with an application-level `{"error":…}` payload.
async fn spawn_fake_rex_method_app_error(method: &str, error: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let method = method.to_owned();
    let error = error.to_owned();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let method = method.clone();
            let error = error.clone();
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(mut socket) = accept_hdr_async(stream, callback).await else { return };
                while let Some(Ok(frame)) = socket.next().await {
                    let tungstenite::Message::Text(text) = frame else { continue };
                    let message: Value = serde_json::from_str(&text).unwrap();
                    match message["type"].as_str() {
                        Some("hello") => { let _ = socket.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await; }
                        Some("request") => {
                            let payload = if message["method"] == "session.list" {
                                json!({"sessions": []})
                            } else if message["method"].as_str() == Some(method.as_str()) {
                                json!({"error": error})
                            } else {
                                json!({"ok": true})
                            };
                            let reply = json!({"type":"response","id":message["id"],"payload":payload});
                            let _ = socket.send(tungstenite::Message::Text(reply.to_string())).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    url
}


/// Fake Rex that answers matching methods with a Rex frame-level `response.error` (no payload),
/// matching real Rex (`method_not_found` / `bad_request` / …).
async fn spawn_fake_rex_frame_error(method: &str, error: Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let method = method.to_owned();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let method = method.clone();
            let error = error.clone();
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(mut socket) = accept_hdr_async(stream, callback).await else { return };
                while let Some(Ok(frame)) = socket.next().await {
                    let tungstenite::Message::Text(text) = frame else { continue };
                    let message: Value = serde_json::from_str(&text).unwrap();
                    match message["type"].as_str() {
                        Some("hello") => { let _ = socket.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await; }
                        Some("request") => {
                            let reply = if message["method"] == "session.list" {
                                json!({"type":"response","id":message["id"],"payload":{"sessions":[]}})
                            } else if message["method"].as_str() == Some(method.as_str()) {
                                json!({"type":"response","id":message["id"],"error":error})
                            } else {
                                json!({"type":"response","id":message["id"],"payload":{"ok":true}})
                            };
                            let _ = socket.send(tungstenite::Message::Text(reply.to_string())).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    url
}

/// Fake Rex that echoes selected request fields under non-`session_id` keys so the gateway
/// response path cannot re-wrap them. Used to prove outbound denamespace.
async fn spawn_fake_rex_echo_forwarded_session_ids() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(mut socket) = accept_hdr_async(stream, callback).await else { return };
                while let Some(Ok(frame)) = socket.next().await {
                    let tungstenite::Message::Text(text) = frame else { continue };
                    let message: Value = serde_json::from_str(&text).unwrap();
                    match message["type"].as_str() {
                        Some("hello") => { let _ = socket.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await; }
                        Some("request") => {
                            let payload = if message["method"] == "session.list" {
                                json!({"sessions": []})
                            } else {
                                let req = &message["payload"];
                                json!({
                                    "ok": true,
                                    "forwarded_top": req.get("session_id").cloned().unwrap_or(Value::Null),
                                    "forwarded_view": req.pointer("/view/session_id").cloned().unwrap_or(Value::Null),
                                    "forwarded_child": req.pointer("/alternates/0/session_id").cloned().unwrap_or(Value::Null),
                                })
                            };
                            let reply = json!({"type":"response","id":message["id"],"payload":payload});
                            let _ = socket.send(tungstenite::Message::Text(reply.to_string())).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    url
}

async fn rpc_frame(socket: &mut Agent, method: &str, payload: Value) -> Value {
    socket.send(tungstenite::Message::Text(json!({"type":"request","id":"r1","method":method,"payload":payload}).to_string())).await.unwrap();
    let raw = loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next()).await.expect("gateway must answer").unwrap().unwrap() {
            tungstenite::Message::Text(text)=>break text,
            tungstenite::Message::Ping(bytes)=> { socket.send(tungstenite::Message::Pong(bytes)).await.unwrap(); }
            other=>panic!("expected controlled response, got {other:?}"),
        }
    };
    let reply: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(reply["id"], "r1");
    reply
}

struct Harness { addr: SocketAddr, pool: UpstreamPool, state: AppState }

/// Builds the same wiring as `main` (lazy clients, probe loop) around the given upstreams.
async fn start_gateway(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration) -> Harness {
    start_gateway_with_limits(upstreams, call_timeout, probe_every, data_timeout, Duration::from_secs(20), Duration::from_secs(120), 128, 32).await
}

async fn start_gateway_with_keepalive(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, ping_interval: Duration, idle_timeout: Duration) -> Harness {
    start_gateway_with_limits(upstreams, call_timeout, probe_every, data_timeout, ping_interval, idle_timeout, 128, 32).await
}

async fn start_gateway_with_limits(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, ping_interval: Duration, idle_timeout: Duration, max_data_streams: usize, max_data_streams_per_token: usize) -> Harness {
    start_gateway_with_store(upstreams,call_timeout,probe_every,data_timeout,ping_interval,idle_timeout,max_data_streams,max_data_streams_per_token,128,32,None).await
}
async fn start_gateway_with_control_limits(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, max_control_connections: usize, max_control_connections_per_token: usize) -> Harness {
    start_gateway_with_store(upstreams,call_timeout,probe_every,data_timeout,Duration::from_secs(20),Duration::from_secs(120),128,32,max_control_connections,max_control_connections_per_token,None).await
}
async fn start_gateway_with_store(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, ping_interval: Duration, idle_timeout: Duration, max_data_streams: usize, max_data_streams_per_token: usize, max_control_connections: usize, max_control_connections_per_token: usize, store: Option<crate::sessions::SessionStore>) -> Harness {
    start_gateway_with_event_cap(upstreams, call_timeout, probe_every, data_timeout, ping_interval, idle_timeout, max_data_streams, max_data_streams_per_token, max_control_connections, max_control_connections_per_token, store, 32).await
}
async fn start_gateway_with_event_cap(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, ping_interval: Duration, idle_timeout: Duration, max_data_streams: usize, max_data_streams_per_token: usize, max_control_connections: usize, max_control_connections_per_token: usize, store: Option<crate::sessions::SessionStore>, event_cap: usize) -> Harness {
    let pool = UpstreamPool::new();
    let clients = ClientMap::new();
    let (events, _) = broadcast::channel(event_cap.max(1));
    for (id, url) in upstreams {
        pool.upsert(id, url, Source::Manual).await;
        clients.insert((*id).to_owned(), Arc::new(ControlClient::new((*id).to_owned(), (*url).to_owned(), crate::control_client::Options { call_timeout, ping_interval, idle_timeout }, events.clone())));
    }
    probe::spawn(pool.clone(), clients.clone(), probe_every);
    let metrics = Metrics::new();
    let holds = crate::subscriptions::HoldRegistry::new(clients.clone());
    let state = AppState {
        pool: pool.clone(),
        clients,
        auth: Arc::new(Authenticator::new(HashMap::from([
            ("it-secret".to_owned(), vec!["*".to_owned()]),
            ("only-online".to_owned(), vec!["online".to_owned()]),
        ]))),
        tickets: TicketMap::new(Duration::from_secs(30), 16, metrics.clone()),
        sessions: store.unwrap_or_else(||crate::sessions::SessionStore::open(tempfile::tempdir().unwrap().path().join("sessions.json"),Duration::from_secs(86400),16384).unwrap()),
        metrics,
        options: Options { data_connect_timeout: data_timeout, ping_interval, idle_timeout, max_data_streams, max_data_streams_per_token, max_control_connections, max_control_connections_per_token, create_reservation_ttl: Duration::from_secs(5) },
        data_limiter: OwnerLimiter::new(),
        control_limiter: OwnerLimiter::new(),
        events,
        discovery: crate::discovery::DiscoveryHealth::disabled(),
        holds,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Harness { addr, pool, state }
}

async fn agent(addr: SocketAddr, path: &str, protocol: &'static str) -> Agent {
    agent_with_auth(addr, path, protocol, SECRET).await
}

async fn agent_with_auth(addr: SocketAddr, path: &str, protocol: &'static str, authorization: &'static str) -> Agent {
    let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
    request.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(protocol));
    request.headers_mut().insert("authorization", HeaderValue::from_static(authorization));
    connect_async(request).await.unwrap().0
}


async fn next_binary(socket: &mut Agent) -> Vec<u8> {
    loop {
        match tokio::time::timeout(Duration::from_secs(2), socket.next()).await.expect("frame").unwrap().unwrap() {
            tungstenite::Message::Binary(bytes) => return bytes,
            tungstenite::Message::Ping(bytes) => { let _ = socket.send(tungstenite::Message::Pong(bytes)).await; }
            tungstenite::Message::Pong(_) => {}
            other => panic!("expected binary, got {other:?}"),
        }
    }
}

async fn control_agent(addr: SocketAddr) -> Agent {
    control_agent_with_auth(addr, SECRET).await
}

async fn control_agent_with_auth(addr: SocketAddr, authorization: &'static str) -> Agent {
    let mut socket = agent_with_auth(addr, "/api/control", SUBPROTOCOL, authorization).await;
    socket.send(tungstenite::Message::Text(json!({"type":"hello"}).to_string())).await.unwrap();
    let welcome = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let welcome: Value = serde_json::from_str(&welcome).unwrap();
    assert_eq!(welcome["type"], "welcome");
    assert_eq!(welcome["api_server_revision"], 36);
    assert_eq!(welcome["limits"]["max_in_flight_control_rpcs"], MAX_IN_FLIGHT_CONTROL_RPCS);
    socket
}

async fn rpc(socket: &mut Agent, method: &str, payload: Value) -> Value {
    socket.send(tungstenite::Message::Text(json!({"type":"request","id":"r1","method":method,"payload":payload}).to_string())).await.unwrap();
    let raw = loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next()).await.expect("gateway must answer").unwrap().unwrap() {
            tungstenite::Message::Text(text)=>break text,
            tungstenite::Message::Ping(bytes)=> { socket.send(tungstenite::Message::Pong(bytes)).await.unwrap(); }
            other=>panic!("expected controlled response, got {other:?}"),
        }
    };
    let reply = raw;
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["id"], "r1");
    reply["payload"].clone()
}

async fn wait_state(pool: &UpstreamPool, id: &str, wanted: UpstreamState) {
    for _ in 0..200 {
        if pool.get(id).await.unwrap().state == wanted { return; }
        tokio::time::sleep(tmo(25)).await;
    }
    panic!("{id} never became {wanted:?}, is {:?}", pool.get(id).await.unwrap());
}

fn ids(payload: &Value) -> Vec<String> {
    payload["sessions"].as_array().unwrap().iter().map(|s| s["session_id"].as_str().unwrap().to_owned()).collect()
}

#[tokio::test]
async fn starts_with_dead_upstream_and_probe_promotes_it_when_it_comes_up() {
    let good = spawn_fake_rex(vec![json!({"session_id":"session:g1"})], false).await;
    // Reserve a port, release it, and bring a server up on it only later.
    let late_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let late_addr = late_listener.local_addr().unwrap();
    drop(late_listener);
    let late = format!("http://{late_addr}");

    let h = start_gateway(&[("good", &good), ("late", &late)], tmo(500), tmo(50), tmo(500)).await;
    // The gateway is already serving even though "late" is unreachable.
    wait_state(&h.pool, "good", UpstreamState::Online).await;
    wait_state(&h.pool, "late", UpstreamState::Offline).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    assert_eq!(ids(&reply), ["good:session:g1"]);
    assert_eq!(reply["partial"], true);
    assert_eq!(reply["failed_upstreams"], json!(["late"]));
    assert!(reply["upstream_errors"]["late"].as_str().unwrap().contains("Offline"));

    // /status reports the dead upstream as Offline.
    let status = h.pool.get("late").await.unwrap();
    assert_eq!((status.state, status.consecutive_failures >= 2), (UpstreamState::Offline, true));

    // Bring it up: the next probe promotes it, and the list is complete again.
    spawn_fake_rex_on(TcpListener::bind(late_addr).await.unwrap(), vec![json!({"session_id":"session:l1"})], false).await;
    wait_state(&h.pool, "late", UpstreamState::Online).await;
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    assert_eq!(ids(&reply), ["good:session:g1", "late:session:l1"]);
    assert!(reply.get("partial").is_none() && reply.get("failed_upstreams").is_none(), "complete list is unchanged: {reply}");
}

#[tokio::test]
async fn session_list_errors_only_when_every_allowed_upstream_fails() {
    let dead = dead_url().await;
    let h = start_gateway(&[("dead", &dead)], tmo(300), tmo(50), tmo(300)).await;
    wait_state(&h.pool, "dead", UpstreamState::Offline).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    assert!(reply["error"].as_str().unwrap().contains("all upstreams failed"), "{reply}");
    assert!(reply["error"].as_str().unwrap().contains("dead"), "{reply}");
}

#[tokio::test]
async fn failing_online_upstream_is_skipped_not_fatal() {
    let good = spawn_fake_rex(vec![json!({"session_id":"session:g1"}), json!({"session_id":"session:g2"})], false).await;
    let dead = dead_url().await;
    // Probe effectively disabled: force "flaky" Online so the gateway really calls it and sees the failure.
    let h = start_gateway(&[("flaky", &dead), ("good", &good)], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("flaky", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("good", UpstreamState::Online, Some(1), 2).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    assert_eq!(ids(&reply), ["good:session:g1", "good:session:g2"]);
    assert_eq!((&reply["partial"], &reply["failed_upstreams"]), (&json!(true), &json!(["flaky"])));
}

#[tokio::test]
async fn hung_upstream_times_out_without_hanging_the_agent() {
    let good = spawn_fake_rex(vec![json!({"session_id":"session:g1"})], false).await;
    let hung = spawn_fake_rex(vec![], true).await;
    let h = start_gateway(&[("good", &good), ("hung", &hung)], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("good", UpstreamState::Online, Some(1), 1).await;
    h.pool.mark("hung", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;

    let started = tokio::time::Instant::now();
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    assert_eq!(ids(&reply), ["good:session:g1"]);
    assert_eq!(reply["failed_upstreams"], json!(["hung"]));
    assert!(reply["upstream_errors"]["hung"].as_str().unwrap().contains("timeout"), "{reply}");

    // A routed (non-list) call to the hung upstream fails within the timeout, and the gateway keeps working.
    let started = tokio::time::Instant::now();
    let reply = rpc(&mut socket, "server.version", json!({"host":"hung"})).await;
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(reply["error"].as_str().unwrap().contains("timeout"), "{reply}");
    assert_eq!(rpc(&mut socket, "server.version", json!({"host":"good"})).await, json!({"ok":true}));
}

#[tokio::test]
async fn client_fails_fast_during_backoff_and_never_fails_construction() {
    let client = ControlClient::new("dead".into(), dead_url().await, crate::control_client::Options { call_timeout:tmo(300), ping_interval:Duration::from_secs(20), idle_timeout:Duration::from_secs(120) }, broadcast::channel(4).0);
    let first = client.call("session.list", json!({})).await.unwrap_err().to_string();
    let started = tokio::time::Instant::now();
    let second = client.call("session.list", json!({})).await.unwrap_err().to_string();
    assert!(started.elapsed() < tmo(100), "backoff must fail fast, took {:?}", started.elapsed());
    assert!(second.contains("retry in"), "first={first} second={second}");
}

#[tokio::test]
async fn data_plane_hello_timeout_rejects_and_closes() {
    let h = start_gateway(&[("a", "http://127.0.0.1:9")], tmo(300), Duration::from_secs(3600), tmo(200)).await;
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await; // sends nothing
    let started = tokio::time::Instant::now();
    let first = tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must not hang").unwrap().unwrap();
    assert_eq!(first, tungstenite::Message::Binary(vec![0x82, 0x05].into()));
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must close").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1008, "HELLO timeout")),
        other => panic!("expected close, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn data_plane_upstream_connect_timeout_closes_with_1011() {
    // Accepts TCP but never completes the WebSocket handshake.
    let stuck = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", stuck.local_addr().unwrap());
    let held = tokio::spawn(async move { let mut keep = Vec::new(); while let Ok((s, _)) = stuck.accept().await { keep.push(s); } });
    let h = start_gateway(&[("stuck", &url)], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("stuck", UpstreamState::Online, Some(1), 0).await;
    let external = h.state.tickets.insert("stuck", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();

    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    let started = tokio::time::Instant::now();
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must not hang").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1011, "upstream connect timeout")),
        other => panic!("expected close, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(3));
    // Connect-path failure restores the gateway ticket so the agent may retry until TTL.
    assert_eq!(h.state.tickets.pending(), 1, "ticket restored after connect timeout");
    let restored = h.state.tickets.take(&external, SECRET).expect("same ticket takeable again");
    assert_eq!(restored.upstream, "stuck");
    assert_eq!(restored.upstream_ticket, "AAAAAAAAAAAAAAAAAAAAAA");
    held.abort();
}

#[tokio::test]
async fn data_plane_upstream_connection_failed_restores_ticket() {
    // Nothing listens: TCP connect fails immediately → 1011 + ticket restored.
    let h = start_gateway(&[("down", "http://127.0.0.1:9")], tmo(300), Duration::from_secs(3600), tmo(500)).await;
    h.pool.mark("down", UpstreamState::Online, Some(1), 0).await;
    let external = h.state.tickets.insert("down", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must not hang").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1011, "upstream connection failed")),
        other => panic!("expected close, got {other:?}"),
    }
    assert_eq!(h.state.tickets.pending(), 1, "ticket restored after connection failed");
    assert!(h.state.tickets.take(&external, SECRET).is_some());
}

#[tokio::test]
async fn data_plane_missing_upstream_restores_ticket() {
    let h = start_gateway(&[("a", "http://127.0.0.1:9")], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    let external = h.state.tickets.insert("gone", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must not hang").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1011, "upstream unavailable")),
        other => panic!("expected close, got {other:?}"),
    }
    assert_eq!(h.state.tickets.pending(), 1);
    assert!(h.state.tickets.take(&external, SECRET).is_some());
}

/// Sticky control refuses Offline hosts; data attach must too (fail-fast, restore ticket) instead of
/// dialing a known-Offline URL and waiting for connect timeout / connection failed.
#[tokio::test]
async fn data_plane_offline_upstream_refuses_and_restores_ticket() {
    let h = start_gateway(&[("dead", "http://127.0.0.1:9")], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("dead", UpstreamState::Offline, None, 0).await;
    let external = h.state.tickets.insert("dead", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(2), socket.next()).await.expect("must not hang").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1011, "upstream offline")),
        other => panic!("expected offline close, got {other:?}"),
    }
    assert_eq!(h.state.tickets.pending(), 1, "ticket restored after offline refuse");
    assert_eq!(h.state.metrics.snapshot().tickets_restored, 1);
    assert!(h.state.tickets.take(&external, SECRET).is_some());
}


#[tokio::test]
async fn data_plane_invalid_upstream_ticket_restores_ticket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let Ok(mut upstream) = accept_hdr_async(stream, |req: &Request, mut response: Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(DATA_SUBPROTOCOL));
                Ok(response)
            }).await else { continue };
            while let Some(Ok(_)) = upstream.next().await {}
        }
    });
    let h = start_gateway(&[("local", &url)], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external = h.state.tickets.insert("local", "!!!not-valid-base64!!!", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must not hang").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1011, "invalid upstream ticket")),
        other => panic!("expected close, got {other:?}"),
    }
    assert_eq!(h.state.tickets.pending(), 1, "ticket restored after invalid upstream ticket");
    let restored = h.state.tickets.take(&external, SECRET).expect("same ticket takeable again");
    assert_eq!(restored.upstream, "local");
    assert_eq!(restored.upstream_ticket, "!!!not-valid-base64!!!");
}

#[tokio::test]
async fn data_plane_upstream_hello_send_failed_restores_ticket() {
    // Complete the WS handshake then RST the peer while the gateway flushes a large HELLO so
    // `upstream_socket.send` returns Err and the ticket is restored (not committed).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            {
                use std::os::fd::AsRawFd;
                #[repr(C)]
                struct Linger { l_onoff: i32, l_linger: i32 }
                extern "C" {
                    fn setsockopt(fd: i32, level: i32, name: i32, val: *const Linger, len: u32) -> i32;
                }
                let linger = Linger { l_onoff: 1, l_linger: 0 };
                unsafe { setsockopt(stream.as_raw_fd(), 1, 13, &linger, std::mem::size_of::<Linger>() as u32); }
            }
            let Ok(upstream) = accept_hdr_async(stream, |req: &Request, mut response: Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(DATA_SUBPROTOCOL));
                Ok(response)
            }).await else { continue };
            drop(upstream);
        }
    });
    let oversized = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        vec![0u8; 256 * 1024],
    );
    let h = start_gateway(&[("local", &url)], tmo(300), Duration::from_secs(3600), tmo(500)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external = h.state.tickets.insert("local", &oversized, SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must not hang").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1011, "upstream HELLO failed")),
        other => panic!("expected close, got {other:?}"),
    }
    assert_eq!(h.state.tickets.pending(), 1, "ticket restored after HELLO send failure");
    let restored = h.state.tickets.take(&external, SECRET).expect("same ticket takeable again");
    assert_eq!(restored.upstream, "local");
    assert_eq!(restored.upstream_ticket, oversized);
}

#[tokio::test]
async fn data_plane_successful_hello_consumes_ticket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let Ok(mut upstream) = accept_hdr_async(stream, |req: &Request, mut response: Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(DATA_SUBPROTOCOL));
                Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(hello))) = upstream.next().await else { continue };
            if hello.first() != Some(&1) { continue; }
            if upstream.send(tungstenite::Message::Binary(vec![0x81])).await.is_err() { continue; }
            while let Some(Ok(_)) = upstream.next().await {}
        }
    });
    let h = start_gateway(&[("local", &url)], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external = h.state.tickets.insert("local", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    assert!(!next_binary(&mut socket).await.is_empty());
    assert_eq!(h.state.tickets.pending(), 0, "successful HELLO commits the ticket");
    assert!(h.state.tickets.take(&external, SECRET).is_none(), "committed ticket is not restorable");
}

#[tokio::test]
async fn wrong_bearer_is_still_rejected_before_upgrade() {
    let h = start_gateway(&[("a", "http://127.0.0.1:9")], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    let mut request = format!("ws://{}/api/control", h.addr).into_client_request().unwrap();
    request.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
    request.headers_mut().insert("authorization", HeaderValue::from_static("Bearer it-secre"));
    let error = connect_async(request).await.unwrap_err();
    assert!(error.to_string().contains("401"), "{error}");
}

#[tokio::test]
async fn events_are_namespaced_forwarded_and_do_not_break_rpc() {
    let good=spawn_fake_rex(vec![json!({"session_id":"session:a"})],false).await;
    let h=start_gateway(&[("good",&good)],tmo(500),Duration::from_secs(3600),tmo(300)).await;
    wait_state(&h.pool, "good", UpstreamState::Online).await;
    let mut socket=control_agent(h.addr).await;
    rpc(&mut socket, "session.attach", json!({"session_id":"good:session:e","event_scope":"session"})).await;
    let sender=h.state.events.clone();
    let before_tickets = h.state.tickets.pending();
    sender.send(UpstreamEvent { upstream:"good".into(), event:json!({"type":"event","seq":99,"payload":{"session_id":"session:e","view":{"session_id":"session:v","ticket":"up-ticket"}}}) }).unwrap();
    tokio::time::sleep(tmo(30)).await;
    socket.send(tungstenite::Message::Text(json!({"type":"request","id":"correlate","method":"server.version","payload":{}}).to_string())).await.unwrap();
    let event=match socket.next().await.unwrap().unwrap() { tungstenite::Message::Text(text)=>serde_json::from_str::<Value>(&text).unwrap(), other=>panic!("unexpected {other:?}") };
    assert_eq!(event["type"],"event");
    assert_eq!(event["payload"]["session_id"],"good:session:e");
    assert_eq!(event["payload"]["view"]["session_id"],"good:session:v");
    let ticket = event["payload"]["view"]["ticket"].as_str().unwrap();
    assert_ne!(ticket, "up-ticket");
    assert_eq!(h.state.tickets.pending(), before_tickets + 1, "event tickets rewritten once, not twice");
    assert!(h.state.sessions.contains("good:session:e"), "event must record top-level session");
    assert!(h.state.sessions.contains("good:session:v"), "event must record nested session");
    let mapped = h.state.tickets.take(ticket, SECRET).unwrap();
    assert_eq!(mapped.upstream_ticket, "up-ticket");
    assert_eq!(mapped.session_id.as_deref(), Some("good:session:v"), "event tickets bind to nearest session");
    let response=loop {
        match socket.next().await.unwrap().unwrap() {
            tungstenite::Message::Text(text)=>break serde_json::from_str::<Value>(&text).unwrap(),
            tungstenite::Message::Ping(bytes)=>socket.send(tungstenite::Message::Pong(bytes)).await.unwrap(),
            other=>panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(response["id"],"correlate");
    assert_eq!(response["payload"],json!({"ok":true}));
}

#[tokio::test]
async fn session_list_includes_degraded_and_skips_offline() {
    let online = spawn_fake_rex(vec![json!({"session_id":"session:on"})], false).await;
    let slow = spawn_fake_rex(vec![json!({"session_id":"session:slow"})], false).await;
    let dead = dead_url().await;
    // Long probe interval so our manual marks stick for the list call.
    let h = start_gateway(&[("online", &online), ("slow", &slow), ("dead", &dead)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "online", UpstreamState::Online).await;
    wait_state(&h.pool, "slow", UpstreamState::Online).await;
    h.pool.mark("slow", UpstreamState::Degraded, Some(1500), 1).await;
    h.pool.mark("dead", UpstreamState::Offline, None, 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    assert_eq!(ids(&reply), ["online:session:on", "slow:session:slow"], "{reply}");
    assert_eq!(reply["partial"], true);
    assert_eq!(reply["failed_upstreams"], json!(["dead"]));
    assert!(reply["upstream_errors"]["dead"].as_str().unwrap().contains("Offline"), "{reply}");
}

#[tokio::test]
async fn session_list_recursively_rewrites_nested_tickets() {
    let live = spawn_fake_rex(vec![json!({
        "session_id":"session:root",
        "label":"nested",
        "view":{"session_id":"session:view","ticket":"list-ticket"}
    })], false).await;
    let h = start_gateway(&[("live", &live)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "live", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    let sessions = reply["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "{reply}");
    assert_eq!(sessions[0]["session_id"], "live:session:root");
    assert_eq!(sessions[0]["view"]["session_id"], "live:session:view");
    let ticket = sessions[0]["view"]["ticket"].as_str().unwrap();
    assert_ne!(ticket, "list-ticket");
    let mapped = h.state.tickets.take(ticket, SECRET).unwrap();
    assert_eq!(mapped.upstream_ticket, "list-ticket");
    assert_eq!(mapped.session_id.as_deref(), Some("live:session:view"), "list tickets bind to nearest session");
    assert!(h.state.sessions.contains("live:session:root"));
    assert!(h.state.sessions.contains("live:session:view"));
}

#[tokio::test]
async fn data_bridges_send_pings_and_propagate_upstream_close() {
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url=format!("http://{}",listener.local_addr().unwrap());
    let (closed_tx,closed_rx)=tokio::sync::oneshot::channel();
    // Probe also dials this URL; reject /api/control and keep accepting until /api/data arrives.
    tokio::spawn(async move {
        loop {
            let Ok((stream,_))=listener.accept().await else { return };
            let Ok(mut upstream)=accept_hdr_async(stream,|req:&Request,mut response:Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol",HeaderValue::from_static(DATA_SUBPROTOCOL)); Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(hello)))=upstream.next().await else { continue };
            if hello.first()!=Some(&1) { continue; }
            if upstream.send(tungstenite::Message::Binary(vec![0x81])).await.is_err() { continue; }
            while let Some(Ok(frame))=tokio::time::timeout(Duration::from_secs(2),upstream.next()).await.unwrap_or(None) {
                match frame {
                    tungstenite::Message::Pong(_)=>{},
                    tungstenite::Message::Close(_)=>break,
                    tungstenite::Message::Ping(_)=> {
                        if upstream.send(tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame { code:4421.into(),reason:"custom close".into() }))).await.is_err() { break; }
                        let _=closed_tx.send(true);
                        return;
                    },
                    _=>{}
                }
            }
        }
    });
    let h=start_gateway_with_keepalive(&[("local",&url)],tmo(300),Duration::from_secs(3600),tmo(300),tmo(30),tmo(120)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external=h.state.tickets.insert("local","AAAAAAAAAAAAAAAAAAAAAA",SECRET);
    let raw=base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,external).unwrap();
    let mut socket=agent(h.addr,"/api/data",DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..],&raw].concat())).await.unwrap();
    assert!(!next_binary(&mut socket).await.is_empty());
    let mut saw_ping=false;
    let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
    loop {
        let left=deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left,socket.next()).await {
            Err(_)=>panic!("missing upstream close"),
            Ok(None)|Ok(Some(Err(_)))=>panic!("socket dropped"),
            Ok(Some(Ok(tungstenite::Message::Ping(_))))=>{ saw_ping=true; }
            Ok(Some(Ok(tungstenite::Message::Pong(_))))=>{}
            Ok(Some(Ok(tungstenite::Message::Close(frame))))=> {
                let frame=frame.unwrap();
                assert_eq!((u16::from(frame.code),frame.reason.as_ref()),(4421,"custom close"));
                break;
            }
            Ok(Some(Ok(other)))=>panic!("unexpected {other:?}"),
        }
    }
    assert!(closed_rx.await.unwrap());
    assert!(saw_ping);
}

#[tokio::test]
async fn idle_control_connections_ping_then_close_1001() {
    let good=spawn_fake_rex(vec![],false).await;
    // Application-idle (not pong-idle): keepalive pings still flow, but with no RPC the agent is closed.
    let h=start_gateway_with_keepalive(&[("good",&good)],tmo(300),Duration::from_secs(3600),tmo(300),tmo(30),tmo(120)).await;
    let mut socket=control_agent(h.addr).await;
    let mut saw_ping=false;
    let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
    loop {
        let left=deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left,socket.next()).await {
            Err(_)=>panic!("idle agent was not closed"),
            Ok(None)|Ok(Some(Err(_)))=>panic!("agent dropped without close frame"),
            Ok(Some(Ok(tungstenite::Message::Ping(_))))=>{ saw_ping=true; }
            Ok(Some(Ok(tungstenite::Message::Pong(_))))=>{}
            Ok(Some(Ok(tungstenite::Message::Close(frame))))=> {
                let frame=frame.expect("close frame");
                assert_eq!((u16::from(frame.code),frame.reason.as_ref()),(1001,"idle timeout"));
                assert!(saw_ping, "expected keepalive ping before idle close");
                return;
            }
            Ok(Some(Ok(other)))=>panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn idle_data_bridges_send_pings_then_close_both_sides() {
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url=format!("http://{}",listener.local_addr().unwrap());
    let (closed_tx,closed_rx)=tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream,_))=listener.accept().await else { return };
            let Ok(mut upstream)=accept_hdr_async(stream,|req:&Request,mut response:Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol",HeaderValue::from_static(DATA_SUBPROTOCOL)); Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(hello)))=upstream.next().await else { continue };
            if hello.first()!=Some(&1) { continue; }
            if upstream.send(tungstenite::Message::Binary(vec![0x81])).await.is_err() { continue; }
            let mut saw_ping=false;
            while let Some(Ok(frame))=tokio::time::timeout(Duration::from_secs(2),upstream.next()).await.unwrap_or(None) {
                match frame {
                    tungstenite::Message::Ping(_)=>saw_ping=true,
                    tungstenite::Message::Close(frame)=>{ let _=closed_tx.send((saw_ping,u16::from(frame.unwrap().code))); return; },
                    _=>{}
                }
            }
        }
    });
    let h=start_gateway_with_keepalive(&[("local",&url)],tmo(300),Duration::from_secs(3600),tmo(300),tmo(30),tmo(120)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external=h.state.tickets.insert("local","AAAAAAAAAAAAAAAAAAAAAA",SECRET);
    let raw=base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,external).unwrap();
    let mut socket=agent(h.addr,"/api/data",DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..],&raw].concat())).await.unwrap();
    assert!(!next_binary(&mut socket).await.is_empty());
    let mut saw_ping=false;
    let mut saw_close=false;
    let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
    loop {
        let left=deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left,socket.next()).await {
            Err(_)=>break,
            Ok(None)|Ok(Some(Err(_)))=>break,
            Ok(Some(Ok(tungstenite::Message::Ping(_))))=>{ saw_ping=true; }
            Ok(Some(Ok(tungstenite::Message::Pong(_))))=>{}
            Ok(Some(Ok(tungstenite::Message::Close(frame))))=> {
                assert_eq!(u16::from(frame.unwrap().code),1001);
                saw_close=true;
                break;
            }
            Ok(Some(Ok(other)))=>panic!("unexpected {other:?}"),
        }
    }
    assert!(saw_ping, "gateway should ping the idle data agent");
    let (upstream_ping, code)=closed_rx.await.expect("upstream should observe idle close");
    assert!(upstream_ping && code==1001, "upstream saw ping={upstream_ping} code={code}");
    let _ = saw_close; // Close frame is best-effort; upstream 1001 is authoritative
}

#[tokio::test]
async fn agent_abrupt_disconnect_closes_upstream_data_socket() {
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url=format!("http://{}",listener.local_addr().unwrap());
    let (closed_tx,closed_rx)=tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream,_))=listener.accept().await else { return };
            let Ok(mut upstream)=accept_hdr_async(stream,|req:&Request,mut response:Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol",HeaderValue::from_static(DATA_SUBPROTOCOL)); Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(hello)))=upstream.next().await else { continue };
            if hello.first()!=Some(&1) { continue; }
            if upstream.send(tungstenite::Message::Binary(vec![0x81])).await.is_err() { continue; }
            while let Some(Ok(frame))=tokio::time::timeout(Duration::from_secs(2),upstream.next()).await.unwrap_or(None) {
                match frame {
                    tungstenite::Message::Close(frame)=>{
                        let frame=frame.expect("close frame");
                        let _=closed_tx.send((u16::from(frame.code), frame.reason.to_string()));
                        return;
                    }
                    _=>{}
                }
            }
        }
    });
    let h=start_gateway(&[("local",&url)],tmo(300),Duration::from_secs(3600),tmo(300)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external=h.state.tickets.insert("local","AAAAAAAAAAAAAAAAAAAAAA",SECRET);
    let raw=base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,external).unwrap();
    let mut socket=agent(h.addr,"/api/data",DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..],&raw].concat())).await.unwrap();
    assert!(!next_binary(&mut socket).await.is_empty());
    // Drop the TCP without a WebSocket Close frame.
    drop(socket);
    let (code, reason)=tokio::time::timeout(Duration::from_secs(2), closed_rx).await
        .expect("upstream should observe peer-closed close")
        .expect("oneshot");
    assert_eq!((code, reason.as_str()), (1001, "peer closed"));
}

/// Upstream is mid-send when the agent disappears: either the agent_stream EOF arm or an
/// agent_sink.send failure must close the upstream with 1001 "peer closed" (shared helper).
#[tokio::test]
async fn agent_gone_during_upstream_send_closes_upstream_1001() {
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url=format!("http://{}",listener.local_addr().unwrap());
    let (closed_tx,closed_rx)=tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream,_))=listener.accept().await else { return };
            let Ok(mut upstream)=accept_hdr_async(stream,|req:&Request,mut response:Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol",HeaderValue::from_static(DATA_SUBPROTOCOL)); Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(hello)))=upstream.next().await else { continue };
            if hello.first()!=Some(&1) { continue; }
            if upstream.send(tungstenite::Message::Binary(vec![0x81])).await.is_err() { continue; }
            // Keep pushing application frames so a late agent_sink.send failure is exercised
            // if the agent disappears after ACCEPT while traffic is in flight.
            let mut closed_tx = Some(closed_tx);
            loop {
                if upstream.send(tungstenite::Message::Binary(vec![0x01, 0x02, 0x03, 0x04])).await.is_err() { return; }
                match tokio::time::timeout(Duration::from_millis(50), upstream.next()).await {
                    Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                        let frame = frame.expect("close frame");
                        if let Some(tx) = closed_tx.take() {
                            let _ = tx.send((u16::from(frame.code), frame.reason.to_string()));
                        }
                        return;
                    }
                    Ok(Some(Ok(_))) | Ok(None) | Err(_) => {}
                    Ok(Some(Err(_))) => return,
                }
            }
        }
    });
    let h=start_gateway(&[("local",&url)],tmo(300),Duration::from_secs(3600),tmo(300)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external=h.state.tickets.insert("local","AAAAAAAAAAAAAAAAAAAAAA",SECRET);
    let raw=base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,external).unwrap();
    let mut socket=agent(h.addr,"/api/data",DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..],&raw].concat())).await.unwrap();
    assert!(!next_binary(&mut socket).await.is_empty());
    // Let at least one upstream→agent frame land, then drop without a Close frame.
    let _ = tokio::time::timeout(Duration::from_millis(100), socket.next()).await;
    drop(socket);
    let (code, reason)=tokio::time::timeout(Duration::from_secs(2), closed_rx).await
        .expect("upstream should observe peer-closed close")
        .expect("oneshot");
    assert_eq!((code, reason.as_str()), (1001, "peer closed"));
}

#[tokio::test]
async fn data_stream_limit_closes_1013_without_burning_ticket() {
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url=format!("http://{}",listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream,_))=listener.accept().await else { return };
            let Ok(mut upstream)=accept_hdr_async(stream,|req:&Request,mut response:Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol",HeaderValue::from_static(DATA_SUBPROTOCOL)); Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(_)))=upstream.next().await else { continue };
            let _=upstream.send(tungstenite::Message::Binary(vec![0x81])).await;
            // Hold the bridge open until the peer closes.
            while let Some(Ok(_))=upstream.next().await {}
        }
    });
    let h=start_gateway_with_limits(&[("local",&url)],tmo(300),Duration::from_secs(3600),tmo(300),Duration::from_secs(20),Duration::from_secs(120),1,1).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let first=h.state.tickets.insert("local","AAAAAAAAAAAAAAAAAAAAAA",SECRET);
    let second=h.state.tickets.insert("local","BBBBBBBBBBBBBBBBBBBBBB",SECRET);
    let raw1=base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,&first).unwrap();
    let raw2=base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,&second).unwrap();
    let mut held=agent(h.addr,"/api/data",DATA_SUBPROTOCOL).await;
    held.send(tungstenite::Message::Binary([&[1u8][..],&raw1].concat())).await.unwrap();
    assert!(!next_binary(&mut held).await.is_empty());
    let mut limited=agent(h.addr,"/api/data",DATA_SUBPROTOCOL).await;
    limited.send(tungstenite::Message::Binary([&[1u8][..],&raw2].concat())).await.unwrap();
    let close=loop {
        match tokio::time::timeout(Duration::from_secs(2),limited.next()).await.expect("limit close").unwrap().unwrap() {
            tungstenite::Message::Close(frame)=>break frame.unwrap(),
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_)=>{}
            other=>panic!("expected limit close, got {other:?}"),
        }
    };
    assert_eq!((u16::from(close.code), close.reason.as_ref()), (1013, "per-token data stream limit"));
    // Ticket was not consumed on the capacity miss.
    let mapped=h.state.tickets.take(&second, SECRET).expect("limited ticket must remain usable");
    assert_eq!(mapped.upstream_ticket, "BBBBBBBBBBBBBBBBBBBBBB");
}

#[tokio::test]
async fn control_per_token_limit_closes_1013_without_welcome() {
    let url = spawn_fake_rex(vec![], false).await;
    let h = start_gateway_with_control_limits(&[("local", &url)], tmo(300), Duration::from_secs(3600), tmo(300), 128, 1).await;
    let _held = control_agent(h.addr).await;
    let mut limited = agent(h.addr, "/api/control", SUBPROTOCOL).await;
    let close = loop {
        match tokio::time::timeout(Duration::from_secs(2), limited.next()).await.expect("limit close").unwrap().unwrap() {
            tungstenite::Message::Close(frame) => break frame.unwrap(),
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => {}
            other => panic!("expected limit close before welcome, got {other:?}"),
        }
    };
    assert_eq!((u16::from(close.code), close.reason.as_ref()), (1013, "per-token control connection limit"));
}

#[tokio::test]
async fn control_gateway_limit_closes_1013_without_welcome() {
    let url = spawn_fake_rex(vec![], false).await;
    let h = start_gateway_with_control_limits(&[("local", &url), ("online", &url)], tmo(300), Duration::from_secs(3600), tmo(300), 1, 32).await;
    let _held = control_agent(h.addr).await;
    let mut limited = agent_with_auth(h.addr, "/api/control", SUBPROTOCOL, "Bearer only-online").await;
    let close = loop {
        match tokio::time::timeout(Duration::from_secs(2), limited.next()).await.expect("limit close").unwrap().unwrap() {
            tungstenite::Message::Close(frame) => break frame.unwrap(),
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => {}
            other => panic!("expected gateway limit close before welcome, got {other:?}"),
        }
    };
    assert_eq!((u16::from(close.code), close.reason.as_ref()), (1013, "gateway control connection limit"));
}

#[tokio::test]
async fn agent_control_rejects_frame_over_max_message_bytes() {
    // Agent sockets must apply max_frame_size == MAX_MESSAGE_BYTES (not tungstenite's 16 MiB
    // default). A single frame one byte over the cap must fail the read and end the socket.
    let h = start_gateway(&[("local", &spawn_fake_rex(vec![], false).await)], tmo(500), tmo(5_000), tmo(500)).await;
    let mut socket = control_agent(h.addr).await;
    let oversized = "x".repeat(MAX_MESSAGE_BYTES + 1);
    let frame = json!({"type":"request","id":"big","method":"server.version","payload":{"pad":oversized}}).to_string();
    assert!(frame.len() > MAX_MESSAGE_BYTES);
    // Send may succeed (client-side) while the server rejects during frame parse.
    let _ = socket.send(tungstenite::Message::Text(frame)).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(tungstenite::Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(tungstenite::Message::Ping(b))) => {
                    let _ = socket.send(tungstenite::Message::Pong(b)).await;
                }
                _ => {}
            }
        }
    }).await;
    assert!(closed.is_ok(), "gateway must drop the agent after an oversize frame");
}


#[tokio::test]
async fn namespaced_call_to_offline_upstream_returns_clear_error() {
    let offline = spawn_fake_rex(vec![json!({"session_id":"session:o1"})], false).await;
    let online = spawn_fake_rex(vec![json!({"session_id":"session:g1"})], false).await;
    let h = start_gateway(&[("offline", &offline), ("online", &online)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("offline", UpstreamState::Offline, None, 0).await;
    h.pool.mark("online", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.rename", json!({"session_id":"offline:session:o1","label":"x"})).await;
    let err = reply["error"].as_str().unwrap();
    assert!(err.contains("Offline"), "{reply}");
    assert!(!err.contains("not allowed and online"), "{reply}");

    // Missing-from-pool (even with "*") is reported as unknown, not Offline.
    let reply = rpc(&mut socket, "session.rename", json!({"session_id":"missing:session:x","label":"x"})).await;
    assert!(reply["error"].as_str().unwrap().contains("unknown"), "{reply}");

    // ACL denial stays distinct from Offline / Unknown.
    let mut limited = control_agent_with_auth(h.addr, "Bearer only-online").await;
    let reply = rpc(&mut limited, "session.rename", json!({"session_id":"offline:session:o1","label":"x"})).await;
    let err = reply["error"].as_str().unwrap();
    assert!(err.contains("not allowed"), "{reply}");
    assert!(!err.contains("Offline"), "{reply}");
}

#[tokio::test]
async fn host_targeted_unknown_and_degraded_routing() {
    let live = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("live", &live), ("gone", "http://127.0.0.1:9")], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    // Let the initial probe finish so later marks are not overwritten mid-flight.
    wait_state(&h.pool, "live", UpstreamState::Online).await;
    for _ in 0..200 {
        if h.pool.get("gone").await.unwrap().state != UpstreamState::Unknown { break; }
        tokio::time::sleep(tmo(25)).await;
    }
    h.pool.mark("live", UpstreamState::Degraded, Some(20), 0).await;
    h.pool.mark("gone", UpstreamState::Unknown, None, 0).await;
    let mut socket = control_agent(h.addr).await;

    let reply = rpc(&mut socket, "server.version", json!({"host":"gone"})).await;
    let err = reply["error"].as_str().unwrap();
    assert!(err.contains("Unknown"), "{reply}");
    assert!(err.contains("pinned host is unavailable"), "host pin must not suggest remove/recreate: {reply}");
    assert!(!err.contains("remove/recreate"), "{reply}");

    h.pool.mark("gone", UpstreamState::Offline, None, 0).await;
    let reply = rpc(&mut socket, "server.version", json!({"host":"gone"})).await;
    let err = reply["error"].as_str().unwrap();
    assert!(err.contains("Offline"), "{reply}");
    assert!(err.contains("pinned host is unavailable"), "{reply}");
    assert!(!err.contains("remove/recreate"), "host-pinned non-create Offline: {reply}");

    // Degraded remains routable.
    assert_eq!(rpc(&mut socket, "server.version", json!({"host":"live"})).await, json!({"ok":true}));
}

#[tokio::test]
async fn session_create_picks_least_loaded_online_upstream() {
    let heavy = spawn_fake_rex(vec![], false).await;
    let light = spawn_fake_rex(vec![], false).await;
    // ids intentionally reverse of load so "first by id" would pick heavy (aaa)
    let h = start_gateway(&[("aaa-heavy", &heavy), ("zzz-light", &light)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "aaa-heavy", UpstreamState::Online).await;
    wait_state(&h.pool, "zzz-light", UpstreamState::Online).await;
    h.pool.mark("aaa-heavy", UpstreamState::Online, Some(1), 9).await;
    h.pool.mark("zzz-light", UpstreamState::Online, Some(5), 1).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.create", json!({})).await;
    assert_eq!(reply["session_id"], "zzz-light:session:created", "{reply}");
}

#[tokio::test]
async fn data_plane_unexpected_upstream_drop_closes_agent_1011() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let Ok(mut upstream) = accept_hdr_async(stream, |req: &Request, mut response: Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(DATA_SUBPROTOCOL));
                Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(hello))) = upstream.next().await else { continue };
            if hello.first() != Some(&1) { continue; }
            let _ = upstream.send(tungstenite::Message::Binary(vec![0x81])).await;
            // Abruptly drop the TCP side with no Close frame.
            drop(upstream);
            return;
        }
    });
    let h = start_gateway(&[("local", &url)], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external = h.state.tickets.insert("local", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat())).await.unwrap();
    assert!(!next_binary(&mut socket).await.is_empty());
    let close = loop {
        match tokio::time::timeout(Duration::from_secs(2), socket.next()).await.expect("close").unwrap().unwrap() {
            tungstenite::Message::Close(frame) => break frame.unwrap(),
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => {}
            other => panic!("expected close after upstream drop, got {other:?}"),
        }
    };
    assert_eq!((u16::from(close.code), close.reason.as_ref()), (1011, "upstream closed"));
}

/// When forwarding agent→upstream fails (upstream already gone), the agent must get a clean
/// 1011 "upstream closed" — mirroring the upstream→agent peer-close path.
#[tokio::test]
async fn agent_to_upstream_send_failure_closes_agent_1011() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let Ok(mut upstream) = accept_hdr_async(stream, |req: &Request, mut response: Response| {
                if !req.uri().path().ends_with("/api/data") { return Err(ErrorResponse::new(None)); }
                response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(DATA_SUBPROTOCOL));
                Ok(response)
            }).await else { continue };
            let Some(Ok(tungstenite::Message::Binary(hello))) = upstream.next().await else { continue };
            if hello.first() != Some(&1) { continue; }
            let _ = upstream.send(tungstenite::Message::Binary(vec![0x81])).await;
            // Tear down the TCP immediately so the next gateway→upstream write fails (or the
            // upstream stream ends); either arm must close the agent with 1011.
            drop(upstream);
            return;
        }
    });
    let h = start_gateway(&[("local", &url)], tmo(300), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("local", UpstreamState::Online, Some(1), 0).await;
    let external = h.state.tickets.insert("local", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat())).await.unwrap();
    assert!(!next_binary(&mut socket).await.is_empty());
    // Push an application frame so the bridge exercises agent→upstream send after the peer is gone.
    let _ = socket.send(tungstenite::Message::Binary(vec![0x01, 0x02, 0x03])).await;
    let close = loop {
        match tokio::time::timeout(Duration::from_secs(2), socket.next()).await.expect("close").unwrap().unwrap() {
            tungstenite::Message::Close(frame) => break frame.unwrap(),
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => {}
            tungstenite::Message::Binary(_) | tungstenite::Message::Text(_) => {}
            other => panic!("expected close after upstream send failure, got {other:?}"),
        }
    };
    assert_eq!((u16::from(close.code), close.reason.as_ref()), (1011, "upstream closed"));
}

#[tokio::test]
async fn status_reports_session_store_gauges() {
    let h = start_gateway(&[("local", &spawn_fake_rex(vec![], false).await)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    let id = h.state.sessions.record_at("local", "session:gauge", 10);
    assert!(h.state.sessions.forget(&id).unwrap());
    let _ = h.state.sessions.record_at("local", "session:live", 20);
    let stream = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    writer.write_all(format!("GET /status HTTP/1.1\r\nHost: x\r\nAuthorization: {SECRET}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    // HTTP may use \n; find JSON object
    let json_start = text.find('{').expect("json");
    let json: Value = serde_json::from_str(&text[json_start..]).unwrap();
    assert_eq!(json["counters"]["session_refs"], 1, "{json}");
    assert!(json["counters"]["session_forgotten"].as_u64().unwrap() >= 1, "{json}");
    let _ = body;
}

#[tokio::test]
async fn capability_tags_create_routing_bootstrap_and_owner_degradation() {
    let low=spawn_fake_rex(vec![],false).await;
    let busy=spawn_fake_rex(vec![json!({"session_id":"session:busy"})],false).await;
    let h=start_gateway(&[("low",&low),("busy",&busy)],tmo(500),Duration::from_secs(3600),tmo(300)).await;
    h.pool.upsert_with_metadata("low",&low,Source::Manual,vec!["perf".into()],Some("compile box".into())).await;
    h.pool.upsert_with_metadata("busy",&busy,Source::Manual,vec!["perf".into(),"prod-svc".into()],None).await;
    h.pool.mark("low",UpstreamState::Online,Some(5),1).await;
    h.pool.mark("busy",UpstreamState::Online,Some(1),0).await;
    let mut socket=control_agent(h.addr).await;
    let reply=rpc(&mut socket,"session.create",json!({"prefer_tags":["perf"],"avoid_tags":["prod-svc"]})).await;
    assert_eq!(reply["session_id"],"low:session:created");
    let reply=rpc(&mut socket,"session.create",json!({"prefer_tags":["macos"]})).await;
    assert!(reply["error"].as_str().unwrap().contains("change tag requirements"));
    let reply=rpc(&mut socket,"session.bootstrap",json!({"session_id":"busy:session:busy"})).await;
    assert_eq!(reply["upstream"]["id"],"busy");
    assert_eq!(reply["upstreams"][1]["tags"],json!(["perf"]));
    assert_eq!(reply["upstreams"][1]["description"],"compile box");
    assert!(reply["upstreams"][1]["session_count"].is_u64());
    h.pool.mark("busy",UpstreamState::Offline,None,0).await;
    let reply=rpc(&mut socket,"session.create",json!({"host":"busy"})).await;
    let err=reply["error"].as_str().unwrap();
    assert!(err.contains("Offline"), "{reply}");
    assert!(err.contains("wait") || err.contains("choose a different host"), "{reply}");
    assert!(!err.contains("remove/recreate"), "create has no session yet: {reply}");
    let reply=rpc(&mut socket,"session.bootstrap",json!({"session_id":"busy:session:busy"})).await;
    assert!(reply["error"].as_str().unwrap().contains("remove/recreate"));
    let reply=rpc(&mut socket,"session.list",json!({})).await;
    assert_eq!(ids(&reply),Vec::<String>::new()); // no sessions on low, old session is not hidden by avoid/tags
    h.pool.mark("low",UpstreamState::Degraded,Some(5),1).await;
    let reply=rpc(&mut socket,"session.create",json!({"host":"low","avoid_tags":["perf"],"prefer_tags":["macos"]})).await;
    assert_eq!(reply["session_id"],"low:session:created", "explicit host pin wins over tag constraints");
}

#[tokio::test]
async fn manual_forget_then_every_session_call_fails_clearly() {
    let live=spawn_fake_rex(vec![json!({"session_id":"session:kept"})],false).await;
    let h=start_gateway(&[("local",&live)],tmo(500),Duration::from_secs(3600),tmo(300)).await;
    wait_state(&h.pool,"local",UpstreamState::Online).await;
    let mut socket=control_agent(h.addr).await;
    let listed=rpc(&mut socket,"session.list",json!({})).await;
    let id=listed["sessions"][0]["session_id"].as_str().unwrap().to_owned();
    let reply=rpc(&mut socket,"session.forget",json!({"session_id":id})).await;
    assert_eq!(reply["forgotten"],true);
    for method in ["session.rename","session.read","session.send","session.bootstrap"] {
        let reply=rpc(&mut socket,method,json!({"session_id":id,"label":"x"})).await;
        assert_eq!(reply["error"],crate::sessions::FORGOTTEN_ERROR,"{method}: {reply}");
    }
}

#[tokio::test]
async fn data_attach_after_forget_rejects_before_upstream() {
    let url="http://127.0.0.1:9";
    let h=start_gateway(&[("local",url)],tmo(100),Duration::from_secs(3600),tmo(300)).await;
    h.pool.mark("local",UpstreamState::Online,Some(1),0).await;
    let id="local:session:stale";
    h.state.sessions.record("local","session:stale");
    let external=h.state.tickets.insert("local","AAAAAAAAAAAAAAAAAAAAAA",SECRET);
    h.state.tickets.bind_session(&external,id);
    assert!(h.state.sessions.forget(id).unwrap());
    let raw=base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,external).unwrap();
    let mut socket=agent(h.addr,"/api/data",DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..],&raw].concat())).await.unwrap();
    let first = socket.next().await.unwrap().unwrap();
    assert_eq!(first, tungstenite::Message::Binary(vec![0x82, 0x01].into()), "forgotten attach must send binary REJECT like bad-ticket");
    match socket.next().await.unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => {
            assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1008, crate::sessions::FORGOTTEN_ERROR));
        }
        other => panic!("{other:?}"),
    }
}

/// Tickets rewritten out of session.list / bootstrap / events must refuse attach after
/// session.forget without any manual bind_session — that was previously only wired for
/// top-level data.connect responses.
#[tokio::test]
async fn list_issued_ticket_rejects_after_forget() {
    let live = spawn_fake_rex(vec![json!({
        "session_id":"session:root",
        "view":{"session_id":"session:view","ticket":"AAAAAAAAAAAAAAAAAAAAAA"}
    })], false).await;
    let h = start_gateway(&[("live", &live)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "live", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.list", json!({})).await;
    let external = reply["sessions"][0]["view"]["ticket"].as_str().unwrap().to_owned();
    let view_id = reply["sessions"][0]["view"]["session_id"].as_str().unwrap().to_owned();
    assert_eq!(view_id, "live:session:view");
    // Forget the view session the ticket is bound to.
    assert_eq!(rpc(&mut socket, "session.forget", json!({"session_id": view_id})).await["forgotten"], true);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &external).unwrap();
    let mut data = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    data.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat())).await.unwrap();
    let first = data.next().await.unwrap().unwrap();
    assert_eq!(first, tungstenite::Message::Binary(vec![0x82, 0x01].into()), "forgotten attach must send binary REJECT");
    match data.next().await.unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => {
            assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1008, crate::sessions::FORGOTTEN_ERROR));
        }
        other => panic!("expected forgotten close, got {other:?}"),
    }
}

#[tokio::test]
async fn persist_harness_restart_ttl_and_capacity_route_or_error() {
    let live=spawn_fake_rex(vec![json!({"session_id":"session:a"})],false).await;
    let dir=tempfile::tempdir().unwrap();
    let store=crate::sessions::SessionStore::open(dir.path().join("sessions.json"),Duration::from_millis(20),1).unwrap();
    let h=start_gateway_with_store(&[("a",&live)],tmo(300),Duration::from_secs(3600),tmo(300),Duration::from_secs(20),Duration::from_secs(120),128,32,128,32,Some(store.clone())).await;
    wait_state(&h.pool,"a",UpstreamState::Online).await;
    // The router and this test share the real temporary-file store.
    let mut socket=control_agent(h.addr).await;
    let id=ids(&rpc(&mut socket,"session.list",json!({})).await)[0].clone();
    assert_eq!(rpc(&mut socket,"session.rename",json!({"session_id":id})).await,json!({"ok":true}));
    // A new handle against the same JSON file models a gateway process restart.
    let restarted=crate::sessions::SessionStore::open(dir.path().join("sessions.json"),Duration::from_millis(20),1).unwrap();
    assert_eq!(restarted.resolve(&id).unwrap().session_id,"session:a");
    store.reap_at(u64::MAX);
    assert_eq!(rpc(&mut socket,"session.rename",json!({"session_id":id})).await["error"],crate::sessions::FORGOTTEN_ERROR);
    // A second reference under max=1 removes the older one, not the freshly learned one.
    h.state.sessions.record_at("a","session:old",1);
    h.state.sessions.record_at("a","session:new",2);
    h.state.sessions.reap_at(3);
    assert_eq!(rpc(&mut socket,"session.rename",json!({"session_id":"a:session:old"})).await["error"],crate::sessions::FORGOTTEN_ERROR);
    assert_eq!(rpc(&mut socket,"session.rename",json!({"session_id":"a:session:new"})).await,json!({"ok":true}));
}

#[tokio::test]
async fn prefer_avoid_hosts_create_routing_and_list_visibility() {
    let a=spawn_fake_rex(vec![json!({"session_id":"session:on-a"})],false).await;
    let b=spawn_fake_rex(vec![json!({"session_id":"session:on-b"})],false).await;
    let h=start_gateway(&[("host-a",&a),("host-b",&b)],tmo(500),Duration::from_secs(3600),tmo(300)).await;
    h.pool.mark("host-a",UpstreamState::Online,Some(1),0).await;
    h.pool.mark("host-b",UpstreamState::Online,Some(1),0).await;
    let mut socket=control_agent(h.addr).await;
    // prefer_hosts boosts host-b
    let reply=rpc(&mut socket,"session.create",json!({"prefer_hosts":["host-b"]})).await;
    assert_eq!(reply["session_id"],"host-b:session:created");
    // avoid_hosts excludes host-b
    let reply=rpc(&mut socket,"session.create",json!({"avoid_hosts":["host-b"]})).await;
    assert_eq!(reply["session_id"],"host-a:session:created");
    // hard host pin overrides avoid
    let reply=rpc(&mut socket,"session.create",json!({"host":"host-b","avoid_hosts":["host-b"]})).await;
    assert_eq!(reply["session_id"],"host-b:session:created", "explicit host pin wins over avoid_hosts");
    // list still shows sessions on avoided hosts
    let reply=rpc(&mut socket,"session.list",json!({})).await;
    let listed=ids(&reply);
    assert!(listed.iter().any(|id| id.starts_with("host-b:")), "avoid must not hide list: {listed:?}");
    // all avoided → clear error
    let reply=rpc(&mut socket,"session.create",json!({"avoid_hosts":["host-a","host-b"]})).await;
    assert!(reply["error"].as_str().unwrap().contains("avoid_hosts"), "{reply}");
}

#[tokio::test]
async fn create_failovers_transport_error_to_next_upstream() {
    // aaa sorts before zzz; equal load → first pick is the hung host, then failover to live.
    let hung = spawn_fake_rex(vec![], true).await;
    let live = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("aaa-hung", &hung), ("zzz-live", &live)], tmo(250), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("aaa-hung", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("zzz-live", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.create", json!({})).await;
    assert_eq!(reply["session_id"], "zzz-live:session:created", "{reply}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.create_transport_failovers, 1, "{snap:?}");
    assert_eq!(snap.create_failover_exhausted, 0, "{snap:?}");
}

#[tokio::test]
async fn create_hard_host_pin_does_not_failover() {
    let hung = spawn_fake_rex(vec![], true).await;
    let live = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("hung", &hung), ("live", &live)], tmo(250), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("hung", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("live", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.create", json!({"host":"hung"})).await;
    assert!(reply["error"].as_str().unwrap().contains("timeout") || reply["error"].as_str().unwrap().contains("unavailable") || reply["error"].as_str().unwrap().contains("closed"), "{reply}");
    // Live still works after the pinned failure.
    let reply = rpc(&mut socket, "session.create", json!({"host":"live"})).await;
    assert_eq!(reply["session_id"], "live:session:created", "{reply}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.create_transport_failovers, 0, "{snap:?}");
    assert_eq!(snap.create_failover_exhausted, 0, "{snap:?}");
}

#[tokio::test]
async fn create_application_error_does_not_failover() {
    // aaa-err sorts first; app-level error must be returned without trying zzz-ok.
    let err_host = spawn_fake_rex_create_app_error("quota exceeded").await;
    let ok_host = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("aaa-err", &err_host), ("zzz-ok", &ok_host)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("aaa-err", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("zzz-ok", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.create", json!({})).await;
    assert_eq!(reply["error"], "quota exceeded", "{reply}");
    assert!(reply.get("session_id").is_none(), "{reply}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.create_transport_failovers, 0, "{snap:?}");
    assert_eq!(snap.create_failover_exhausted, 0, "{snap:?}");
}

#[tokio::test]
async fn create_all_transport_failures_aggregate_error() {
    let a = spawn_fake_rex(vec![], true).await;
    let b = spawn_fake_rex(vec![], true).await;
    let h = start_gateway(&[("host-a", &a), ("host-b", &b)], tmo(200), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("host-a", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("host-b", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.create", json!({})).await;
    let err = reply["error"].as_str().unwrap();
    assert!(err.contains("session.create failed on all candidates"), "{reply}");
    assert!(err.contains("host-a"), "{reply}");
    assert!(err.contains("host-b"), "{reply}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.create_transport_failovers, 2, "{snap:?}");
    assert_eq!(snap.create_failover_exhausted, 1, "{snap:?}");
}

#[tokio::test]
async fn hostless_failovers_transport_error_to_next_upstream() {
    // aaa sorts before zzz under pick_default; hung first, then live for server.version.
    let hung = spawn_fake_rex(vec![], true).await;
    let live = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("aaa-hung", &hung), ("zzz-live", &live)], tmo(250), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("aaa-hung", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("zzz-live", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "server.version", json!({})).await;
    assert_eq!(reply["ok"], true, "{reply}");
    // Hung host should have been marked failed (Degraded after one transport failure).
    let state = h.pool.get("aaa-hung").await.unwrap().state;
    assert!(matches!(state, UpstreamState::Degraded | UpstreamState::Offline), "{state:?}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.hostless_transport_failovers, 1, "{snap:?}");
    assert_eq!(snap.hostless_failover_exhausted, 0, "{snap:?}");
}

#[tokio::test]
async fn hostless_hard_host_pin_does_not_failover() {
    let hung = spawn_fake_rex(vec![], true).await;
    let live = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("hung", &hung), ("live", &live)], tmo(250), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("hung", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("live", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "server.version", json!({"host":"hung"})).await;
    assert!(reply["error"].as_str().unwrap().contains("timeout") || reply["error"].as_str().unwrap().contains("unavailable") || reply["error"].as_str().unwrap().contains("closed"), "{reply}");
    let reply = rpc(&mut socket, "server.version", json!({"host":"live"})).await;
    assert_eq!(reply["ok"], true, "{reply}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.hostless_transport_failovers, 0, "{snap:?}");
    assert_eq!(snap.hostless_failover_exhausted, 0, "{snap:?}");
}

#[tokio::test]
async fn hostless_application_error_does_not_failover() {
    let err_host = spawn_fake_rex_method_app_error("server.version", "not supported").await;
    let ok_host = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("aaa-err", &err_host), ("zzz-ok", &ok_host)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("aaa-err", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("zzz-ok", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "server.version", json!({})).await;
    assert_eq!(reply["error"], "not supported", "{reply}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.hostless_transport_failovers, 0, "{snap:?}");
    assert_eq!(snap.hostless_failover_exhausted, 0, "{snap:?}");
}

#[tokio::test]
async fn hostless_all_transport_failures_aggregate_error() {
    let a = spawn_fake_rex(vec![], true).await;
    let b = spawn_fake_rex(vec![], true).await;
    let h = start_gateway(&[("host-a", &a), ("host-b", &b)], tmo(200), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("host-a", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("host-b", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "server.version", json!({})).await;
    let err = reply["error"].as_str().unwrap();
    assert!(err.contains("server.version failed on all candidates"), "{reply}");
    assert!(err.contains("host-a"), "{reply}");
    assert!(err.contains("host-b"), "{reply}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.hostless_transport_failovers, 2, "{snap:?}");
    assert_eq!(snap.hostless_failover_exhausted, 1, "{snap:?}");
}


#[tokio::test]
async fn nested_session_ids_are_denamespaced_before_upstream() {
    let live = spawn_fake_rex_echo_forwarded_session_ids().await;
    let h = start_gateway(&[("local", &live)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "local", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    h.state.sessions.record("local", "session:root");
    let reply = rpc(&mut socket, "session.rename", json!({
        "session_id":"local:session:root",
        "view":{"session_id":"local:session:view","label":"x"},
        "alternates":[{"session_id":"local:session:child"}]
    })).await;
    assert_eq!(reply["forwarded_top"], "session:root", "{reply}");
    assert_eq!(reply["forwarded_view"], "session:view", "{reply}");
    assert_eq!(reply["forwarded_child"], "session:child", "{reply}");
}

#[tokio::test]
async fn foreign_nested_session_id_is_rejected() {
    let live = spawn_fake_rex_echo_forwarded_session_ids().await;
    let h = start_gateway(&[("local", &live)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "local", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    h.state.sessions.record("local", "session:root");
    let reply = rpc(&mut socket, "session.rename", json!({
        "session_id":"local:session:root",
        "view":{"session_id":"other:session:view"}
    })).await;
    let err = reply["error"].as_str().unwrap_or("");
    assert!(err.contains("other"), "{reply}");
    assert!(err.contains("expected local") || err.contains("mismatched"), "{reply}");
}

#[tokio::test]
async fn forwards_rex_frame_level_errors_without_decorating() {
    let err = json!({"code":"bad_request","message":"event_scope must be \"all\" or \"session\"","status":400});
    let live = spawn_fake_rex_frame_error("session.bootstrap", err.clone()).await;
    let h = start_gateway(&[("local", &live)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "local", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    let frame = rpc_frame(&mut socket, "session.bootstrap", json!({"session_id":"local:session:x"})).await;
    assert!(frame.get("payload").is_none() || frame["payload"].is_null(), "must not invent a success payload: {frame}");
    assert_eq!(frame["error"], err, "{frame}");
    // Must not have been decorated with gateway upstream metadata.
    assert!(frame.get("payload").and_then(|p| p.get("upstream")).is_none(), "{frame}");
}

#[tokio::test]
async fn frame_level_create_error_does_not_failover() {
    let err = json!({"code":"conflict","message":"quota exceeded","status":409});
    // aaa sorts first; frame error must surface without trying zzz-ok.
    let err_host = spawn_fake_rex_frame_error("session.create", err.clone()).await;
    let ok_host = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("aaa-err", &err_host), ("zzz-ok", &ok_host)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("aaa-err", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("zzz-ok", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let frame = rpc_frame(&mut socket, "session.create", json!({})).await;
    assert_eq!(frame["error"], err, "{frame}");
    assert!(frame.get("payload").is_none() || frame["payload"].is_null(), "{frame}");
    let snap = h.state.metrics.snapshot();
    assert_eq!(snap.create_transport_failovers, 0, "{snap:?}");
    assert_eq!(snap.create_failover_exhausted, 0, "{snap:?}");
}

#[tokio::test]
async fn frame_level_data_connect_error_is_not_masked() {
    let err = json!({"code":"bad_request","message":"invalid data reference: reference is empty","status":400});
    let live = spawn_fake_rex_frame_error("data.connect", err.clone()).await;
    let h = start_gateway(&[("local", &live)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "local", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    // Record a session so resolve/touch succeed, then data.connect hits the frame error.
    h.state.sessions.record("local", "session:x");
    let frame = rpc_frame(&mut socket, "data.connect", json!({"session_id":"local:session:x"})).await;
    assert_eq!(frame["error"], err, "must forward Rex error, not invent omitted-ticket: {frame}");
    assert_ne!(frame.pointer("/payload/error").and_then(Value::as_str), Some("upstream data.connect omitted ticket"));
}

#[tokio::test]
async fn slow_rpc_does_not_stall_events_or_concurrent_rpc() {
    // A slow upstream RPC must not block event forwarding or a second concurrent RPC.
    let url = spawn_fake_rex_delayed("server.slow", tmo(400)).await;
    let h = start_gateway_with_keepalive(
        &[("local", &url)],
        tmo(2000),
        Duration::from_secs(3600),
        tmo(300),
        tmo(40),
        tmo(5000),
    ).await;
    wait_state(&h.pool, "local", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    rpc(&mut socket, "session.attach", json!({"session_id":"local:session:live","event_scope":"session"})).await;

    socket.send(tungstenite::Message::Text(
        json!({"type":"request","id":"slow","method":"server.slow","payload":{}}).to_string(),
    )).await.unwrap();
    socket.send(tungstenite::Message::Text(
        json!({"type":"request","id":"fast","method":"server.version","payload":{}}).to_string(),
    )).await.unwrap();
    h.state.events.send(UpstreamEvent {
        upstream: "local".into(),
        event: json!({"type":"event","seq":1,"payload":{"session_id":"session:live","note":"while-slow"}}),
    }).unwrap();

    let mut saw_fast = false;
    let mut saw_event = false;
    let mut saw_ping = false;
    let mut saw_slow = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline && !(saw_fast && saw_event && saw_slow) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = match tokio::time::timeout(remaining, socket.next()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(e))) => panic!("socket error: {e}"),
            Ok(None) => panic!("socket closed early"),
            Err(_) => break,
        };
        match frame {
            tungstenite::Message::Ping(bytes) => {
                saw_ping = true;
                socket.send(tungstenite::Message::Pong(bytes)).await.unwrap();
            }
            tungstenite::Message::Text(text) => {
                let msg: Value = serde_json::from_str(&text).unwrap();
                match msg["type"].as_str() {
                    Some("event") => {
                        assert_eq!(msg["payload"]["session_id"], "local:session:live");
                        saw_event = true;
                        // Event must arrive while the slow RPC is still outstanding.
                        assert!(!saw_slow, "event arrived after slow RPC finished — select was stalled");
                    }
                    Some("response") if msg["id"] == "fast" => {
                        assert_eq!(msg["payload"], json!({"ok": true}));
                        saw_fast = true;
                        assert!(!saw_slow, "fast RPC completed only after slow — select was stalled");
                    }
                    Some("response") if msg["id"] == "slow" => {
                        assert_eq!(msg["payload"], json!({"slow": true}));
                        saw_slow = true;
                    }
                    other => panic!("unexpected message {other:?}: {msg}"),
                }
            }
            tungstenite::Message::Pong(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert!(saw_fast, "fast concurrent RPC must complete");
    assert!(saw_event, "upstream event must be forwarded during slow RPC");
    assert!(saw_slow, "slow RPC must eventually complete");
    let _ = saw_ping; // keepalive may or may not fire in the short window; event+fast prove liveness
    assert!(h.state.metrics.snapshot().events_forwarded >= 1);
}

#[tokio::test]
async fn in_flight_control_rpc_bound_returns_clear_error() {
    // Hung upstream keeps calls in flight until call timeout; overflow must reject immediately.
    let hung = spawn_fake_rex(vec![], true).await;
    let h = start_gateway(&[("hung", &hung)], Duration::from_secs(5), Duration::from_secs(3600), tmo(300)).await;
    // Mark online without waiting for probe (hung never answers session.list).
    h.pool.mark("hung", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;

    for i in 0..MAX_IN_FLIGHT_CONTROL_RPCS {
        socket.send(tungstenite::Message::Text(
            json!({"type":"request","id":format!("hold-{i}"),"method":"server.version","payload":{"host":"hung"}}).to_string(),
        )).await.unwrap();
    }
    // Give spawns a moment to claim in-flight slots before the overflow request.
    tokio::time::sleep(tmo(50)).await;
    socket.send(tungstenite::Message::Text(
        json!({"type":"request","id":"overflow","method":"server.version","payload":{"host":"hung"}}).to_string(),
    )).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut overflow: Option<Value> = None;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = match tokio::time::timeout(remaining, socket.next()).await {
            Ok(Some(Ok(frame))) => frame,
            _ => break,
        };
        match frame {
            tungstenite::Message::Ping(bytes) => { let _ = socket.send(tungstenite::Message::Pong(bytes)).await; }
            tungstenite::Message::Text(text) => {
                let msg: Value = serde_json::from_str(&text).unwrap();
                if msg["type"] == "response" && msg["id"] == "overflow" {
                    overflow = Some(msg);
                    break;
                }
            }
            _ => {}
        }
    }
    let overflow = overflow.expect("overflow response must arrive promptly");
    assert_eq!(
        overflow["payload"]["error"].as_str(),
        Some("too many in-flight control RPCs"),
        "{overflow}"
    );
}

/// A panicked RPC handler must still free its in-flight slot so later calls are not stuck
/// behind a phantom occupancy until the agent reconnects.
#[tokio::test]
async fn panicked_control_rpc_releases_in_flight_slot() {
    let hung = spawn_fake_rex(vec![], true).await;
    let h = start_gateway(&[("hung", &hung)], Duration::from_secs(5), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("hung", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;

    // Panic returns a clear gateway error and must not tear down the agent socket.
    let boom = rpc(&mut socket, "gateway.__test_panic", json!({})).await;
    assert_eq!(boom["error"].as_str(), Some("control RPC task panicked"), "{boom}");

    // Slot freed: occupying all 16 with hung upstream calls, then overflow must still fire.
    for i in 0..MAX_IN_FLIGHT_CONTROL_RPCS {
        socket.send(tungstenite::Message::Text(
            json!({"type":"request","id":format!("hold-{i}"),"method":"server.version","payload":{"host":"hung"}}).to_string(),
        )).await.unwrap();
    }
    tokio::time::sleep(tmo(50)).await;
    socket.send(tungstenite::Message::Text(
        json!({"type":"request","id":"overflow","method":"server.version","payload":{"host":"hung"}}).to_string(),
    )).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut overflow: Option<Value> = None;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = match tokio::time::timeout(remaining, socket.next()).await {
            Ok(Some(Ok(frame))) => frame,
            _ => break,
        };
        match frame {
            tungstenite::Message::Ping(bytes) => { let _ = socket.send(tungstenite::Message::Pong(bytes)).await; }
            tungstenite::Message::Text(text) => {
                let msg: Value = serde_json::from_str(&text).unwrap();
                if msg["type"] == "response" && msg["id"] == "overflow" {
                    overflow = Some(msg);
                    break;
                }
            }
            _ => {}
        }
    }
    let overflow = overflow.expect("overflow response must arrive promptly after panic freed its slot");
    assert_eq!(
        overflow["payload"]["error"].as_str(),
        Some("too many in-flight control RPCs"),
        "{overflow}"
    );
}


#[tokio::test]
async fn lagged_events_notify_agent_with_gateway_notice() {
    // Tiny broadcast buffer so flooding while the agent is slow to read produces Lagged.
    let good = spawn_fake_rex(vec![], false).await;
    let h = start_gateway_with_event_cap(
        &[("good", &good)], tmo(500), Duration::from_secs(3600), tmo(300),
        Duration::from_secs(20), Duration::from_secs(120), 128, 32, 128, 32, None, 2,
    ).await;
    wait_state(&h.pool, "good", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    let sender = h.state.events.clone();

    // Flood far past capacity without giving the agent a chance to drain.
    for i in 0..64u64 {
        sender.send(UpstreamEvent {
            upstream: "good".into(),
            event: json!({"type":"event","seq":i,"payload":{"session_id":format!("session:e{i}"),"n":i}}),
        }).unwrap();
    }
    // Brief pause so serve_agent observes Lagged (and may deliver a few early events).
    tokio::time::sleep(tmo(50)).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut saw_notice = false;
    let mut skipped = 0u64;
    while tokio::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = match tokio::time::timeout(left, socket.next()).await {
            Ok(Some(Ok(frame))) => frame,
            _ => break,
        };
        match frame {
            tungstenite::Message::Ping(bytes) => { let _ = socket.send(tungstenite::Message::Pong(bytes)).await; }
            tungstenite::Message::Pong(_) => {}
            tungstenite::Message::Text(text) => {
                let msg: Value = serde_json::from_str(&text).unwrap();
                if msg["type"] == "event" {
                    if let Some(n) = msg["payload"]["gateway"]["skipped"].as_u64() {
                        assert_eq!(msg["payload"]["gateway"]["notice"], "events_lagged");
                        skipped = n;
                        saw_notice = true;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    assert!(saw_notice, "agent must receive gateway events_lagged notice");
    assert!(skipped >= 1, "skipped count must be positive, got {skipped}");
    assert!(h.state.metrics.snapshot().events_lagged >= skipped);
}

#[tokio::test]
async fn forwarded_events_refresh_control_application_idle() {
    // Application-idle (not pong-idle): keepalive pings alone do not keep the socket, but
    // successfully forwarded upstream events must refresh last_activity.
    let good = spawn_fake_rex(vec![], false).await;
    let h = start_gateway_with_keepalive(
        &[("good", &good)], tmo(300), Duration::from_secs(3600), tmo(300), tmo(30), tmo(120),
    ).await;
    wait_state(&h.pool, "good", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    rpc(&mut socket, "session.attach", json!({"session_id":"good:session:alive","event_scope":"session"})).await;
    let sender = h.state.events.clone();

    // Keep delivering events across several idle windows; connection must stay open.
    let keep_until = tokio::time::Instant::now() + Duration::from_millis(360);
    let mut n = 0u64;
    while tokio::time::Instant::now() < keep_until {
        sender.send(UpstreamEvent {
            upstream: "good".into(),
            event: json!({"type":"event","seq":n,"payload":{"session_id":"session:alive","n":n}}),
        }).unwrap();
        n += 1;
        // Drain any pending frames so the sink does not stall.
        loop {
            match tokio::time::timeout(tmo(10), socket.next()).await {
                Ok(Some(Ok(tungstenite::Message::Text(_)))) => {}
                Ok(Some(Ok(tungstenite::Message::Ping(bytes)))) => {
                    let _ = socket.send(tungstenite::Message::Pong(bytes)).await;
                }
                Ok(Some(Ok(tungstenite::Message::Pong(_)))) => {}
                Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                    panic!("idle closed while events were flowing: {frame:?}");
                }
                _ => break,
            }
        }
        tokio::time::sleep(tmo(40)).await;
    }
    assert!(h.state.metrics.snapshot().events_forwarded >= 1, "expected at least one forward");

    // After events stop, application idle must still reap.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Err(_) => panic!("idle agent was not closed after events stopped"),
            Ok(None) | Ok(Some(Err(_))) => panic!("agent dropped without close frame"),
            Ok(Some(Ok(tungstenite::Message::Ping(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Pong(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Text(_)))) => {} // late event
            Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                let frame = frame.expect("close frame");
                assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1001, "idle timeout"));
                return;
            }
            Ok(Some(Ok(other))) => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn control_rpc_responses_refresh_application_idle() {
    // Application-idle: a late but successful control response must refresh last_activity.
    // Request at T=0, response at ~100ms, idle=120ms. Without response refresh the socket
    // would close ~120ms after the request (before or just as the agent finished reading);
    // with refresh it stays open until ~100+120ms after the request.
    let delayed = spawn_fake_rex_delayed("server.version", tmo(150)).await;
    let h = start_gateway_with_keepalive(
        &[("slow", &delayed)], tmo(800), Duration::from_secs(3600), tmo(300), tmo(40), tmo(200),
    ).await;
    wait_state(&h.pool, "slow", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;

    let sent_at = tokio::time::Instant::now();
    socket.send(tungstenite::Message::Text(
        json!({"type":"request","id":"slow-1","method":"server.version","payload":{"host":"slow"}}).to_string(),
    )).await.unwrap();

    // Wait for the response; tolerate keepalive frames.
    let mut got_response = false;
    let deadline = sent_at + Duration::from_millis(700);
    while tokio::time::Instant::now() < deadline && !got_response {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Ok(Some(Ok(tungstenite::Message::Text(text)))) => {
                let msg: Value = serde_json::from_str(&text).unwrap();
                if msg["type"] == "response" && msg["id"] == "slow-1" {
                    assert_eq!(msg["payload"], json!({"slow":true}), "{msg}");
                    got_response = true;
                }
            }
            Ok(Some(Ok(tungstenite::Message::Ping(bytes)))) => {
                let _ = socket.send(tungstenite::Message::Pong(bytes)).await;
            }
            Ok(Some(Ok(tungstenite::Message::Pong(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                panic!("closed before delayed response arrived: {frame:?}");
            }
            Ok(Some(Err(e))) => panic!("socket error before response: {e}"),
            Ok(None) => panic!("socket ended before response"),
            Err(_) => break,
            Ok(Some(Ok(other))) => panic!("unexpected {other:?}"),
        }
    }
    assert!(got_response, "delayed response never arrived");
    let after_response = tokio::time::Instant::now();
    assert!(
        after_response.duration_since(sent_at) >= Duration::from_millis(120),
        "response arrived too fast to distinguish request vs response idle: {:?}",
        after_response.duration_since(sent_at),
    );

    // Still open past the request-relative idle window (request + 120ms).
    let past_request_idle = sent_at + Duration::from_millis(250);
    while tokio::time::Instant::now() < past_request_idle {
        let left = past_request_idle.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Ok(Some(Ok(tungstenite::Message::Ping(bytes)))) => {
                let _ = socket.send(tungstenite::Message::Pong(bytes)).await;
            }
            Ok(Some(Ok(tungstenite::Message::Pong(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                panic!(
                    "idle closed on request clock despite response refresh (elapsed since request {:?}): {frame:?}",
                    tokio::time::Instant::now().duration_since(sent_at),
                );
            }
            Ok(Some(Ok(tungstenite::Message::Text(_)))) => {}
            Ok(Some(Err(_))) | Ok(None) => panic!("socket dropped while proving response refresh"),
            Err(_) => {} // timeout until past_request_idle — expected
            Ok(Some(Ok(other))) => panic!("unexpected {other:?}"),
        }
    }

    // After responses stop, application idle measured from the response must still reap.
    let close_deadline = after_response + Duration::from_secs(2);
    loop {
        let left = close_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Err(_) => panic!("idle agent was not closed after response went idle"),
            Ok(None) | Ok(Some(Err(_))) => panic!("agent dropped without close frame"),
            Ok(Some(Ok(tungstenite::Message::Ping(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Pong(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Text(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                let frame = frame.expect("close frame");
                assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1001, "idle timeout"));
                assert!(
                    tokio::time::Instant::now().duration_since(after_response) >= Duration::from_millis(150),
                    "closed too early after response",
                );
                return;
            }
            Ok(Some(Ok(other))) => panic!("unexpected {other:?}"),
        }
    }
}

/// Bound-overflow responses are still delivered control replies: they must refresh application-idle
/// the same way successful RPC responses do (README: "successfully delivered control response").
///
/// The hung upstream must stay application-alive (so the 16 holds remain in flight and overflow
/// stays local). Ping/pong alone no longer counts on the upstream control client, so the mock
/// emits ignored application text (`type: keepalive`) that refreshes upstream idle without
/// completing RPCs or forwarding events to the agent.
#[tokio::test]
async fn overflow_control_responses_refresh_application_idle() {
    let hung = spawn_fake_rex_hung_keepalive_text().await;
    let h = start_gateway_with_keepalive(
        &[("hung", &hung)], Duration::from_secs(5), Duration::from_secs(3600), tmo(300), tmo(40), tmo(200),
    ).await;
    h.pool.mark("hung", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;

    // Fill all in-flight slots with hung upstream calls (never answer).
    for i in 0..MAX_IN_FLIGHT_CONTROL_RPCS {
        socket.send(tungstenite::Message::Text(
            json!({"type":"request","id":format!("hold-{i}"),"method":"server.version","payload":{"host":"hung"}}).to_string(),
        )).await.unwrap();
    }
    tokio::time::sleep(tmo(50)).await;

    // Deliver overflow replies across several idle windows; connection must stay open.
    let keep_until = tokio::time::Instant::now() + Duration::from_millis(360);
    let mut n = 0u64;
    while tokio::time::Instant::now() < keep_until {
        let id = format!("overflow-{n}");
        socket.send(tungstenite::Message::Text(
            json!({"type":"request","id":id,"method":"server.version","payload":{"host":"hung"}}).to_string(),
        )).await.unwrap();
        n += 1;
        let drain_until = tokio::time::Instant::now() + tmo(40);
        while tokio::time::Instant::now() < drain_until {
            let left = drain_until.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, socket.next()).await {
                Ok(Some(Ok(tungstenite::Message::Text(text)))) => {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    if msg["type"] == "response" && msg["id"].as_str().unwrap_or("").starts_with("overflow-") {
                        assert_eq!(msg["payload"]["error"].as_str(), Some("too many in-flight control RPCs"), "{msg}");
                    }
                }
                Ok(Some(Ok(tungstenite::Message::Ping(bytes)))) => {
                    let _ = socket.send(tungstenite::Message::Pong(bytes)).await;
                }
                Ok(Some(Ok(tungstenite::Message::Pong(_)))) => {}
                Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                    panic!("idle closed while overflow responses were flowing: {frame:?}");
                }
                _ => break,
            }
        }
    }
    assert!(n >= 2, "expected multiple overflow deliveries, got {n}");

    // After overflow traffic stops, application idle must still reap.
    // Upstream keepalive text also stops shortly after; once holds fail they may deliver late
    // error texts (still application traffic). Then idle close.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Err(_) => panic!("idle agent was not closed after overflow traffic stopped"),
            Ok(None) | Ok(Some(Err(_))) => panic!("agent dropped without close frame"),
            Ok(Some(Ok(tungstenite::Message::Ping(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Pong(_)))) => {}
            Ok(Some(Ok(tungstenite::Message::Text(_)))) => {} // late hung replies
            Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                let frame = frame.expect("close frame");
                assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1001, "idle timeout"));
                return;
            }
            Ok(Some(Ok(other))) => panic!("unexpected {other:?}"),
        }
    }
}

/// Hung upstream that never answers RPCs, but periodically sends ignored application text so the
/// gateway's upstream-control application-idle timer does not reap the socket mid-test.
async fn spawn_fake_rex_hung_keepalive_text() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(mut socket) = accept_hdr_async(stream, callback).await else { return };
                let mut keep = tokio::time::interval(Duration::from_millis(50));
                keep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Stop keepalive text after ~500ms so the agent-side idle close phase can finish.
                let stop_keep_at = tokio::time::Instant::now() + Duration::from_millis(500);
                loop {
                    tokio::select! {
                        frame = socket.next() => {
                            match frame {
                                Some(Ok(tungstenite::Message::Text(text))) => {
                                    let message: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                                    if message["type"] == "hello" {
                                        let _ = socket.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await;
                                    }
                                    // requests: swallow (hung)
                                }
                                Some(Ok(tungstenite::Message::Ping(bytes))) => {
                                    let _ = socket.send(tungstenite::Message::Pong(bytes)).await;
                                }
                                Some(Ok(tungstenite::Message::Pong(_))) => {}
                                Some(Ok(tungstenite::Message::Close(_))) | None | Some(Err(_)) => return,
                                _ => {}
                            }
                        }
                        _ = keep.tick(), if tokio::time::Instant::now() < stop_keep_at => {
                            // Text refreshes upstream application-idle; unknown type is ignored by the actor
                            // (not a correlated response, not a forwarded event).
                            if socket.send(tungstenite::Message::Text(json!({"type":"keepalive"}).to_string())).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    url
}

#[tokio::test]
async fn attach_all_fans_out_across_upstreams_and_reports_partial() {
    let a = spawn_fake_rex(vec![json!({"session_id":"session:a1","label":"a"})], false).await;
    let b = spawn_fake_rex(vec![json!({"session_id":"session:b1","label":"b"}), json!({"session_id":"bogus"})], false).await;
    let dead = dead_url().await;
    let h = start_gateway(&[("a", &a), ("b", &b), ("dead", &dead)], tmo(500), tmo(50), tmo(300)).await;
    wait_state(&h.pool, "a", UpstreamState::Online).await;
    wait_state(&h.pool, "b", UpstreamState::Online).await;
    wait_state(&h.pool, "dead", UpstreamState::Offline).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "session.attach_all", json!({"event_scope":"session"})).await;
    assert_eq!(ids(&reply), ["a:session:a1", "b:session:b1"], "{reply}");
    assert_eq!(reply["attached_upstreams"], json!(["a", "b"]), "{reply}");
    assert_eq!(reply["partial"], true);
    assert_eq!(reply["failed_upstreams"], json!(["dead"]));
    assert!(h.state.sessions.contains("b:session:b1"));
    // A hard host pin still goes to exactly one upstream (no fan-out decoration).
    let pinned = rpc(&mut socket, "session.attach_all", json!({"event_scope":"session","host":"a"})).await;
    assert_eq!(ids(&pinned), ["a:session:a1"], "{pinned}");
    assert!(pinned.get("attached_upstreams").is_none(), "{pinned}");
}

#[tokio::test]
async fn attach_all_forwards_frame_error_when_every_upstream_rejects() {
    let err = json!({"code":"bad_request","message":"event_scope must be \"all\" or \"session\"","status":400});
    let x = spawn_fake_rex_frame_error("session.attach_all", err.clone()).await;
    let y = spawn_fake_rex_frame_error("session.attach_all", err.clone()).await;
    let h = start_gateway(&[("x", &x), ("y", &y)], tmo(500), tmo(50), tmo(300)).await;
    wait_state(&h.pool, "x", UpstreamState::Online).await;
    wait_state(&h.pool, "y", UpstreamState::Online).await;
    let mut socket = control_agent(h.addr).await;
    let frame = rpc_frame(&mut socket, "session.attach_all", json!({"event_scope":"bogus"})).await;
    assert_eq!(frame["error"], err, "{frame}");
    assert!(frame.get("payload").is_none() || frame["payload"].is_null(), "{frame}");
}

#[tokio::test]
async fn hostless_nested_session_reference_routes_to_its_owner() {
    // "aaa" would be the pick_default choice; the nested reference must win.
    let aaa = spawn_fake_rex_echo_forwarded_session_ids().await;
    let zzz = spawn_fake_rex_echo_forwarded_session_ids().await;
    let h = start_gateway(&[("aaa", &aaa), ("zzz", &zzz)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    h.pool.mark("aaa", UpstreamState::Online, Some(1), 0).await;
    h.pool.mark("zzz", UpstreamState::Online, Some(1), 0).await;
    let mut socket = control_agent(h.addr).await;
    let reply = rpc(&mut socket, "target.resolve", json!({"view":{"session_id":"zzz:session:ctx"},"queries":[""]})).await;
    assert_eq!(reply["forwarded_view"], "session:ctx", "routed to zzz and stripped: {reply}");
    // Forgotten nested reference is refused like a top-level one.
    h.state.sessions.record("zzz", "session:gone");
    h.state.sessions.forget("zzz:session:gone").unwrap();
    let reply = rpc(&mut socket, "target.resolve", json!({"view":{"session_id":"zzz:session:gone"}})).await;
    assert!(reply["error"].as_str().unwrap_or("").contains("forgotten"), "{reply}");
}

/// Next text frame, answering pings; `None` when nothing arrives within `wait`.
async fn next_text(socket: &mut Agent, wait: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Ok(Some(Ok(tungstenite::Message::Text(text)))) => return Some(serde_json::from_str(&text).unwrap()),
            Ok(Some(Ok(tungstenite::Message::Ping(bytes)))) => { let _ = socket.send(tungstenite::Message::Pong(bytes)).await; }
            Ok(Some(Ok(_))) => {}
            _ => return None,
        }
    }
}

#[tokio::test]
async fn events_follow_each_agents_own_subscriptions() {
    let good = spawn_fake_rex(vec![], false).await;
    let h = start_gateway(&[("good", &good)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "good", UpstreamState::Online).await;
    let mut x = control_agent(h.addr).await;
    let mut y = control_agent(h.addr).await;
    let mut z = control_agent_with_auth(h.addr, "Bearer only-online").await;
    rpc(&mut x, "session.attach", json!({"session_id":"good:session:a","event_scope":"session"})).await;
    rpc(&mut y, "session.attach", json!({"session_id":"good:session:a","event_scope":"session"})).await;
    rpc(&mut y, "session.attach", json!({"session_id":"good:session:b","event_scope":"session"})).await;
    let send = |session: &str| h.state.events.send(UpstreamEvent {
        upstream: "good".into(),
        event: json!({"type":"event","payload":{"type":"session_event","payload":{"session_id":session,"event":{"type":"tick"}}}}),
    }).unwrap();
    send("session:b");
    send("session:a");
    let first = next_text(&mut x, tmo(500)).await.expect("x gets a");
    assert_eq!(first["payload"]["payload"]["session_id"], "good:session:a", "x never sees b: {first}");
    assert_eq!(next_text(&mut y, tmo(500)).await.unwrap()["payload"]["payload"]["session_id"], "good:session:b");
    assert_eq!(next_text(&mut y, tmo(500)).await.unwrap()["payload"]["payload"]["session_id"], "good:session:a");
    assert!(next_text(&mut z, tmo(100)).await.is_none(), "token without access to good gets nothing");
    let counters = h.state.metrics.snapshot();
    assert_eq!(counters.events_dropped_scope, 1, "b dropped for x");
    assert_eq!(counters.events_dropped_acl, 2, "both dropped for z");

    // y still holds a, so x's detach is answered locally and Rex keeps sending a.
    let local = rpc(&mut x, "session.detach", json!({"session_id":"good:session:a"})).await;
    assert_eq!(local, json!({}), "answered by the gateway: {local}");
    send("session:a");
    assert_eq!(next_text(&mut y, tmo(500)).await.unwrap()["payload"]["payload"]["session_id"], "good:session:a");
    assert!(next_text(&mut x, tmo(100)).await.is_none(), "x detached a");
    // Last holder: the detach reaches the (fake) upstream, which answers {"ok":true}.
    let forwarded = rpc(&mut y, "session.detach", json!({"session_id":"good:session:a"})).await;
    assert_eq!(forwarded, json!({"ok":true}), "{forwarded}");
    assert_eq!(h.state.holds.holders("good", "session:a"), 0);

    // attach_all with scope "session" covers every session; failed attaches roll back.
    rpc(&mut x, "session.attach_all", json!({"event_scope":"session"})).await;
    send("session:zzz");
    assert_eq!(next_text(&mut x, tmo(500)).await.unwrap()["payload"]["payload"]["session_id"], "good:session:zzz");
    drop(y);
    tokio::time::sleep(tmo(50)).await;
    assert_eq!(h.state.holds.holders("good", "session:b"), 0, "closed agent releases its holds");
}

#[tokio::test]
async fn failed_attach_does_not_subscribe_and_resubscribe_notice_reaches_subscribers() {
    let err = json!({"code":"session_not_found","message":"session not found","status":404});
    let bad = spawn_fake_rex_frame_error("session.attach", err).await;
    let h = start_gateway(&[("bad", &bad)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "bad", UpstreamState::Online).await;
    let mut x = control_agent(h.addr).await;
    let mut y = control_agent(h.addr).await;
    let frame = rpc_frame(&mut x, "session.attach", json!({"session_id":"bad:session:a","event_scope":"session"})).await;
    assert!(frame["error"].is_object(), "{frame}");
    assert_eq!(h.state.holds.holders("bad", "session:a"), 0, "rolled back");
    h.state.events.send(UpstreamEvent { upstream: "bad".into(), event: json!({"type":"event","payload":{"session_id":"session:a"}}) }).unwrap();
    assert!(next_text(&mut x, tmo(100)).await.is_none(), "failed attach must not subscribe");
    // y subscribes to everything on "bad" (host-pinned attach_all; this fake answers ok).
    rpc(&mut y, "session.attach_all", json!({"event_scope":"all","host":"bad"})).await;
    h.state.events.send(UpstreamEvent { upstream: "bad".into(), event: json!({"type":crate::control_client::RESUBSCRIBED_EVENT_TYPE}) }).unwrap();
    let notice = next_text(&mut y, tmo(500)).await.expect("notice");
    assert_eq!(notice["payload"]["gateway"], json!({"notice":"upstream_resubscribed","upstream":"bad"}));
    assert!(next_text(&mut x, tmo(100)).await.is_none(), "unsubscribed agent gets no resubscribe notice");
}

/// Fake Rex control server that answers every request with `{}` and records `(method, payload)`.
async fn spawn_fake_rex_recording() -> (String, Arc<std::sync::Mutex<Vec<(String, Value)>>>) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let log = log.clone();
            tokio::spawn(async move {
                let callback = |_: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
                    Ok(response)
                };
                let Ok(mut socket) = accept_hdr_async(stream, callback).await else { return };
                while let Some(Ok(tungstenite::Message::Text(text))) = socket.next().await {
                    let message: Value = serde_json::from_str(&text).unwrap();
                    match message["type"].as_str() {
                        Some("hello") => { let _ = socket.send(tungstenite::Message::Text(json!({"type":"welcome"}).to_string())).await; }
                        Some("request") => {
                            log.lock().unwrap().push((message["method"].as_str().unwrap_or_default().to_owned(), message["payload"].clone()));
                            let payload = if message["method"] == "session.attach_all" || message["method"] == "session.list" { json!({"sessions":[]}) } else { json!({}) };
                            let _ = socket.send(tungstenite::Message::Text(json!({"type":"response","id":message["id"],"payload":payload}).to_string())).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    (format!("http://{addr}"), seen)
}

#[tokio::test]
async fn closing_last_holder_detaches_session_upstream() {
    let (url, seen) = spawn_fake_rex_recording().await;
    let h = start_gateway(&[("rec", &url)], tmo(500), Duration::from_secs(3600), tmo(300)).await;
    wait_state(&h.pool, "rec", UpstreamState::Online).await;
    let mut x = control_agent(h.addr).await;
    let mut y = control_agent(h.addr).await;
    rpc(&mut x, "session.attach", json!({"session_id":"rec:session:a","event_scope":"session"})).await;
    rpc(&mut x, "session.attach", json!({"session_id":"rec:session:b","event_scope":"session"})).await;
    rpc(&mut x, "session.attach_all", json!({"event_scope":"all"})).await;
    rpc(&mut y, "session.attach", json!({"session_id":"rec:session:a","event_scope":"session"})).await;
    let detaches = || seen.lock().unwrap().iter().filter(|(m, _)| m == "session.detach").map(|(_, p)| p.clone()).collect::<Vec<_>>();
    x.close(None).await.unwrap();
    let deadline = tokio::time::Instant::now() + tmo(2000);
    while detaches().is_empty() && tokio::time::Instant::now() < deadline { tokio::time::sleep(tmo(20)).await; }
    tokio::time::sleep(tmo(100)).await;
    assert_eq!(detaches(), vec![json!({"session_id":"session:b"})], "a is still held by y; all cannot be detached");
    assert_eq!(h.state.holds.holders("rec", "session:a"), 1);
    assert_eq!(h.state.holds.scope_holders("rec"), (0, 0), "x's scope all released");
    drop(y);
    let deadline = tokio::time::Instant::now() + tmo(2000);
    while detaches().len() < 2 && tokio::time::Instant::now() < deadline { tokio::time::sleep(tmo(20)).await; }
    assert_eq!(detaches(), vec![json!({"session_id":"session:b"}), json!({"session_id":"session:a"})]);
    assert_eq!(h.state.holds.holders("rec", "session:a"), 0);
}
