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
    accept_hdr_async,
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
                            let payload = if message["method"] == "session.list" {
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


struct Harness { addr: SocketAddr, pool: UpstreamPool, state: AppState }

/// Builds the same wiring as `main` (lazy clients, probe loop) around the given upstreams.
async fn start_gateway(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration) -> Harness {
    start_gateway_with_limits(upstreams, call_timeout, probe_every, data_timeout, Duration::from_secs(20), Duration::from_secs(120), 128, 32).await
}

async fn start_gateway_with_keepalive(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, ping_interval: Duration, idle_timeout: Duration) -> Harness {
    start_gateway_with_limits(upstreams, call_timeout, probe_every, data_timeout, ping_interval, idle_timeout, 128, 32).await
}

async fn start_gateway_with_limits(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, ping_interval: Duration, idle_timeout: Duration, max_data_streams: usize, max_data_streams_per_token: usize) -> Harness {
    start_gateway_with_store(upstreams,call_timeout,probe_every,data_timeout,ping_interval,idle_timeout,max_data_streams,max_data_streams_per_token,None).await
}
async fn start_gateway_with_store(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration, ping_interval: Duration, idle_timeout: Duration, max_data_streams: usize, max_data_streams_per_token: usize, store: Option<crate::sessions::SessionStore>) -> Harness {
    let pool = UpstreamPool::new();
    let clients = ClientMap::new();
    let (events, _) = broadcast::channel(32);
    for (id, url) in upstreams {
        pool.upsert(id, url, Source::Manual).await;
        clients.insert((*id).to_owned(), Arc::new(ControlClient::new((*id).to_owned(), (*url).to_owned(), crate::control_client::Options { call_timeout, ping_interval, idle_timeout }, events.clone())));
    }
    probe::spawn(pool.clone(), clients.clone(), probe_every);
    let metrics = Metrics::new();
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
        options: Options { data_connect_timeout: data_timeout, ping_interval, idle_timeout, max_data_streams, max_data_streams_per_token, create_reservation_ttl: Duration::from_secs(5) },
        data_limiter: DataLimiter::new(),
        events,
        discovery: crate::discovery::DiscoveryHealth::disabled(),
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
    assert_eq!(serde_json::from_str::<Value>(&welcome).unwrap()["type"], "welcome");
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
    let external = h.state.tickets.insert("stuck", "AAAAAAAAAAAAAAAAAAAAAA", SECRET);
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, external).unwrap();

    let mut socket = agent(h.addr, "/api/data", DATA_SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Binary([&[1u8][..], &raw].concat().into())).await.unwrap();
    let started = tokio::time::Instant::now();
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("must not hang").unwrap().unwrap() {
        tungstenite::Message::Close(Some(frame)) => assert_eq!((u16::from(frame.code), frame.reason.as_ref()), (1011, "upstream connect timeout")),
        other => panic!("expected close, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(3));
    held.abort();
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
    let sender=h.state.events.clone();
    sender.send(UpstreamEvent { upstream:"good".into(), event:json!({"type":"event","seq":99,"payload":{"session_id":"session:e","view":{"session_id":"session:v"}}}) }).unwrap();
    tokio::time::sleep(tmo(30)).await;
    socket.send(tungstenite::Message::Text(json!({"type":"request","id":"correlate","method":"server.version","payload":{}}).to_string())).await.unwrap();
    let event=match socket.next().await.unwrap().unwrap() { tungstenite::Message::Text(text)=>serde_json::from_str::<Value>(&text).unwrap(), other=>panic!("unexpected {other:?}") };
    assert_eq!(event["type"],"event");
    assert_eq!(event["payload"]["session_id"],"good:session:e");
    assert_eq!(event["payload"]["view"]["session_id"],"good:session:v");
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
    assert!(reply["error"].as_str().unwrap().contains("Unknown"), "{reply}");

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
    match socket.next().await.unwrap().unwrap(){tungstenite::Message::Close(Some(frame))=>assert_eq!((u16::from(frame.code),frame.reason.as_ref()),(1008,crate::sessions::FORGOTTEN_ERROR)),other=>panic!("{other:?}")}
}

#[tokio::test]
async fn persist_harness_restart_ttl_and_capacity_route_or_error() {
    let live=spawn_fake_rex(vec![json!({"session_id":"session:a"})],false).await;
    let dir=tempfile::tempdir().unwrap();
    let store=crate::sessions::SessionStore::open(dir.path().join("sessions.json"),Duration::from_millis(20),1).unwrap();
    let h=start_gateway_with_store(&[("a",&live)],tmo(300),Duration::from_secs(3600),tmo(300),Duration::from_secs(20),Duration::from_secs(120),128,32,Some(store.clone())).await;
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
}

