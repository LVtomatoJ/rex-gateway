//! End-to-end tests: fake Rex control servers <-> real `ControlClient`/pool/probe <-> the real
//! gateway router <-> a real WebSocket agent client, all over loopback sockets.
use super::*;
use crate::{
    control_client::ControlClient,
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
                            let payload = if message["method"] == "session.list" { json!({"sessions": sessions}) } else { json!({"ok": true}) };
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

struct Harness { addr: SocketAddr, pool: UpstreamPool, state: AppState }

/// Builds the same wiring as `main` (lazy clients, probe loop) around the given upstreams.
async fn start_gateway(upstreams: &[(&str, &str)], call_timeout: Duration, probe_every: Duration, data_timeout: Duration) -> Harness {
    let pool = UpstreamPool::new();
    let mut clients = HashMap::new();
    for (id, url) in upstreams {
        pool.upsert(id, url, Source::Manual).await;
        clients.insert((*id).to_owned(), Arc::new(ControlClient::new((*url).to_owned(), call_timeout)));
    }
    let clients = Arc::new(clients);
    probe::spawn(pool.clone(), clients.clone(), probe_every);
    let metrics = Metrics::new();
    let state = AppState {
        pool: pool.clone(),
        clients,
        auth: Arc::new(Authenticator::new(HashMap::from([("it-secret".to_owned(), vec!["*".to_owned()])]))),
        tickets: TicketMap::new(Duration::from_secs(30), 16, metrics.clone()),
        metrics,
        options: Options { data_connect_timeout: data_timeout },
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Harness { addr, pool, state }
}

async fn agent(addr: SocketAddr, path: &str, protocol: &'static str) -> Agent {
    let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
    request.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(protocol));
    request.headers_mut().insert("authorization", HeaderValue::from_static(SECRET));
    connect_async(request).await.unwrap().0
}

async fn control_agent(addr: SocketAddr) -> Agent {
    let mut socket = agent(addr, "/api/control", SUBPROTOCOL).await;
    socket.send(tungstenite::Message::Text(json!({"type":"hello"}).to_string())).await.unwrap();
    let welcome = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert_eq!(serde_json::from_str::<Value>(&welcome).unwrap()["type"], "welcome");
    socket
}

async fn rpc(socket: &mut Agent, method: &str, payload: Value) -> Value {
    socket.send(tungstenite::Message::Text(json!({"type":"request","id":"r1","method":method,"payload":payload}).to_string())).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(10), socket.next()).await.expect("gateway must answer").unwrap().unwrap().into_text().unwrap();
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
    let client = ControlClient::new(dead_url().await, tmo(300));
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
