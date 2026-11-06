# Rex Gateway (control plane)

A self-use authenticated control-plane gateway in front of Rex servers. Rust 2021,
Axum, Tokio, tokio-tungstenite with Rustls. No repository or remote service was created.

## Run

```sh
cp rex-gateway.toml my-gateway.toml # replace the example token
REX_GATEWAY_CONFIG=my-gateway.toml RUST_LOG=info cargo run
```

The config contains `listen`, `probe_interval_ms`, repeated `[[upstreams]]` entries
(`id`, `url`) and `[[auth.tokens]]` entries (`token`, `allow = ["*"]` or upstream IDs).
Environment overrides are `REX_GATEWAY_CONFIG`, `REX_GATEWAY_LISTEN`,
`REX_GATEWAY_PROBE_INTERVAL_MS`, `REX_GATEWAY_TICKET_TTL_MS`, `REX_GATEWAY_TICKET_MAX`,
`REX_GATEWAY_UPSTREAM_CALL_TIMEOUT_MS`, `REX_GATEWAY_DATA_CONNECT_TIMEOUT_MS`, `REX_GATEWAY_WS_PING_INTERVAL_MS`,
`REX_GATEWAY_WS_IDLE_TIMEOUT_MS`, and `REX_GATEWAY_UPSTREAM_LOCAL_URL` (for the
upstream id `local`). Timeouts: `upstream_call_timeout_ms` (default 10000) bounds every call to an
upstream and each (re)connect of its control socket; `data_connect_timeout_ms` (default 10000) bounds the
agent's data-plane HELLO read and the connect to the upstream data socket. Zero is rejected for both. Optional top-level settings `ticket_ttl_ms` (default 30000) and
`ticket_max` (default 1024) bound unused data tickets (see Data plane). Tokens and the token map are intentionally TOML-only for now.

## Protocol and routing decisions

* `GET /api/control`, subprotocol `rex.control.v1`, bearer token required before upgrade.
  Agent sends `{"type":"hello"}`, then receives a gateway welcome (revision 11).
* `session.list` fans out concurrently to allowed upstreams and returns `local:session:<uuid>`-style
  namespaced IDs in sorted upstream-ID order. Upstreams that are not `Online`, or that error or time
  out, are skipped and reported: the response then also carries `"partial":true`,
  `"failed_upstreams":["id",...]` and `"upstream_errors":{"id":"reason"}`. A complete list has none
  of these fields. If every allowed upstream fails, the request returns an error instead
  (`all upstreams failed: ...`). An ACL that permits no upstream returns an empty list.
* Namespaced session calls are routed to their owner, with the prefix stripped upstream.
  Top-level returned session IDs, and session data nested beneath `view`, are wrapped.
* `session.create` targets payload `host` when supplied, otherwise the first allowed
  online upstream by ID. Other non-session methods follow the same documented default.
  `host` is a gateway routing hint stripped before forwarding.
* Startup never needs an upstream: control clients connect lazily on their first call (the probe loop
  makes it) and reconnect after socket loss, with exponential backoff after failed connects
  (200 ms doubling to 5 s; calls fail fast with `retry in N ms` meanwhile). Upstreams start
  `Unknown` and the probe loop (concurrent per upstream) promotes them to `Online` once reachable.
* Agent requests are read serially; upstream calls use a single actor-owned WebSocket,
  ID to oneshot map, and support concurrent callers; each call is bounded by
  `upstream_call_timeout_ms`. Upstream events are forwarded independently to agent controls
  whose token can access the owning upstream, with recursively namespaced session references
  and gateway ticket rewrites. Event and response sequence numbers share one monotonically
  increasing per-agent sequence; request/response IDs retain upstream-independent correlation.
* Probes use `session.list`: success under 1 second = Online, under/over threshold =
  Degraded; two consecutive failed probes = Offline. First failure is Degraded, initial
  state Unknown. Socket reconnection and a fresh hello happen on the next call.
* Routed calls are restricted to Online upstreams (the default router also ignores
  Degraded). No upstream discovery or persistence yet.

## Verify

```sh
cargo build
cargo test
cargo run # separately, with the supplied local config
python3 smoke.py > smoke.out
curl -s -H 'Authorization: Bearer smoke-secret' http://127.0.0.1:7300/status
```

The smoke test checks absent/wrong tokens, hello/welcome, aggregated namespaced list,
default `server.version`, and translating/routing `session.rename`.

## Data plane

`GET /api/data` uses subprotocol `rex.data.terminal.v1` and the same `Authorization:
Bearer ...` token as `/api/control`. Authentication happens before WebSocket upgrade.
A data ticket is additionally bound to that bearer string, so one configured token cannot
consume another token's ticket. The control connection itself need not remain open after
`data.connect`; keep it open if upstream attachment semantics require it.

The gateway recursively rewrites `session_id` and `ticket` fields in responses, including
`data.connect`, `session.bootstrap`, `view`, arrays and other nested ticket-bearing structures.
It records each real upstream ticket privately and returns a new random 16-byte base64url
ticket to the agent. The same TTL, capacity, single-use and bearer-owner rules apply.
When the agent sends binary `0x01 || ticket`, the gateway consumes that ticket once,
connects to the owning upstream, and sends the real binary HELLO. ACCEPT/REJECT, terminal
snapshots, terminal output, and agent input are relayed frame-for-frame between the data
sockets. Ping/pong and close frames, including close codes and reasons, are forwarded.
The gateway also originates keepalive pings on both legs and idle-closes both sides with
`1001 "idle timeout"` when no application (binary/text) traffic arrives for
`ws_idle_timeout_ms`. This is not a terminal protocol parser and does not rewrite bytes
inside stream frames.

Tickets are kept in memory, single-use and bound to the bearer token. An unused ticket lives
at most `ticket_ttl_ms` (default 30000 ms): expiry is enforced when the ticket is consumed and
by a background reaper that purges expired entries (period = TTL/2, clamped to 50 ms..5 s).
At most `ticket_max` (default 1024) tickets are pending; when full, the oldest is evicted, so
memory never grows unbounded. Unknown, expired, evicted, wrong-owner and already-used tickets
all receive REJECT `0x82 0x01` (indistinguishable to the caller); malformed HELLO receives
`0x82 0x05`. An agent that connects but never sends HELLO within `data_connect_timeout_ms` gets
`0x82 0x05` and a close `1008 "HELLO timeout"`; if the upstream data socket cannot be opened in that
time (or fails), the agent socket is closed with `1011 "upstream connect timeout"` /
`"upstream connection failed"`. A wrong-owner attempt does not burn the legitimate owner's live ticket.

## Status endpoint

`GET /status` with `Authorization: Bearer <token>` (401 otherwise) returns JSON:

```json
{
  "upstreams": [
    {"id":"local","url":"http://127.0.0.1:7297","source":"Manual","state":"Online",
     "latency_ms":3,"consecutive_failures":0,"last_error":null,
     "last_probe_age_ms":412,"session_count":2}
  ],
  "counters": {
    "pending_tickets":0,"active_control_connections":1,"active_data_streams":0,
    "tickets_issued":5,"tickets_consumed":4,"tickets_expired":1,"tickets_evicted":0
  }
}
```

Upstream `url`s are shown without credentials: userinfo (`user:pass@`), query and fragment are
stripped (and also removed from `last_error` text). `upstreams` lists only upstreams the token's ACL permits (in any state, sorted by id).
`state` is `Unknown|Online|Degraded|Offline`; `latency_ms` is the last probe's latency
(null if the last probe failed or none ran); `last_error` is the most recent probe error and is
cleared by the next successful probe. `counters` are gateway-wide (not ACL-filtered), totals since
start; `tickets_expired` counts TTL expiries, `tickets_evicted` capacity evictions.

## Authentication

Bearer tokens are hashed with SHA-256 at startup (the `Authenticator` is built once and shared via
`Arc` in the app state). A presented token is hashed and compared in constant time against every
configured digest with no early exit, so neither the token contents nor its length leak through
timing. Ticket-owner binding uses a constant-time comparison too. Behavior is otherwise unchanged:
`Authorization: Bearer <token>` (case-sensitive scheme), per-token upstream ACL list.

## WebSocket keepalive and idle handling
Control and data sockets emit WebSocket pings at `ws_ping_interval_ms` (default 20000) on both
agent and upstream sides. Incoming application frames and pong frames keep a connection alive
(WebSocket libraries normally answer pings automatically). If no incoming frame arrives for
`ws_idle_timeout_ms` (default 120000), the affected connection closes: agent-side idle uses
close 1001 / `idle timeout`; data idle closes both bridge endpoints. The idle timeout must be
greater than the ping interval and both must be nonzero. An agent control initial HELLO/welcome
is completed before the keepalive loop; data HELLO/setup timeouts remain separate as above.
## Remaining TODOs

- Upstream discovery / persistent configuration synchronization.
- Configurable data-plane concurrent stream limits and fragmented-message preservation if
  required by a future Rex protocol version.
- Preserve fragmented-message boundaries if a future Rex version relies on them (Rex
  currently sends complete binary messages; relay preserves each message's bytes/type).

## Data-plane verification

With the supplied local configuration and a running Rex server:

```sh
python3 smoke_data.py > smoke_data.out
```

This obtains a ticket through the gateway, asserts data ACCEPT, sends terminal output via
the real Rex CLI, and checks that `HELLO_FROM_GATEWAY` appears on the gateway data socket.

## Ticket TTL / status verification

Start the gateway with a short TTL, then run the check (it asserts reaper purge, post-TTL
REJECT, and the `/status` gauges):

```sh
REX_GATEWAY_TICKET_TTL_MS=2000 ./target/debug/rex-gateway &
python3 smoke_ttl.py
```
