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
`REX_GATEWAY_PROBE_INTERVAL_MS`, `REX_GATEWAY_TICKET_TTL_MS`, `REX_GATEWAY_TICKET_MAX`, and `REX_GATEWAY_UPSTREAM_LOCAL_URL` (for the
upstream id `local`). Optional top-level settings `ticket_ttl_ms` (default 30000) and
`ticket_max` (default 1024) bound unused data tickets (see Data plane). Tokens and the token map are intentionally TOML-only for now.

## Protocol and routing decisions

* `GET /api/control`, subprotocol `rex.control.v1`, bearer token required before upgrade.
  Agent sends `{"type":"hello"}`, then receives a gateway welcome (revision 11).
* `session.list` fans out to allowed `Online` upstreams in sorted upstream-ID order and
  returns `local:session:<uuid>`-style namespaced IDs. An upstream failure fails that
  list request rather than silently hiding part of the result.
* Namespaced session calls are routed to their owner, with the prefix stripped upstream.
  Top-level returned session IDs, and session data nested beneath `view`, are wrapped.
* `session.create` targets payload `host` when supplied, otherwise the first allowed
  online upstream by ID. Other non-session methods follow the same documented default.
  `host` is a gateway routing hint stripped before forwarding.
* Agents are read/served serially; upstream calls use a single actor-owned WebSocket,
  ID to oneshot map, and support concurrent callers. Events between responses are ignored.
* Probes use `session.list`: success under 1 second = Online, under/over threshold =
  Degraded; two consecutive failed probes = Offline. First failure is Degraded, initial
  state Unknown. Socket reconnection and a fresh hello happen on the next call.
* Routed calls are restricted to Online upstreams (the default router also ignores
  Degraded). No upstream discovery, persistence, or event forwarding yet.

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

The gateway rewrites only the ticket returned by `data.connect`. It records the real
upstream ticket privately and returns a new random 16-byte base64url ticket to the agent.
When the agent sends binary `0x01 || ticket`, the gateway consumes that ticket once,
connects to the owning upstream, and sends the real binary HELLO. ACCEPT/REJECT, terminal
snapshots, terminal output, and agent input are relayed frame-for-frame between the data
sockets. Ping/pong and close frames, including close codes and reasons, are forwarded.
This is not a terminal protocol parser and does not rewrite bytes inside stream frames.

Tickets are kept in memory, single-use and bound to the bearer token. An unused ticket lives
at most `ticket_ttl_ms` (default 30000 ms): expiry is enforced when the ticket is consumed and
by a background reaper that purges expired entries (period = TTL/2, clamped to 50 ms..5 s).
At most `ticket_max` (default 1024) tickets are pending; when full, the oldest is evicted, so
memory never grows unbounded. Unknown, expired, evicted, wrong-owner and already-used tickets
all receive REJECT `0x82 0x01` (indistinguishable to the caller); malformed HELLO receives
`0x82 0x05`. A wrong-owner attempt does not burn the legitimate owner's live ticket.

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

`upstreams` lists only upstreams the token's ACL permits (in any state, sorted by id).
`state` is `Unknown|Online|Degraded|Offline`; `latency_ms` is the last probe's latency
(null if the last probe failed or none ran); `last_error` is the most recent probe error and is
cleared by the next successful probe. `counters` are gateway-wide (not ACL-filtered), totals since
start; `tickets_expired` counts TTL expiries, `tickets_evicted` capacity evictions.

## Remaining TODOs

- Multiplexed inbound event forwarding on control connections.
- Richer recursive response namespacing for ticket-bearing `session.bootstrap` payloads.
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
