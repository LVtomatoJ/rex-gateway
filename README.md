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
`REX_GATEWAY_PROBE_INTERVAL_MS`, and `REX_GATEWAY_UPSTREAM_LOCAL_URL` (for the
upstream id `local`). Tokens and the token map are intentionally TOML-only for now.

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

Tickets are kept in memory. They expire only when consumed or the gateway restarts;
Unused-ticket expiry/capacity limits are a hardening TODO. Unknown and already-used
tickets receive REJECT `0x82 0x01`; malformed HELLO receives `0x82 0x05`.

## Remaining TODOs

- Reaper with bounded unused-ticket TTL/capacity.
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
