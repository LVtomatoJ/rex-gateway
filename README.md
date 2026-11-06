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
  Degraded). No upstream discovery, persistence, data-plane proxy, or event forwarding yet.

## Verify

```sh
cargo build
cargo test
cargo run # separately, with the supplied local config
python3 smoke.py > smoke.out
```

The smoke test checks absent/wrong tokens, hello/welcome, aggregated namespaced list,
default `server.version`, and translating/routing `session.rename`.

## Data-plane TODO

Do not treat `/api/data`, terminal block streams, binary hello/tickets, ticket refresh,
or terminal controls as implemented. A later phase should add those plus multiplexed
inbound event routing and a richer recursive response-namespacing strategy for
`session.bootstrap`/`session.attach_all` data ticket fields.
