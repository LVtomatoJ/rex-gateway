# Rex Gateway

A self-use authenticated control + data gateway in front of one or more Rex servers.
One listen address and one bearer key give agents open/list/send/read plus bidirectional
terminal streams, with multi-upstream routing, health probes, failover, and ticketed
data-plane bridging. Rust 2021, Axum, Tokio, tokio-tungstenite with Rustls.

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
`REX_GATEWAY_WS_IDLE_TIMEOUT_MS`, `REX_GATEWAY_MAX_DATA_STREAMS`,
`REX_GATEWAY_MAX_DATA_STREAMS_PER_TOKEN`, `REX_GATEWAY_MAX_CONTROL_CONNECTIONS`,
`REX_GATEWAY_MAX_CONTROL_CONNECTIONS_PER_TOKEN`, `REX_GATEWAY_UPSTREAM_LOCAL_URL` (for the
upstream id `local`), and the discovery / session-store envs documented below. Timeouts: `upstream_call_timeout_ms` (default 10000) bounds every call to an
upstream and each (re)connect of its control socket; `data_connect_timeout_ms` (default 10000) bounds the
agent's data-plane HELLO read and the connect to the upstream data socket. Zero is rejected for both. Optional top-level settings `ticket_ttl_ms` (default 30000) and
`ticket_max` (default 1024) bound unused data tickets (see Data plane). Concurrent control sockets are bounded by `max_control_connections` /
`max_control_connections_per_token` (defaults 128 / 32; close `1013` before welcome on overflow). Tokens and the token map are intentionally TOML-only for now.

## Protocol and routing decisions

* `GET /api/control`, subprotocol `rex.control.v1`, bearer token required before upgrade.
  Agent sends `{"type":"hello"}`, then receives a gateway welcome (revision 19).
* `session.list` fans out concurrently to allowed upstreams and returns `local:session:<uuid>`-style
  namespaced IDs (recursively wrapping nested `session_id` / `ticket` fields the same way as
  other responses) in sorted upstream-ID order. Upstreams that are not routable (`Online` or
  `Degraded`), or that error or time out, are skipped and reported: the response then also carries
  `"partial":true`, `"failed_upstreams":["id",...]` and `"upstream_errors":{"id":"reason"}`. A
  complete list has none of these fields. If every allowed upstream fails, the request returns an
  error instead (`all upstreams failed: ...`). An ACL that permits no upstream returns an empty
  list. Listing Degraded hosts matches create/RPC routing so a slow-but-alive upstream still
  surfaces its sessions.
* Namespaced session calls are routed to their owner, with the prefix stripped upstream.
  Top-level returned session IDs, and session data nested beneath `view`, are wrapped.
  `wrap_session_id` is idempotent: an already-namespaced id is never double-prefixed.
* `session.create` (and other hostless non-list methods) targets payload `host` when
  supplied; otherwise the gateway picks an ACL-allowed upstream by policy: prefer
  `Online`, then fall back to `Degraded`, scoring by capability tags, soft preferred host
  ids, least effective load (`session_count + reserved`), then lowest `latency_ms`
  (`None` after `Some`), then `id` ascending. Explicit `host` must still be
  ACL-allowed and `Online|Degraded` (not `Offline`/`Unknown`) and wins over soft prefer/avoid
  lists. `host` is a gateway routing hint stripped before forwarding. Namespaced session
  calls stay sticky to their owner; Offline/Unknown owners return a clear
  `upstream {id} is Offline|Unknown` error (ACL denial stays `not allowed`).
* Hostless `session.create` **failovers on transport errors** (timeout, connect failure,
  missing client, socket closed, "retry in …"): the reservation is dropped, the failed
  upstream is marked, and the next-best candidate under the same tag/host preferences is
  tried (already-tried host ids are excluded for that request only). Application-level
  create errors (`{"error":…}` from Rex) and hard `host` pins do **not** failover. When
  every candidate fails with a transport error the agent sees
  `session.create failed on all candidates: id: reason; …`. Each transport hop and
  exhaustion are counted on `/status` (`create_transport_failovers` /
  `create_failover_exhausted`).
* Other hostless methods (no `session_id`, no hard `host` — e.g. `server.version`) use the
  same transport-error failover: candidates are tried in `pick_default` order (Manual Online
  first, then any routable create-eligible by id). Already-tried ids are excluded for that
  request only; the failed upstream is marked. Application-level `{"error":…}` and hard
  `host` pins do **not** failover. Exhaustion surfaces as
  `{method} failed on all candidates: id: reason; …`. Hops and exhaustion are counted
  on `/status` (`hostless_transport_failovers` / `hostless_failover_exhausted`).
* Startup never needs an upstream: control clients connect lazily on their first call (the probe loop
  makes it) and reconnect after socket loss, with exponential backoff after failed connects
  (200 ms doubling to 5 s; calls fail fast with `retry in N ms` meanwhile). Upstreams start
  `Unknown` and the probe loop (concurrent per upstream) promotes them to `Online` once reachable.
* Agent requests are read serially; upstream calls use a single actor-owned WebSocket,
  ID to oneshot map, and support concurrent callers; each call is bounded by
  `upstream_call_timeout_ms`. Upstream events are forwarded independently to agent controls
  whose token can access the owning upstream, with recursively namespaced session references
  and gateway ticket rewrites (events are namespaced once and recorded into the session store;
  they are not re-wrapped). Event and response sequence numbers share one monotonically
  increasing per-agent sequence; request/response IDs retain upstream-independent correlation.
* Rex frame-level errors (`{"type":"response","id":…,"error":{"code","message","status"}}`,
  no `payload`) are forwarded to the agent with the same top-level `error` object. The gateway
  does not collapse them to `payload: null`, does not decorate failed `session.bootstrap` with
  upstream metadata, and does not replace a real `data.connect` frame error with a synthetic
  "omitted ticket" message. Payload-level `{"error":…}` replies (if an upstream uses them) still
  pass through inside `payload`. Gateway-originated failures remain `payload: {"error":"<string>"}`.
  Frame-level application errors do not trigger hostless transport failover.
* Probes use `session.list`: success under 1 second = Online, under/over threshold =
  Degraded; two consecutive failed probes = Offline. First failure is Degraded, initial
  state Unknown. Socket reconnection and a fresh hello happen on the next call.
* Default create/hostless routing prefers Online and may fall back to Degraded; Offline
  and Unknown are never selected. Discovered upstreams with create eligibility cleared
  (withdrawn from the discovery file but still sticky for existing sessions) are also
  skipped for new creates.

## Capability tags, host prefer/avoid, and reservations

Each upstream accepts `tags = ["perf", "macos"]` and optional `description = "..."`.
Token entries accept `prefer_tags` / `avoid_tags` and soft `prefer_hosts` / `avoid_hosts`
(host ids). `REX_GATEWAY_UPSTREAM_<exact-id>_TAGS` is comma-separated and `_DESCRIPTION`
overrides metadata; `REX_GATEWAY_AUTH_TOKEN_<zero-based-token-index>_PREFER_TAGS` /
`_AVOID_TAGS` / `_PREFER_HOSTS` / `_AVOID_HOSTS` override defaults (comma-separated).
`create_reservation_ttl_ms` (default 5000, env `REX_GATEWAY_CREATE_RESERVATION_TTL_MS`) is nonzero.

A routed create may override defaults with `prefer_tags` / `avoid_tags` / `prefer_hosts` /
`avoid_hosts` string arrays. **Tags are hard:** all preferred tags are required so a request
for `macos` never falls back to a Linux host. **Hosts are soft:** a preferred host id gets a
score bonus, but a missing preferred host falls through to other candidates instead of
hard-erroring. Any avoided tag or host id excludes an upstream exclusively for create; this
never hides existing sessions from `session.list`. Scoring rewards matching tags and preferred
host ids, keeps Online above Degraded, and subtracts `session_count + reserved_session_count`;
highest score, then lowest latency, then ID wins. An explicit, allowed and routable `host`
wins over both tag and host prefer/avoid lists (including avoid). Unsatisfiable tags and
exclusion of every candidate are returned as explicit errors, never downgraded.

Reservation and selection happen under one mutex, so simultaneous clients observe each other's effective
load. Completion or failure releases the guard; forced expiry is reaped at selection/status time. `/status`
reports real sessions, outstanding reserves and their sum (`effective_session_count`), alongside
`tags`, `description`, `latency_ms`, and `state`. `session.bootstrap` adds the owning `upstream` and an
ACL-filtered `upstreams` array with the same capability/load fields. Real Rex requires
`event_scope` of `"session"` or `"all"` on bootstrap (otherwise Rex returns a frame-level
`bad_request` which the gateway now forwards unchanged). Unavailable owners cause bootstrap
to error with remove/recreate guidance; the data plane still closes 1011 on unexpected stream loss.
CPU is not gathered by Rex probes, so session count is the current load signal.

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
If the upstream data socket ends mid-bridge without a Close frame, the agent is closed with
`1011 "upstream closed"` (or `"upstream offline"` when the pool already marks that upstream
Offline). If the agent drops mid-bridge without a Close frame, or if forwarding upstream→agent
fails because the agent socket is already gone, the upstream is closed with
`1001 "peer closed"` so Rex can release the terminal attach promptly (rather than waiting
for idle timeout). The gateway also originates keepalive pings on both legs and idle-closes both sides with
`1001 "idle timeout"` when no application (binary/text) traffic arrives for
`ws_idle_timeout_ms`. Concurrent bridges are bounded by `max_data_streams` /
`max_data_streams_per_token` (defaults 128 / 32; close `1013` on overflow, ticket preserved),
and concurrent control sockets by `max_control_connections` /
`max_control_connections_per_token` (same defaults; close `1013` before welcome). This is not a
terminal protocol parser and does not rewrite bytes inside stream frames.

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

## Durable session references and cleanup

Every session learned from `session.list`, `session.create`, a session RPC response or an event is
stored as the stable external reference `upstream:session:<uuid>` together with its owning upstream
and real upstream ID. `rex-gateway-sessions.json` is atomically replaced (temporary file + rename)
on update, and loaded at startup. An agent can retain the external reference, disconnect, and attach
or open a new data stream after a **gateway restart** without recreating the Rex session. The Rex
upstream must still own the live session. Unlisted but well-formed references retain normal routing
compatibility (the upstream validates whether the session exists).

* `session_store_path` (default `rex-gateway-sessions.json`), env `REX_GATEWAY_SESSION_STORE_PATH`.
* `session_ttl_ms` (default `86400000`, one day), env `REX_GATEWAY_SESSION_TTL_MS`.
* `session_max` (default `16384`), env `REX_GATEWAY_SESSION_MAX`. All three are validated; both
  lifetime and capacity must be nonzero.
* `session.forget` with `{"session_id":"local:session:<uuid>"}` manually deletes one mapping and
  returns `{"forgotten":true,"session_id":"..."}`. ACLs are enforced; repeating forget is safe.

A background reaper removes idle references after TTL, then the least-recently-active references
when over the cap. Removals are written to the store immediately so a restart cannot resurrect
forgotten references. It never kills the Rex session itself. Session RPCs, listing, attach, data.connect,
and binary terminal traffic refresh activity; fetching the full session list refreshes all listed
references by design. After TTL/capacity cleanup or `session.forget`, list/send/read/bootstrap/
attach/data.connect receive the clear control error **`session reference expired/forgotten`**.
If a data ticket was already issued, attach closes with WebSocket **1008** and the same reason.

### Live verification

With Rex on 127.0.0.1:7297, a terminal-bearing session, and the supplied gateway on :7300:

```sh
REX_GATEWAY_SESSION_STORE_PATH=/tmp/rex-session-test.json cargo run
python3 smoke_sessions.py
# Stop and restart the gateway using the same store path, then:
python3 smoke_sessions.py --expect-ref local:session:<uuid> --check-gc
REX_GATEWAY_SESSION_STORE_PATH=/tmp/rex-session-test.json \
REX_GATEWAY_SESSION_TTL_MS=250 cargo run
python3 smoke_sessions.py --after-ttl 1
```

The script does not log data tickets. Tests also cover on-disk restart loading, TTL cleanup,
least-recently-active capacity cleanup, manual deletion, and the data-plane close behavior.

## Status endpoint

`GET /status` with `Authorization: Bearer <token>` (401 otherwise) returns JSON:

```json
{
  "upstreams": [
    {"id":"local","url":"http://127.0.0.1:7297","source":"Manual","state":"Online",
     "latency_ms":3,"consecutive_failures":0,"last_error":null,
     "last_probe_age_ms":412,"session_count":2,"reserved_session_count":0,
     "effective_session_count":2,"tags":["perf"],"description":"heavy compile host"}
  ],
  "counters": {
    "pending_tickets":0,"active_control_connections":1,"active_data_streams":0,
    "tickets_issued":5,"tickets_consumed":4,"tickets_expired":1,"tickets_evicted":0,
    "create_transport_failovers":0,"hostless_transport_failovers":0,
    "create_failover_exhausted":0,"hostless_failover_exhausted":0
  },
  "discovery": {
    "enabled":true,"mode":"command","last_success_age_ms":1234,"last_error":null,
    "last_error_age_ms":null,"last_applied":true,"refresh_count":5,"error_count":1
  }
}
```

Upstream `url`s are shown without credentials: userinfo (`user:pass@`), query and fragment are
stripped (and also removed from `last_error` text). `upstreams` lists only upstreams the token's ACL permits (in any state, sorted by id).
`state` is `Unknown|Online|Degraded|Offline`; `latency_ms` is the last probe's latency
(null if the last probe failed or none ran); `last_error` is the most recent probe error and is
cleared by the next successful probe. `counters` are gateway-wide (not ACL-filtered), totals since
start; `tickets_expired` counts TTL expiries, `tickets_evicted` capacity evictions.
Hostless transport-failover activity is also counted: `create_transport_failovers` /
`hostless_transport_failovers` increment once per tried upstream that failed with a
transport error (each hop / retry trigger); `create_failover_exhausted` /
`hostless_failover_exhausted` increment when every candidate fails and the agent sees
the aggregate `… failed on all candidates: …` error. Application-level errors and hard
`host` pins do not touch these counters.
`discovery` reports whether pool fill is configured (`enabled`/`mode` = `command`|`file`|`none`),
ages since last success/error (`null` if never), whether the last refresh applied a snapshot
(`last_applied`), and `refresh_count` / `error_count` since process start. When discovery is
disabled the object is still present with `enabled:false`, `mode:"none"`, null ages and zero counts.

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
Control upgrades set WebSocket `max_message_size` to the advertised `limits.max_message_bytes`
(1 MiB), matching Rex; the data plane keeps the library default so large terminal snapshots
are not truncated.
## Upstream discovery

Optional `[discovery]` fills the upstream pool from a `rex-discover --json` snapshot —
either by watching an external JSON file, or by periodically spawning a discover command
whose stdout is that same JSON array
(`[{ "source": "tailnet"|"lan", "name": "...", "addr": "https://...", "mode": "..." }, ...]`):

```toml
[discovery]
# Live subprocess (preferred when set). argv as a TOML array; first element is the program.
# Needs `rex` / `tailscale` on PATH the same way a manual `rex-discover` run would.
command = ["rex-discover", "--json", "--tailnet-only"]
# file = "discovered.json"        # used only when command is unset; re-read each interval
interval_ms = 30000               # default 30000; must be nonzero when discovery is enabled
store_path = "rex-gateway-discovered.json"  # optional atomic restart snapshot
```

Env overrides: `REX_GATEWAY_DISCOVERY_FILE`, `REX_GATEWAY_DISCOVERY_COMMAND` (single string
split on ASCII whitespace into argv; empty/whitespace clears the command),
`REX_GATEWAY_DISCOVERY_INTERVAL_MS`, `REX_GATEWAY_DISCOVERY_STORE_PATH`. Discovery is enabled
when `file` **or** `command` is nonempty; empty Manual `[[upstreams]]` is then allowed.
When both are set, **command wins for each live refresh** (the file is ignored until
`command` is unset). When neither is set the gateway behaves as before (Manual only).

Each command run is bounded by `max(interval_ms, 60s)` so a slow LAN scan cannot hang
across ticks forever; nonzero exit / bad JSON leave the pool unchanged and log a warning.
Discovered ids are sanitized from `name`; `addr` keeps its scheme or defaults to `https`.
`source` becomes `Tailnet` or `Lan` (shown on `/status`). **Manual upstreams are never
overwritten or deleted** when a discovered name collides. Hostless RPCs / `pick_default`
still prefer a Manual Online upstream over discovered peers (and failover across that
ordered candidate list on transport errors), so command-filled hosts do
not steal default routing from an explicit Manual entry.

Reconciliation: a discovered host that disappears from the snapshot is **removed when idle**
(no remembered session references). If sessions still point at it, it stays sticky so
attach/list/RPC keep working, but create eligibility is cleared so new `session.create`
will not pick it. On a successful apply the optional `store_path` is written atomically
(temp + rename); the store is loaded at startup after Manual upserts so a restart can
route before the next live refresh. Each discovered id also gets a lazy control client so
probes and RPCs work the same as Manual upstreams. Live refresh outcomes update the
`discovery` object on `/status` (success/error ages, applied flag, counters).

## Remaining TODOs

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
