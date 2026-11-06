"""Ticket TTL / status check. Run the gateway with REX_GATEWAY_TICKET_TTL_MS=2000 first."""
import base64, json, time, urllib.request
src = open('smoke_data.py').read().split('control = WS(')[0]  # reuse WS helper + constants
exec(src)

def status():
    req = urllib.request.Request(f'http://{HOST}:{PORT}/status', headers={'Authorization': 'Bearer smoke-secret'})
    return json.load(urllib.request.urlopen(req))['counters']

def issue(control, ident):
    r = control.request(ident, 'data.connect', {'session_id': EXTERNAL_SID, 'block_id': BLOCK,
        'data_ref_id': 'terminal', 'subprotocol': 'rex.data.terminal.v1'})
    t = r['payload']['ticket']
    return base64.urlsafe_b64decode(t + '=' * (-len(t) % 4))

control = WS('/api/control', 'rex.control.v1')
control.send(json.dumps({'type': 'hello'})); control.recv()
control.request('attach', 'session.attach', {'session_id': EXTERNAL_SID})
before = status()
fresh, stale = issue(control, 'c1'), issue(control, 'c2')
mid = status()
assert mid['pending_tickets'] - before['pending_tickets'] == 2, mid
assert mid['active_control_connections'] >= 1, mid

live = WS('/api/data', 'rex.data.terminal.v1')
live.send(b'\x01' + fresh, binary=True)
op, accept = live.recv()
assert op == 2 and accept[:1] == b'\x81', accept
print('PASS: fresh ticket accepted before TTL')
time.sleep(0.3)
s = status(); assert s['active_data_streams'] == 1, s
print('PASS: /status shows active data stream:', s)

time.sleep(4.5)  # TTL is 2s, reaper period 1s
s = status()
assert s['pending_tickets'] == 0, s
assert s['tickets_expired'] - before['tickets_expired'] == 1, s
print('PASS: reaper purged the unused ticket:', s)

late = WS('/api/data', 'rex.data.terminal.v1')
late.send(b'\x01' + stale, binary=True)
op, rejection = late.recv()
assert op == 2 and rejection[:2] == b'\x82\x01', rejection
print('PASS: ticket left unused past TTL rejected 0x82 0x01')
live.sock.close(); late.sock.close(); control.sock.close()
time.sleep(0.5)
s = status(); assert s['active_data_streams'] == 0 and s['active_control_connections'] == 0, s
print('PASS: gauges back to zero after disconnect:', s)
