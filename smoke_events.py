# Live check: each agent only receives events for what it subscribed to, even though the
# gateway shares one upstream control connection. Pokes sessions with a direct Rex client.
import socket, json, time, urllib.request
from pathlib import Path
ns = {}
exec(Path('smoke.py').read_text().split("for label,token in")[0], ns)
frame, recv, connect, recv_exact = ns['frame'], ns['recv'], ns['connect'], ns['recv_exact']
import base64, os

def agent():
    s, status = connect('smoke-secret'); assert '101' in status
    frame(s, {'type': 'hello'}); assert json.loads(recv(s)[1])['type'] == 'welcome'
    return s

def text(s, wait):
    s.settimeout(wait)
    try:
        while True:
            op, data = recv(s)
            if op == 1: return json.loads(data)
    except (socket.timeout, TimeoutError):
        return None
    finally:
        s.settimeout(10)

def rpc(s, method, payload):
    frame(s, {'type': 'request', 'id': method, 'method': method, 'payload': payload})
    while True:
        msg = text(s, 10); assert msg is not None, method
        if msg['type'] == 'response': return msg

def events(s, wait=1.0):
    out = []
    while (msg := text(s, wait)) is not None:
        if msg['type'] == 'event': out.append(msg)
    return out

def poke(raw_session):
    # Direct Rex client attach: Rex emits client_connected/... events for that session.
    d = socket.create_connection(('127.0.0.1', 7297)); d.settimeout(5)
    key = base64.b64encode(os.urandom(16)).decode()
    d.sendall(f'GET /api/control HTTP/1.1\r\nHost: 127.0.0.1:7297\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: rex.control.v1\r\n\r\n'.encode())
    buf = b''
    while b'\r\n\r\n' not in buf: buf += d.recv(4096)
    frame(d, {'type': 'hello'}); recv(d)
    frame(d, {'type': 'request', 'id': 'p', 'method': 'session.attach', 'payload': {'session_id': raw_session, 'event_scope': 'session'}})
    time.sleep(0.4); d.close()

def sessions_of(evs):
    return {e['payload'].get('payload', {}).get('session_id') for e in evs}

x, y = agent(), agent()
listed = rpc(x, 'session.list', {})['payload']['sessions']
assert len(listed) >= 2, 'need two sessions'
a, b = listed[0]['session_id'], listed[1]['session_id']
raw = lambda ext: ext.split(':', 1)[1]
assert 'error' not in rpc(x, 'session.attach', {'session_id': a, 'event_scope': 'session'})
assert 'error' not in rpc(y, 'session.attach', {'session_id': b, 'event_scope': 'session'})
events(x, 0.5); events(y, 0.5)
poke(raw(a))
ex, ey = events(x), events(y)
assert a in sessions_of(ex), ex
assert a not in sessions_of(ey), ey
print('PASS x (attached a) got a events; y (attached b) did not', len(ex), len(ey))
poke(raw(b))
ex, ey = events(x), events(y)
assert b in sessions_of(ey) and b not in sessions_of(ex), (ex, ey)
print('PASS y got b events; x did not')
# y also attaches a; x detaches a -> answered locally, y keeps receiving a.
rpc(y, 'session.attach', {'session_id': a, 'event_scope': 'session'}); events(y, 0.5)
detached = rpc(x, 'session.detach', {'session_id': a})
assert detached['payload'] == {}, detached
poke(raw(a))
ex, ey = events(x), events(y)
assert a in sessions_of(ey) and a not in sessions_of(ex), (ex, ey)
print('PASS detach by x keeps y subscribed on the shared upstream connection')
x.close(); y.close()
req = urllib.request.Request('http://127.0.0.1:7300/status', headers={'Authorization': 'Bearer smoke-secret'})
with urllib.request.urlopen(req) as r: counters = json.load(r)['counters']
assert counters['events_dropped_scope'] >= 1 and 'events_dropped_acl' in counters, counters
print('PASS /status', {k: counters[k] for k in ('events_forwarded', 'events_dropped_scope', 'events_dropped_acl')})

# Closing the last agent holding a session detaches the shared upstream connection from it.
def direct():
    d = socket.create_connection(('127.0.0.1', 7297)); d.settimeout(5)
    key = base64.b64encode(os.urandom(16)).decode()
    d.sendall(f'GET /api/control HTTP/1.1\r\nHost: 127.0.0.1:7297\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: rex.control.v1\r\n\r\n'.encode())
    buf = b''
    while b'\r\n\r\n' not in buf: buf += d.recv(4096)
    frame(d, {'type': 'hello'}); recv(d)
    return d
def clients_on(d, raw_session):
    n = clients_on.n = getattr(clients_on, 'n', 0) + 1
    frame(d, {'type': 'request', 'id': f'c{n}', 'method': 'session.list_clients', 'payload': {'session_id': raw_session}})
    while True:
        msg = json.loads(recv(d)[1])
        if msg.get('id') == f'c{n}': return len(msg['payload']['clients'])
d = direct()
frame(d, {'type': 'request', 'id': 'da', 'method': 'session.attach', 'payload': {'session_id': raw(a), 'event_scope': 'session'}})
while json.loads(recv(d)[1]).get('id') != 'da': pass
time.sleep(0.3)
baseline = clients_on(d, raw(a))
z = agent()
assert 'error' not in rpc(z, 'session.attach', {'session_id': a, 'event_scope': 'session'})['payload']
time.sleep(0.3)
held = clients_on(d, raw(a))
assert held == baseline + 1, (baseline, held)
z.close()
time.sleep(1.0)
after = clients_on(d, raw(a))
d.close()
assert after == baseline, (baseline, held, after)
print('PASS closing the last holder detached the gateway connection upstream', (baseline, held, after))
