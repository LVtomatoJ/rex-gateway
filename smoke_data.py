import base64, json, os, socket, struct, subprocess, time

HOST, PORT = '127.0.0.1', 7300
SID = 'session:01a1b0eb-20ad-73fb-9c27-0bdf0ed5bfee'
EXTERNAL_SID = 'local:' + SID
BLOCK = 'block:01a1b0eb-20ae-72e5-9999-1fe4212d9650'

class WS:
    def __init__(self, path, protocol, token='smoke-secret'):
        self.sock = socket.create_connection((HOST, PORT))
        self.sock.settimeout(4)
        self.buf = b''
        key = base64.b64encode(os.urandom(16)).decode()
        auth = f'Authorization: Bearer {token}\r\n' if token else ''
        self.sock.sendall((f'GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n'
            'Upgrade: websocket\r\nConnection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
            f'Sec-WebSocket-Protocol: {protocol}\r\n{auth}\r\n').encode())
        while b'\r\n\r\n' not in self.buf:
            self.buf += self.sock.recv(4096)
        headers, _, self.buf = self.buf.partition(b'\r\n\r\n')
        self.status = headers.split(b'\r\n')[0].decode()
        print(path, 'upgrade:', self.status)

    def _need(self, n):
        while len(self.buf) < n:
            self.buf += self.sock.recv(4096)

    def recv(self):
        self._need(2)
        op = self.buf[0] & 15
        length = self.buf[1] & 127
        offset = 2
        if length == 126:
            self._need(4); length = struct.unpack('>H', self.buf[2:4])[0]; offset = 4
        elif length == 127:
            self._need(10); length = struct.unpack('>Q', self.buf[2:10])[0]; offset = 10
        self._need(offset + length)
        data = self.buf[offset:offset + length]
        self.buf = self.buf[offset + length:]
        return op, data

    def send(self, data, binary=False):
        if isinstance(data, str): data = data.encode()
        key = os.urandom(4); n = len(data)
        header = bytes([0x82 if binary else 0x81])
        if n < 126: header += bytes([0x80 | n])
        elif n < 65536: header += bytes([126 | 128]) + struct.pack('>H', n)
        else: header += bytes([127 | 128]) + struct.pack('>Q', n)
        self.sock.sendall(header + key + bytes(b ^ key[i % 4] for i, b in enumerate(data)))

    def request(self, ident, method, payload):
        self.send(json.dumps({'type':'request', 'id':ident, 'method':method, 'payload':payload}))
        while True:
            op, data = self.recv()
            value = json.loads(data)
            if value.get('type') == 'response' and value.get('id') == ident:
                print(method, '->', json.dumps(value))
                return value

control = WS('/api/control', 'rex.control.v1')
assert '101' in control.status
control.send(json.dumps({'type':'hello'}))
print('welcome:', control.recv()[1].decode())
listed=control.request('list','session.list',{})['payload']['sessions']
assert listed
EXTERNAL_SID=listed[0]['session_id']
attachment=control.request('attach', 'session.attach', {'session_id': EXTERNAL_SID})
BLOCK=attachment['payload']['view']['windows'][0]['focused_block_id']
response = control.request('connect', 'data.connect', {'session_id':EXTERNAL_SID,
    'block_id':BLOCK, 'data_ref_id':'terminal', 'subprotocol':'rex.data.terminal.v1'})
ticket = response['payload']['ticket']
raw = base64.urlsafe_b64decode(ticket + '=' * (-len(ticket) % 4))
assert len(raw) == 16
print('gateway issued a 16-byte single-use ticket')

data = WS('/api/data', 'rex.data.terminal.v1')
assert '101' in data.status
data.send(b'\x01' + raw, binary=True)
op, accept = data.recv()
assert op == 2 and accept[:1] == b'\x81'
print('PASS: upstream ACCEPT passed through gateway:', accept.hex())
op, snapshot = data.recv()
assert op == 2 and snapshot.startswith(b'GHOSTSNP')
print('PASS: full-screen snapshot preserved:', len(snapshot), 'bytes')

subprocess.run([os.environ.get('REX_BIN','rex'), '-S', 'http://127.0.0.1:7297', 'send', '-b', BLOCK,
    'echo HELLO_FROM_GATEWAY\n'], check=True)
found = False
for _ in range(10):
    try: op, stream = data.recv()
    except socket.timeout: break
    if op != 2: continue
    found = found or b'HELLO_FROM_GATEWAY' in stream
    print('terminal binary frame:', len(stream), 'bytes; marker:', b'HELLO_FROM_GATEWAY' in stream)
assert found, 'terminal echo did not stream through gateway'
print('PASS: HELLO_FROM_GATEWAY terminal output streamed through /api/data')
control.sock.close()
data.sock.close()
# The upstream owns the data stream lifetime; control close does not terminate it.
used = WS('/api/data', 'rex.data.terminal.v1')
used.send(b'\x01' + raw, binary=True)
op, rejection = used.recv()
assert op == 2 and rejection[:2] == b'\x82\x01'
op, close = used.recv()
assert op == 8 and struct.unpack('>H', close[:2])[0] == 1008
print('PASS: reused ticket rejected 0x82 0x01 and close 1008 propagated')
used.sock.close()
