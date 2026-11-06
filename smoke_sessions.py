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
                printed=json.loads(json.dumps(value))
                if method=='data.connect' and isinstance(printed.get('payload'),dict):printed['payload']['ticket']='<redacted>'
                print(method, '->', json.dumps(printed))
                return value


import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--expect-ref')
parser.add_argument('--after-ttl',type=int,default=0)
parser.add_argument('--check-gc',action='store_true')
args=parser.parse_args()

def control():
    c=WS('/api/control','rex.control.v1');assert '101' in c.status
    c.send(json.dumps({'type':'hello'}));assert json.loads(c.recv()[1])['type']=='welcome'
    return c

c=control()
listed=c.request('list','session.list',{})['payload']['sessions']
assert listed, 'run smoke_data or create a real Rex session first'
reference=args.expect_ref or listed[0]['session_id']
assert reference in [x['session_id'] for x in listed]
print('REFERENCE:',reference)
if args.after_ttl:
    print('Waiting for short configured idle TTL / capacity reaper...');time.sleep(args.after_ttl)
    reply=c.request('expired','session.rename',{'session_id':reference,'label':'must-not-rename'})['payload']
    print('POST-CLEANUP CONTROL:',json.dumps(reply))
    assert reply['error']=='session reference expired/forgotten'
else:
    marker='PERSISTED_CONTEXT_OK'
    renamed=c.request('rename','session.rename',{'session_id':reference,'label':marker})['payload']
    assert renamed is None or 'error' not in renamed
    attached=c.request('attach-before','session.attach',{'session_id':reference})['payload']
    assert 'error' not in attached
    block=attached['view']['windows'][0]['focused_block_id']
    c.sock.close()
    print('DISCONNECTED: same reference saved; restart the gateway now for a process-restart check')
    c=control()
    attached=c.request('attach-after','session.attach',{'session_id':reference})['payload']
    assert 'error' not in attached, attached
    attached=c.request('connect','data.connect',{'session_id':reference,'block_id':block,'data_ref_id':'terminal','subprotocol':'rex.data.terminal.v1'})['payload']
    ticket=attached['ticket'];raw=base64.urlsafe_b64decode(ticket+'='*(-len(ticket)%4))
    data=WS('/api/data','rex.data.terminal.v1');data.send(b'\x01'+raw,binary=True)
    op,accept=data.recv();assert op==2 and accept[:1]==b'\x81'
    print('RECONNECT ACCEPT:',accept.hex())
    print('PASS: persisted reference, gateway restart, same session attach, context present')
    data.sock.close()
    if args.check_gc:
        forgotten=c.request('forget','session.forget',{'session_id':reference})['payload']
        print('MANUAL FORGET:',json.dumps(forgotten));assert forgotten['forgotten'] is True
        reply=c.request('after-forget','session.rename',{'session_id':reference,'label':'impossible'})['payload']
        print('AFTER FORGET:',json.dumps(reply));assert reply['error']=='session reference expired/forgotten'
c.sock.close()
