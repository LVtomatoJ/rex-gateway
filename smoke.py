import socket,base64,os,struct,json,time

def recv_exact(s,n):
    data=b''
    while len(data)<n:data+=s.recv(n-len(data))
    return data

def frame(s,obj):
    data=json.dumps(obj).encode();key=os.urandom(4);n=len(data)
    h=bytes([0x81,0x80+n])+key if n<126 else bytes([0x81,254])+struct.pack('>H',n)+key
    s.sendall(h+bytes(b^key[i%4] for i,b in enumerate(data)))

def recv(s):
    b=recv_exact(s,2);n=b[1]&127
    if n==126:n=struct.unpack('>H',recv_exact(s,2))[0]
    elif n==127:n=struct.unpack('>Q',recv_exact(s,8))[0]
    return b[0]&15,recv_exact(s,n)

def connect(token=None):
    s=socket.create_connection(('127.0.0.1',7300));s.settimeout(10)
    key=base64.b64encode(os.urandom(16)).decode()
    auth=f'Authorization: Bearer {token}\r\n' if token else ''
    request=f'GET /api/control HTTP/1.1\r\nHost: 127.0.0.1:7300\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: rex.control.v1\r\n{auth}\r\n'
    s.sendall(request.encode());response=b''
    while b'\r\n\r\n' not in response:response+=s.recv(4096)
    status=response.split(b'\r\n')[0].decode();return s,status

for label,token in [('absent',None),('wrong','wrong-secret')]:
    s,status=connect(token);print(f'{label} token: {status}');assert '401' in status;s.close()

s,status=connect('smoke-secret');print('valid token:',status);assert '101' in status
frame(s,{'type':'hello'});op,data=recv(s);welcome=json.loads(data);print('hello ->',json.dumps(welcome));assert welcome['type']=='welcome'
frame(s,{'type':'request','id':'smoke-list','method':'session.list','payload':{}});op,data=recv(s);response=json.loads(data);print('session.list ->',json.dumps(response))
expected=response['payload']['sessions'][0]['session_id']
assert response['id']=='smoke-list';assert response['payload']['sessions'] and expected.startswith('local:session:')
print('PASS: namespaced local session found')
frame(s,{'type':'request','id':'smoke-version','method':'server.version','payload':{}});op,data=recv(s);print('server.version (default local) ->',data.decode());assert json.loads(data)['id']=='smoke-version'
frame(s,{'type':'request','id':'smoke-route','method':'session.rename','payload':{'session_id':expected,'label':'bold-strait'}});op,data=recv(s);print('routed session.rename ->',data.decode());assert json.loads(data)['id']=='smoke-route'
s.close();print('PASS: default method and namespaced session routing')
