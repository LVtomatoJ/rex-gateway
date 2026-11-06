import socket, json, urllib.request
from pathlib import Path
namespace={}
exec(Path('smoke.py').read_text().split("for label,token in")[0],namespace)
frame,recv,connect=namespace['frame'],namespace['recv'],namespace['connect']
s,status=connect('smoke-secret');assert '101' in status
frame(s,{'type':'hello'});assert json.loads(recv(s)[1])['type']=='welcome'
def rpc(method,payload):
    frame(s,{'type':'request','id':'tags','method':method,'payload':payload})
    return json.loads(recv(s)[1])['payload']
sessions=rpc('session.list',{})['sessions']
assert sessions
session_id=sessions[0]['session_id']
bootstrap=rpc('session.bootstrap',{'session_id':session_id})
assert bootstrap['upstream']['id']=='local'
assert bootstrap['upstream']['tags']==['perf','ci']
assert bootstrap['upstream']['description']=='Local performance compile host'
assert isinstance(bootstrap['upstream']['session_count'],int)
assert bootstrap['upstreams'][0]['effective_session_count'] >= bootstrap['upstreams'][0]['session_count']
print('PASS bootstrap exposes ACL-scoped tags, description and load')
preferred=rpc('session.bootstrap',{'session_id':session_id,'prefer_tags':['perf'],'avoid_tags':['prod-svc']})
assert preferred['upstream']['id']=='local'
print('PASS matching preferences reach the tagged real upstream')
avoided=rpc('session.create',{'prefer_tags':['perf'],'avoid_tags':['perf']})
assert 'avoid_tags' in avoided['error'],avoided
print('PASS all candidates avoided returns a clear rejection')
impossible=rpc('session.create',{'prefer_tags':['macos']})
assert 'change tag requirements' in impossible['error'],impossible
print('PASS unsatisfiable macos requirement hard-fails')
s.close()
request=urllib.request.Request('http://127.0.0.1:7300/status',headers={'Authorization':'Bearer smoke-secret'})
with urllib.request.urlopen(request) as response: status=json.load(response)
local=status['upstreams'][0]
assert local['tags']==['perf','ci'] and local['description']=='Local performance compile host'
assert isinstance(local['session_count'],int) and isinstance(local['effective_session_count'],int)
print('STATUS_SAMPLE '+json.dumps(local,separators=(',',':')))
print('PASS live /status contains capabilities and effective load')
