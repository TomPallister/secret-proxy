"""Disposable kernel packet-filter test; no VPN login, vault or Internet traffic.

Two internal networks emulate cleartext and tunnel paths. Tests actual nftables,
including an established TCP connection and route restoration after tunnel loss.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host
import vpn_gateway

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--connection', required=True)
parser.add_argument('--image', required=True)
parser.add_argument('--mutation', choices=['open', 'established', 'dns'])
args = parser.parse_args()
env = {'HOME': str(Path.home()), 'PATH': '/opt/podman/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CONTAINERS_MACHINE_PROVIDER': 'libkrun'}
base = [host.PODMAN, '--connection', args.connection]

def run(*argv, **kw):
    result = subprocess.run(base + list(argv), env=env, capture_output=True, timeout=60, **kw)
    if result.returncode:
        raise RuntimeError(result.stderr.decode() + result.stdout.decode())
    return result.stdout

suffix = secrets.token_hex(4)
name = 'fw-smoke-' + suffix
server = 'sp-' + name + '-server'
dep = host.Deployment.from_dict({'instance': name, 'machine': args.connection, 'port': 10260,
    'networks': {'fixture': {'type': 'vpnc', 'gateway': 'vpn.example.org', 'group': 'Fixture', 'dhGroup': 'dh14',
        'dns': ['10.20.0.53'], 'usernameSecret': 'VPN_USER', 'passwordSecret': 'VPN_PASSWORD', 'groupSecret': 'VPN_GROUP'}}}).select_network('fixture')
clear, tunnel = dep.network.network, 'sp-' + name + '-tunnel'
image = run('image', 'inspect', '--format', '{{.Id}}', args.image).decode().strip()
if not image.startswith('sha256:'): image = 'sha256:' + image
server_code = '''import socket,threading,time

def tcp(family,address):
 s=socket.socket(family,socket.SOCK_STREAM)
 if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((address,18080)); s.listen()
 def answer(c):
  with c:
   while c.recv(128): c.sendall(b'OK')
 while True: threading.Thread(target=answer,args=(s.accept()[0],),daemon=True).start()
def udp(port):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',port))
 while True:
  data,addr=s.recvfrom(128); s.sendto(data,addr)
for f,a in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]: threading.Thread(target=tcp,args=(f,a),daemon=True).start()
for port in (500,53): threading.Thread(target=udp,args=(port,),daemon=True).start()
time.sleep(600)
'''
try:
    for network in (clear, tunnel): run('network', 'create', '--internal', network)
    run('run', '-d', '--name', server, '--network', clear, '--read-only', '--user=0',
        '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_BIND_SERVICE', '--security-opt=no-new-privileges',
        '--entrypoint=/opt/secret-proxy/.venv/bin/python', image, '-c', server_code)
    run('network', 'connect', tunnel, server)
    command = vpn_gateway.command(dep, image, 'a' * 32)
    # Keep production hardening/device/cap flags; omit only the private mounts
    # and replace the VPN login process with an idle namespace for kernel tests.
    for _ in range(2):
        index = command.index('--volume'); del command[index:index+2]
    command.remove('-i'); command.insert(1, '-d')
    index = command.index('--entrypoint=/opt/secret-proxy/.venv/bin/python')
    command = command[:index] + ['--entrypoint=/bin/sleep', image, '600']
    run(*command)
    run('network', 'connect', tunnel, dep.network.container)
    row, = json.loads(run('container', 'inspect', server))
    clear_ip = row['NetworkSettings']['Networks'][clear]['IPAddress']
    tunnel_ip = row['NetworkSettings']['Networks'][tunnel]['IPAddress']
    row, = json.loads(run('network', 'inspect', clear))
    subnet = row['subnets'][0]['subnet']
    v6base = 'fd39:' + suffix[:4] + ':' + suffix[4:] + '::'
    run('exec', server, 'ip', '-6', 'address', 'add', v6base + '3/64', 'dev', 'eth0')
    run('exec', dep.network.container, 'ip', '-6', 'address', 'add', v6base + '2/64', 'dev', 'eth0')
    run('exec', dep.network.container, 'ip', 'link', 'set', 'eth1', 'name', 'tun0')
    code = '''import json,socket,subprocess,time
from vpnc_runtime import firewall
clear,tunnel,subnet,v6,mutation = json.loads(INPUT)
def ping(address):
 with socket.create_connection((address,18080),timeout=1) as s:
  s.sendall(b'fixture'); assert s.recv(128)==b'OK'
def udp_ping(address,port):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(1); s.sendto(b'fixture',(address,port)); assert s.recv(128)==b'fixture'
def blocked(address):
 try: ping(address)
 except OSError: return
 raise AssertionError('Direct traffic escaped the kill switch')
# Enable namespace conntrack BEFORE establishing the control connection. With
# no earlier ct rule, a pre-existing socket may be first observed as NEW, making
# a blanket-established mutant appear safe for the wrong reason.
subprocess.run(['nft','-f','-'],input=b'table inet secret_proxy_vpn { chain output { type filter hook output priority 0; policy accept; ct state established,related counter accept; }'+bytes([10])+b'}'+bytes([10]),check=True)
# Positive controls, including IPv6, precede the drop policy.
for _ in range(10):
 try:
  for address in (clear,tunnel,v6): ping(address)
  break
 except OSError as exc: last_error=exc; time.sleep(.1)
else: raise AssertionError('Positive control failed: '+address+' '+str(last_error))
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.settimeout(1); s.sendto(b'IKE-before',(clear,500)); assert s.recv(128)==b'IKE-before'
udp_ping(clear,53); udp_ping(tunnel,53)
existing=socket.create_connection((clear,18080),timeout=1)
existing.sendall(b'before'); assert existing.recv(128)==b'OK'
tracked=json.loads(subprocess.check_output(['nft','-j','list','chain','inet','secret_proxy_vpn','output']))
counters=[expr['counter']['packets'] for item in tracked['nftables'] if 'rule' in item for expr in item['rule']['expr'] if 'counter' in expr]
assert counters and max(counters)>0,'Conntrack positive control failed'
rules=firewall(clear,subnet)
original=rules
if mutation=='open': rules=rules.replace('policy drop','policy accept')
if mutation=='established': rules=rules.replace('oifname "lo" accept','ct state established,related accept\\n  oifname "lo" accept')
if mutation=='dns': rules=rules.replace('oifname "lo" accept','udp dport 53 accept\\n  oifname "lo" accept')
if mutation: assert rules!=original,'Mutation did not apply'
subprocess.run(['nft','-f','-'],input=b'delete table inet secret_proxy_vpn'+bytes([10])+rules.encode(),check=True)
existing.sendall(b'after')
try:
 data=existing.recv(128)
 assert not data,'Established cleartext connection escaped'
except OSError: pass
existing.close()
blocked(clear); blocked(v6)
try: udp_ping(clear,53)
except OSError: pass
else: raise AssertionError('DNS escaped outside the tunnel')
udp_ping(tunnel,53)
ping(tunnel) # Traffic over the synthetic tunnel interface remains possible.
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.settimeout(1); s.sendto(b'IKE-control',(clear,500)); assert s.recv(128)==b'IKE-control'
subprocess.run(['ip','link','set','tun0','down'],check=True)
subprocess.run(['ip','route','replace',tunnel+'/32','via',clear,'dev','eth0'],check=True)
blocked(tunnel) # Even when a cleartext route exists after tunnel loss.
# Remove ONLY the fixture's firewall to prove failed probes were filter-driven.
subprocess.run(['nft','delete','table','inet','secret_proxy_vpn'],check=True)
ping(clear); ping(tunnel); ping(v6); udp_ping(clear,53)
print('PASS: tunnel/IKE/DNS controls; direct TCP, established TCP, off-tunnel DNS, IPv6 and post-loss fallback blocked')
'''.replace('INPUT', repr(json.dumps([clear_ip, tunnel_ip, subnet, v6base + '3', args.mutation])))
    print(run('exec', '-i', dep.network.container, '/opt/secret-proxy/.venv/bin/python', '-B', '-', input=code.encode()).decode(), end='')
finally:
    for container in (dep.network.container, server):
        subprocess.run(base + ['rm', '-f', container], env=env, capture_output=True, timeout=30)
    for network in (tunnel, clear):
        subprocess.run(base + ['network', 'rm', network], env=env, capture_output=True, timeout=30)
