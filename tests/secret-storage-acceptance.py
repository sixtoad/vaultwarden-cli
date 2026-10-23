#!/usr/bin/env python3
"""Isolated real Vaultwarden/native Mac storage acceptance support.

prepare HOST -> root and public endpoint (requires built bins/tests)
start ROOT | resume ROOT | stop ROOT -> isolated production fixture
submit ROOT OPERATION -> distinct-UID signed production agent
snapshot ROOT -> safe backend inventory and proxy request counters
arm-drop ROOT -> discard exactly the next successful cipher POST response
provision-consumer ROOT ITEM_ID | reconcile ROOT REQUEST_ID ITEM_ID
mac-config ROOT COMMAND [OPERATION/REQUEST_ID] -> private driver JSON path
cleanup ROOT -> identity-checked service/container/agent cleanup; evidence retained
proxy ROOT -> internal bounded HTTPS proxy (never invoke against other services)

No remote Mac operations are performed here. Use the native StorageAcceptance
fixture with mac-config's private file after replacing local artifact paths.
"""
import base64
import contextlib
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse

spec = importlib.util.spec_from_file_location("companion_acceptance", Path(__file__).with_name("companion-acceptance.py"))
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
PASSWORD = "synthetic-storage-acceptance-password"
FIXTURE = "adapters::companion::storage_acceptance_tests::storage_acceptance_fixture"


def save(path, value):
    data = json.dumps(value, indent=2).encode() + b"\n"
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as file: file.write(data); file.flush(); os.fsync(file.fileno())
    os.replace(temporary, path)


def load(root, name): return json.loads((root / name).read_text())
def check(root):
    root = base.check_root(root)
    if (root / "storage-owner.json").exists():
        owner = load(root, "storage-owner.json")
        if owner["root"] != str(root) or owner["uid"] != os.getuid(): raise ValueError("storage owner mismatch")
    return root


def property(unit, name):
    return base.run(["systemctl", "--user", "show", unit, f"--property={name}", "--value"], env=base.systemd_env(), capture_output=True, text=True, timeout=10).stdout.strip()


def start_unit(root, suffix, args, private_env=None, stdin=None):
    owner = load(root, "storage-owner.json")
    unit = owner["tag"] + "-" + suffix + ".service"
    if property(unit, "LoadState") != "not-found": raise ValueError("unit collision")
    owner["units"][unit] = {"invocation": None}; save(root / "storage-owner.json", owner)
    command = ["systemd-run", "--user", "--quiet", "--unit", unit, "--property=Type=exec", "--property=KillMode=control-group", "--property=UMask=0077", "--property=RuntimeMaxSec=3600", "--property=TimeoutStopSec=10", f"--property=StandardOutput=file:{root}/private/{suffix}-stdout", f"--property=StandardError=file:{root}/private/{suffix}-stderr"]
    if stdin: command.append(f"--property=StandardInput=file:{stdin}")
    command += ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin"]
    command += [f"{k}={v}" for k,v in (private_env or {}).items()]
    base.run(command + list(map(str,args)), env=base.systemd_env(), timeout=15)
    invocation = property(unit, "InvocationID")
    if not invocation: raise ValueError("unit identity unconfirmed; retain private material")
    owner["units"][unit]["invocation"] = invocation; save(root / "storage-owner.json", owner)


def wait_for(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate(): return
        except (OSError, ValueError, http.client.HTTPException): pass
        time.sleep(0.2)
    raise TimeoutError("bounded fixture readiness failed")


def api(root, path, data=None, form=False, authenticated=True):
    bootstrap = load(root, "private/bootstrap.json")
    url = bootstrap["backend"] + path
    headers = {}
    if authenticated: headers["Authorization"] = "Bearer " + bootstrap["bearer"]
    if data is not None:
        if form:
            data = urllib.parse.urlencode(data).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
        else: data = json.dumps(data).encode(); headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    context = ssl.create_default_context(cafile=str(root / "tls/ca.pem"))
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        raw = response.read(4 * 1024 * 1024)
        return json.loads(raw) if raw else {}


def encrypt(value, symmetric):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    if isinstance(value,str): value=value.encode()
    iv = secrets.token_bytes(16); padder = PKCS7(128).padder(); padded = padder.update(value) + padder.finalize()
    cipher = Cipher(algorithms.AES(symmetric[:32]), modes.CBC(iv)).encryptor(); encrypted = cipher.update(padded) + cipher.finalize()
    mac = hmac.digest(symmetric[32:], iv + encrypted, "sha256")
    return "2." + "|".join(base64.b64encode(p).decode() for p in (iv,encrypted,mac))


def decrypt(value, symmetric):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    if not value.startswith("2."): raise ValueError("unexpected synthetic cipher")
    iv, encrypted, mac = map(base64.b64decode, value[2:].split("|"))
    if not hmac.compare_digest(mac,hmac.digest(symmetric[32:],iv+encrypted,"sha256")): raise ValueError("cipher authentication failed")
    dec = Cipher(algorithms.AES(symmetric[:32]),modes.CBC(iv)).decryptor(); padded = dec.update(encrypted)+dec.finalize()
    unpad = PKCS7(128).unpadder(); return unpad.update(padded)+unpad.finalize()


def provision(root):
    config = load(root, "launcher.json"); owner = load(root,"storage-owner.json")
    private = root / "private"; private.mkdir(mode=0o700)
    for directory in ["home", "config", "data", "runtime"]: (private/directory).mkdir(mode=0o700)
    env = {"HOME":str(private/"home"), "XDG_CONFIG_HOME":str(private/"config"), "XDG_DATA_HOME":str(private/"data"), "XDG_RUNTIME_DIR":str(private/"runtime"), "DBUS_SESSION_BUS_ADDRESS":f"unix:path={private}/bus", "SSL_CERT_FILE":str(root/"tls/ca.pem")}
    (private/"password").write_text(PASSWORD); (private/"password").chmod(0o600)
    (private/"bus.conf").write_text('<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth><policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    start_unit(root,"bus",["/usr/bin/dbus-daemon",f"--config-file={private}/bus.conf","--nofork","--nopidfile",f"--address=unix:path={private}/bus"],env)
    wait_for(lambda: (private/"bus").exists())
    (private/"keyring-input").write_text("synthetic-storage-keyring\n")
    start_unit(root,"keyring",["/usr/bin/gnome-keyring-daemon","--foreground","--components=secrets","--unlock"],env,private/"keyring-input")
    wait_for(lambda: "true" in base.run(["gdbus","call","--session","--dest","org.freedesktop.DBus","--object-path","/org/freedesktop/DBus","--method","org.freedesktop.DBus.NameHasOwner","org.freedesktop.secrets"],env=dict(os.environ,**env),capture_output=True,text=True,timeout=5).stdout)
    vaulttls = private/"vault-tls"; vaulttls.mkdir(mode=0o700)
    shutil.copy2(root/"tls/server.pem",vaulttls/"server.pem"); shutil.copy2(root/"tls/server-key.pem",vaulttls/"server.key")
    owner = load(root,"storage-owner.json"); owner["container_intent"]=True; save(root/"storage-owner.json",owner)
    result = base.run(["docker","create","--label",f"vw.storage.acceptance={owner['tag']}","--publish","127.0.0.1::80","--tmpfs","/data:rw,nosuid,nodev,noexec","--mount",f"type=bind,src={vaulttls},dst=/acceptance-tls,readonly","--env","SIGNUPS_ALLOWED=true","--env","LOG_LEVEL=error","--env",'ROCKET_TLS={certs="/acceptance-tls/server.pem",key="/acceptance-tls/server.key"}',"vaultwarden/server:1.36.0"],capture_output=True,text=True,timeout=30)
    container=result.stdout.strip()
    if len(container)!=64 or any(c not in "0123456789abcdef" for c in container): raise ValueError("container identity unconfirmed")
    owner["container"]=container; save(root/"storage-owner.json",owner)
    base.run(["docker","start",container],capture_output=True,timeout=15)
    endpoint=base.run(["docker","port",container,"80/tcp"],capture_output=True,text=True,timeout=10).stdout.strip()
    if not endpoint.startswith("127.0.0.1:") or "\n" in endpoint: raise ValueError("non-loopback backend")
    with socket.socket() as listener: listener.bind(("127.0.0.1",0)); proxyport=listener.getsockname()[1]
    save(private/"bootstrap.json",{"backend":"https://"+endpoint,"proxy_port":proxyport})
    wait_for(lambda: api(root,"/alive",authenticated=False) is not None)
    email="storage-acceptance@test.invalid"; master=hashlib.pbkdf2_hmac("sha256",PASSWORD.encode(),email.encode(),100000)
    stretched=hmac.digest(master,b"enc\x01","sha256")+hmac.digest(master,b"mac\x01","sha256")
    symmetric=secrets.token_bytes(64); protected=encrypt(symmetric,stretched)
    password_hash=base64.b64encode(hashlib.pbkdf2_hmac("sha256",master,PASSWORD.encode(),1)).decode()
    api(root,"/identity/accounts/register",{"email":email,"name":"Disposable storage acceptance","masterPasswordHash":password_hash,"key":protected,"kdfType":0,"kdfIterations":100000},authenticated=False)
    token=api(root,"/identity/connect/token",{"grant_type":"password","username":email,"password":password_hash,"scope":"api offline_access","client_id":"web","deviceType":"9","deviceIdentifier":owner["tag"],"deviceName":"acceptance"},form=True,authenticated=False)
    bootstrap=load(root,"private/bootstrap.json"); bootstrap.update(bearer=token["access_token"],symmetric=base64.b64encode(symmetric).decode()); save(private/"bootstrap.json",bootstrap)
    sync=api(root,"/api/sync"); profile=sync.get("profile",sync.get("Profile")); account=profile.get("id",profile.get("Id"))
    rotated=api(root,"/api/accounts/rotate-api-key",{"masterPasswordHash":password_hash}); secret=rotated.get("apiKey",rotated.get("ApiKey"))
    base.run(["secret-tool","store","--label=Synthetic storage bootstrap","service","vaultwarden-accessd","username","bootstrap-client-secret"],input=secret.encode(),env=dict(os.environ,**env),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    folder=api(root,"/api/folders",{"name":encrypt("storage-acceptance",symmetric)})
    folder_id=folder.get("id",folder.get("Id")); proxyurl=f"https://127.0.0.1:{proxyport}"
    save(private/"setup.json",{"server":proxyurl,"email":email,"client_id":"user."+account,"encrypted_key":protected,"kdf_iterations":100000,"org_keys":{}})
    effect={"server":proxyurl,"destination":{"account_id":account,"folder":"storage-acceptance","folder_id":folder_id,"reference":"storage-acceptance/create"},"fields":["password"],"eligibility_marker":"storage-consume"}
    save(root/"storage.json",{"effect":effect})
    start_unit(root,"proxy",[sys.executable,Path(__file__).resolve(),"proxy",root],env)
    wait_for(lambda: (root/"proxy-observed.json").exists())
    config.update(fixture=FIXTURE,fixture_environment=env); save(root/"launcher.json",config)
    compiler=["cc","-nostdlib","-static","-no-pie","-fno-stack-protector","-fno-builtin","-O2","-Wl,--build-id=none"]
    for name,source in [("producer","protected-producer.S"),("consumer","storage-credential-check.c")]:
        base.run(compiler+["-o",root/"bin"/f"{name}-image",base.REPO/"tests/fixtures"/source],capture_output=True,timeout=20)
        (root/"bin"/f"{name}-image").chmod(0o500)


def prepare(hostname):
    os.umask(0o077)
    captured=io.StringIO()
    with contextlib.redirect_stdout(captured): base.prepare(hostname)
    prepared=json.loads(captured.getvalue()); root=check(Path(prepared["root"]))
    save(root/"storage-owner.json",{"root":str(root),"uid":os.getuid(),"tag":"vw-storage-acceptance-"+secrets.token_hex(8),"units":{},"container":None})
    # Publish recovery location before any external resource creation.
    print(json.dumps({"root":str(root),"phase":"provisioning"}),flush=True)
    provision(root)
    print(json.dumps({"root":str(root),"endpoint":prepared["endpoint"],"status":"prepared"}))


def proxy(root):
    config=load(root,"private/bootstrap.json"); upstream=config["backend"].removeprefix("https://"); host,port=upstream.split(":")
    if host!="127.0.0.1": raise ValueError("proxy backend must be fixture loopback")
    counters={"requests":{},"cipher_posts":0,"committed_cipher_posts":0,"dropped_cipher_replies":0,"dropped_item_ids":[]}
    lock=threading.Lock()
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def log_message(self,*args): pass
        def dispatch(self):
            length=int(self.headers.get("Content-Length","0"))
            if length<0 or length>1024*1024: self.send_error(413); return
            body=self.rfile.read(length) if length else None
            key=self.command+" "+self.path
            with lock:
                counters["requests"][key]=counters["requests"].get(key,0)+1
                is_post=self.command=="POST" and self.path=="/api/ciphers"
                if is_post: counters["cipher_posts"]+=1
                save(root/"proxy-observed.json",counters)
            connection=http.client.HTTPSConnection(host,int(port),context=ssl.create_default_context(cafile=str(root/"tls/ca.pem")),timeout=15)
            try:
                headers={k:v for k,v in self.headers.items() if k.lower() not in ("host","connection","transfer-encoding")}
                connection.request(self.command,self.path,body,headers)
                response=connection.getresponse(); data=response.read(4*1024*1024)
                drop=False
                with lock:
                    if is_post and 200<=response.status<300:
                        counters["committed_cipher_posts"]+=1
                        if (root/"drop-next-post").exists():
                            (root/"drop-next-post").unlink(); drop=True
                            value=json.loads(data); item=value.get("id",value.get("Id"))
                            if not isinstance(item,str) or len(item)!=36: raise ValueError("committed item ID missing")
                            counters["dropped_cipher_replies"]+=1; counters["dropped_item_ids"].append(item)
                    save(root/"proxy-observed.json",counters)
                if drop:
                    self.close_connection=True
                    self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
                self.send_response(response.status)
                for k,v in response.getheaders():
                    if k.lower() not in ("content-length","connection","transfer-encoding"): self.send_header(k,v)
                self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
            finally: connection.close()
        do_GET=dispatch; do_POST=dispatch; do_PUT=dispatch; do_DELETE=dispatch
    server=http.server.ThreadingHTTPServer(("127.0.0.1",config["proxy_port"]),Handler)
    server.daemon_threads=True
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/"tls/server.pem",root/"tls/server-key.pem")
    server.socket=context.wrap_socket(server.socket,server_side=True)
    save(root/"proxy-observed.json",counters); server.serve_forever()


def inventory_items(items, symmetric, effect):
    safe=[]
    destination=effect["destination"]
    expected_references={destination["folder"]+"/"+scenario for scenario in ["create","deny","interrupt"]}
    for item in items:
        wrapped=item.get("key",item.get("Key"))
        if not wrapped: raise ValueError("expected per-item encrypted key")
        item_key=decrypt(wrapped,symmetric)
        if len(item_key)!=64: raise ValueError("invalid per-item key size")
        name=decrypt(item.get("name",item.get("Name")),item_key).decode()
        reference=destination["folder"]+"/"+name
        if reference not in expected_references or item.get("folderId",item.get("FolderId"))!=destination["folder_id"] or item.get("organizationId",item.get("OrganizationId")) is not None:
            raise ValueError("unexpected vault item namespace")
        login=item.get("login",item.get("Login")); password=decrypt(login.get("password",login.get("Password")),item_key)
        fields=item.get("fields",item.get("Fields",[]))
        markers=[decrypt(field.get("value",field.get("Value")),item_key) for field in fields if decrypt(field.get("name",field.get("Name")),item_key)==b"vw-access"]
        safe.append({"id":item.get("id",item.get("Id")),"name":name,"reference":reference,"synthetic_value_matches":password==b"private-producer-sentinel","eligibility_marker_matches":markers==[effect["eligibility_marker"].encode()]})
    return safe


def snapshot(root):
    bootstrap=load(root,"private/bootstrap.json"); symmetric=base64.b64decode(bootstrap["symmetric"])
    synced=api(root,"/api/sync"); items=synced.get("ciphers",synced.get("Ciphers",[]))
    safe=inventory_items(items,symmetric,load(root,"storage.json")["effect"])
    result={"vault_item_count":len(items),"items":safe,"proxy":load(root,"proxy-observed.json")}
    if (root/"observed.json").exists(): result["provider"]=load(root,"observed.json")
    print(json.dumps(result,indent=2))


def operator(root,value):
    (root/"operator-result.json").unlink(missing_ok=True)
    if (root/"operator-command.json").exists(): raise ValueError("operator command still pending")
    save(root/"operator-command.json",value)
    wait_for(lambda: (root/"operator-result.json").exists() and not (root/"operator-command.json").exists())
    print((root/"operator-result.json").read_text())


def cleanup(root):
    owner=load(root,"storage-owner.json"); config=load(root,"launcher.json")
    provider=config["unit"]
    state=property(provider,"ActiveState")
    if state not in ("inactive","failed"):
        invocation_path=root/"provider-invocation.json"
        expected=load(root,"provider-invocation.json").get("invocation") if invocation_path.exists() else None
        if not expected or property(provider,"InvocationID")!=expected:
            raise ValueError("active provider ownership unconfirmed; retain recovery material")
        (root/"stop").touch(mode=0o600)
        wait_for(lambda: property(provider,"ActiveState") in ("inactive","failed"),25)
    for unit,identity in reversed(list(owner["units"].items())):
        state=property(unit,"ActiveState")
        if state not in ("inactive","failed"):
            if not identity["invocation"] or property(unit,"InvocationID")!=identity["invocation"]: raise ValueError("service ownership mismatch; retain private material")
            base.run(["systemctl","--user","stop",unit],env=base.systemd_env(),capture_output=True,timeout=20)
        if property(unit,"ActiveState") not in ("inactive","failed") or property(unit,"MainPID") not in ("0",""): raise ValueError("owned service remains")
    container=owner["container"]
    if container:
        ids=base.run(["docker","ps","-aq","--no-trunc"],capture_output=True,text=True,timeout=10).stdout.split()
        if container in ids:
            inspected=json.loads(base.run(["docker","inspect",container],capture_output=True,text=True,timeout=10).stdout)[0]
            if inspected["Id"]!=container or inspected["Config"]["Labels"].get("vw.storage.acceptance")!=owner["tag"]: raise ValueError("container ownership mismatch")
            base.run(["docker","rm","-f",container],capture_output=True,timeout=20)
        if container in base.run(["docker","ps","-aq","--no-trunc"],capture_output=True,text=True,timeout=10).stdout.split(): raise ValueError("owned container remains")
    elif owner.get("container_intent"): raise ValueError("uncertain container ownership; retain recovery material")
    transport=Path(config["transport"])
    if transport.exists():
        if not transport.name.startswith("vw-companion-agent-") or transport.stat().st_uid!=os.getuid(): raise ValueError("transport ownership mismatch")
        keyroot=transport/"agent"
        if keyroot.exists():
            if keyroot.stat().st_uid!=config["uid"]: raise ValueError("agent ownership mismatch")
            program='import os,sys,pathlib; os.setgid(0); os.setuid(8); p=pathlib.Path(sys.argv[1]); (p/"seed").unlink(missing_ok=True)'
            base.run(["unshare","--user","--map-auto","--map-root-user","python3","-c",program,keyroot],capture_output=True,timeout=10)
            keyroot.rmdir()
        shutil.rmtree(transport)
    # Preserve sanitized evidence, remove bootstrap/keyring and TLS private identities.
    if (root/"private").exists(): shutil.rmtree(root/"private")
    if (root/"tls").exists(): shutil.rmtree(root/"tls")
    save(root/"cleanup.json",{"owned_services_stopped":True,"owned_container_absent":True,"agent_material_removed":True,"private_bootstrap_removed":True})
    print((root/"cleanup.json").read_text())


def main():
    os.umask(0o077)
    action=sys.argv[1]
    if action=="prepare": return prepare(sys.argv[2] if len(sys.argv)>2 else "192.168.1.235")
    root=check(Path(sys.argv[2]))
    if action=="proxy": return proxy(root)
    if action in ("start","resume"):
        base.start(root,resume=action=="resume")
        save(root/"provider-invocation.json",{"invocation":property(load(root,"launcher.json")["unit"],"InvocationID")}); return
    if action=="stop":
        (root/"stop").touch(mode=0o600)
        wait_for(lambda: (root/"finished.json").exists(),25)
        print((root/"finished.json").read_text()); return
    if action=="submit":
        output=base.agent(root,"submit",sys.argv[3]); sys.stdout.buffer.write(output.stdout); sys.stderr.buffer.write(output.stderr); raise SystemExit(output.returncode)
    if action=="snapshot": return snapshot(root)
    if action=="arm-drop":
        if (root/"drop-next-post").exists(): raise ValueError("drop already armed")
        (root/"drop-next-post").touch(mode=0o600); print('{"armed":true}'); return
    if action=="provision-consumer": return operator(root,{"action":action,"item_id":sys.argv[3]})
    if action=="reconcile": return operator(root,{"action":action,"request_id":sys.argv[3],"item_id":sys.argv[4]})
    if action=="cleanup": return cleanup(root)
    if action=="mac-config":
        ready=load(root,"ready.json"); command=sys.argv[3]
        setup={"synthetic_only":True,"endpoint":ready["endpoint"],"identity":str(root/"tls/client.p12"),"identity_password":base.P12_PASSWORD,"ca":str(root/"tls/ca.der"),"pin":ready["provider_fingerprint"],"password":PASSWORD,"command":command}
        if command in ("approve","deny"):
            operation=sys.argv[4]; setup["operation"]=operation
            effect=load(root,"storage.json")["effect"]; effect["destination"]["reference"]="storage-acceptance/"+operation.removeprefix("storage-"); setup["expected_create"]=effect
        if command=="status": setup["request_id"]=sys.argv[4]
        path=root/"private/mac-config.json"; save(path,setup); print(path); return
    raise ValueError("unknown action")

if __name__=="__main__": main()
