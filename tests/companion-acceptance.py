#!/usr/bin/env python3
"""Bounded synthetic real-Mac/Linux acceptance, never a production provider.

prepare [hostname] -> creates fixtures, checks a real distinct userns agent UID.
continue ROOT -> prepares fresh state/agent while retaining only synthetic TLS identity/endpoint.
start ROOT -> launches only an isolated 20-minute user systemd service.
start-revoked ROOT -> revokes the synthetic client offline before launching.
start-lost-reply ROOT -> drops one successful approval reply after real dispatch.
resume ROOT -> restarts the same stopped durable fixture, locked.
resume-revoked ROOT -> revokes its client offline, then restarts the same fixture locked.
submit ROOT -> actual signed non-TTY CLI submission from that distinct UID.
stop ROOT -> asks fixture to reap work and stop; retains evidence and test identities.

Requires existing cargo-built test/helper/CLI binaries, openssl, cc, user systemd,
and configured subordinate UID/GID ranges. Run outside the remapping sandbox.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
FIXTURE = "adapters::companion::acceptance_tests::companion_acceptance_fixture"
P12_PASSWORD = "synthetic-companion-identity"


def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def check_root(root):
    root = root.absolute()
    if not root.name.startswith(".vw-companion-acceptance-"):
        raise ValueError("refusing a non-fixture directory")
    for ancestor in [root, *root.parents]:
        meta = ancestor.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, os.getuid()) or meta.st_mode & 0o7022:
            raise ValueError(f"unsafe fixture ancestry: {ancestor}")
    return root


def systemd_env():
    return dict(os.environ, XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",
                DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")


def agent(root, mode):
    # Python reads the ready file and the complete helper before dropping uid.
    # Only the signing seed belongs to the mapped agent; no provider secret is read.
    program = r'''
import base64,json,os,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]); mode=sys.argv[2]
config=json.loads((root/"launcher.json").read_text()); transport=pathlib.Path(config["transport"])
ready=json.loads((root/"ready.json").read_text()) if mode=="submit" else None
mapping=[list(map(int,line.split())) for line in pathlib.Path("/proc/self/uid_map").read_text().splitlines()]
outer=next(out+8-ins for ins,out,count in mapping if ins<=8<ins+count)
os.setgid(0); os.setuid(8)
keyroot=transport/"agent"
if mode=="prepare":
    keyroot.mkdir(mode=0o700); seed=os.urandom(32)
    descriptor=os.open(keyroot/"seed",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,"wb") as output: output.write(seed)
    der=bytes.fromhex("302e020100300506032b657004220420")+seed
    public=subprocess.run(["openssl","pkey","-inform","DER","-pubout","-outform","DER"],input=der,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout[-32:]
    print(json.dumps({"uid":outer,"public_key":base64.urlsafe_b64encode(public).decode().rstrip("=")}))
else:
    args=[str(transport/"vw-access"),"submit","synthetic-deploy","--socket",ready["socket"],"--key-file",str(keyroot/"seed"),"--binding-id",ready["binding"]["id"],"--revision",ready["revision"],"--wait","--timeout-seconds","300","--","exit","synthetic"]
    os.setsid()
    with open(os.devnull,"rb") as null: os.dup2(null.fileno(),0)
    os.execv(args[0],args)
'''
    return subprocess.run(["unshare", "--user", "--map-auto", "--map-root-user",
                           "python3", "-c", program, str(root), mode],
                          check=(mode == "prepare"), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=315 if mode == "submit" else 15)


def prepare(hostname, prior=None):
    if not hostname or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in hostname):
        raise ValueError("expected a DNS hostname")
    os.umask(0o077)
    root = check_root(Path(tempfile.mkdtemp(prefix=".vw-companion-acceptance-", dir=Path.home())))
    tls = root / "tls"; tls.mkdir(mode=0o700)
    binaries = root / "bin"; binaries.mkdir(mode=0o700)
    transport = Path(tempfile.mkdtemp(prefix="vw-companion-agent-", dir="/tmp")); transport.chmod(0o770)
    config = {"transport": str(transport), "hostname": hostname,
              "unit": "vw-companion-acceptance-" + root.name.rsplit("-", 1)[-1] + ".service"}
    save(root / "launcher.json", config)
    identity = json.loads(agent(root, "prepare").stdout)
    assert identity["uid"] != os.getuid(), "agent must have a distinct real UID"
    transport.chmod(0o750)
    seed_meta = (transport / "agent").stat()
    assert seed_meta.st_uid == identity["uid"], "user namespace did not yield real outer UID"
    config.update(identity, gid=os.getgid())
    shutil.copy2(REPO / "target/debug/vw-access", transport / "vw-access"); (transport / "vw-access").chmod(0o750)
    shutil.copy2(REPO / "target/debug/vaultwarden-access-exec", binaries / "vaultwarden-access-exec"); (binaries / "vaultwarden-access-exec").chmod(0o500)
    with socket.socket() as listener:
        listener.bind(("0.0.0.0", 0)); config["port"] = listener.getsockname()[1]
    with open(root / "provision.log", "wb") as log:
        def openssl(*args): run(["openssl", *args], stdout=log, stderr=log)
        if prior is not None:
            old = json.loads((prior / "launcher.json").read_text())
            config["port"] = old["port"]
            for name in ["ca.pem", "ca.der", "server.pem", "server-key.pem", "client.pem", "client-key.pem", "client.p12"]:
                shutil.copy2(prior / "tls" / name, tls / name)
        else:
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", tls / "ca-key.pem", "-out", tls / "ca.pem", "-days", "2", "-subj", "/CN=Synthetic companion acceptance CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            issued_serials = set()
            for name, purpose in [("server", "serverAuth"), ("client", "clientAuth")]:
                # Keychain identifies certificates by issuer/serial across fixture renewals.
                serial = 0
                while serial == 0 or serial in issued_serials:
                    serial = secrets.randbits(159)
                issued_serials.add(serial)
                openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", tls / f"{name}-key.pem", "-out", tls / f"{name}.csr", "-subj", f"/CN=Synthetic companion {name}")
                extensions = f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={purpose}\n"
                if name == "server": extensions += f"subjectAltName=DNS:{hostname},IP:127.0.0.1\n"
                (tls / f"{name}.ext").write_text(extensions)
                openssl("x509", "-req", "-in", tls / f"{name}.csr", "-CA", tls / "ca.pem", "-CAkey", tls / "ca-key.pem", "-set_serial", str(serial), "-out", tls / f"{name}.pem", "-days", "2", "-extfile", tls / f"{name}.ext")
            openssl("x509", "-in", tls / "ca.pem", "-outform", "DER", "-out", tls / "ca.der")
            openssl("pkcs12", "-export", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1", "-inkey", tls / "client-key.pem", "-in", tls / "client.pem", "-certfile", tls / "ca.pem", "-name", "Synthetic Companion Acceptance", "-out", tls / "client.p12", "-passout", "pass:" + P12_PASSWORD)
        run(["cc", "-nostdlib", "-static", "-no-pie", "-fno-stack-protector", "-fno-builtin", "-O2", "-Wl,--build-id=none", "-o", binaries / "protected-image", REPO / "tests/fixtures/protected-tree.c"], stdout=log, stderr=log)
    for path in tls.iterdir(): path.chmod(0o600)
    (tls / "ca-key.pem").unlink(missing_ok=True)
    (binaries / "protected-image").chmod(0o500)
    save(root / "launcher.json", config)
    run(["systemctl", "--user", "show-environment"], env=systemd_env(), stdout=subprocess.DEVNULL, timeout=10)
    print(json.dumps({"root": str(root), "endpoint": f"https://{hostname}:{config['port']}",
                      "agent_uid": identity["uid"], "agent_gid": config["gid"],
                      "server_ca": str(tls / "ca.pem"), "client_identity": str(tls / "client.p12"),
                      "identity_password": P12_PASSWORD, "approval_password": "synthetic-companion-password",
                      "status": "prepared; no service started"}, indent=2))


def start(root, client_revoked=False, drop_approval_reply=False, resume=False):
    root = check_root(root); config = json.loads((root / "launcher.json").read_text())
    if resume:
        active = run(["systemctl", "--user", "show", config["unit"], "--property=ActiveState", "--value"],
                     env=systemd_env(), capture_output=True, text=True, timeout=10).stdout.strip()
        if active != "inactive": raise ValueError("resume requires an actually inactive fixture service")
        if json.loads((root / "finished.json").read_text()).get("shutdown") != "complete":
            raise ValueError("resume requires completed fixture cleanup")
        if not (root / "provider").is_dir(): raise ValueError("resume requires existing durable state")
        previous = json.loads((root / "ready.json").read_text())
        if previous["endpoint"] != f"https://{config['hostname']}:{config['port']}":
            raise ValueError("resume endpoint mismatch")
        reports = []
        for name in ["ready.json", "observed.json", "finished.json", "transport-observation.json", "stop", "lock", "revoke-agent"]:
            path = root / name
            if path.exists() or path.is_symlink():
                meta = path.lstat()
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_nlink != 1 or meta.st_mode & 0o077:
                    raise ValueError("unsafe fixture report")
                reports.append(path)
        runs = root / "runs"
        runs.mkdir(mode=0o700, exist_ok=True)
        meta = runs.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
            raise ValueError("unsafe fixture report archive directory")
        archive = runs / str(time.time_ns())
        archive.mkdir(mode=0o700)
        for path in reports:
            shutil.copy2(path, archive / path.name)
            if (archive / path.name).read_bytes() != path.read_bytes():
                raise ValueError("fixture report archive mismatch")
        save(root / "resume-ready.json", previous)
    elif (root / "provider").exists():
        raise ValueError("fixture already used; prepare a fresh one or explicitly resume")
    candidates = [p for p in (REPO / "target/debug/deps").glob("vaultwarden_cli-*") if p.is_file() and os.access(p, os.X_OK) and not p.suffix]
    binary = None
    for candidate in sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True):
        probe = subprocess.run([candidate, "--list"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
        if probe.returncode == 0 and FIXTURE in probe.stdout:
            binary = candidate
            break
    if binary is None: raise ValueError("test binary does not yet contain acceptance fixture; await implementation build")
    installed = root / "bin/provider-fixture"
    if resume:
        installed.unlink()
    shutil.copy2(binary, installed); installed.chmod(0o500)
    tls = root / "tls"
    settings = {"CONTROL": root, "SERVER_CERT": tls / "server.pem", "SERVER_KEY": tls / "server-key.pem", "SERVER_CA": tls / "ca.pem", "CLIENT_CA": tls / "ca.pem", "CLIENT_CERT": tls / "client.pem", "CLIENT_IDENTITY": tls / "client.p12", "PUBLIC_ENDPOINT": f"https://{config['hostname']}:{config['port']}", "AGENT_SOCKET_DIR": config["transport"], "LISTEN": f"{'127.0.0.1' if config['hostname'] == '127.0.0.1' else '0.0.0.0'}:{config['port']}", "AGENT_UID": config["uid"], "AGENT_GID": config["gid"], "AGENT_PUBLIC_KEY": config["public_key"], "SYSTEMD_UNIT": config["unit"], "HELPER": root / "bin/vaultwarden-access-exec", "IMAGE": root / "bin/protected-image", "LIFETIME_SECONDS": 1200, "REQUEST_SECONDS": 300}
    command = ["systemd-run", "--user", "--quiet", "--unit", config["unit"], "--property=Type=exec", "--property=KillMode=control-group", "--property=RuntimeMaxSec=1220s", "--property=TimeoutStopSec=15s", "--property=StandardOutput=journal", "--property=StandardError=journal"]
    if resume:
        settings["RESUME"] = "1"
    if client_revoked:
        settings["START_CLIENT_REVOKED"] = "1"
    if drop_approval_reply:
        settings["DROP_APPROVAL_REPLY"] = "1"
    command += [f"--setenv=VW_COMPANION_{key}={value}" for key, value in settings.items()]
    command += [str(installed), "--exact", FIXTURE, "--ignored", "--nocapture"]
    if resume:
        for path in reports:
            path.unlink()
    try:
        run(command, env=systemd_env(), timeout=15)
    except subprocess.CalledProcessError:
        if resume:
            for path in reports:
                if not path.exists():
                    shutil.copy2(archive / path.name, path)
        raise
    deadline = time.monotonic() + 25
    ready = None
    while ready is None:
        try:
            ready = json.loads((root / "ready.json").read_text())
        except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                run(["journalctl", "--user", "--unit", config["unit"], "--no-pager", "-n", "30"], env=systemd_env())
                raise TimeoutError("fixture did not reach readiness")
            time.sleep(0.1)
    print(json.dumps(ready))


def main():
    if len(sys.argv) < 2: raise ValueError(__doc__)
    action = sys.argv[1]
    if action == "prepare": return prepare(sys.argv[2] if len(sys.argv) > 2 else "pop-os.int.cantolla.casa")
    root = check_root(Path(sys.argv[2]))
    if action == "continue":
        old = json.loads((root / "launcher.json").read_text())
        return prepare(old["hostname"], prior=root)
    if action == "start": return start(root)
    if action == "start-revoked": return start(root, client_revoked=True)
    if action == "start-lost-reply": return start(root, drop_approval_reply=True)
    if action == "resume": return start(root, resume=True)
    if action == "resume-revoked": return start(root, client_revoked=True, resume=True)
    if action == "submit":
        output = agent(root, "submit")
        sys.stdout.buffer.write(output.stdout); sys.stderr.buffer.write(output.stderr)
        raise SystemExit(output.returncode)
    if action == "stop":
        (root / "stop").touch(mode=0o600)
        deadline = time.monotonic() + 20
        while not (root / "finished.json").exists() and time.monotonic() < deadline: time.sleep(0.1)
        if not (root / "finished.json").exists(): raise TimeoutError("fixture cleanup not yet confirmed")
        print((root / "finished.json").read_text()); return
    raise ValueError("unknown action")


if __name__ == "__main__": main()
