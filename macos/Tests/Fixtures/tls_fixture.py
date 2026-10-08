#!/usr/bin/env python3
"""Synthetic localhost mutual-TLS fixture. No production keys or backend required."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading


def provision(root):
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    openssl = os.environ.get("OPENSSL", "openssl")

    def run(*args):
        subprocess.run([openssl, *map(str, args)], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    for ca in ["ca", "other-ca"]:
        (root / f"{ca}.cnf").write_text(f"[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=Synthetic {ca}\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", f"{ca}.cnf", "-keyout", f"{ca}.key", "-out", f"{ca}.pem")
        run("x509", "-in", f"{ca}.pem", "-outform", "DER", "-out", f"{ca}.der")
    for name, ca, client, san in [
        ("server", "ca", False, "DNS:localhost,DNS:companion.localhost,IP:127.0.0.1"),
        ("wrong-host", "ca", False, "DNS:wrong.invalid"),
        ("client", "ca", True, None),
        ("revoked", "ca", True, None),
        ("foreign", "other-ca", True, None),
    ]:
        (root / f"{name}.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + ("clientAuth" if client else "serverAuth") + "\n" + (f"subjectAltName={san}\n" if san else ""))
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN=Synthetic {name}", "-keyout", f"{name}.key", "-out", f"{name}.csr")
        run("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.pem", "-CAkey", f"{ca}.key", "-CAcreateserial", "-days", "2", "-extfile", f"{name}.ext", "-out", f"{name}.pem")
        run("x509", "-in", f"{name}.pem", "-outform", "DER", "-out", f"{name}.der")
        if client:
            run("pkcs12", "-export", "-inkey", f"{name}.key", "-in", f"{name}.pem", "-certfile", f"{ca}.pem", "-passout", "pass:synthetic-only", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1", "-out", f"{name}.p12")
    # Historical dates produce a correctly signed but expired test leaf.
    (root / "expired-index").write_text("")
    (root / "expired-serial").write_text("01\n")
    (root / "expired-ca.cnf").write_text("[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=expired-index\nserial=expired-serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n")
    run("ca", "-batch", "-config", "expired-ca.cnf", "-in", "server.csr", "-extfile", "server.ext", "-startdate", "20000101000000Z", "-enddate", "20010101000000Z", "-notext", "-out", "expired.pem")
    run("x509", "-in", "expired.pem", "-outform", "DER", "-out", "expired.der")
    for path in root.iterdir():
        os.chmod(path, 0o600)


def serve(root, mode):
    expected_client = hashlib.sha256((root / "client.der").read_bytes()).hexdigest()
    lock = threading.Lock()
    counters = root / "requests.jsonl"
    counters.write_text("")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 16384:
                self.close_connection = True
                return
            body = json.loads(self.rfile.read(size))
            with lock:
                with counters.open("a") as out:
                    # Record only the command; never store the password or review.
                    out.write(json.dumps({"command": body.get("command")}) + "\n")
            peer = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            if peer != expected_client:
                return self.reply(403, {"version": 1, "error": "unauthorized"})
            if mode in ["authentication403", "authentication422", "authentication-unlock422"] and body.get("command") in ["decision", "unlock"]:
                return self.reply(int(mode[-3:]), {"version": 1, "error": "authentication_failed"})
            if mode == "success503":
                return self.reply(503, {"version": 1, "state": "unlocked", "generation": 1})
            if mode == "error200":
                return self.reply(200, {"version": 1, "error": "authentication_failed"})
            if mode == "mismatched-error422":
                return self.reply(422, {"version": 1, "error": "unavailable"})
            if mode == "unknown-error422":
                return self.reply(422, {"version": 1, "error": "future_error"})
            if mode == "extra-error422":
                return self.reply(422, {"version": 1, "error": "authentication_failed", "future": None})
            if mode == "valid-error422":
                return self.reply(422, {"version": 1, "error": "authentication_failed"})
            if mode == "drop" and body.get("command") == "decision":
                self.close_connection = True
                self.connection.shutdown(2)
                self.connection.close()
                return
            if mode == "redirect":
                self.send_response(307)
                self.send_header("Location", "/redirected")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                return
            if mode == "oversized":
                # Valid JSON larger than the cap, not a truncated response that
                # would fail even if all client bounds were accidentally removed.
                return self.reply(200, {"version": 1, "state": "unlocked", "generation": 1, "padding": "x" * 1048576})
            if body.get("command") == "status":
                return self.reply(200, {"version": 1, "status": {"status": "pending"}})
            self.reply(200, {"version": 1, "state": "unlocked", "generation": 1})

        def reply(self, code, value):
            body = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass  # Expected when a bounded client cancels oversized output.
            self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    name = mode if mode in ["wrong-host", "expired"] else "server"
    key_name = "server" if name == "expired" else name
    context.load_cert_chain(root / f"{name}.pem", root / f"{key_name}.key")
    if mode == "tls11":
        context.minimum_version = ssl.TLSVersion.TLSv1_1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("DEFAULT:@SECLEVEL=0" if ssl.OPENSSL_VERSION.startswith("OpenSSL") else "DEFAULT")
    context.load_verify_locations(root / "ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(server.server_port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["provision", "serve"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--mode", default="normal")
    args = parser.parse_args()
    if args.action == "provision":
        provision(args.directory)
    else:
        serve(args.directory, args.mode)
