#!/usr/bin/env python3
"""Bounded fake v1 provider for the actual packaged Mac adapter, never execution.

Reuses the existing disposable certificate generator. Counts command names only;
no passwords, tickets, review bodies or private material enter evidence logs.
"""
import argparse
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("companion_tls", ROOT / "macos/Tests/Fixtures/tls_fixture.py")
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


def serve(directory, mode):
    review = json.loads((ROOT / "tests/fixtures/companion/review.json").read_text())
    expected = hashlib.sha256((directory / "client.der").read_bytes()).hexdigest()
    counters = directory / "requests.jsonl"
    counters.write_text("")
    lock = threading.Lock()
    status = {"status": "pending"}
    locked = mode == "controller"

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            nonlocal status, locked
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 16384:
                self.close_connection = True
                return
            body = json.loads(self.rfile.read(size))
            command = body.get("command")
            with lock:
                with counters.open("a") as log:
                    log.write(json.dumps({"command": command}) + "\n")
            peer = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            if peer != expected:
                return self.reply(403, {"version": 1, "error": "unauthorized"})
            if mode == "redirect":
                self.send_response(307)
                self.send_header("Location", "/redirected")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                return
            if mode == "invalid-schema":
                return self.reply(200, {"version": 1, "state": "unlocked", "generation": 1, "extra": True})
            if mode == "oversized":
                return self.reply(200, {"version": 1, "padding": "x" * 1048576})
            if command == "session":
                return self.reply(200, {"version": 1, "state": "locked" if locked else "unlocked", "generation": 1})
            if command == "unlock":
                locked = False
                return self.reply(200, {"version": 1, "state": "unlocked", "generation": 1})
            if command == "list":
                return self.reply(200, {"version": 1, "requests": [] if locked else [review["review"]["id"]]})
            if command == "review":
                return self.reply(200, review)
            if command == "decision":
                if body.get("decision") == "deny" and "password" in body:
                    return self.reply(400, {"version": 1, "error": "invalid_request"})
                if mode == "authentication422":
                    return self.reply(422, {"version": 1, "error": "authentication_failed"})
                status = {"status": "denied" if body.get("decision") == "deny" else "approved"}
                if mode in ["drop", "drop-pending"]:
                    if mode == "drop-pending":
                        status = {"status": "pending"}
                    self.close_connection = True
                    self.connection.shutdown(2)
                    self.connection.close()
                    return
                return self.reply(200, {"version": 1, "status": status})
            if command == "status":
                if mode == "controller":
                    status = ({"status": "running"} if status["status"] == "approved"
                              else {"status": "completed", "exit_code": 0})
                return self.reply(200, {"version": 1, "status": status})
            return self.reply(400, {"version": 1, "error": "invalid_request"})

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
                pass
            self.close_connection = True

    server = legacy.LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    leaf = mode if mode in ["wrong-host", "expired"] else "server"
    key = "server" if leaf == "expired" else leaf
    context.load_cert_chain(directory / f"{leaf}.pem", directory / f"{key}.key")
    context.load_verify_locations(directory / "ca.pem")
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
        legacy.provision(args.directory)
    else:
        serve(args.directory, args.mode)
