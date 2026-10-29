#!/usr/bin/env python3
"""Bounded fake v1/v2 provider for the actual packaged Mac adapter, never execution.

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
    locked = mode in ["controller", "pilot"]
    agent_id = "A" * 43
    action_id = "C" * 42 + "A"
    ticket = "d" * 64
    prepared = None
    action = None
    revoked = set()

    def identity(kind, identifier):
        return {"kind": kind, "id": identifier,
                "label": "Synthetic administrator" if kind == "approval_client" else "Synthetic requester",
                "fingerprint": expected if kind == "approval_client" else "b" * 64,
                "roles": [] if identifier in revoked else (["approve", "admin"] if kind == "approval_client" else ["request"]),
                "trust": "revoked" if identifier in revoked else "enabled",
                "this_client": kind == "approval_client"}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            nonlocal status, locked, prepared, action
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
            if command in {"identity_list", "identity_detail", "identity_prepare", "identity_revoke", "identity_status"}:
                # Strict fixture assertions make wrong targets, replay, retained
                # passwords/tickets on status, and missing fresh auth fail closed.
                keys = {"version", "command"}
                if command == "identity_list":
                    valid = (set(body) == keys | {"limit", "after"}
                             and body.get("limit") == 64 and body.get("after") is None)
                else:
                    keys |= {"target"}
                    if command in {"identity_revoke", "identity_status"}:
                        keys |= {"action_id"}
                    if command == "identity_revoke":
                        keys |= {"ticket", "password"}
                    target = body.get("target")
                    valid = set(body) == keys and target in [
                        {"kind": "approval_client", "id": expected},
                        {"kind": "requester_agent", "id": agent_id}]
                if not mode.startswith("management") or body.get("version") != 2 or not valid:
                    return self.reply(400, {"version": 1, "error": "invalid_request"})
                if command == "identity_list":
                    return self.reply(200, {"version": 2, "identities": [identity("approval_client", expected), identity("requester_agent", agent_id)],
                                           "next_cursor": None, "generation": 1,
                                           "provider": {"fingerprint": "e" * 64, "execution_configured": True, "execution_available": True}})
                if command == "identity_detail":
                    return self.reply(200, {"version": 2, "identity": identity(target["kind"], target["id"]), "generation": 1})
                if command == "identity_prepare":
                    if action is not None or prepared is not None:
                        return self.reply(409, {"version": 1, "error": "stale"})
                    prepared = target.copy()
                    return self.reply(200, {"version": 2, "identity": identity(target["kind"], target["id"]),
                                           "action_id": action_id, "ticket": ticket, "generation": 1, "valid_for_seconds": 55})
                if command == "identity_revoke":
                    matches = prepared == target and body.get("action_id") == action_id and body.get("ticket") == ticket
                    prepared = None  # consumed even for bad fresh authentication
                    if not matches or action is not None:
                        return self.reply(409, {"version": 1, "error": "stale"})
                    if body.get("password") != "synthetic-management-only":
                        return self.reply(422, {"version": 1, "error": "authentication_failed"})
                    action = {"version": 2, "target": target.copy(), "action_id": action_id,
                              "revocation": "recorded", "cleanup": "complete", "owner_reconciled": False}
                    revoked.add(target["id"])
                    if mode == "management-drop-pending":
                        action.update(revocation="pending", cleanup="unknown")
                    if mode in {"management-drop", "management-drop-pending"}:
                        self.close_connection = True
                        self.connection.shutdown(2)
                        self.connection.close()
                        return
                    return self.reply(200, action)
                if action is None or body.get("action_id") != action_id or target != action["target"]:
                    return self.reply(409, {"version": 1, "error": "stale"})
                return self.reply(200, action)
            if command == "session":
                return self.reply(200, {"version": 1, "state": "locked" if locked else "unlocked", "generation": 1})
            if command == "unlock":
                if mode == "pilot" and body.get("password") != "synthetic-pilot-unlock-only":
                    return self.reply(422, {"version": 1, "error": "authentication_failed"})
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
                if mode in ["controller", "pilot"]:
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
