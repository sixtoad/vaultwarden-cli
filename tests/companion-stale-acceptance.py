#!/usr/bin/env python3
"""Explicit, bounded synthetic TLS stale-authority cases; never submits agent work.

CASE ROOT REQUEST_ID: lock, revoke-agent, replay-deny, restart, restart-revoked.
Requires one separately authorized pending request in the existing manual fixture.
Only synthetic fixture controls are mutated. Tickets and passwords stay in memory.
Restart cases explicitly stop and resume the same durable fixture, initially locked.
"""
import argparse
import datetime
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

PASSWORD = "synthetic-companion-password"
MAX_RESPONSE = 1024 * 1024


def require(condition):
    if not condition:
        raise AssertionError("synthetic acceptance invariant failed")


class Driver:
    def __init__(self, root, request_id):
        spec = importlib.util.spec_from_file_location(
            "companion_fixture_launcher", Path(__file__).with_name("companion-acceptance.py"))
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        self.launcher = launcher
        self.root = launcher.check_root(root)
        self.request_id = request_id
        require(re.fullmatch(r"[A-Za-z0-9_-]{43}", request_id) is not None)
        self.ready = json.loads((self.root / "ready.json").read_text())
        configuration = json.loads((self.root / "launcher.json").read_text())
        hostname, port = configuration["hostname"], configuration["port"]
        require(isinstance(hostname, str)
                and re.fullmatch(r"[A-Za-z0-9.-]+", hostname) is not None)
        require(type(port) is int and 1 <= port <= 65535)
        self.endpoint = f"https://{hostname}:{port}"
        require(self.ready["endpoint"] == self.endpoint)
        self.server_pin = self.certificate_pin(self.root / "tls/server.pem")
        client_pin = self.certificate_pin(self.root / "tls/client.pem")
        require(self.ready["provider_fingerprint"] == self.server_pin)
        require(self.ready["client_fingerprint"] == client_pin)
        require(self.ready["client_revoked"] is False)
        require(not self.ready.get("drop_approval_reply", False))
        self.context = ssl.create_default_context(cafile=str(self.root / "tls/ca.pem"))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(self.root / "tls/client.pem"),
                                     str(self.root / "tls/client-key.pem"))
        self.commands = []
        self.decision_responses = []
        self.restart_evidence = None

    @staticmethod
    def certificate_pin(path):
        # The checked private fixture root is the trusted provisioning boundary.
        pem = path.read_text()
        require(pem.count("-----BEGIN CERTIFICATE-----") == 1)
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()

    def call(self, command, **values):
        require(len(self.commands) < 64)
        endpoint = urlsplit(self.endpoint)
        connection = http.client.HTTPSConnection(
            endpoint.hostname, endpoint.port, timeout=10, context=self.context)
        try:
            connection.connect()
            require(hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
                    == self.server_pin)
            body = json.dumps(dict(version=1, command=command, **values))
            self.commands.append(command)
            connection.request("POST", "/v1/companion", body=body,
                               headers={"Content-Type": "application/json", "Connection": "close"})
            response = connection.getresponse()
            require(response.status in (200, 403, 409, 422, 429, 503))
            require(response.getheader("Content-Type", "").split(";")[0] == "application/json")
            data = response.read(MAX_RESPONSE + 1)
            require(len(data) <= MAX_RESPONSE)
            decoded = json.loads(data)
            require(decoded.get("version") == 1)
            if command == "decision":
                self.decision_responses.append({"http_status": response.status,
                                                "error": decoded.get("error"),
                                                "status": decoded.get("status")})
            return response.status, decoded
        finally:
            connection.close()

    def state(self):
        return json.loads((self.root / "provider/provider-state.json").read_text())

    def request(self):
        return next(record["direct"] for record in self.state()["requests"]
                    if record["id"] == self.request_id)

    def observe(self):
        direct = self.request()
        return {"request_id": self.request_id, "status": direct["review"]["status"],
                "execution_claimed": direct["execution_claimed"],
                "audit_outcomes": [event["outcome"] for event in direct["audit"]]}

    def control(self, name):
        require(name in ("lock", "revoke-agent"))
        descriptor = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        os.close(descriptor)

    def restart(self, revoked):
        before = self.state()
        launcher_path = Path(__file__).with_name("companion-acceptance.py")
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        stopped = subprocess.run([sys.executable, str(launcher_path), "stop", str(self.root)],
                                 capture_output=True, timeout=30, env=environment)
        require(stopped.returncode == 0)
        configuration = json.loads((self.root / "launcher.json").read_text())
        deadline = time.monotonic() + 15
        while True:
            active = subprocess.run(
                ["systemctl", "--user", "show", configuration["unit"],
                 "--property=ActiveState", "--value"], capture_output=True, text=True,
                timeout=5, env=self.launcher.systemd_env())
            if active.returncode == 0 and active.stdout.strip() == "inactive":
                break
            require(time.monotonic() < deadline)
            time.sleep(0.2)
        restarted = subprocess.run(
            [sys.executable, str(launcher_path), "resume-revoked" if revoked else "resume",
             str(self.root)], capture_output=True, timeout=45, env=environment)
        require(restarted.returncode == 0)
        ready = json.loads((self.root / "ready.json").read_text())
        after = self.state()
        require(ready["resumed"] is True)
        require(ready["binding"] == self.ready["binding"])
        require(ready["revision"] == self.ready["revision"])
        require(ready["client_revoked"] == revoked)
        require(before["pairings"] == after["pairings"])
        require(before["operations"] == after["operations"])
        require([record["id"] for record in before["requests"]]
                == [record["id"] for record in after["requests"]])
        self.restart_evidence = {"same_durable_root": True, "binding_preserved": True,
                                 "policy_preserved": True, "request_ids_preserved": True,
                                 "client_revoked_offline": revoked}

    def run(self, case):
        before = self.observe()
        require(before["status"]["status"] == "pending" and not before["execution_claimed"])
        code, session = self.call("session")
        require(code == 200 and session["state"] == "unlocked")
        code, review = self.call("review", request_id=self.request_id)
        require(code == 200 and review["generation"] == session["generation"])
        ticket = review["ticket"]
        require(isinstance(ticket, str) and re.fullmatch(r"[a-f0-9]{64}", ticket) is not None)
        if case == "replay-deny":
            code, first = self.call("decision", request_id=self.request_id, ticket=ticket,
                                    decision="deny")
            require(code == 200 and first["status"]["status"] == "denied")
            code, rejected = self.call("decision", request_id=self.request_id, ticket=ticket,
                                       decision="deny")
        elif case in ("restart", "restart-revoked"):
            self.restart(case == "restart-revoked")
            code, current = self.call("session")
            if case == "restart":
                require(code == 200 and current["state"] == "locked")
            else:
                require(code == 403 and current.get("error") == "unauthorized")
            code, rejected = self.call("decision", request_id=self.request_id, ticket=ticket,
                                       decision="approve", password=PASSWORD)
        else:
            self.control(case)
            deadline = time.monotonic() + 10
            while True:
                if case == "lock":
                    code, current = self.call("session")
                    changed = (code == 200 and current["state"] == "locked"
                               and current["generation"] != session["generation"])
                else:
                    changed = any(binding["id"] == self.ready["binding"]["id"]
                                  and binding["status"] == "revoked"
                                  for binding in self.state()["pairings"])
                if changed:
                    break
                require(time.monotonic() < deadline)
                time.sleep(0.2)
            code, rejected = self.call("decision", request_id=self.request_id, ticket=ticket,
                                       decision="approve", password=PASSWORD)
        expected_code, expected_error = ((403, "unauthorized") if case == "restart-revoked"
                                          else (409, "stale"))
        require(code == expected_code and rejected.get("error") == expected_error)
        after = self.observe()
        require(not after["execution_claimed"])
        require("execution_started" not in after["audit_outcomes"])
        require(after["status"]["status"] == ("denied" if case == "replay-deny" else "expired"))
        return {"case": case, "fixture_root": str(self.root),
                "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "before": before, "after": after, "commands": self.commands,
                "decision_responses": self.decision_responses, "passed": True,
                "tls": "selected CA, hostname, TLS1.2+, exact leaf pin and enrolled client identity",
                "operator_ui_observation": "separate; this driver does not automate the Mac",
                "restart": self.restart_evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("lock", "revoke-agent", "replay-deny", "restart", "restart-revoked"))
    parser.add_argument("root", type=Path)
    parser.add_argument("request_id")
    args = parser.parse_args()
    driver = None
    try:
        driver = Driver(args.root, args.request_id)
        print(json.dumps(driver.run(args.case), indent=2))
    except Exception as error:
        # Never print exception messages: a decoder could include a response body.
        print(json.dumps({"case": args.case, "passed": False,
                          "failure_type": type(error).__name__,
                          "commands": driver.commands if driver else [],
                          "decision_responses": driver.decision_responses if driver else []}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
