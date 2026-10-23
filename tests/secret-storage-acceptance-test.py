#!/usr/bin/env python3
"""Focused regressions for the test-only fault injection and inventory crypto."""
import http.client
import http.server
import importlib.util
import json
import multiprocessing
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

spec = importlib.util.spec_from_file_location("storage_acceptance", Path(__file__).with_name("secret-storage-acceptance.py"))
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


class StorageAcceptanceTests(unittest.TestCase):
    def test_cleanup_retains_material_without_matching_active_provider_identity(self):
        for recorded in [None, "", "different-invocation"]:
            with self.subTest(recorded=recorded), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary); (root/"private").mkdir(); (root/"private/recovery").write_text("retain")
                runner.save(root/"storage-owner.json",{"units":{},"container":None})
                runner.save(root/"launcher.json",{"unit":"fixture.service"})
                if recorded is not None: runner.save(root/"provider-invocation.json",{"invocation":recorded})
                def property_value(unit,name): return "active" if name=="ActiveState" else "actual-invocation"
                with patch.object(runner,"property",side_effect=property_value), patch.object(runner.base,"run") as run:
                    with self.assertRaisesRegex(ValueError,"ownership unconfirmed"): runner.cleanup(root)
                    run.assert_not_called()
                self.assertEqual((root/"private/recovery").read_text(),"retain")
                self.assertFalse((root/"stop").exists())
                self.assertFalse((root/"cleanup.json").exists())

    def test_api_constructs_get_json_and_form_without_leaking_auth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "private").mkdir()
            runner.save(root / "private/bootstrap.json", {"backend": "https://127.0.0.1:443", "bearer": "private-test-bearer"})
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def read(self, limit): return b'{"ok":true}'
            with patch.object(runner.ssl, "create_default_context", return_value=object()), patch.object(runner.urllib.request, "urlopen", return_value=Response()) as send:
                self.assertTrue(runner.api(root, "/api/sync")["ok"])
                request = send.call_args.args[0]
                self.assertEqual(request.get_method(), "GET")
                self.assertTrue(request.get_header("Authorization") == "Bearer private-test-bearer")
                runner.api(root, "/identity/accounts/register", {"name": "fixture"}, authenticated=False)
                request = send.call_args.args[0]
                self.assertEqual(request.get_method(), "POST")
                self.assertIsNone(request.get_header("Authorization"))
                self.assertEqual(json.loads(request.data), {"name": "fixture"})
                runner.api(root, "/identity/connect/token", {"grant_type": "password", "password": "synthetic+a&b"}, form=True, authenticated=False)
                request = send.call_args.args[0]
                self.assertEqual(request.get_header("Content-type"), "application/x-www-form-urlencoded")
                self.assertTrue(runner.urllib.parse.parse_qs(request.data.decode())["password"] == ["synthetic+a&b"])

    def test_inventory_unwraps_item_key_and_enforces_namespace(self):
        account_key=secrets.token_bytes(64); item_key=secrets.token_bytes(64)
        effect={"destination":{"folder":"storage-acceptance","folder_id":"11111111-1111-1111-1111-111111111111"},"eligibility_marker":"storage-consume"}
        item={"id":"22222222-2222-2222-2222-222222222222","key":runner.encrypt(item_key,account_key),"name":runner.encrypt("create",item_key),"folderId":effect["destination"]["folder_id"],"login":{"password":runner.encrypt("private-producer-sentinel",item_key)},"fields":[{"name":runner.encrypt("vw-access",item_key),"value":runner.encrypt("storage-consume",item_key)}]}
        result=runner.inventory_items([item],account_key,effect)
        self.assertTrue(result[0]["synthetic_value_matches"])
        self.assertTrue(result[0]["eligibility_marker_matches"])
        self.assertEqual(result[0]["reference"],"storage-acceptance/create")
        item["login"]["password"]=runner.encrypt("wrong-synthetic-value",item_key)
        self.assertFalse(runner.inventory_items([item],account_key,effect)[0]["synthetic_value_matches"])
        for fields in [[],[{"name":runner.encrypt("vw-access",item_key),"value":runner.encrypt("wrong-marker",item_key)}]]:
            item["fields"]=fields
            self.assertFalse(runner.inventory_items([item],account_key,effect)[0]["eligibility_marker_matches"])
        item["folderId"]="33333333-3333-3333-3333-333333333333"
        with self.assertRaises(ValueError): runner.inventory_items([item],account_key,effect)

    def test_inventory_decryption_checks_integrity(self):
        key = secrets.token_bytes(64)
        encrypted = runner.encrypt(b"synthetic-check-only", key)
        self.assertTrue(runner.decrypt(encrypted, key) == b"synthetic-check-only")
        fields = encrypted.split("|"); fields[-1] = runner.base64.b64encode(bytes(32)).decode()
        with self.assertRaises(ValueError): runner.decrypt("|".join(fields), key)

    def test_fault_commits_exactly_once_and_discards_only_armed_reply(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root/"tls").mkdir(); (root/"private").mkdir()
            subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(root/"tls/server-key.pem"),"-out",str(root/"tls/server.pem"),"-days","1","-subj","/CN=localhost","-addext","subjectAltName=IP:127.0.0.1"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            (root/"tls/ca.pem").write_bytes((root/"tls/server.pem").read_bytes())
            committed=[]
            class Backend(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args): pass
                def do_POST(self):
                    self.rfile.read(int(self.headers.get("Content-Length","0")))
                    committed.append(f"11111111-1111-1111-1111-{len(committed)+1:012d}")
                    body=json.dumps({"id":committed[-1]}).encode()
                    self.send_response(201); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
                def do_GET(self):
                    body=json.dumps({"count":len(committed)}).encode()
                    self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
            backend=http.server.ThreadingHTTPServer(("127.0.0.1",0),Backend)
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(root/"tls/server.pem",root/"tls/server-key.pem")
            backend.socket=tls.wrap_socket(backend.socket,server_side=True)
            thread=threading.Thread(target=backend.serve_forever,daemon=True)
            with socket.socket() as listener: listener.bind(("127.0.0.1",0)); port=listener.getsockname()[1]
            runner.save(root/"private/bootstrap.json",{"backend":f"https://127.0.0.1:{backend.server_port}","proxy_port":port})
            process=multiprocessing.get_context("fork").Process(target=runner.proxy,args=(root,)); process.start(); thread.start()
            try:
                runner.wait_for(lambda:(root/"proxy-observed.json").exists(),5)
                context=ssl.create_default_context(cafile=str(root/"tls/ca.pem"))
                def ordinary_post(expected_number):
                    connection=http.client.HTTPSConnection("127.0.0.1",port,context=context,timeout=5)
                    connection.request("POST","/api/ciphers",b"{}",{"Content-Type":"application/json"})
                    response=connection.getresponse()
                    self.assertEqual(response.status,201)
                    self.assertEqual(json.loads(response.read()),{"id":f"11111111-1111-1111-1111-{expected_number:012d}"})
                    connection.close()
                ordinary_post(1)
                (root/"drop-next-post").touch(mode=0o600)
                connection=http.client.HTTPSConnection("127.0.0.1",port,context=context,timeout=5)
                connection.request("POST","/api/ciphers",b"{}",{"Content-Type":"application/json"})
                with self.assertRaises((http.client.RemoteDisconnected,ConnectionError)): connection.getresponse()
                connection.close()
                self.assertEqual(len(committed),2)
                ordinary_post(3)
                connection=http.client.HTTPSConnection("127.0.0.1",port,context=context,timeout=5)
                connection.request("GET","/api/sync")
                response=connection.getresponse(); self.assertEqual(response.status,200); self.assertEqual(json.loads(response.read())["count"],3); connection.close()
                counts=runner.load(root,"proxy-observed.json")
                self.assertEqual(counts["cipher_posts"],3)
                self.assertEqual(counts["committed_cipher_posts"],3)
                self.assertEqual(counts["dropped_cipher_replies"],1)
                self.assertEqual(counts["dropped_item_ids"],[committed[1]])
                self.assertFalse((root/"drop-next-post").exists())
            finally:
                process.terminate(); process.join(timeout=5)
                backend.shutdown(); backend.server_close(); thread.join(timeout=5)
                self.assertFalse(process.is_alive())

if __name__ == "__main__": unittest.main()
