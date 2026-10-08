#!/usr/bin/env python3
"""Test real fixture socket startup independently of external DNS and TLS setup."""
from contextlib import redirect_stdout
import http.server
import io
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest import mock

import tls_fixture


class LoopbackBindTests(unittest.TestCase):
    def test_serve_binds_loopback_without_reverse_dns(self):
        started = []

        def observe_server(server):
            try:
                address, port = server.socket.getsockname()
                self.assertEqual(address, "127.0.0.1")
                self.assertGreater(port, 0)
                self.assertEqual(server.server_address, (address, port))
                self.assertEqual(server.server_port, port)
                self.assertEqual(server.socket.family, socket.AF_INET)
                server.socket.settimeout(1)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(1)
                    client.connect((address, port))
                    accepted, peer = server.socket.accept()
                    with accepted:
                        self.assertEqual(peer, client.getsockname())
                        self.assertEqual(accepted.getsockname(), (address, port))
                started.append(port)
            finally:
                server.server_close()

        with tempfile.TemporaryDirectory(prefix="companion-loopback-bind-") as directory:
            root = Path(directory)
            (root / "client.der").write_bytes(b"synthetic client fingerprint input")
            output = io.StringIO()
            with (
                mock.patch.object(socket, "getfqdn", side_effect=AssertionError("fixture startup attempted reverse DNS")) as fqdn,
                mock.patch.object(socket, "gethostbyaddr", side_effect=AssertionError("fixture startup attempted reverse DNS")) as reverse,
                mock.patch.object(tls_fixture.ssl, "SSLContext") as context_factory,
                mock.patch.object(http.server.ThreadingHTTPServer, "serve_forever", observe_server),
                redirect_stdout(output),
            ):
                # Leave the real bind/listen socket intact; native tests exercise
                # actual TLS. No certificate generation or DNS is needed here.
                context = context_factory.return_value
                context.wrap_socket.side_effect = lambda sock, **_kwargs: sock
                tls_fixture.serve(root, "normal")
                fqdn.assert_not_called()
                reverse.assert_not_called()
                context_factory.assert_called_once_with(ssl.PROTOCOL_TLS_SERVER)
                self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
            self.assertEqual(len(started), 1)
            self.assertEqual(output.getvalue(), f"{started[0]}\n")


if __name__ == "__main__":
    unittest.main()
