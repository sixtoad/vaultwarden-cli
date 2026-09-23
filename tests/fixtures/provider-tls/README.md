# Synthetic TLS identities for tests

These public test certificates and private keys secure no real data. Never trust
them or use them for a deployed provider. `server.pem` has IP SAN 127.0.0.1 and is
signed by `ca.pem`; `replacement.pem` is independently self-signed for the stale
origin takeover regression. Test fixtures copy PEM files to mode-0600 temporary
paths. Tests trust only this temporary CA in their client; no machine trust store
is modified. Certificates expire in 2036 and must then be regenerated together.
