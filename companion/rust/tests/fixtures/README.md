# Desktop transport test identities

Synthetic, public test material that secures no real data. Both PKCS#12 files
hold `tests/companion-tls/client.pem` and `client-key.pem` (repository root),
encrypted with the passphrase `synthetic-p12-passphrase`:

- `client-3des.p12`: the provider `setup tls` format (`-keypbe PBE-SHA1-3DES
  -certpbe PBE-SHA1-3DES -macalg sha1`, with the companion CA as an extra
  certificate);
- `client-aes.p12`: OpenSSL 3 defaults (PBES2, AES-256-CBC, HMAC-SHA-256).

The transport tests serve `tests/fixtures/provider-tls/server.pem` (IP SAN
127.0.0.1) and trust only `tests/fixtures/provider-tls/ca.pem`. Regenerate
with the commands in `companion/rust/src/desktop/identity.rs` tests when the
client certificate is regenerated (it expires with the other fixtures).
