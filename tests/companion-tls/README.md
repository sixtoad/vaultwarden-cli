# Synthetic companion TLS identities

These keys secure no real data. Never deploy or trust them outside tests.
The two client-auth certificates chain to the synthetic CA and expire in 2036.
The CA private key was discarded after generation. The provider server identity
uses the existing `fixtures/provider-tls` fixtures. Tests copy identities to
private temporary paths and never modify system trust.
