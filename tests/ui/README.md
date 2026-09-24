# Direct request browser verification

`direct-request.mjs` drives real Firefox against an ignored Rust test fixture. The fixture uses a synthetic backend, a test-only desktop opener, and real private Unix and trusted HTTPS transports. It never opens a production vault or installs a production inspection endpoint.

Install the locked browser-test dependencies with `npm ci --prefix tests/ui`, or copy `package.json` and `package-lock.json` into a disposable directory and run `npm ci` there. Provide Firefox and NSS `certutil`. Build the CLI with `cargo build --bin vw-access`, then run:

```sh
VW_UI_DEPS=/tmp/vw-story14-browser/node_modules \
CERTUTIL=/tmp/vw-story13-nss/extracted/usr/bin/certutil \
node tests/ui/direct-request.mjs
```

The harness starts the ignored fixture through Cargo, creates a disposable Firefox profile, and trusts only the synthetic fixture CA in that profile. `acceptInsecureCerts` remains false. The fixture exits after the harness writes its private stop file or after 180 seconds. Local socket access is required.

Checks include keyboard navigation and computed visible focus, semantic labels, atomic live status, WCAG 2 A/AA and 2.1 AA axe auditing, actual artifact navigation, safe metadata rendering, one-use launch replay, invalid or absent independent proof, preserved existing browser sessions, and pending-to-expired status observable while locked. Automated accessibility results are not a manual screen-reader exercise.
