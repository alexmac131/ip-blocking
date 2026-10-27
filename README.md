# IP Blocking Tools

Standalone tools extracted from the server project for reviewing Nginx
traffic, collecting attempted exploit scans against the server, and managing
reviewed IP denies.
No live IP blocklist, logs, credentials, or deployment configuration is included.

## Start here

Requirements: a supported Node.js 24+ runtime for reports/tests. Shell helpers
have separate requirements documented in their headers and the scripts guide.
There are no third-party npm dependencies and no build step.

```bash
cd /path/to/ip-blocking
npm test
npm run check
```

Tests create isolated temporary fixtures; they do not contact AWS, connect to
MongoDB, change Nginx, or ban visitors.

## Configure before scanning

The tools retain fixed settings, not command-line switches:

1. In `scripts/analyze-nginx-scans.js`, set `DEFAULT_LOG`,
   `DEFAULT_DIST`, `DEFAULT_ANGULAR_ROOT`, `DEFAULT_BLOCKED_LIST`, and
   `ROUTE_PREFIXES` for **your application**.
2. `DEFAULT_DIST` initially points to the intentionally absent
   `application-dist/`. Point it to your compiled Express build, containing
   `routes/*.js`. This repository does not contain your application's routes
   or a TypeScript compiler. Do not treat unknown-route reports as reliable
   until route discovery is configured.
3. Configure `REPORT_LOGS` in `scripts/analyze-nginx-weather.js` if necessary.
   This report needs only access logs and the shared parser.
4. The collector uses the scanner settings and optionally reads
   `/var/log/nginx/access.log.1`. It saves history under `reports/`.
   Back up the entire JSON, including checkpoints.

Run on the Nginx host after configuration (sudo only if permissions require it):

```bash
sudo node scripts/analyze-nginx-scans.js
sudo node scripts/analyze-nginx-weather.js
sudo node scripts/collect-nginx-attempts.js
```

The first two are read-only reports. The third writes local history but does
not modify bans. All three scripts must stay together.

## Setup guides

- [Nginx IP blocking](docs/NGINX_BLOCKLIST_SYNC.md): installation, HTTP/HTTPS,
  proxy trust, deny includes, verification, and rollback.
- [Express integration](docs/EXPRESS_IP_BLOCKING_SETUP.md): reference setup for
  the original middleware, its integration points, and known limitations.
  **Express middleware is not packaged in this project.**
- [All six scripts](docs/SCRIPTS_REFERENCE.md): commands, inputs, effects,
  permissions, and infrastructure.
- [Blocklist format](docs/BLOCKLIST_USAGE.md).
- [Optional AWS NACL setup](docs/AWS_NACL_IP_BLOCKING_GUIDE.md).

## Safe defaults

The IP lists and AWS rule list are empty. Probe rules are an illustrative
template, not active middleware. No rules are applied by installing or testing.
The Nginx sync helper changes configuration and reloads Nginx; AWS changes
require an explicit `--apply`. Review their documentation first.

Do not commit credentials, production lists, raw traffic, reports, or backups.
IP and path data may be sensitive. A suspicious path is not proof of abuse,
and two addresses in a subnet are not sufficient justification to ban its
256-address `/24`.

## License and publishing

This project is licensed under the [MIT License](./LICENSE). You may use,
modify, and distribute it, including commercially, provided you retain the
copyright and license notice.
