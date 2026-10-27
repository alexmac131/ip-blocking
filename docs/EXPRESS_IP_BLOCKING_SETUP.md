# Express/Node IP blocking setup

This guide describes the original server implementation and how to move it
into another Express application. Source links below refer to that original
repository, not bundled middleware. Copying these tools alone does not install
Express blocking.

For the command-line tools, see [Scripts reference](./SCRIPTS_REFERENCE.md).
For the configuration format, see [Block list usage](./BLOCKLIST_USAGE.md).

## 1. Understand the layers

```text
Client -> optional AWS subnet NACL -> Nginx -> Express -> application routes
```

- Express rejects matching requests with HTTP `403` and `{"error":"Forbidden"}`.
- Nginx can enforce the same IP list earlier, including on HTTPS requests.
- AWS NACL blocking is optional, separate, and applies to entire subnets.
- The log-analysis scripts report traffic; they do not install or enforce bans.
- No layer replaces authentication, input validation, or protecting secret files.

Start with Express only. Add Nginx synchronization after verifying the client IP
and your application's legitimate routes.

## 2. Prerequisites and source files

For the original server, use its existing Node version, dependency manifest, TypeScript
build, environment configuration, and process manager. The full server also
requires MongoDB and unrelated application services; do not copy all of
[server.ts](https://github.com/alexmac131/server/blob/main/src/server.ts) into a new project just to get blocking.

For another application, begin with a working Express server using a currently
supported Node.js LTS release. A TypeScript application also needs its usual
compiler and Express/Node types. The blocking logic itself uses Express and Node
`fs`/`path`; it does not need MongoDB, GeoIP, or AWS credentials.

Locate these components in the original server repository:

| Component | Source |
|---|---|
| Client IP normalization and trusted local proxy | [clientIp.ts](https://github.com/alexmac131/server/blob/main/src/lib/clientIp.ts) |
| Rule types, IPv4/CIDR matching, config loaders, persistence, blocking middleware | [server.ts](https://github.com/alexmac131/server/blob/main/src/server.ts) |
| IP/CIDR entries | [blocked-ips.json](../config/blocked-ips.json) |
| Probe patterns | [probe-block-rules.json](../config/probe-block-rules.json) |
| Application warning/error logging | [logger.ts](https://github.com/alexmac131/server/blob/main/src/lib/logger.ts) |
| Regression examples | [activityGeo.test.cjs](https://github.com/alexmac131/server/blob/main/tests/activityGeo.test.cjs), [clientIp.test.cjs](https://github.com/alexmac131/server/blob/main/tests/clientIp.test.cjs) |

If extracting this implementation, move the blocking functions into middleware
in the new application and adapt their logger/config paths. The current middleware
also contains activity logging: leave the MongoDB activity section behind if the
new project only needs blocking. Preserve the warning/error logs for rejections
and failed persistence.

## 3. Establish trustworthy client IPs first

Never take the first `X-Forwarded-For` value directly from an arbitrary request.
An attacker can supply that header.

### Direct-to-Node deployment

Leave Express `trust proxy` disabled. Resolve the address from `req.ip`, with the
socket address as a fallback, and normalize IPv4-mapped addresses such as
`::ffff:192.0.2.10`. Bind to the interface appropriate to your deployment and
restrict network exposure with your firewall.

### Nginx on the same host

This repository binds Node to `127.0.0.1` and trusts only the immediate local
proxy hop through `configureProxyTrust`. Use that helper before the blocking
middleware. Keep the Node port inaccessible from the public network.

For a simple deployment with **no upstream CDN/proxy**, the relevant Nginx
location can use:

```nginx
location / {
    proxy_pass http://127.0.0.1:3030;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Match the port to your Node listener. This replaces a visitor-supplied forwarding
header with the source address Nginx actually sees.

If Cloudflare, a CDN, a remote proxy, or containers are involved, do not copy
these trust settings unchanged. Configure Nginx real-IP handling using only
verified trusted proxy ranges, restrict origin access as appropriate, and
recheck the Express trust boundary. Do not use blanket `trust proxy = true`.
See the [Nginx client-IP guide](./NGINX_BLOCKLIST_SYNC.md#2-verify-which-client-ip-nginx-sees).

## 4. Create your own configuration

Keep configuration outside any public/static web root. Begin with an empty
blocklist rather than publishing or inheriting this site's production IP list:

```json
[]
```

An entry can later look like:

```json
[
  {
    "ip": "192.0.2.10",
    "reason": "Documentation example only"
  }
]
```

`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` are documentation
networks, not a recommended real-world deny list.

The current implementation supports IPv4 CIDR matching and IPv4 auto-bans.
Do not assume it supports IPv6 CIDR or IPv6 auto-banning; it does not. The
standalone Nginx analyzer has different IPv6 capabilities.

Create a probe-rules file with narrow patterns applicable to your application:

```json
{
  "rules": [
    {
      "contains": ".env",
      "reason": "Auto-blocked: requested .env path"
    }
  ]
}
```

Do not copy the site's broad `php`, `/api/`, `/js/`, `.md`, or `actuator`
patterns without reviewing your own legitimate URLs. A false match can
permanently ban a real visitor's IPv4 address.

Rule behavior:

- Paths are lowercased and query strings removed. The matcher does not decode
  percent-encoded paths.
- `contains` is a substring match; `endsWith` is a suffix match.
- If both fields are supplied, either can match.
- `exceptPrefixes` bypasses only that rule, using a string-prefix comparison,
  not a path-segment boundary check.
- Rules run in order; an exception in a later rule cannot undo an earlier match.
- The first applicable rule supplies the saved ban reason.

For the current loaders, an invalid/missing IP list logs a warning and becomes
an empty file-based list. Invalid/missing/empty probe rules fall back to compiled
defaults; an empty `rules` array does **not** disable blocking. Monitor startup
warnings and use the explicit environment flag to disable auto-banning.

## 5. Set environment options

Start cautiously while verifying deployment:

```dotenv
AUTO_BLOCK_PROBE_PATHS=false
BLOCKED_USER_AGENTS=
```

| Variable | Behavior |
|---|---|
| `AUTO_BLOCK_PROBE_PATHS` | `true` enables probe rejection and IPv4 auto-bans; defaults to `true` when neither it nor the legacy flag is supplied. |
| `AUTO_BLOCK_PHP_PROBES` | Legacy fallback used only when `AUTO_BLOCK_PROBE_PATHS` is absent. Prefer the newer flag. |
| `BLOCKED_USER_AGENTS` | Comma-separated, case-insensitive substring tokens. Defaults to `ahrefsbot`; an explicitly empty value disables this check. |
| `BLOCKED_IPS` | Additional comma-separated exact addresses or IPv4 CIDRs. Checked before the JSON list for the IP decision. |
| `SKIP_LOG_IPS` | Activity-log exclusion only. It does not allowlist an IP or bypass bans. |

Once probe patterns and client attribution are verified, set
`AUTO_BLOCK_PROBE_PATHS=true` and restart the application.

## 6. Wire middleware before routes

Configure proxy trust first, load the configurations, then mount the blocking
middleware before application routes, static file serving, and catch-all/SPA
fallbacks. In this repository it is also before body parsing and CORS.

Preserve the current decision order:

1. A matching User-Agent token returns `403` without adding an IP ban.
2. A matching probe rule returns `403`, immediately adds a valid IPv4 address
   to memory, and attempts to save it to the JSON list.
3. An existing IP/CIDR ban returns `403`.
4. Otherwise, call `next()` so normal handling continues.

Do not copy the startup call or unrelated routes/services from the existing
server. Use your application's normal listener and shutdown handling.

## 7. Make bans persistent safely

The process user needs read access to both JSON files and write access to the
IP list for auto-banning. Restrict write permissions to trusted administrators
and the service account; never make the configuration world-writable.

Current behavior and limitations:

- Auto-bans apply immediately in that Node process, including to the triggering
  request. The file write is synchronous.
- A failed save logs an error; the in-memory ban still applies but is not
  guaranteed to survive a restart.
- Manual JSON/probe-rule edits require an application restart; there is no file
  watcher. Environment changes also require restart/update through your manager.
- Bans do not expire automatically.
- This file-based implementation assumes a **single writer/process**. Multiple
  PM2 workers, replicas, or manual edits during auto-banning can overwrite each
  other's changes. Use coordinated shared storage before scaling it.
- Put live state on persistent storage. Do not overwrite it with an old deploy
  copy; the original server's deploy transfers `config/`, so back up and
  reconcile server-side bans before deploying.

## 8. Verify before enabling automatic bans

Use an isolated test server/config, not a real visitor's address:

1. With auto-banning off and an empty list, confirm a known route works.
2. Add a test client address to JSON, restart, and verify `403`.
3. Remove it, restart, and verify access returns.
4. Try an IPv4 `/24` rule in a fixture and check both inside/outside addresses.
5. Enable probe blocking in the fixture. Request a configured probe and confirm
   `403`, a saved IP/reason, and rejection of the same IP's next ordinary request.
6. Confirm legitimate routes, query strings, and configured exceptions still work.
7. Check spoofed forwarding headers cannot select another client's identity.
8. Test the chosen User-Agent tokens without claiming they prove bot identity:
   anyone can spoof a User-Agent.
9. Restart and confirm saved bans survive. Inspect errors for permission failures.

In the original server repository (not this tools project), the regression command is:

```bash
npm run build
node --test tests/clientIp.test.cjs tests/activityGeo.test.cjs
```

No automatic request should expose `.env`, keys, or credentials even when probe
blocking is disabled. A `200` may be an SPA fallback, not proof of file exposure.

## 9. Optional Nginx enforcement

Follow [Nginx synchronization](./NGINX_BLOCKLIST_SYNC.md). Add the include inside
the active HTTPS server block (and HTTP server block if appropriate), then run
the sync script with explicit paths. It writes the include, tests, and reloads
Nginx; it does not edit your site configuration.

Express auto-bans do not automatically update Nginx. Conversely, editing the
Nginx deny file does not reload Express's memory. Keep JSON as the intended
source of truth and synchronize deliberately.

## 10. Recover from an accidental ban

1. Use SSH/console access independent of the blocked web request.
2. Back up the current list; remove the exact IP or covering CIDR from JSON.
3. Remove it from `BLOCKED_IPS` too if present, then restart Node.
4. If Nginx enforces it, regenerate the include, test, and reload Nginx.
5. Review the probe rule that caused the ban before restoring auto-banning.
6. If AWS has a separate deny, remove the reviewed AWS entry separately.

Avoid adding an unreviewed IP allowlist shortcut. Shared NAT, VPN, and proxy
addresses can represent many visitors; a few abusive IPs do not establish that
an entire `/24` (256 addresses) is malicious.

## Preparing the standalone repository

Use the [extraction checklist](./SCRIPTS_REFERENCE.md#standalone-repository-checklist).
These documents describe the current implementation; they do not claim a
reusable middleware module, IPv6 parity, distributed persistence, or a published
package already exists.
