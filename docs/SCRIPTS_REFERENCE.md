# IP blocking and traffic scripts

This is the operator reference for all six files in [scripts/](../scripts).
Each also has a purpose/usage/requirements header. Commands below assume the
repository root and a Linux Nginx server unless noted. Replace paths, domains,
ports, and AWS IDs for your installation.

For installing Express-side enforcement, start with
[Express IP blocking setup](./EXPRESS_IP_BLOCKING_SETUP.md).

## Quick selection

| Need | Script | Changes made |
|---|---|---|
| Identify suspect traffic | [analyze-nginx-scans.js](../scripts/analyze-nginx-scans.js) | None; terminal report |
| Inspect weather-related requests | [analyze-nginx-weather.js](../scripts/analyze-nginx-weather.js) | None; terminal report |
| Collect attempted exploit scans against the server | [collect-nginx-attempts.js](../scripts/collect-nginx-attempts.js) | Local history JSON/checkpoints |
| Enforce the JSON IP list in Nginx | [sync-blocked-ips-to-nginx.sh](../scripts/sync-blocked-ips-to-nginx.sh) | Overwrites deny include and reloads Nginx |
| Diagnose Nginx/Node connectivity | [diagnose-nginx-node.sh](../scripts/diagnose-nginx-node.sh) | Diagnostic GETs; no config changes |
| Add selected AWS subnet denies | [apply-aws-nacl-denies.sh](../scripts/apply-aws-nacl-denies.sh) | AWS changes only with `--apply` |

## Shared requirements

- The JavaScript tools use Node built-ins, no additional npm packages. This
  standalone project's manifest requires Node 24 or newer; use a supported LTS.
- Log tools expect standard uncompressed Nginx access logs with client IP,
  bracketed timestamp, quoted request, and numeric response status. JSON or
  custom log formats may need parser changes. Malformed lines are skipped.
- Log paths are fixed near the top of the scripts; there are no CLI switches
  for the three JavaScript tools.
- Use a user with read access to the logs, or `sudo` where required. Logs are
  loaded into memory, so provision enough RAM for the files being scanned.
- For meaningful IP attribution, configure trusted real-client-IP handling
  behind proxies/CDNs. A matching path or `200` does not prove a human visitor,
  and suspicious results are candidates for review rather than automatic bans.
- Reports can contain IP addresses and sensitive-looking paths. Restrict access
  and review/redact exports before sharing them with other people.

## 1. Suspect-traffic report

```bash
sudo node scripts/analyze-nginx-scans.js
```

**Inputs:** defaults in `REPORT_OPTIONS`:

| Input | Default |
|---|---|
| Access log | `/var/log/nginx/access.log` |
| Compiled Express build | `application-dist/`, deliberately absent until you supply your application's build or change the path |
| Angular build | `/var/www/html` |
| Nginx deny include | `/etc/nginx/blocked-ips.conf` |
| Repeated unknown-error threshold | 10 requests per IP |

Deploy/build your Express routes first. Route discovery reads simple compiled
`router.get(...)`/similar declarations and selected `app` declarations, not the
live Express router. Adapt `ROUTE_PREFIXES` for mounted routers in a different
application; dynamic route composition may not be discovered. Angular route
discovery is also heuristic. Missing frontend files can create false positives.

**Output:** one row per candidate IP/path, showing `NGINX BLOCKED`,
`ATTEMPTED PAGE`, count, and status-code counts. Known routes/assets are excluded.
Remaining requests qualify through a probe signature or repeated unknown errors.
The current error counter includes statuses of 400 and above, including 5xx,
despite its internal `unknown4xx` name.

**Effects:** no files, bans, or database records are modified. It reads no
application probe-rules JSON: signatures in this analyzer are separate from
Express's configurable auto-ban rules.

## 2. Weather-traffic report

```bash
sudo node scripts/analyze-nginx-weather.js
```

**Requires:** the shared parser in `analyze-nginx-scans.js` in the same directory,
and readable logs listed in `REPORT_LOGS` (default current access log).
It does not require the deny include, compiled routes, Angular, MongoDB, or AWS.

**Output:** IP, HTTP method, requested path, count, and all status-code counts
for decoded paths containing `getWeather` case-insensitively. Query strings
are excluded; different query values group under the same path. Paths with
different casing remain separate output rows.

**Effects:** none. Edit `PATH_TAG` or log paths to adapt the report.

## 3. Persistent attempted exploit scan collector

```bash
sudo node scripts/collect-nginx-attempts.js
```

**Requires:** the suspect analyzer alongside it and the same build/log/deny
inputs. It also reads `/var/log/nginx/access.log.1` if present. The execution
user needs write permission for the repository's `reports/` directory.

**Output/state:** `reports/nginx-attempts.json`, plus a terminal table sorted by
count. `pages` contains the cumulative normalized path, count, status counts,
and first/last collection timestamps. `sources` holds IP/path checkpoints and
file identities/hashes; keep this section when backing up.

**Counting rules:**

- Accumulates suspected exploit-scan requests from the analyzer, not all website traffic.
- Unchanged logs add zero; appended requests add only uncounted attempts.
- Earlier retained requests may enter the totals when their IP first qualifies.
- Device/inode tracking recognizes rename-based rotation on the same filesystem.
  Copied logs are new sources and may be recounted.
- Query strings are excluded. Timestamps are collection times, not request times.
- Incomplete final lines wait for a later run.

Run regularly before logs are compressed or deleted. Compressed inputs are not
supported; missing historical logs cannot be recovered automatically.
`copytruncate` or rewriting a tracked file raises an error, rather than silently
guessing counts. Use rename-based rotation.

The collector uses an exclusive `.lock`, a temporary file, and atomic rename.
History is written owner-only; use a consistent execution user, particularly
after a `sudo` run. If it is forcibly killed, confirm no collector is running
before removing stale `.lock`/`.tmp` files. Do not delete the JSON as a routine
fix: it loses counts and causes retained logs to be counted again.

The history is gitignored and excluded by the current deployment allowlist.
Back it up separately. It changes neither MongoDB nor any blocklist.

## 4. Synchronize IP bans to Nginx

```bash
bash scripts/sync-blocked-ips-to-nginx.sh \
  /path/to/project/config/blocked-ips.json \
  /etc/nginx/blocked-ips.conf
```

**Requires:** Bash, `jq`, Nginx, systemd, and sudo permission for the write,
configuration test, and reload. Pass the JSON path explicitly: the script's
no-argument source defaults to this project's `config/blocked-ips.json`.

**Steps performed:** render JSON `ip` values as deny directives, overwrite the
output include, run `sudo nginx -t`, then `sudo systemctl reload nginx`.

**Before running:** back up the include and review JSON values. The active Nginx
configuration must already include this file in the correct server/http scope.
The script does not add the include or configure TLS.

**Caution:** no dry-run or rollback. The file is overwritten before validation;
on failure, reload is skipped but the on-disk file stays changed. Restore a
known-good include, test, and reload manually. Node's in-memory list and AWS
rules are unaffected. See [Nginx setup](./NGINX_BLOCKLIST_SYNC.md).

## 5. Diagnose Nginx and Node

```bash
bash scripts/diagnose-nginx-node.sh your-domain.example 3030
```

Arguments are optional hostname and Node port; defaults are the original site's
hostname and port 3030. Override the hostname for another installation.

**Requires:** Linux, Bash, systemd, Nginx, curl, iproute2 (`ss`), awk, sed,
standard GNU utilities, and sudo access. Run as the normal PM2 application user
so PM2 inspection refers to that user's processes. PM2, ufw, and `lsb_release`
are optional.

**Checks:** system information, Nginx config/service, local Node listener, PM2,
selected proxy directives, direct Node HTTP, local Nginx HTTPS with normal
certificate verification, Nginx error logs, and ufw status.

Node must listen on `127.0.0.1:<port>` and HTTPS on `127.0.0.1:443`, with a
trusted certificate for the selected hostname. The script sends actual GET `/`
requests, which may create ordinary access/activity logs. It changes no
configuration and does not inspect AWS security groups or NACLs.

Exit 1 indicates a failed config test or HTTP/TLS check, not a comprehensive
pass/fail verdict on every diagnostic. Review output before sharing it.

## 6. Optional AWS Network ACL denies

Preview first:

```bash
bash scripts/apply-aws-nacl-denies.sh acl-0123456789abcdef0
```

Only after reviewing the preview and
[AWS setup guide](./AWS_NACL_IP_BLOCKING_GUIDE.md):

```bash
bash scripts/apply-aws-nacl-denies.sh acl-0123456789abcdef0 --apply
```

**Requires:** Bash, jq, AWS CLI v2, AWS API access, configured account/Region and
credentials. IAM needs `ec2:DescribeNetworkAcls` and, for apply,
`ec2:CreateNetworkAclEntry`. Run from a trusted administrator machine; it need
not be the EC2 server.

**Input:** `config/aws-nacl-blocked-ip-rules.json`, relative to the script's parent.
It is a reviewed snapshot, not automatically regenerated from Express/Nginx.

**Safety:** rules affect every resource in every associated subnet, not just
one instance. Verify the approved inbound quota, rule ordering, existing rules,
and source IPs. The script checks the hard-coded maximum of 40 but does not
verify that your account has that quota approved. Preserve outbound rules:
NACLs are stateless.

Applying adds entries individually; a failure can leave a partial update.
There is no automatic rollback. Inspect the ACL before retrying. No load
balancer is needed, and the script does not synchronize Node/Nginx bans.

## Deployment and operation

No production deployment script is included. Copy the tools and reviewed
configuration to your intended server without overwriting live bans or history.
The JavaScript tools need no server
restart to run. Nginx sync reloads Nginx; manual Express config edits require
an application restart.

See the [README](../README.md) to configure paths before running.

## Standalone repository checklist

Before publishing or moving these tools:

1. Choose a license and confirm what you have permission to publish.
2. Keep the three JavaScript scripts together, their tests, and this reference.
   Preserve the expected `scripts/`, `config/`, and optional `application-dist/` layout or
   update all paths consistently.
3. Replace developer paths, original domains, SSH host aliases, EC2 addresses,
   deployment directories, and site-specific route prefixes with documented
   examples or deliberate configuration. The existing deploy script is
   site-specific, not a general installer.
4. Ship empty/example IP lists and reviewed probe rules, not this site's live
   ban decisions. Use TEST-NET addresses only as examples, never as inferred
   attackers. Review the AWS rule snapshot separately.
5. Do not publish `.env`, credentials, private keys, raw access logs, MongoDB
   exports, reports, lock files, or backups. Review Git history too, not only
   the latest working tree. Keep history/report state out of deploy payloads.
6. Extract Express blocking into its own middleware before describing it as a
   reusable package. Separate it from MongoDB activity logging and application
   startup; document proxy assumptions, IPv4 limits, and single-writer storage.
7. Provide a minimal manifest/runtime requirement and a test command for the
   new repository. The log tools use no third-party runtime packages; the
   extracted middleware will need Express and its own logging integration.
8. Include installation steps for jq, AWS CLI, or Nginx only for tools that need
   them. Do not require AWS credentials for local reports or Express blocking.
9. Test fresh installation, forwarding-header attribution, legitimate paths,
   persistence failures, duplicate scans, rotation, and recovery procedures.

In this repository the report regression tests can run without a TypeScript
build:

```bash
node --test tests/nginxScanAnalyzer.test.cjs \
  tests/nginxWeatherAnalyzer.test.cjs tests/nginxAttemptHistory.test.cjs
```

This project is a local extraction. Review and choose a license before publishing;
no GitHub remote or publication is configured automatically.
