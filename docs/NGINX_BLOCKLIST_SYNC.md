# Set up IP blocking on an Nginx server

This guide uses Nginx `deny` directives to reject requests before they reach
Express/Node or static website content. It works without Express too.
No AWS account, load balancer, MongoDB, or Node.js runtime is needed for Nginx
IP blocking itself.

Examples assume Ubuntu/Debian with systemd. Replace `example.com`,
`/path/to/project`, and port `3030` with your own values. Do not replace a
working site configuration wholesale with these examples.

Related guides:

- [Express IP blocking setup](./EXPRESS_IP_BLOCKING_SETUP.md)
- [All scripts and their requirements](./SCRIPTS_REFERENCE.md)
- [Blocklist format](./BLOCKLIST_USAGE.md)

## 1. Prerequisites

You need:

- Administrative SSH/console access to the Nginx host.
- Nginx with its HTTP access module (normally present in distribution packages).
- Permission to edit the active site configuration and reload Nginx.
- Bash and `jq` if generating the deny include from JSON.
- A working site; HTTPS requires an already configured certificate and key.

On a new Ubuntu/Debian host, install missing packages using your normal package
management procedure:

```bash
sudo apt-get update
sudo apt-get install nginx jq
```

Inspect the existing service and configuration:

```bash
sudo systemctl status nginx --no-pager
sudo nginx -t
sudo nginx -T
```

`nginx -T` shows the loaded configuration and its source filenames. On
Ubuntu/Debian, active sites are often linked from `/etc/nginx/sites-enabled/`;
other distributions commonly use `/etc/nginx/conf.d/`.
Do not assume editing an unused file affects the running site.
Review configuration output before sharing it.

Keep your SSH session open, preserve an independent administrative route, and
back up the active site file before editing. For example, if its actual source
is `/etc/nginx/sites-available/example.com.conf`:

```bash
sudo cp -p /etc/nginx/sites-available/example.com.conf \
  /etc/nginx/sites-available/example.com.conf.before-ip-blocking
```

Keep backups outside directories/wildcards automatically included by Nginx.

## 2. Verify which client IP Nginx sees

Check the site's access-log location in its active configuration. A typical
location is:

```bash
sudo tail -n 20 /var/log/nginx/access.log
```

For direct visitor connections, `$remote_addr` should identify the connecting
client. Shared NAT/VPN addresses can represent multiple people.

If a CDN or reverse proxy sits in front, Nginx normally sees the proxy address.
Before banning visitor IPs:

1. Follow the proxy provider's real-IP instructions.
2. Trust only verified proxy source ranges with `set_real_ip_from`.
3. Use the provider's documented header and configure `real_ip_header` and
   `real_ip_recursive` as appropriate to the actual topology.
4. Restrict direct origin access where appropriate and test header spoofing.
5. Verify the resolved client address in logs before enabling bans.

**Never trust forwarded headers from every address**, for example by using
`set_real_ip_from 0.0.0.0/0`. Visitors could choose another IP or evade a ban.
Do not copy provider ranges from an unrelated example; maintain current ranges.

## 3. Create the deny include

Use `/etc/nginx/blocked-ips.conf` as a plain list of directives. It contains no
`http`, `server`, or `location` wrapper.

### Option A: manage the file manually

Create a new file, or back up an existing one before editing:

```bash
sudo touch /etc/nginx/blocked-ips.conf
sudo cp -p /etc/nginx/blocked-ips.conf \
  /etc/nginx/blocked-ips.conf.before-update
sudoedit /etc/nginx/blocked-ips.conf
```

Example contents:

```nginx
# Documentation examples only; replace with reviewed addresses.
deny 192.0.2.10;
deny 198.51.100.0/24;
```

`deny 198.51.100.0/24;` covers all 256 addresses in that range.
Nginx also supports IPv6 addresses and IPv6 CIDRs, although this project's
Express matcher does not support IPv6 CIDR/auto-ban parity.

The TEST-NET addresses above are examples, not evidence of attackers. Start
with an empty include if you have no reviewed bans. Never add `deny all;`
unless you intentionally want to reject everyone in that configuration scope.

### Option B: generate from the JSON list

Use this project's [blocked-ips.json](../config/blocked-ips.json) format as the
source of truth. For a new installation, create your own list, not a copy of
this site's live ban decisions:

```json
[
  { "ip": "192.0.2.10", "reason": "Documentation example only" },
  { "ip": "198.51.100.0/24", "reason": "Documentation example range" }
]
```

An empty list is `[]`. Keep JSON outside the public web root. Validate its
structure and inspect every IP/CIDR; this check does not validate address syntax:

```bash
jq -e 'type == "array" and all(.[];
  type == "object" and (.ip | type == "string" and length > 0))' \
  /path/to/project/config/blocked-ips.json
```

Generate the initial include:

```bash
set -o pipefail
jq -r '.[] | select(.ip and (.ip|length>0)) | "deny \(.ip);"' \
  /path/to/project/config/blocked-ips.json \
  | sudo tee /etc/nginx/blocked-ips.conf > /dev/null
```

Only trusted administrators or the intended application service account should
be able to modify the source. It is rendered into Nginx configuration, so
unreviewed strings must not be accepted as arbitrary `ip` values.
The output is overwritten; preserve a backup first when updating an existing list.

## 4. Include it in the active site

In the HTTPS `server` block, outside any `location`, add:

```nginx
include /etc/nginx/blocked-ips.conf;
```

An illustrative reverse-proxy configuration is:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    # Keep your existing, valid certificate paths and TLS settings.
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    include /etc/nginx/blocked-ips.conf;

    location / {
        proxy_pass http://127.0.0.1:3030;
        proxy_set_header Host $host;
        # Direct-client topology only; review real-IP handling behind a CDN.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Preserve your actual static-file/SPA locations instead if Nginx serves files.
Preserve existing certificate renewal, ACME challenge, API, and authentication
configuration. If the site has IPv6 listeners or additional virtual hosts,
review those blocks as well.

### HTTPS behavior

TLS negotiation happens **before** the HTTP deny decision. A denied client
normally completes TLS and then receives `403 Forbidden`, not the upstream
page. These rules do not block the TCP connection or eliminate TLS costs.
For pre-instance network blocking, see the separate
[AWS NACL guide](./AWS_NACL_IP_BLOCKING_GUIDE.md).

### HTTP redirects and access-rule inheritance

A common HTTP site is:

```nginx
server {
    listen 80;
    server_name example.com;
    return 301 https://example.com$request_uri;
}
```

The redirect is expected here. Adding the deny include does **not** guarantee a
`403` before a server-level `return`: rewrite-phase returns run before access
checks. The HTTPS destination must enforce its own deny list.

If you also serve ordinary HTTP content, add the include to that serving
server block and verify it there. Do not move redirects or ACME handlers merely
to force HTTP `403` responses without understanding their phase behavior.

Nginx inherits `allow`/`deny` rules only when the child context defines none.
A `location` with its own `allow` or `deny` does not automatically combine that
list with the server-level rules. Also review `satisfy any`, authentication
combinations, error handling, and early `return` directives that can change the
result. Access rules use the first matching rule, so an earlier `allow all;`
can defeat a later deny. Do not assume the include's visual placement alone
overrides those behaviors.

For all virtual hosts, the include may instead be placed inside the main
`http` block. Inheritance caveats still apply. Prefer one deliberate scope,
not redundant includes in multiple inherited contexts.

## 5. Test, then reload

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Do not reload on a failed configuration test. Fix the reported problem or
restore the backed-up file first. A successful reload activates changes for
new request handling without a full stop/start.

## 6. Verify allowed and denied clients

First, from an allowed machine:

```bash
curl -I https://example.com/
```

Confirm the normal response, including any expected application redirects.
Then use a separate controlled test client whose actual public address you
temporarily add as an exact deny:

1. Back up the include and add the test address.
2. Test and reload Nginx.
3. Request an ordinary served/proxied URL from that test client; expect `403`.
4. Verify an allowed client can still access that URL.
5. Check API/static locations and alternate hostnames you intend to protect.
6. Remove the test entry, test, and reload again.

Do not test by blocking your only administrative connection or by adding
`127.0.0.1`, a proxy address, or a broad cloud subnet. Sending an arbitrary
`X-Forwarded-For` header is not a valid simulation of a real visitor.
If Express separately banned the test client, remove that ban too to verify
unblocking end to end.

Inspect the configured access/error logs and, for a proxied endpoint, verify
that a denied request did not reach the application. Keep the final configuration
test successful before closing the session.

## 7. Maintain the list with the existing helper

Once the include is wired into the site:

```bash
sudo cp -p /etc/nginx/blocked-ips.conf \
  /etc/nginx/blocked-ips.conf.before-update
bash /path/to/project/scripts/sync-blocked-ips-to-nginx.sh \
  /path/to/project/config/blocked-ips.json \
  /etc/nginx/blocked-ips.conf
```

The [helper](../scripts/sync-blocked-ips-to-nginx.sh) needs Bash, jq, sudo,
Nginx, and systemd. Pass the JSON path explicitly; its no-argument source
default is this project's `config/blocked-ips.json`.

It overwrites the include, runs `nginx -t`, and reloads Nginx. It does **not**:

- Edit your site configuration or install TLS certificates.
- Provide a dry-run, automatic backup, or rollback.
- Restart Node or reload Express's in-memory IP list.
- Change AWS rules or automatically run whenever Express adds a ban.

On a failed test, reload is skipped but the on-disk include remains overwritten.
Restore the backup before any later reload. Manual include edits are lost on
the next JSON sync, so maintain entries in JSON when using this workflow.

For automation, first establish backups, validated inputs, consistent ownership,
and prevention of overlapping writes. Avoid blindly scheduling privileged
configuration writes from a file untrusted users can modify.

## 8. Rollback and troubleshooting

Restore the previous list:

```bash
sudo cp -p /etc/nginx/blocked-ips.conf.before-update \
  /etc/nginx/blocked-ips.conf
sudo nginx -t && sudo systemctl reload nginx
```

If the site configuration itself is incorrect, restore its backup too.
Reconcile the JSON source so the next sync does not reintroduce the problem.

| Symptom | Check |
|---|---|
| Include file not found | Create it first; verify the exact absolute include path. |
| Changes have no effect | Confirm the loaded site with `nginx -T`, successful reload, hostname/listener, and actual client IP. |
| Blocked IP gets `301`/`302` | Check early `return`/rewrite rules; inspect the HTTPS destination separately. |
| Blocked IP reaches one location | Review child access rules, `satisfy`, and early returns. |
| Many unrelated visitors blocked | Check proxy real-IP handling, shared NAT, and overly broad CIDRs. |
| Nginx allows, but app returns `403` | Check Express's separate in-memory/config/environment/User-Agent bans. |
| HTTP `200` for a nonexistent sensitive path | Check SPA fallback and response content; `200` alone does not establish exposure. Never serve secrets. |
| JSON changes do not affect Nginx | Run the sync helper, inspect its result, and verify reload. |

Keep Express blocking as optional defense in depth, and use the read-only
[traffic tools](./SCRIPTS_REFERENCE.md) to review attempted paths and responses.
