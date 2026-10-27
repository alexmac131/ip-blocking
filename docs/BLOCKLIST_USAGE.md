# Block List Usage

This project includes an empty JSON block list in [config/blocked-ips.json](../config/blocked-ips.json).
It can generate Nginx deny rules. The Express behavior described below belongs
to the original server middleware, which is not packaged here; follow the
integration guide to adapt that implementation to your application.

For installation and adapting this to another Express application, follow
[Express IP blocking setup](./EXPRESS_IP_BLOCKING_SETUP.md). For commands,
requirements, and operational cautions for every helper, see the
[scripts reference](./SCRIPTS_REFERENCE.md).

## File format

Each item in the array must contain an `ip` field. The value may be either:

- a single IPv4 address, such as `203.0.113.10`
- a CIDR block, such as `203.0.113.0/24`

The optional `reason` field can be blank or a short description.
The optional `addedAt` field is an ISO timestamp. For live auto-blocking, the server sets this automatically when it adds a new IP.

Example:

```json
[
  { "ip": "203.0.113.10", "reason": "Known scraping bot", "addedAt": "2026-10-06T04:00:00.000Z" },
  { "ip": "198.51.100.0/24", "reason": "Abuse range" },
  { "ip": "192.0.2.77", "reason": "" }
]
```

## Why use CIDR ranges?

A CIDR range is useful when you want to block a whole class-C subnet, such as:

```json
{ "ip": "198.51.100.0/24", "reason": "Documentation example range" }
```

This example covers `198.51.100.0` through `198.51.100.255`.

## Server behavior

When the app receives a request, it reads the client IP from the request headers and proxy trust settings, then checks the block list. If the IP matches an entry, the server immediately responds with HTTP `403 Forbidden`.

The app also blocks requests by user-agent token. By default, `AhrefsBot` traffic is blocked. This is controlled by `BLOCKED_USER_AGENTS` (comma-separated tokens) in your environment.

Example:

```env
BLOCKED_USER_AGENTS=ahrefsbot,semrushbot
```

Matching is case-insensitive and token-based (`includes`), so `AhrefsBot/7.0` will match `ahrefsbot`.

 `php` (with or without a dot), `.env`, `/.github/`, `/.amper/`, `config.js`, `/wordpress/`, `/wp-json/`, `/wp-` paths, `.md` paths, and suspicious `/api/` paths. Generic words such as `site`, `blog`, `chunk`, `feed`, `dev`, `staging`, and `cms` are not used as block triggers, so legitimate routes or asset names containing them remain allowed. This is enabled by default and controlled by `AUTO_BLOCK_PROBE_PATHS`.

Example:

```env
AUTO_BLOCK_PROBE_PATHS=true
```

When enabled, requests like `/wp-login.php`, `/.env`, `/wp-json/`, or unknown `/api/` paths are rejected with `403` and the source IP is added to [blocked-ips.json](../config/blocked-ips.json) with an auto-block reason.

Probe path rules are now config-driven in [probe-block-rules.json](../config/probe-block-rules.json), so you can add/remove patterns without changing code.

Rule format:

```json
{
  "rules": [
    {
      "contains": "/api/",
      "reason": "Auto-blocked: requested /api/ path",
      "exceptPrefixes": ["/api/auth", "/api/sales"]
    },
    {
      "endsWith": ".md",
      "reason": "Auto-blocked: requested .md path"
    }
  ]
}
```

- `contains`: case-insensitive substring match against the request path (for example, `php` matches both `/index.php` and `/phpmyadmin`)
- `endsWith`: case-insensitive path suffix match (for example `.md`)
- `reason`: saved into the auto-blocked IP record
- `exceptPrefixes` (optional): prefixes that bypass that rule

## Nginx global blocking

For a broader, earlier enforcement layer, you can also generate nginx deny rules from the same JSON file using the sync script:

```bash
bash scripts/sync-blocked-ips-to-nginx.sh \
  /path/to/project/config/blocked-ips.json /etc/nginx/blocked-ips.conf
```

This script reads the block list and writes the deny directives to
`/etc/nginx/blocked-ips.conf`, then tests and reloads Nginx. It does **not**
edit `example.com.conf` or add the include to a site config. Add
`include /etc/nginx/blocked-ips.conf;` once inside the active site's `server`
block, outside any `location` block. See [NGINX_BLOCKLIST_SYNC.md](./NGINX_BLOCKLIST_SYNC.md)
for the full example.

## Keeping it maintained

Keep the file in a single source of truth and prefer a short reason for each entry. If you add a large block list, you may want to group ranges by abuse pattern and document the reason clearly.

## Example workflow

1. Open [config/blocked-ips.json](../config/blocked-ips.json)
2. Add a new IP or CIDR range
3. Save the file
4. Run the nginx sync script if you want the same list enforced at the edge
5. Restart or reload the server and nginx as needed

## Notes

- The app is intentionally separate from `SKIP_LOG_IPS`; that list is for excluding endpoints or internal IPs from logging, not for blocking access.
- The original implementation uses Express's resolved `req.ip`, trusting only the immediate local Nginx peer, and binds Node to `127.0.0.1`. See [proxy setup](./EXPRESS_IP_BLOCKING_SETUP.md#3-establish-trustworthy-client-ips-first); a CDN or remote proxy requires a trust configuration review.
