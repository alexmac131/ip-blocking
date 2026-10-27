#!/usr/bin/env node
/*
 * Purpose: Report suspected probes and repeated unknown error requests, grouped
 * by IP and attempted page, with counts, HTTP statuses, and Nginx deny matches.
 * Usage (from the deployed repository root):
 *   sudo node scripts/analyze-nginx-scans.js
 * No command-line switches; edit REPORT_OPTIONS/defaults below for other paths
 * or thresholds. Output goes to the terminal; no files, MongoDB data, or bans
 * are changed. A candidate is not proof of malicious activity.
 *
 * Requirements: Node.js 18+; no npm packages needed by this script. Run on the
 * Nginx host, or supply local copies of its inputs. Expects standard Nginx
 * access-log lines with client IP, quoted request, and numeric HTTP status.
 * Defaults: /var/log/nginx/access.log, /etc/nginx/blocked-ips.conf, and compiled
 * Express routes in ../application-dist/routes (supply your application's build).
 * /var/www/html is used for Angular routes/assets when present; without it,
 * frontend requests may be classified as unknown. Read permissions are needed
 * for all inputs; sudo is only for restricted files. Logs are read into memory,
 * so allow RAM for their contents. Configure real-client-IP logging behind a
 * proxy/CDN; otherwise reports attribute requests to the proxy.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const DEFAULT_LOG = '/var/log/nginx/access.log';
const DEFAULT_DIST = path.resolve(__dirname, '../application-dist');
const DEFAULT_ANGULAR_ROOT = '/var/www/html';
const DEFAULT_BLOCKED_LIST = '/etc/nginx/blocked-ips.conf';
const DEFAULT_MIN_UNKNOWN = 10;
const REPORT_OPTIONS = {
  logs: [DEFAULT_LOG],
  dist: DEFAULT_DIST,
  angularRoot: DEFAULT_ANGULAR_ROOT,
  blockedList: DEFAULT_BLOCKED_LIST,
  minUnknown: DEFAULT_MIN_UNKNOWN,
};
// Map your compiled router module names to their mounted URL prefixes.
const ROUTE_PREFIXES = {};
const SCAN_SIGNATURES = [
  ['WordPress', /(?:^|\/)(?:wp-admin|wp-login\.php|wp-content|wp-includes|wp-json|xmlrpc\.php)(?:\/|$)/i],
  ['PHP probe', /(?:^|\/)[^/]*\.php(?:\/|$)/i],
  ['secret/config probe', /(?:^|\/)(?:\.env(?:\.[^/]*)?|\.git|\.aws|\.ssh|config\.php)(?:\/|$)/i],
  ['admin/database probe', /(?:^|\/)(?:phpmyadmin|pma|adminer|cgi-bin)(?:\/|$)/i],
  ['framework/debug probe', /(?:^|\/)(?:vendor\/phpunit|actuator|\.well-known\/security\.txt)(?:\/|$)/i],
];
const STATIC_EXTENSIONS = new Set([
  '.css', '.gif', '.ico', '.jpeg', '.jpg', '.js', '.json', '.map', '.mjs',
  '.png', '.svg', '.txt', '.webmanifest', '.webp', '.woff', '.woff2',
]);

function parseAccessLine(line) {
  const match = line.match(/^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?:(\S+)\s+(\S+)\s+\S+|[^"]*)"\s+(\d{3})(?:\s|$)/);
  if (!match || !match[2] || !match[3] || net.isIP(match[1]) === 0) {
    return null;
  }

  let requestPath;
  try {
    requestPath = new URL(match[3], 'http://nginx-log.invalid').pathname;
    requestPath = decodeURIComponent(requestPath);
  } catch {
    requestPath = match[3].split(/[?#]/, 1)[0];
  }

  return {
    ip: match[1],
    method: match[2].toUpperCase(),
    path: normalizePath(requestPath),
    status: Number(match[4]),
  };
}

function normalizePath(value) {
  let normalized = value.replace(/\/{2,}/g, '/');
  if (!normalized.startsWith('/')) {
    normalized = `/${normalized}`;
  }
  if (normalized.length > 1) {
    normalized = normalized.replace(/\/+$/, '');
  }
  return normalized || '/';
}

function routeRegex(routePath) {
  const segments = normalizePath(routePath).split('/').slice(1);
  const pattern = segments.map((segment) => {
    if (segment.startsWith(':')) {
      return '[^/]+';
    }
    if (segment === '*') {
      return '.*';
    }
    return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('/');
  return new RegExp(`^/${pattern}/?$`, 'i');
}

function collectServerRoutes(distRoot) {
  if (!fs.existsSync(distRoot)) {
    throw new Error(`Compiled server directory not found: ${distRoot}`);
  }
  const routesRoot = path.join(distRoot, 'routes');
  if (!fs.existsSync(routesRoot)) {
    throw new Error(`Compiled route directory not found: ${routesRoot}`);
  }

  const routes = [];
  const files = fs.readdirSync(routesRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.js'));
  for (const file of files) {
    const source = fs.readFileSync(path.join(routesRoot, file.name), 'utf8');
    const moduleName = file.name.slice(0, -3);
    const prefix = ROUTE_PREFIXES[moduleName] ?? '';
    const expression = /\brouter\.(get|post|put|patch|delete|all)\s*\(\s*(['"])([^'"]+)\2/g;
    for (const match of source.matchAll(expression)) {
      const routePath = `${prefix}${match[3]}`;
      routes.push({
        method: match[1].toUpperCase(),
        path: normalizePath(routePath),
        regex: routeRegex(routePath),
      });
    }
  }

  const serverFile = path.join(distRoot, 'server.js');
  if (fs.existsSync(serverFile)) {
    const source = fs.readFileSync(serverFile, 'utf8');
    for (const match of source.matchAll(/\bapp\.(get|post|put|patch|delete|all)\s*\(\s*(['"])([^'"]+)\2/g)) {
      const routePath = normalizePath(match[3]);
      routes.push({
        method: match[1].toUpperCase(),
        path: routePath,
        regex: routeRegex(routePath),
      });
    }
  }

  if (routes.length === 0) {
    throw new Error(`No compiled Express routes found under ${routesRoot}.`);
  }
  return routes;
}

function collectAngularRoutes(angularRoot) {
  const routes = new Set();
  if (!fs.existsSync(angularRoot)) {
    return routes;
  }

  const pending = [angularRoot];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const entryPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        pending.push(entryPath);
        continue;
      }
      if (!entry.isFile() || !/\.(?:html|js|mjs)$/.test(entry.name)) {
        continue;
      }
      const source = fs.readFileSync(entryPath, 'utf8');
      const routePatterns = [
        /\bpath\s*:\s*(['"])(\/?[^'"]*)\1/g,
        /\b(?:href|routerLink)\s*=\s*(['"])(\/[^'"]*)\1/g,
      ];
      for (const routePattern of routePatterns) {
        for (const match of source.matchAll(routePattern)) {
          const routePath = normalizePath(match[2]);
          if (!routePath.includes('${') && !routePath.includes('*')) {
            routes.add(routeRegex(routePath));
          }
        }
      }
    }
  }
  return routes;
}

function isAngularFile(requestPath, angularRoot) {
  const resolvedRoot = path.resolve(angularRoot);
  const resolvedPath = path.resolve(resolvedRoot, `.${requestPath}`);
  if (resolvedPath !== resolvedRoot && !resolvedPath.startsWith(`${resolvedRoot}${path.sep}`)) {
    return false;
  }
  try {
    return fs.statSync(resolvedPath).isFile();
  } catch {
    return false;
  }
}

function matchServerRoute(request, routes) {
  return routes.some((route) =>
    (route.method === request.method || route.method === 'ALL' || (request.method === 'HEAD' && route.method === 'GET'))
    && route.regex.test(request.path));
}

function getSignature(requestPath) {
  return SCAN_SIGNATURES.find(([, pattern]) => pattern.test(requestPath))?.[0] ?? null;
}

function parseIpAddress(value) {
  const ip = value.split('/')[0];
  const family = net.isIP(ip);
  if (family === 0) {
    throw new Error(`Invalid IP address in Nginx deny list: ${value}`);
  }

  if (family === 4) {
    const number = ip.split('.').reduce((result, octet) => (result << 8n) | BigInt(octet), 0n);
    return { family: 4, bits: 32, number };
  }

  let normalized = ip.toLowerCase();
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    const ipv4 = normalized.slice(lastColon + 1);
    const octets = ipv4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${high}:${low}`;
  }

  const [leftText, rightText] = normalized.split('::');
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const missing = 8 - left.length - right.length;
  const groups = normalized.includes('::')
    ? [...left, ...Array(missing).fill('0'), ...right]
    : left;
  const number = groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group || '0'}`), 0n);

  if (number >> 32n === 0xffffn) {
    return { family: 4, bits: 32, number: number & 0xffffffffn };
  }
  return { family: 6, bits: 128, number };
}

function parseDenyNetworks(blockedListPath) {
  if (!fs.existsSync(blockedListPath)) {
    throw new Error(`Nginx blocked-list file not found: ${blockedListPath}`);
  }

  const networks = [];
  const lines = fs.readFileSync(blockedListPath, 'utf8').split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const match = line.match(/^\s*deny\s+([^;\s#]+)\s*;/i);
    if (!match) continue;

    const value = match[1];
    const parsed = parseIpAddress(value);
    const prefixText = value.includes('/') ? value.slice(value.lastIndexOf('/') + 1) : String(parsed.bits);
    if (!/^\d+$/.test(prefixText)) {
      throw new Error(`Invalid CIDR prefix on blocked-list line ${index + 1}: ${value}`);
    }
    const prefix = Number(prefixText);
    if (prefix < 0 || prefix > parsed.bits) {
      throw new Error(`Invalid CIDR prefix on blocked-list line ${index + 1}: ${value}`);
    }
    const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(parsed.bits - prefix);
    networks.push({
      value,
      family: parsed.family,
      bits: parsed.bits,
      network: parsed.number & mask,
      mask,
    });
  }
  return networks;
}

function matchingDenyRules(ip, networks) {
  const parsed = parseIpAddress(ip);
  return networks
    .filter((entry) => entry.family === parsed.family && (parsed.number & entry.mask) === entry.network)
    .map((entry) => entry.value);
}

function analyzeLogs(logs, options, denyNetworks, routes, angularRoutes, readLog = (logPath) => fs.readFileSync(logPath, 'utf8')) {
  const ips = new Map();
  let linesRead = 0;
  let linesParsed = 0;
  let knownRequests = 0;
  let ignoredStatuses = 0;

  for (const logPath of logs) {
    if (!fs.existsSync(logPath)) {
      throw new Error(`Access log not found: ${logPath}`);
    }
    const content = readLog(logPath);
    for (const line of content.split(/\r?\n/)) {
      if (!line) continue;
      linesRead += 1;
      const request = parseAccessLine(line);
      if (!request) continue;
      linesParsed += 1;

      const knownServerRoute = matchServerRoute(request, routes);
      const knownAngularRoute = [...angularRoutes].some((route) => route.test(request.path));
      const angularFile = isAngularFile(request.path, options.angularRoot);
      if (knownServerRoute || knownAngularRoute || angularFile) {
        knownRequests += 1;
        continue;
      }
      const signature = getSignature(request.path);
      if (request.status < 400 && !signature) {
        ignoredStatuses += 1;
        continue;
      }

      const ipData = ips.get(request.ip) ?? {
        ip: request.ip,
        requests: 0,
        unknown4xx: 0,
        signatures: new Set(),
        paths: new Map(),
      };
      ipData.requests += 1;
      if (request.status >= 400) {
        ipData.unknown4xx += 1;
      }
      if (signature) ipData.signatures.add(signature);
      const pathData = ipData.paths.get(request.path) ?? { count: 0, statuses: new Map() };
      pathData.count += 1;
      pathData.statuses.set(request.status, (pathData.statuses.get(request.status) ?? 0) + 1);
      ipData.paths.set(request.path, pathData);
      ips.set(request.ip, ipData);
    }
  }

  const candidates = [...ips.values()]
    .filter((entry) => entry.signatures.size > 0 || entry.unknown4xx >= options.minUnknown)
    .map((entry) => {
      const blockedByRules = matchingDenyRules(entry.ip, denyNetworks);
      return {
        ip: entry.ip,
        requests: entry.requests,
        unknown4xx: entry.unknown4xx,
        signatures: [...entry.signatures].sort(),
        blockedByNginx: blockedByRules.length > 0,
        blockedByRules,
        paths: [...entry.paths.entries()]
          .sort((left, right) => right[1].count - left[1].count)
          .map(([requestPath, details]) => ({
            path: requestPath,
            count: details.count,
            statuses: Object.fromEntries([...details.statuses.entries()].sort()),
          })),
      };
    })
    .sort((left, right) => right.unknown4xx - left.unknown4xx || left.ip.localeCompare(right.ip));

  return {
    summary: {
      logs,
      linesRead,
      linesParsed,
      knownRequests,
      ignoredSuccessfulUnknownRequests: ignoredStatuses,
      suspiciousIpCount: candidates.length,
      minimumUnknown4xx: options.minUnknown,
      blockedList: options.blockedList,
      denyRulesLoaded: denyNetworks.length,
      serverRoutesLoaded: routes.length,
      angularRoutesLoaded: angularRoutes.size,
    },
    candidates,
  };
}

function printTextReport(report) {
  const { summary, candidates } = report;
  console.log('Nginx scan analysis (read-only; no IPs were banned)');
  console.log(`Logs: ${summary.logs.join(', ')}`);
  console.log(`Nginx deny list: ${summary.blockedList} (${summary.denyRulesLoaded} rules loaded)`);
  console.log(`Parsed ${summary.linesParsed}/${summary.linesRead} lines; known routes/assets: ${summary.knownRequests}; successful unknown paths skipped: ${summary.ignoredSuccessfulUnknownRequests}`);
  console.log(`Loaded ${summary.serverRoutesLoaded} server routes and ${summary.angularRoutesLoaded} Angular routes.`);
  console.log(`Candidates: ${summary.suspiciousIpCount} (threshold: ${summary.minimumUnknown4xx} unknown 4xx requests, or a scan signature)\n`);

  if (candidates.length === 0) {
    console.log('No candidate scanning IPs found in these logs.');
    return;
  }

  const rows = [];
  for (const candidate of candidates) {
    for (const entry of candidate.paths) {
      rows.push([
        candidate.ip,
        candidate.blockedByNginx ? `YES (${candidate.blockedByRules.join(', ')})` : 'NO',
        entry.path,
        String(entry.count),
        Object.entries(entry.statuses).map(([status, count]) => `${status}:${count}`).join(' '),
      ]);
    }
  }

  const headers = ['IP', 'NGINX BLOCKED', 'ATTEMPTED PAGE', 'COUNT', 'STATUS'];
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => row[index].length)));
  const formatRow = (row) => row.map((value, index) => value.padEnd(widths[index])).join(' | ');
  console.log(formatRow(headers));
  console.log(widths.map((width) => '-'.repeat(width)).join('-+-'));
  for (const row of rows) console.log(formatRow(row));
}

function main() {
  try {
    if (process.argv.length > 2) {
      throw new Error('This report uses fixed paths; run it without command-line switches.');
    }
    const routes = collectServerRoutes(REPORT_OPTIONS.dist);
    const angularRoutes = collectAngularRoutes(REPORT_OPTIONS.angularRoot);
    const denyNetworks = parseDenyNetworks(REPORT_OPTIONS.blockedList);
    const report = analyzeLogs(REPORT_OPTIONS.logs, REPORT_OPTIONS, denyNetworks, routes, angularRoutes);
    printTextReport(report);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = {
  REPORT_OPTIONS,
  analyzeLogs,
  collectAngularRoutes,
  collectServerRoutes,
  parseAccessLine,
  parseDenyNetworks,
  printTextReport,
};

if (require.main === module) {
  main();
}
