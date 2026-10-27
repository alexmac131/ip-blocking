#!/usr/bin/env node
/*
 * Purpose: Report requests whose decoded path contains getWeather, ignoring
 * case. Groups by IP, method, and path with counts and all HTTP statuses.
 * Query strings are excluded; matching traffic is not necessarily legitimate.
 * Usage (from the deployed repository root):
 *   sudo node scripts/analyze-nginx-weather.js
 * No switches; edit REPORT_LOGS/PATH_TAG below to change the inputs or tag.
 * Read-only terminal output; no history, MongoDB writes, or blocklist changes.
 *
 * Requirements: Node.js 18+ and analyze-nginx-scans.js in this same directory
 * (shared parser). No npm packages, compiled routes, Angular build, database,
 * AWS credentials, or deny list required. Defaults to the uncompressed
 * /var/log/nginx/access.log in standard Nginx access-log format; requires read
 * permission (sudo if needed) and RAM for the selected logs. Run on the Nginx
 * host or edit paths to local log copies. Real-client-IP logging is required
 * for accurate visitor attribution behind a proxy/CDN.
 */
'use strict';

const fs = require('node:fs');
const { parseAccessLine } = require('./analyze-nginx-scans');

const REPORT_LOGS = ['/var/log/nginx/access.log'];
const PATH_TAG = 'getWeather';

function analyzeWeatherLogs(logs) {
  const ips = new Map();
  let linesRead = 0;
  let linesParsed = 0;
  let matchingRequests = 0;

  for (const logPath of logs) {
    const content = fs.readFileSync(logPath, 'utf8');
    for (const line of content.split(/\r?\n/)) {
      if (!line) continue;
      linesRead += 1;
      const request = parseAccessLine(line);
      if (!request) continue;
      linesParsed += 1;
      if (!request.path.toLowerCase().includes(PATH_TAG.toLowerCase())) continue;
      matchingRequests += 1;

      const entry = ips.get(request.ip) ?? { ip: request.ip, requests: 0, paths: new Map() };
      entry.requests += 1;
      const key = `${request.method} ${request.path}`;
      const details = entry.paths.get(key) ?? {
        method: request.method,
        path: request.path,
        count: 0,
        statuses: new Map(),
      };
      details.count += 1;
      details.statuses.set(request.status, (details.statuses.get(request.status) ?? 0) + 1);
      entry.paths.set(key, details);
      ips.set(request.ip, entry);
    }
  }

  return {
    summary: { logs, linesRead, linesParsed, matchingRequests, matchingIps: ips.size },
    visitors: [...ips.values()]
      .sort((a, b) => b.requests - a.requests || a.ip.localeCompare(b.ip))
      .map((entry) => ({
        ip: entry.ip,
        requests: entry.requests,
        paths: [...entry.paths.values()]
          .sort((a, b) => b.count - a.count || a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
          .map((details) => ({
            ...details,
            statuses: Object.fromEntries([...details.statuses].sort((a, b) => a[0] - b[0])),
          })),
      })),
  };
}

function printWeatherReport(report) {
  const { summary, visitors } = report;
  console.log('Nginx weather traffic (read-only; no IPs were banned)');
  console.log(`Logs: ${summary.logs.join(', ')}`);
  console.log(`Path contains "${PATH_TAG}" (case-insensitive; query strings excluded).`);
  console.log(`Parsed ${summary.linesParsed}/${summary.linesRead} lines; matching requests: ${summary.matchingRequests}; unique IPs: ${summary.matchingIps}`);
  console.log('All HTTP statuses included. Matching a weather path does not prove a visitor is legitimate.\n');

  if (visitors.length === 0) {
    console.log('No matching weather requests found in these logs.');
    return;
  }

  const rows = visitors.flatMap((visitor) => visitor.paths.map((entry) => [
    visitor.ip,
    entry.method,
    entry.path,
    String(entry.count),
    Object.entries(entry.statuses).map(([status, count]) => `${status}:${count}`).join(' '),
  ]));
  const headers = ['IP', 'METHOD', 'REQUESTED PAGE', 'COUNT', 'STATUS'];
  const widths = headers.map((header, index) =>
    rows.reduce((width, row) => Math.max(width, row[index].length), header.length));
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
    printWeatherReport(analyzeWeatherLogs(REPORT_LOGS));
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { analyzeWeatherLogs, printWeatherReport };

if (require.main === module) {
  main();
}
