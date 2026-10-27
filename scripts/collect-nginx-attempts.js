#!/usr/bin/env node
/*
 * Purpose: Keep cumulative unique ATTEMPTED PAGE paths from the suspect-traffic
 * analyzer, with request/status counts and first/last collection timestamps.
 * Rerunning unchanged logs adds no counts. No bans or MongoDB data are changed.
 * Usage (from the deployed repository root):
 *   sudo node scripts/collect-nginx-attempts.js
 * No switches; uses REPORT_OPTIONS from analyze-nginx-scans.js plus the optional
 * rotated log below. Prints totals and writes ../reports/nginx-attempts.json.
 *
 * Requirements: Node.js 18+, analyze-nginx-scans.js alongside this file, and
 * its inputs: readable Nginx access logs and deny include, your configured compiled
 * Express routes, and /var/www/html when available for frontend exclusions.
 * No database connection, AWS credentials, or extra npm packages are needed.
 * Needs RAM for logs and write permission for the history directory, lock, and
 * temporary file. sudo-created history is owned by root; use a consistent user.
 * Real-client-IP logging is needed behind proxies. Run regularly before logs
 * are compressed/deleted; only uncompressed files are supported.
 *
 * Preserve/back up the whole history, including sources checkpoints. Normal
 * rename-based rotation on the same filesystem is tracked by device/inode;
 * copied logs are new sources and may be recounted. Truncation/rewrites of a
 * tracked file (including copytruncate) fail rather than guess counts. Earlier
 * entries still in the logs may be counted when an IP first meets the threshold.
 * Timestamps are collection times, not original request times. Do not delete
 * state to resolve errors: restore a valid backup. After a forced termination,
 * remove stale .lock/.tmp files only after verifying no collector is running.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { createHash } = require('node:crypto');
const {
  REPORT_OPTIONS, analyzeLogs, collectServerRoutes, collectAngularRoutes, parseDenyNetworks,
} = require('./analyze-nginx-scans');

const HISTORY_FILE = path.resolve(__dirname, '../reports/nginx-attempts.json');
const OPTIONAL_ROTATED_LOG = '/var/log/nginx/access.log.1';
const hash = (buffer) => createHash('sha256').update(buffer).digest('hex');

function validateHistory(state) {
  const validStatuses = (statuses) => statuses && typeof statuses === 'object'
    && !Array.isArray(statuses) && Object.entries(statuses).every(([code, count]) =>
      /^[1-5]\d{2}$/.test(code) && Number.isSafeInteger(count) && count > 0);
  const validPages = (pages, totals) => Array.isArray(pages)
    && new Set(pages.map((page) => totals ? page?.path : JSON.stringify([page?.ip, page?.path]))).size === pages.length
    && pages.every((page) => page && typeof page.path === 'string'
      && (totals || (typeof page.ip === 'string' && net.isIP(page.ip) !== 0))
      && validStatuses(page.statuses)
      && (!totals || (page.count === Object.values(page.statuses).reduce((a, b) => a + b, 0)
        && typeof page.firstSeen === 'string' && typeof page.lastSeen === 'string')));
  if (!state || state.version !== 1 || !validPages(state.pages, true)
    || !Array.isArray(state.sources)
    || new Set(state.sources.map((source) => source?.id)).size !== state.sources.length
    || !state.sources.every((source) => source && typeof source.id === 'string'
      && Number.isSafeInteger(source.bytes) && source.bytes >= 0
      && typeof source.hash === 'string' && /^[a-f0-9]{64}$/.test(source.hash)
      && validPages(source.pages, false))) {
    throw new Error('Invalid scan history; restore a valid backup rather than resetting counts.');
  }
}

function collectAttempts(logs, historyFile, options, denyNetworks, routes, angularRoutes) {
  if (logs.length === 0) throw new Error('At least one access log is required.');
  fs.mkdirSync(path.dirname(historyFile), { recursive: true });
  const lockFile = `${historyFile}.lock`;
  const lock = fs.openSync(lockFile, 'wx', 0o600);
  const temporary = `${historyFile}.tmp`;
  let temporaryCreated = false;
  try {
    const state = fs.existsSync(historyFile)
      ? JSON.parse(fs.readFileSync(historyFile, 'utf8'))
      : { version: 1, pages: [], sources: [] };
    validateHistory(state);
    const snapshots = new Map();
    const identities = new Set();
    for (const logPath of logs) {
      const fd = fs.openSync(logPath, 'r');
      try {
        const stat = fs.fstatSync(fd);
        const id = `${stat.dev}:${stat.ino}`;
        if (identities.has(id)) continue;
        identities.add(id);
        const buffer = fs.readFileSync(fd);
        // Leave an incomplete final line for the next scan.
        const complete = buffer.subarray(0, buffer.lastIndexOf(10) + 1);
        snapshots.set(logPath, { id, buffer: complete });
      } finally {
        fs.closeSync(fd);
      }
    }
    const logPaths = [...snapshots.keys()];
    const readLog = (logPath) => snapshots.get(logPath).buffer.toString('utf8');
    const report = analyzeLogs(logPaths, options, denyNetworks, routes, angularRoutes, readLog);
    const candidateIps = new Set(report.candidates.map((entry) => entry.ip));
    const totals = new Map(state.pages.map((entry) => [entry.path, entry]));
    const sources = new Map(state.sources.map((entry) => [entry.id, entry]));
    const now = new Date().toISOString();
    let added = 0;

    for (const [logPath, snapshot] of snapshots) {
      let previous = sources.get(snapshot.id);
      if (previous && (snapshot.buffer.length < previous.bytes
        || hash(snapshot.buffer.subarray(0, previous.bytes)) !== previous.hash)) {
        throw new Error(`Previously scanned log was truncated or rewritten: ${logPath}. Preserve the old log and history; counts were not changed. Use rename-based log rotation, not copytruncate.`);
      }
      previous ??= { id: snapshot.id, pages: [] };
      const recorded = new Map(previous.pages.map((entry) => [JSON.stringify([entry.ip, entry.path]), entry]));
      const current = analyzeLogs([logPath], { ...options, minUnknown: 0 }, [], routes, angularRoutes, readLog);
      const pages = new Map();
      for (const candidate of current.candidates) {
        if (!candidateIps.has(candidate.ip)) continue;
        for (const entry of candidate.paths) {
          const key = JSON.stringify([candidate.ip, entry.path]);
          const page = { ip: candidate.ip, path: entry.path, statuses: {} };
          for (const [status, count] of Object.entries(entry.statuses)) {
            page.statuses[status] = (page.statuses[status] ?? 0) + count;
          }
          pages.set(key, page);
        }
      }
      for (const [key, page] of pages) {
        const old = recorded.get(key) ?? { ip: page.ip, path: page.path, statuses: {} };
        const total = totals.get(page.path) ?? {
          path: page.path, count: 0, statuses: {}, firstSeen: now, lastSeen: now,
        };
        for (const [status, count] of Object.entries(page.statuses)) {
          const delta = Math.max(0, count - (old.statuses[status] ?? 0));
          if (delta === 0) continue;
          total.count += delta;
          total.statuses[status] = (total.statuses[status] ?? 0) + delta;
          total.lastSeen = now;
          old.statuses[status] = count;
          added += delta;
        }
        recorded.set(key, old);
        if (total.count > 0) totals.set(page.path, total);
      }
      sources.set(snapshot.id, {
        id: snapshot.id, bytes: snapshot.buffer.length, hash: hash(snapshot.buffer),
        pages: [...recorded.values()],
      });
    }
    state.pages = [...totals.values()].sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));
    state.sources = [...sources.values()];
    state.updatedAt = now;
    validateHistory(state);
    const output = fs.openSync(temporary, 'wx', 0o600);
    temporaryCreated = true;
    try {
      fs.writeFileSync(output, `${JSON.stringify(state, null, 2)}\n`);
    } finally {
      fs.closeSync(output);
    }
    fs.renameSync(temporary, historyFile);
    temporaryCreated = false;
    return { added, pages: state.pages };
  } finally {
    if (temporaryCreated) fs.unlinkSync(temporary);
    fs.closeSync(lock);
    fs.unlinkSync(lockFile);
  }
}

function main() {
  try {
    if (process.argv.length > 2) {
      throw new Error('This collector uses fixed paths; run it without command-line switches.');
    }
    const logs = [...REPORT_OPTIONS.logs];
    if (fs.existsSync(OPTIONAL_ROTATED_LOG)) logs.push(OPTIONAL_ROTATED_LOG);
    const result = collectAttempts(
      logs, HISTORY_FILE, REPORT_OPTIONS, parseDenyNetworks(REPORT_OPTIONS.blockedList),
      collectServerRoutes(REPORT_OPTIONS.dist), collectAngularRoutes(REPORT_OPTIONS.angularRoot),
    );
    console.log(`History saved: ${HISTORY_FILE}`);
    console.log(`New attempts counted: ${result.added}; unique pages: ${result.pages.length}`);
    console.log('ATTEMPTED PAGE | COUNT | STATUS');
    for (const page of result.pages) {
      console.log(`${JSON.stringify(page.path)} | ${page.count} | ${Object.entries(page.statuses).map(([status, count]) => `${status}:${count}`).join(' ')}`);
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { collectAttempts };
if (require.main === module) main();
