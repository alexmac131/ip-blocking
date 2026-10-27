const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { collectAttempts } = require('../scripts/collect-nginx-attempts');

const line = (url, status = 404, ip = '198.51.100.10') =>
  `${ip} - - [26/Oct/2026:13:00:00 -0400] "GET ${url} HTTP/1.1" ${status} 123 "-" "test"\n`;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nginx-history-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const log = path.join(root, 'access.log');
  const history = path.join(root, 'reports/history.json');
  const options = { minUnknown: 2, angularRoot: root, blockedList: 'unused' };
  const routes = [{ method: 'GET', regex: /^\/getweather$/, path: '/getweather' }];
  const scan = (logs = [log]) => collectAttempts(logs, history, options, [], routes, new Set());
  return { root, log, history, scan };
}

test('history persists unique pages and adds only new entries across repeated scans and rotation', (t) => {
  const { log, history, scan } = fixture(t);
  fs.writeFileSync(log, [
    line('/.env', 200), line('/.env?secret=value', 403),
    line('/getweather', 200), 'malformed\n',
  ].join(''));
  let result = scan();
  assert.equal(result.added, 2);
  assert.equal(result.pages.length, 1);
  assert.deepEqual(result.pages[0].statuses, { 200: 1, 403: 1 });
  assert.equal(result.pages[0].path, '/.env');
  assert.equal(scan().added, 0);
  assert.equal(scan([log, log]).added, 0);
  const firstSeen = result.pages[0].firstSeen;
  fs.appendFileSync(log, line('/.env', 404, '203.0.113.20'));
  assert.equal(scan().added, 1);
  const rotated = `${log}.1`;
  fs.renameSync(log, rotated);
  fs.writeFileSync(log, line('/wp-login.php', 200));
  result = scan([log, rotated]);
  assert.equal(result.added, 1);
  assert.equal(result.pages.find((p) => p.path === '/.env').count, 3);
  assert.equal(result.pages.find((p) => p.path === '/.env').firstSeen, firstSeen);
  assert.equal(result.pages.find((p) => p.path === '/wp-login.php').count, 1);
  assert.equal(scan([log, rotated]).added, 0);
  assert.equal(fs.existsSync(`${history}.lock`), false);
  assert.equal(fs.existsSync(`${history}.tmp`), false);
});

test('threshold qualification counts earlier entries once and incomplete lines wait for completion', (t) => {
  const { log, scan } = fixture(t);
  fs.writeFileSync(log, line('/unknown'));
  assert.equal(scan().added, 0);
  fs.appendFileSync(log, line('/other'));
  assert.equal(scan().added, 2);
  assert.equal(scan().added, 0);
  fs.appendFileSync(log, line('/.env').trimEnd());
  assert.equal(scan().added, 0);
  fs.appendFileSync(log, '\n');
  assert.equal(scan().added, 1);
});

test('rewrite, missing input, corrupt history, and concurrent runs fail without replacing counts', (t) => {
  const { log, history, scan } = fixture(t);
  fs.writeFileSync(log, line('/.env'));
  scan();
  const original = fs.readFileSync(history, 'utf8');
  fs.writeFileSync(log, line('/wp-admin'));
  assert.throws(() => scan(), /truncated or rewritten/);
  assert.equal(fs.readFileSync(history, 'utf8'), original);
  assert.throws(() => scan([`${log}.missing`]), { code: 'ENOENT' });
  assert.equal(fs.readFileSync(history, 'utf8'), original);
  fs.writeFileSync(`${history}.lock`, 'locked');
  assert.throws(() => scan(), { code: 'EEXIST' });
  assert.equal(fs.readFileSync(`${history}.lock`, 'utf8'), 'locked');
  fs.unlinkSync(`${history}.lock`);
  fs.writeFileSync(history, '{"version":1,"pages":[],"sources":[{}]}');
  assert.throws(() => scan(), /Invalid scan history/);
  assert.equal(fs.existsSync(`${history}.lock`), false);
});
