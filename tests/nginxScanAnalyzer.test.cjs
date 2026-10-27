const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  analyzeLogs,
  collectAngularRoutes,
  collectServerRoutes,
  parseDenyNetworks,
  printTextReport,
} = require('../scripts/analyze-nginx-scans');

test('Nginx scan analyzer filters known routes/assets and reports scanner candidates without banning', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nginx-scan-analyzer-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const dist = path.join(root, 'dist');
  const routeDir = path.join(dist, 'routes');
  const angularRoot = path.join(root, 'angular');
  fs.mkdirSync(routeDir, { recursive: true });
  fs.mkdirSync(path.join(angularRoot, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(dist, 'server.js'), "app.get('/', handler);");
  fs.writeFileSync(
    path.join(routeDir, 'weather.js'),
    "router.get('/getweather', handler); router.get('/quakedata/:id', handler);",
  );
  fs.writeFileSync(path.join(angularRoot, 'index.html'), '<a href="/about">About</a>');
  fs.writeFileSync(path.join(angularRoot, 'assets', 'main.js'), 'bundle');
  const blockedList = path.join(root, 'blocked-ips.conf');
  fs.writeFileSync(blockedList, [
    'deny 203.0.113.50;',
    'deny 203.0.113.48/29;',
    'deny 2001:db8::/32;',
  ].join('\n'));

  const accessLine = (ip, method, uri, status) =>
    `${ip} - - [22/Oct/2026:13:00:00 -0400] "${method} ${uri} HTTP/1.1" ${status} 123 "-" "test"\n`;
  const log = path.join(root, 'access.log');
  fs.writeFileSync(log, [
    accessLine('198.51.100.10', 'GET', '/getweather?city=Ottawa', 200),
    accessLine('198.51.100.10', 'GET', '/quakedata/weekly', 200),
    accessLine('198.51.100.10', 'GET', '/about', 200),
    accessLine('198.51.100.10', 'GET', '/assets/main.js', 200),
    accessLine('203.0.113.50', 'GET', '/wp-login.php', 200),
    accessLine('203.0.113.51', 'GET', '/not-a-route', 404).repeat(2),
    accessLine('2001:db8::50', 'GET', '/.env', 404),
    '198.51.100.99 - - [22/Oct/2026:13:00:00 -0400] "-" 400 0 "-" "test"\n',
    'not an nginx access log line\n',
  ].join(''));

  const options = {
    angularRoot,
    blockedList,
    minUnknown: 2,
  };
  const report = analyzeLogs(
    [log],
    options,
    parseDenyNetworks(blockedList),
    collectServerRoutes(dist),
    collectAngularRoutes(angularRoot),
  );

  assert.equal(report.summary.linesParsed, 8);
  assert.equal(report.summary.knownRequests, 4);
  assert.equal(report.summary.suspiciousIpCount, 3);
  const repeatedUnknown = report.candidates.find((candidate) => candidate.ip === '203.0.113.51');
  assert.equal(repeatedUnknown.unknown4xx, 2);
  assert.equal(repeatedUnknown.blockedByNginx, true);
  assert.deepEqual(repeatedUnknown.blockedByRules, ['203.0.113.48/29']);
  const signatureMatch = report.candidates.find((candidate) => candidate.ip === '203.0.113.50');
  assert.deepEqual(signatureMatch.signatures, ['WordPress']);
  assert.equal(signatureMatch.blockedByNginx, true);
  assert.deepEqual(signatureMatch.blockedByRules, ['203.0.113.50', '203.0.113.48/29']);
  assert.equal(signatureMatch.paths[0].statuses['200'], 1);
  const ipv6Match = report.candidates.find((candidate) => candidate.ip === '2001:db8::50');
  assert.equal(ipv6Match.blockedByNginx, true);
  assert.deepEqual(ipv6Match.blockedByRules, ['2001:db8::/32']);

  const outputLines = [];
  const originalLog = console.log;
  console.log = (...values) => outputLines.push(values.join(' '));
  try {
    printTextReport(report);
  } finally {
    console.log = originalLog;
  }
  const textReport = outputLines.join('\n');
  assert.match(textReport, /IP\s+\| NGINX BLOCKED\s+\| ATTEMPTED PAGE\s+\| COUNT\s+\| STATUS/);
  assert.match(textReport, /203\.0\.113\.50\s+\| YES \(203\.0\.113\.50, 203\.0\.113\.48\/29\)\s+\| \/wp-login\.php/);
});
