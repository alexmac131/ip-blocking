const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { analyzeWeatherLogs, printWeatherReport } = require('../scripts/analyze-nginx-weather');

test('weather report includes all statuses, methods, and case-insensitive matching paths', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nginx-weather-analyzer-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const line = (ip, method, url, status) =>
    `${ip} - - [26/Oct/2026:13:00:00 -0400] "${method} ${url} HTTP/1.1" ${status} 123 "-" "test"\n`;
  const log = path.join(root, 'access.log');
  const rotated = path.join(root, 'access.log.1');
  fs.writeFileSync(log, [
    line('198.51.100.10', 'GET', '/getweather?city=Ottawa', 200),
    line('198.51.100.10', 'GET', '/getweather?city=Toronto', 403),
    line('2001:db8::10', 'HEAD', '/GetWeather', 304),
    line('198.51.100.11', 'POST', '/prefix/getWeather/details', 404),
    line('198.51.100.12', 'GET', '/%67etWeather', 500),
    line('198.51.100.13', 'GET', '/quakedata?tag=getWeather', 200),
    line('198.51.100.13', 'GET', '/wp-login.php', 200),
    '198.51.100.99 - - [26/Oct/2026:13:00:00 -0400] "-" 400 0 "-" "test"\n',
    'not an access log line\n',
  ].join(''));
  fs.writeFileSync(rotated, line('198.51.100.10', 'GET', '/getweather', 200));
  const before = fs.readFileSync(log, 'utf8');
  const report = analyzeWeatherLogs([log, rotated]);
  assert.deepEqual(report.summary, {
    logs: [log, rotated], linesRead: 10, linesParsed: 8, matchingRequests: 6, matchingIps: 4,
  });
  assert.equal(report.visitors[0].ip, '198.51.100.10');
  assert.equal(report.visitors[0].requests, 3);
  assert.deepEqual(report.visitors[0].paths, [{
    method: 'GET', path: '/getweather', count: 3, statuses: { 200: 2, 403: 1 },
  }]);
  assert.equal(report.visitors.find((v) => v.ip === '2001:db8::10').paths[0].method, 'HEAD');
  assert.deepEqual(report.visitors.find((v) => v.ip === '198.51.100.12').paths[0].statuses, { 500: 1 });
  assert.equal(fs.readFileSync(log, 'utf8'), before);

  const output = [];
  t.mock.method(console, 'log', (...args) => output.push(args.join(' ')));
  printWeatherReport(report);
  const text = output.join('\n');
  assert.match(text, /IP\s+\| METHOD\s+\| REQUESTED PAGE\s+\| COUNT\s+\| STATUS/);
  assert.match(text, /198\.51\.100\.10\s+\| GET\s+\| \/getweather\s+\| 3\s+\| 200:2 403:1/);
  assert.doesNotMatch(text, /Ottawa|Toronto|wp-login/);
});

test('weather report handles no matches and exposes input failures', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nginx-weather-empty-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const log = path.join(root, 'access.log');
  fs.writeFileSync(log, '');
  const output = [];
  t.mock.method(console, 'log', (...args) => output.push(args.join(' ')));
  printWeatherReport(analyzeWeatherLogs([log]));
  assert.match(output.join('\n'), /No matching weather requests found/);
  assert.throws(() => analyzeWeatherLogs([path.join(root, 'missing.log')]), { code: 'ENOENT' });
  const cli = spawnSync(process.execPath, [
    path.resolve(__dirname, '../scripts/analyze-nginx-weather.js'), '--unsupported',
  ], { encoding: 'utf8' });
  assert.equal(cli.status, 1);
  assert.match(cli.stderr, /without command-line switches/);
});
