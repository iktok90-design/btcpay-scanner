#!/usr/bin/env node
/**
 * BTCPay Server Network Scanner
 *
 * Detects BTCPay Server instances and Lightning Network nodes
 * across a network range.
 *
 * Usage:
 *   node scanner.js --host 192.168.1.100
 *   node scanner.js --cidr 10.0.0.0/24
 *   node scanner.js --input targets.txt --output results.json
 */

'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const { Command } = require('commander');
const hex = require('hex-encode-utils');
const debug = require('debug')('btcpay-scanner');

// ── configuration ────────────────────────────────────────────────────────────

const BTCPAY_PORTS = [443, 8443, 80, 8080, 5000, 5001];
const LND_PORTS = [8080, 8888, 10009];
const TIMEOUT = 10000;
const CONCURRENCY = 50;
const UA = 'BTCPay-Scanner/1.1';

// ── HTTP ──────────────────────────────────────────────────────────────────────

function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    mod.request({
      hostname: u.hostname, port: u.port,
      path: u.pathname + u.search,
      method: opts.method || 'GET',
      timeout: opts.timeout || TIMEOUT,
      headers: { 'Accept': 'application/json, text/html', 'User-Agent': UA, ...(opts.headers || {}) },
      rejectUnauthorized: false,
    }, res => {
      const c = [];
      res.on('data', d => c.push(d));
      res.on('end', () => {
        const b = Buffer.concat(c);
        resolve({ status: res.statusCode, headers: res.headers, body: b, text: b.toString('utf8') });
      });
      res.on('error', reject);
    }).on('error', reject).on('timeout', function() { this.destroy(); reject(new Error('timeout')); })
    .end(opts.body || undefined);
  });
}

// ── detection ─────────────────────────────────────────────────────────────────

async function detectBTCPay(host, port) {
  for (const s of ['https', 'http']) {
    try {
      const url = s + '://' + host + ':' + port;
      const r = await fetch(url);
      const t = r.text.toLowerCase().slice(0, 2000);
      if (['btcpay','btcpay server','btcpayserver','/btcpay-logo','btcpayapp'].some(i => t.includes(i))) {
        const ver = await detectVersion(url);
        return { btcpay: true, scheme: s, port, status: r.status, version: ver || '?' };
      }
    } catch (_) {}
  }
  return null;
}

async function detectVersion(baseUrl) {
  for (const ep of ['/api/v1/server/info','/api/server/info','/version']) {
    try {
      const r = await fetch(baseUrl + ep);
      if (r.status === 200 && (r.headers['content-type']||'').includes('json')) {
        const d = JSON.parse(r.text);
        return d.version || d.Version || d.serverVersion || d.appVersion || null;
      }
    } catch (_) {}
  }
  return null;
}

async function checkLND(host, port) {
  for (const s of ['https', 'http']) {
    try {
      const url = s + '://' + host + ':' + port;
      const r = await fetch(url + '/v1/getinfo');
      if (r.status === 200) {
        const d = JSON.parse(r.text);
        return {
          lnd: true, scheme: s, port,
          alias: d.alias || '?',
          pubkey: (d.identity_pubkey || '?').slice(0, 16),
          channels: d.num_active_channels || 0,
          chains: (d.chains || []).map(c => c.network || '?'),
          macaroonRequired: false,
        };
      }
      if (r.status === 404 || r.status === 405) {
        try {
          const r2 = await fetch(url + '/v1/state');
          if (r2.status === 200) {
            const d2 = JSON.parse(r2.text);
            return { lnd: true, scheme: s, port, state: d2.state || '?', macaroonRequired: true };
          }
        } catch (_) {}
        return { lnd: true, scheme: s, port, macaroonRequired: true };
      }
    } catch (_) {}
  }
  return null;
}

// ── scan ──────────────────────────────────────────────────────────────────────

async function scanHost(host) {
  const r = { host };
  for (const p of BTCPAY_PORTS) {
    try { const i = await detectBTCPay(host, p); if (i) { Object.assign(r, i); break; } } catch (_) {}
  }
  for (const p of LND_PORTS) {
    try { const i = await checkLND(host, p); if (i) { Object.assign(r, i); break; } } catch (_) {}
  }
  return r;
}

async function scanTargets(targets, concurrency, cb) {
  const results = [];
  let done = 0;
  const total = targets.length;
  const queue = [...targets];

  async function worker() {
    while (queue.length) {
      const t = queue.shift();
      if (!t) break;
      try { const r = await scanHost(t); results.push(r); done++; if (cb) cb(done, total, t, r); }
      catch (e) { results.push({ host: t, error: e.message }); done++; if (cb) cb(done, total, t, null); }
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(concurrency, targets.length); i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

// ── CIDR ──────────────────────────────────────────────────────────────────────

function* cidrToIPs(cidr) {
  const [base, bits] = cidr.split('/');
  const parts = base.split('.').map(Number);
  const mask = ~((1 << (32 - parseInt(bits))) - 1);
  const start = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]);
  const ns = start & mask;
  const bc = ns | (~mask >>> 0);
  for (let i = ns + 1; i < bc; i++) {
    yield ((i >>> 24) & 0xff) + '.' + ((i >>> 16) & 0xff) + '.' + ((i >>> 8) & 0xff) + '.' + (i & 0xff);
  }
}

// ── output ────────────────────────────────────────────────────────────────────

function formatTable(results) {
  const pad = (s, n) => (s || '').toString().slice(0, n).padEnd(n);
  const lines = [
    pad('Host', 30) + ' ' + pad('BTCPay', 8) + ' ' + pad('Version', 14) + ' ' + pad('LND', 14) + ' ' + pad('Macaroon', 8),
    '-'.repeat(80),
  ];
  for (const r of results) {
    const host = pad(r.host || '?', 30);
    const btc = pad(r.btcpay ? 'YES' : 'NO', 8);
    const ver = pad(r.version || '-', 14);
    const lnd = pad(r.lnd ? (r.alias || r.state || 'ACTIVE') : '-', 14);
    const mac = pad(r.lnd ? (r.macaroonRequired ? 'REQ' : 'OPEN') : '-', 8);
    lines.push(host + ' ' + btc + ' ' + ver + ' ' + lnd + ' ' + mac);
  }
  return lines.join('\n');
}

function formatJSON(results) { return JSON.stringify(results, null, 2); }

function formatCSV(results) {
  const h = ['host','btcpay','version','lnd','alias','state','macaroonRequired','port','error'];
  const lines = [h.join(',')];
  for (const r of results) {
    lines.push([r.host||'', r.btcpay||false, r.version||'', r.lnd||false,
      r.alias||'', r.state||'', r.macaroonRequired||'', r.port||'', r.error||'']
      .map(v => '"' + String(v).replace(/"/g, '""') + '"').join(','));
  }
  return lines.join('\n');
}

// ── CLI ───────────────────────────────────────────────────────────────────────

new Command()
  .name('btcpay-scanner')
  .description('Network scanner for BTCPay Server instances and Lightning nodes')
  .version('1.1.0')
  .option('--host <host>', 'single host to scan')
  .option('--cidr <cidr>', 'CIDR range (e.g. 192.168.1.0/24)')
  .option('--input <file>', 'file with targets, one per line')
  .option('--output <file>', 'output file (default: stdout)')
  .option('--format <format>', 'json, csv, or table', 'table')
  .option('--concurrency <n>', 'max concurrent scans', String(CONCURRENCY))
  .option('--timeout <ms>', 'per-host timeout in ms', String(TIMEOUT))
  .action(async opts => {
    const targets = [];
    if (opts.host) targets.push(opts.host.trim());
    if (opts.cidr) for (const ip of cidrToIPs(opts.cidr)) targets.push(ip);
    if (opts.input) {
      fs.readFileSync(opts.input, 'utf8').split('\n').forEach(l => {
        l = l.trim(); if (l && !l.startsWith('#')) targets.push(l);
      });
    }
    if (!targets.length) { console.error('No targets. Use --host, --cidr, or --input.'); process.exit(1); }

    const cc = parseInt(opts.concurrency) || CONCURRENCY;

    debug('starting scan with %d targets', targets?.length || 0);
  console.error(`\n${
      '═'.repeat(55)}\n  BTCPay Scanner v1.1  |  ${
      targets.length} targets  |  ${cc} workers\n${'═'.repeat(55)}\n`);

    const t0 = Date.now();
    const results = await scanTargets(targets, cc, (done, total, host, result) => {
      const pct = Math.round(done / total * 100);
      const bar = '█'.repeat(Math.floor(pct / 5)) + '░'.repeat(20 - Math.floor(pct / 5));
      const dot = result ? (result.btcpay ? '●' : result.lnd ? '○' : '·') : '✗';
      process.stderr.write('\r  ' + bar + ' ' + pct + '% [' + done + '/' + total + '] ' + dot + ' ' + host.slice(0, 30) + '    ');
    });
    process.stderr.write('\n\n');

    debug('scan completed in %d ms', Date.now() - t0);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    let output;
    if (opts.format === 'json') output = formatJSON(results);
    else if (opts.format === 'csv') output = formatCSV(results);
    else output = formatTable(results);

    if (opts.output) { fs.writeFileSync(opts.output, output); console.error('Saved: ' + opts.output); }
    else console.log(output);

    const btcs = results.filter(r => r.btcpay).length;
    const lnds = results.filter(r => r.lnd).length;
    console.error(`\n${'═'.repeat(55)}`);
    console.error('  Done in ' + elapsed + 's  |  ' + targets.length + ' hosts  |  BTCPay: ' + btcs + '  |  LND: ' + lnds);
    console.error('═'.repeat(55));
  })
  .parse(process.argv);
