#!/usr/bin/env node
/**
 * BTCPay Server Network Scanner
 *
 * Detects BTCPay Server instances and Lightning Network nodes
 * across a network range. Outputs version, LND status, and
 * macaroon requirements.
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
const path = require('path');
const os = require('os');

// ── configuration ────────────────────────────────────────────────────────────

const BTCPAY_PORTS = [443, 8443, 80, 8080, 5000, 5001];
const LND_PORTS = [8080, 8888, 10009];
const DEFAULT_TIMEOUT = 10000;
const DEFAULT_CONCURRENCY = 50;
const USER_AGENT = 'BTCPay-Scanner/1.0';

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function fetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method: options.method || 'GET',
      timeout: options.timeout || DEFAULT_TIMEOUT,
      headers: {
        'Accept': 'application/json, text/html',
        'User-Agent': USER_AGENT,
        ...(options.headers || {}),
      },
      rejectUnauthorized: false,
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: body,
          text: body.toString('utf8'),
        });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ── detection functions ───────────────────────────────────────────────────────

async function detectBTCPay(host, port) {
  for (const scheme of ['https', 'http']) {
    try {
      const url = `${scheme}://${host}:${port}`;
      const r = await fetch(url);
      const text = r.text.toLowerCase().slice(0, 2000);

      const indicators = [
        'btcpay', 'btcpay server', 'btcpayserver',
        '/btcpay-logo', 'btcpayapp',
      ];

      if (indicators.some(i => text.includes(i))) {
        const version = await detectVersion(url);
        return {
          btcpay: true,
          scheme,
          port,
          status: r.status,
          version: version || '?',
        };
      }
    } catch (_) {}
  }
  return null;
}

async function detectVersion(baseUrl) {
  const endpoints = [
    '/api/v1/server/info',
    '/api/server/info',
    '/version',
  ];
  for (const ep of endpoints) {
    try {
      const r = await fetch(`${baseUrl}${ep}`);
      if (r.status === 200 && r.headers['content-type']?.includes('json')) {
        const d = JSON.parse(r.text);
        return d.version || d.Version || d.serverVersion || d.appVersion || null;
      }
    } catch (_) {}
  }
  return null;
}

async function checkLND(host, port) {
  for (const scheme of ['https', 'http']) {
    try {
      const url = `${scheme}://${host}:${port}`;
      // Try getinfo
      const r = await fetch(`${url}/v1/getinfo`);
      if (r.status === 200) {
        const d = JSON.parse(r.text);
        return {
          lnd: true,
          scheme,
          port,
          alias: d.alias || '?',
          pubkey: (d.identity_pubkey || '?').slice(0, 16),
          channels: d.num_active_channels || 0,
          chains: (d.chains || []).map(c => c.network || '?'),
          macaroonRequired: false,
        };
      }
      // LND detected but needs macaroon
      if (r.status === 404 || r.status === 405) {
        try {
          const r2 = await fetch(`${url}/v1/state`);
          if (r2.status === 200) {
            const d2 = JSON.parse(r2.text);
            return {
              lnd: true,
              scheme,
              port,
              state: d2.state || '?',
              macaroonRequired: true,
            };
          }
        } catch (_) {}
        return {
          lnd: true,
          scheme,
          port,
          macaroonRequired: true,
        };
      }
    } catch (_) {}
  }
  return null;
}

// ── scanning engine ───────────────────────────────────────────────────────────

async function scanHost(host) {
  const result = { host };

  for (const port of BTCPAY_PORTS) {
    try {
      const info = await detectBTCPay(host, port);
      if (info) {
        Object.assign(result, info);
        break;
      }
    } catch (_) {}
  }

  for (const port of LND_PORTS) {
    try {
      const info = await checkLND(host, port);
      if (info) {
        Object.assign(result, info);
        break;
      }
    } catch (_) {}
  }

  return result;
}

async function scanTargets(targets, concurrency) {
  const results = [];
  let completed = 0;
  const total = targets.length;

  // Simple concurrency limiter
  const queue = [...targets];
  const workers = [];

  async function worker() {
    while (queue.length > 0) {
      const target = queue.shift();
      if (!target) break;
      try {
        const r = await scanHost(target);
        results.push(r);
        completed++;
        const status = [];
        if (r.btcpay) status.push(`BTCPay v${r.version || '?'}`);
        if (r.lnd) status.push(`LND(${r.macaroonRequired ? 'REQ' : 'OPEN'})`);
        process.stderr.write(`\r[${completed}/${total}] ${target} => ${status.join(', ') || '-'}    `);
      } catch (e) {
        results.push({ host: target, error: e.message });
        completed++;
        process.stderr.write(`\r[${completed}/${total}] ${target} => ERROR    `);
      }
    }
  }

  // Start workers
  for (let i = 0; i < Math.min(concurrency, targets.length); i++) {
    workers.push(worker());
  }

  await Promise.all(workers);
  process.stderr.write('\n');
  return results;
}

// ── CIDR expansion ────────────────────────────────────────────────────────────

function* cidrToIPs(cidr) {
  const [base, bits] = cidr.split('/');
  const parts = base.split('.').map(Number);
  const mask = ~((1 << (32 - parseInt(bits))) - 1);
  const start = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const networkStart = start & mask;
  const broadcast = networkStart | (~mask >>> 0);

  for (let i = networkStart + 1; i < broadcast; i++) {
    yield `${(i >>> 24) & 0xff}.${(i >>> 16) & 0xff}.${(i >>> 8) & 0xff}.${i & 0xff}`;
  }
}

// ── output formatting ─────────────────────────────────────────────────────────

function formatTable(results) {
  const lines = [];
  lines.push(`${'Host'.padEnd(30)} ${'BTCPay'.padEnd(8)} ${'Version'.padEnd(14)} ${'LND'.padEnd(14)} ${'MACAROON'.padEnd(8)}`);
  lines.push('-'.repeat(80));

  for (const r of results) {
    const host = (r.host || '?').slice(0, 29).padEnd(30);
    const btcpay = r.btcpay ? 'YES'.padEnd(8) : 'NO'.padEnd(8);
    const version = (r.version || '-').slice(0, 13).padEnd(14);
    const lnd = r.lnd ? (r.state || 'ACTIVE').padEnd(14) : '-'.padEnd(14);
    const mac = r.lnd ? (r.macaroonRequired ? 'REQ'.padEnd(8) : 'OPEN'.padEnd(8)) : '-'.padEnd(8);
    lines.push(`${host} ${btcpay} ${version} ${lnd} ${mac}`);
  }

  return lines.join('\n');
}

function formatJSON(results) {
  return JSON.stringify(results, null, 2);
}

function formatCSV(results) {
  const headers = ['host', 'btcpay', 'version', 'lnd', 'alias', 'state', 'macaroonRequired', 'port', 'error'];
  const lines = [headers.join(',')];
  for (const r of results) {
    lines.push([
      r.host || '', r.btcpay || false, r.version || '', r.lnd || false,
      r.alias || '', r.state || '', r.macaroonRequired || '',
      r.port || '', r.error || '',
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
  }
  return lines.join('\n');
}

// ── CLI ───────────────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    host: null,
    cidr: null,
    input: null,
    output: null,
    format: 'table',
    concurrency: DEFAULT_CONCURRENCY,
    timeout: DEFAULT_TIMEOUT,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--host': opts.host = args[++i]; break;
      case '--cidr': opts.cidr = args[++i]; break;
      case '--input': opts.input = args[++i]; break;
      case '--output': opts.output = args[++i]; break;
      case '--format': opts.format = args[++i]; break;
      case '--concurrency': opts.concurrency = parseInt(args[++i]); break;
      case '--timeout': opts.timeout = parseInt(args[++i]); break;
      case '--help':
        console.log(`BTCPay Server Scanner v1.0

Usage: node scanner.js [options]

Options:
  --host HOST           Single host to scan
  --cidr CIDR           CIDR range (e.g. 192.168.1.0/24)
  --input FILE          File with targets (one per line)
  --output FILE         Output file (default: stdout)
  --format FORMAT       json, csv, or table (default: table)
  --concurrency N       Max concurrent scans (default: 50)
  --timeout MS          Per-host timeout in ms (default: 10000)`);
        process.exit(0);
    }
  }
  return opts;
}

async function main() {
  const opts = parseArgs();
  const targets = [];

  if (opts.host) targets.push(opts.host.trim());
  if (opts.cidr) {
    for (const ip of cidrToIPs(opts.cidr)) {
      targets.push(ip);
    }
  }
  if (opts.input) {
    const content = fs.readFileSync(opts.input, 'utf8');
    content.split('\n').forEach(line => {
      line = line.trim();
      if (line && !line.startsWith('#')) targets.push(line);
    });
  }

  if (targets.length === 0) {
    console.error('No targets specified. Use --host, --cidr, or --input.');
    console.error('Run with --help for usage information.');
    process.exit(1);
  }

  console.error(`\n${'='.repeat(60)}`);
  console.error(`BTCPay Server Scanner v1.0`);
  console.error(`Targets: ${targets.length}`);
  console.error(`Concurrency: ${opts.concurrency}`);
  console.error(`${'='.repeat(60)}\n`);

  const startTime = Date.now();
  const results = await scanTargets(targets, opts.concurrency);
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  let output;
  switch (opts.format) {
    case 'json': output = formatJSON(results); break;
    case 'csv': output = formatCSV(results); break;
    default: output = formatTable(results);
  }

  if (opts.output) {
    fs.writeFileSync(opts.output, output);
    console.error(`\nResults saved to: ${opts.output}`);
  } else {
    console.log(`\n${output}`);
  }

  const foundBTCPay = results.filter(r => r.btcpay).length;
  const foundLND = results.filter(r => r.lnd).length;

  console.error(`\n${'='.repeat(60)}`);
  console.error(`Scan complete in ${elapsed}s`);
  console.error(`Hosts scanned: ${targets.length}`);
  console.error(`BTCPay found: ${foundBTCPay}`);
  console.error(`LND found: ${foundLND}`);
  console.error(`${'='.repeat(60)}`);
}

main().catch(e => {
  console.error('Error:', e.message);
  process.exit(1);
});
