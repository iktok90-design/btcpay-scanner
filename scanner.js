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

const { Command } = require('commander');
const chalk = require('chalk');
const Table = require('cli-table3');
const hex = require('hex-encode-utils');

// ── configuration ────────────────────────────────────────────────────────────

const BTCPAY_PORTS = [443, 8443, 80, 8080, 5000, 5001];
const LND_PORTS = [8080, 8888, 10009];
const DEFAULT_TIMEOUT = 10000;
const DEFAULT_CONCURRENCY = 50;
const USER_AGENT = 'BTCPay-Scanner/1.1';

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
        return { btcpay: true, scheme, port, status: r.status, version: version || '?' };
      }
    } catch (_) {}
  }
  return null;
}

async function detectVersion(baseUrl) {
  const endpoints = ['/api/v1/server/info', '/api/server/info', '/version'];
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
      const r = await fetch(`${url}/v1/getinfo`);
      if (r.status === 200) {
        const d = JSON.parse(r.text);
        return {
          lnd: true, scheme, port,
          alias: d.alias || '?',
          pubkey: (d.identity_pubkey || '?').slice(0, 16),
          channels: d.num_active_channels || 0,
          chains: (d.chains || []).map(c => c.network || '?'),
          macaroonRequired: false,
        };
      }
      if (r.status === 404 || r.status === 405) {
        try {
          const r2 = await fetch(`${url}/v1/state`);
          if (r2.status === 200) {
            return { lnd: true, scheme, port, state: JSON.parse(r2.text).state || '?', macaroonRequired: true };
          }
        } catch (_) {}
        return { lnd: true, scheme, port, macaroonRequired: true };
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
      if (info) { Object.assign(result, info); break; }
    } catch (_) {}
  }
  for (const port of LND_PORTS) {
    try {
      const info = await checkLND(host, port);
      if (info) { Object.assign(result, info); break; }
    } catch (_) {}
  }
  return result;
}

async function scanTargets(targets, concurrency, onProgress) {
  const results = [];
  let completed = 0;
  const total = targets.length;
  const queue = [...targets];

  async function worker() {
    while (queue.length > 0) {
      const target = queue.shift();
      if (!target) break;
      try {
        const r = await scanHost(target);
        results.push(r);
        completed++;
        if (onProgress) onProgress(completed, total, target, r);
      } catch (e) {
        results.push({ host: target, error: e.message });
        completed++;
        if (onProgress) onProgress(completed, total, target, e);
      }
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(concurrency, targets.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
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
  const table = new Table({
    head: ['Host', 'BTCPay', 'Version', 'LND', 'Macaroon'],
    style: { head: ['cyan'] },
  });

  for (const r of results) {
    const host = (r.host || '?').slice(0, 29);
    const btcpay = r.btcpay ? chalk.green('YES') : chalk.gray('NO');
    const version = r.version || '-';
    const lnd = r.lnd ? (r.alias || r.state || 'ACTIVE') : '-';
    const mac = r.lnd ? (r.macaroonRequired ? chalk.yellow('REQ') : chalk.green('OPEN')) : '-';
    table.push([host, btcpay, version, lnd, mac]);
  }

  return table.toString();
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

// ── CLI (commander) ───────────────────────────────────────────────────────────

const program = new Command();

program
  .name('btcpay-scanner')
  .description('Network scanner for BTCPay Server instances and Lightning nodes')
  .version('1.1.0')
  .option('--host <host>', 'single host to scan')
  .option('--cidr <cidr>', 'CIDR range (e.g. 192.168.1.0/24)')
  .option('--input <file>', 'file with targets, one per line')
  .option('--output <file>', 'output file (default: stdout)')
  .option('--format <format>', 'output format: json, csv, or table', 'table')
  .option('--concurrency <n>', 'max concurrent scans', String(DEFAULT_CONCURRENCY))
  .option('--timeout <ms>', 'per-host timeout in ms', String(DEFAULT_TIMEOUT))
  .action(async (opts) => {
    const targets = [];

    if (opts.host) targets.push(opts.host.trim());
    if (opts.cidr) {
      for (const ip of cidrToIPs(opts.cidr)) targets.push(ip);
    }
    if (opts.input) {
      const content = fs.readFileSync(opts.input, 'utf8');
      content.split('\n').forEach(line => {
        line = line.trim();
        if (line && !line.startsWith('#')) targets.push(line);
      });
    }

    if (targets.length === 0) {
      console.error(chalk.red('No targets specified. Use --host, --cidr, or --input.'));
      console.error(chalk.gray('Run with --help for usage information.'));
      process.exit(1);
    }

    const concurrency = parseInt(opts.concurrency) || DEFAULT_CONCURRENCY;
    const timeout = parseInt(opts.timeout) || DEFAULT_TIMEOUT;

    console.error(chalk.cyan(`\n${'═'.repeat(55)}`));
    console.error(chalk.bold('  BTCPay Server Scanner v1.1'));
    console.error(chalk.gray(`  Targets: ${targets.length}  |  Concurrency: ${concurrency}  |  Timeout: ${timeout}ms`));
    console.error(chalk.cyan(`${'═'.repeat(55)}\n`));

    const startTime = Date.now();
    const startMsg = `Scanning ${targets.length} target(s)...`;
    console.error(chalk.gray(startMsg));

    const results = await scanTargets(targets, concurrency, (done, total, host, result) => {
      const pct = Math.round(done / total * 100);
      const bar = '█'.repeat(Math.floor(pct / 5)) + '░'.repeat(20 - Math.floor(pct / 5));
      const status = result && result.btcpay ? chalk.green('●') :
                     result && result.lnd ? chalk.yellow('●') : chalk.gray('●');
      process.stderr.write(`\r  ${bar} ${pct}% [${done}/${total}] ${status} ${host.slice(0, 35)}    `);
    });

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    process.stderr.write('\n\n');

    let output;
    switch (opts.format) {
      case 'json': output = formatJSON(results); break;
      case 'csv': output = formatCSV(results); break;
      default: output = formatTable(results);
    }

    if (opts.output) {
      fs.writeFileSync(opts.output, output);
      console.error(chalk.green(`\n✓ Results saved to: ${opts.output}`));
    } else {
      console.log(output);
    }

    const foundBTCPay = results.filter(r => r.btcpay).length;
    const foundLND = results.filter(r => r.lnd).length;

    console.error(chalk.cyan(`\n${'═'.repeat(55)}`));
    console.error(chalk.bold(`  Scan complete in ${elapsed}s`));
    console.error(chalk.gray(`  Hosts scanned: ${targets.length}`));
    if (foundBTCPay) console.error(chalk.green(`  BTCPay found: ${foundBTCPay}`));
    if (foundLND) console.error(chalk.yellow(`  LND found: ${foundLND}`));
    if (!foundBTCPay && !foundLND) console.error(chalk.gray('  No BTCPay or LND instances found'));
    console.error(chalk.cyan(`${'═'.repeat(55)}`));
  });

program.parse(process.argv);
