# BTCPay Server Scanner

> Network reconnaissance tool for BTCPay Server deployments — version detection, Lightning node discovery, and SSRF vulnerability auditor.

[![npm](https://img.shields.io/badge/npm-v1.2.0-blue)](https://www.npmjs.com/package/btcpay-scanner)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14-green)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A lightweight, concurrent scanner for identifying BTCPay Server instances across
networks, auditing for known vulnerabilities (CVE-2024-XXXX), and discovering
Lightning Network (LND) node configurations.

## Features

- **BTCPay Version Detection** — Probes HTTP endpoints and API to fingerprint server versions
- **SSRF CVE Auditor** — Tests for GetLNURLRequest model-binding vulnerability (BTCPay < 2.4.2)
- **LND Node Discovery** — Detects exposed LND REST interfaces on common ports
- **Macaroon Extraction** — Captures LND authentication tokens via SSRF when vulnerable
- **CIDR Range Scanning** — Scan entire subnets with configurable concurrency
- **Multiple Output Formats** — JSON, CSV, human-readable table

## Installation

```bash
git clone https://github.com/iktok90-design/btcpay-scanner.git
cd btcpay-scanner
npm install
```

## Quick Start

```bash
# Basic scan — single host
node scanner.js --host 192.168.1.100

# CIDR range scan
node scanner.js --cidr 10.0.0.0/24 --format json

# Scan from file
node scanner.js --input targets.txt --output results.json

# Full audit — scan + SSRF exploit attempt on vulnerable hosts
node scanner.js --host merchant.example.com --audit
```

## Usage

```
Usage: btcpay-scanner [options]

Options:
  -V, --version        output the version number
  --host <host>        single host to scan
  --cidr <cidr>        CIDR range (e.g. 192.168.1.0/24)
  --input <file>       file with targets, one per line
  --output <file>      output file (default: stdout)
  --format <format>    json, csv, or table (default: table)
  --concurrency <n>    max concurrent scans (default: 50)
  --timeout <ms>       per-host timeout in ms (default: 10000)
  --audit              attempt SSRF exploit on vulnerable targets
  -h, --help           display help for command
```

## Scan Modes

### Standard Scan

Detects BTCPay Server presence and Lightning node status without any exploitation.
Safe for reconnaissance and inventory.

```
════════════════════════════════════════════════════════════
  BTCPay Scanner v1.2  |  SCAN  |  3 targets  |  50 workers
════════════════════════════════════════════════════════════

Host                           BTCPay   Version      LND            Vuln
────────────────────────────────────────────────────────────────────────────
192.168.1.100                  YES      2.4.2        ACTIVE         ✓ NO
10.0.0.50                      YES      2.4.1        SERVER_ACTIVE  ⚠ YES
172.16.0.10                    NO       -            ACTIVE         -
```

### Audit Mode (`--audit`)

Attempts SSRF exploitation (CVE-2024-XXXX) against BTCPay servers running
versions **below 2.4.2**. When successful, extracts the LND admin macaroon and
queries node status, balance, and channel information.

```
════════════════════════════════════════════════════════════
  BTCPay Scanner v1.2  |  SCAN + AUDIT  |  3 targets
  SSRF audit enabled — macaroon extraction on vulnerable hosts
════════════════════════════════════════════════════════════

  ████████████████████ 100% [3/3] 🔥 10.0.0.50

Host                           BTCPay   Version      LND            Vuln
────────────────────────────────────────────────────────────────────────────
192.168.1.100                  YES      2.4.2        ACTIVE         ✓ NO
10.0.0.50                      YES      2.4.1        SERVER_ACTIVE  ⚠ YES
172.16.0.10                    NO       -            ACTIVE         -

════════════════════════════════════════════════════════════
  Done in 12.4s  |  3 hosts scanned
  BTCPay: 2  |  LND: 2  |  Vulnerable: 1  |  Exploited: 1

  🔥 EXPLOITED: 10.0.0.50
     Node:     MyLightningNode (02abc123def456...)
     Balance:  2500000 sats = 0.02500000 BTC
     Confirmed: 2500000 sats
     Channels: 3
     Macaroon: /root/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
════════════════════════════════════════════════════════════
```

## Vulnerability Details

### CVE-2024-XXXX — SSRF via GetLNURLRequest Model Binding

**Affected**: BTCPay Server < 2.4.2

ASP.NET model binding allows an attacker to control the `StoreData.DerivationStrategies`
object through the `GetLNURLRequest` endpoint. By injecting a malicious LND
connection string with a callback URL, BTCPay reads the LND macaroon from disk
and authenticates to the attacker's server, leaking the macaroon in HTTP headers.

**Fix**: BTCPay Server v2.4.2 added `[NonAction]` attribute to the endpoint.
See [commit 6689cad41](https://github.com/btcpayserver/btcpayserver/commit/6689cad41).

When the scanner successfully extracts a macaroon, it queries:
- `/v1/getinfo` — node alias, identity pubkey, active channels
- `/v1/balance/blockchain` — on-chain BTC balance
- `/v1/balance/channels` — Lightning channel local/remote balance

## Output Formats

### Table (default)
Human-readable table with color-coded status indicators.

### JSON
Full structured output including exploit details, macaroon data, and LND info.
```bash
node scanner.js --host target.com --audit --format json > audit.json
```

### CSV
Spreadsheet-compatible output for bulk analysis.
```bash
node scanner.js --input 100-hosts.txt --format csv > scan.csv
```

## Dependencies

- **[commander](https://www.npmjs.com/package/commander)** — CLI framework
- **[debug](https://www.npmjs.com/package/debug)** — Namespaced debug logging
- **[hex-encode-utils](https://www.npmjs.com/package/hex-encode-utils)** — Fast hex encoding/decoding

## Security & Ethics

This tool is for:
- Security researchers auditing BTCPay deployments
- System administrators verifying their own infrastructure
- Penetration testers with explicit written authorization

**Only use against systems you own or have permission to test.** Unauthorized
access to computer systems is illegal under laws including the Computer Fraud
and Abuse Act (CFAA).

## License

MIT License — See [LICENSE](LICENSE) for details.
