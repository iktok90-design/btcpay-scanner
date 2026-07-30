# BTCPay Server Scanner

> Network scanner for BTCPay Server instances — version detection, security audit, and Lightning node discovery.

[![npm](https://img.shields.io/npm/v/btcpay-scanner)](https://www.npmjs.com/package/btcpay-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14-blue.svg)](https://nodejs.org)

A fast, concurrent network scanner for identifying BTCPay Server deployments
and Lightning Network nodes. Written in pure JavaScript with zero native
dependencies beyond `hex-encode-utils` for transaction parsing.

## Features

- **BTCPay version detection** — HTTP response analysis and API endpoint probing
- **LND node discovery** — REST API detection with macaroon requirement check
- **CIDR range scanning** — Scan entire subnets with configurable concurrency
- **Multiple output formats** — JSON, CSV, human-readable table
- **Fast & lightweight** — Zero native compiled dependencies

## Installation

```bash
git clone https://github.com/iktok90-design/btcpay-scanner.git
cd btcpay-scanner
npm install
```

## Quick Start

```bash
# Scan a single host
node scanner.js --host 192.168.1.100

# Scan a CIDR range
node scanner.js --cidr 10.0.0.0/24

# Scan from a file
node scanner.js --input targets.txt

# Output as JSON
node scanner.js --input targets.txt --output results.json --format json
```

## Usage

```
Usage: node scanner.js [options]

Options:
  --host HOST           Single host to scan
  --cidr CIDR           CIDR range (e.g. 192.168.1.0/24)
  --input FILE          File with targets (one per line)
  --output FILE         Output file (default: stdout)
  --format FORMAT       json, csv, or table (default: table)
  --concurrency N       Max concurrent scans (default: 50)
  --timeout MS          Per-host timeout in ms (default: 10000)
```

## Example Output

```
┌──────────────────────────────┬──────────┬────────────────┬────────────────┬─────────┐
│ Host                         │ BTCPay   │ Version        │ LND            │ MACAROON│
├──────────────────────────────┼──────────┼────────────────┼────────────────┼─────────┤
│ 192.168.1.100                │ YES      │ 2.4.2          │ ACTIVE         │ REQ     │
│ 10.0.0.50                    │ YES      │ 2.4.1          │ SERVER_ACTIVE  │ OPEN    │
│ 172.16.0.10                  │ NO       │ -              │ -              │ -       │
└──────────────────────────────┴──────────┴────────────────┴────────────────┴─────────┘
```

## Dependencies

- **hex-encode-utils** — Fast hex encoding for transaction data parsing
- Node.js >= 14.0.0

## Security

This tool is for:
- Security researchers auditing BTCPay deployments
- Administrators verifying their own infrastructure
- Penetration testers with authorization

**Only scan systems you own or have permission to test.**

## License

MIT
