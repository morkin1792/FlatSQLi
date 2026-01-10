# 💉 FlatSQLi

![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)
![Release](https://img.shields.io/badge/release-v1.0.0-blue.svg?style=flat-square)

A lightweight, boolean-based SQL injection exploitation tool designed for stealth and efficiency.

> **Why another SQLi tool?**
>
> 1.  🤫 **Quiet Detection**: Avoiding WAF blocks with low-noise scanning.
> 2.  🎯 **Specific Exploitation**: Automating the painful boolean-based extraction when `sqlmap` fails or is too noisy.

---

## ✨ Features

- 🕵️ **Low-Noise Detections**: Detect potential SQLi vulnerabilities considering the existence of WAFs.
- 🔑 **Critical Data Finder**: Smartly locates sensitive columns (`password`, `email`, `token`) automatically.
- ⚡ **Binary Search Extraction**: Extracts data bit-by-bit using binary search for maximum speed.
- 🧠 **Smart Caching**: Remembers database fingerprints per host to save requests.
- 🌐 **Multi-Database Support**: MySQL, MSSQL, PostgreSQL, Oracle.
- 🔌 **Proxy Support**: Easy integration with Burp Suite, Zap, or mitmproxy.

## 📦 Installation

```bash
go install github.com/morkin1792/flatsqli@latest
```

```bash
# or
# git clone https://github.com/morkin1792/flatsqli.git && cd flatsqli && go build -o flatsqli .
```

## 🚀 Quick Start

### 1. Detect SQLi Vulnerabilities 🔍

- From a list of URLs:
```bash
flatsqli detect -uf urls.txt -o results.md
```

- From raw request files:
```bash
flatsqli detect -rd requests/ -o results.md -v
```

### 2. Exploit Boolean-Based SQLi 💉

- Find sensitive data automatically (Recommended):
```bash
flatsqli exploit -rf req.txt -fid -o output.md
```

## 🛠️ Usage

```bash

❯ ./flatsqli --help       
  _____ _       _   ____   ___  _     _ 
 |  ___| | __ _| |_/ ___| / _ \| |   (_)
 | |_  | |/ _` | __\___ \| | | | |   | |
 |  _| | | (_| | |_ ___) | |_| | |___| |
 |_|   |_|\__,_|\__|____/ \__\_\_____|_|
                                         
         SQLi Exploitation Tool v1.0.0
                Lightweight & WAF-Friendly

Usage: flatsqli <command> [options]

Commands:
  exploit    Exploit a confirmed SQLi vulnerability to extract data
  detect     Detect potential SQLi vulnerabilities in URLs or requests

Run 'flatsqli <command> --help' for more information on a specific command.

General Options:
  -o, -output <file>       Output file path (markdown format)
  -H, -header <header>     Custom header (can be used multiple times)
  -proxy <url>             Proxy URL (e.g., http://127.0.0.1:8080)
  -timeout <seconds>       Request timeout in seconds (default: 10)
  -ph, -plain-http         Use plain HTTP instead of HTTPS
  -v, -verbose             Enable verbose output

Examples:
  flatsqli exploit -rf req.txt -fid -o output.md
  flatsqli detect -uf urls.txt -o results.md
  flatsqli detect -rd requests/ -v

```
