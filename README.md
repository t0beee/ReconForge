<<<<<<< HEAD
# 🔍 ReconForge v1.0 — Intelligent Attack Surface Mapper

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/Version-5.0-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> Clean, professional recon tool. One command → full attack surface map → ONE .txt + ONE .html report.

---

## ⚡ Install & Run

```bash
git clone https://github.com/t0beee/ReconForge.git
cd ReconForge
pip install -r requirements.txt
python reconforge.py example.com --all
```

---

## 🛠️ Usage

```bash
python reconforge.py <domain> [modules] [options]
```

### Module Flags

| Flag | Description |
|------|-------------|
| `--all` | Run EVERYTHING |
| `-s` | Subdomain enumeration (200+ wordlist) |
| `-p` | Port scan (20 ports with risk rating) |
| `-w` | WHOIS lookup |
| `-d` | Directory bruteforce (100+ dirs) |
| `--waf` | WAF/firewall detection |
| `--ssl` | SSL certificate inspection |
| `--geoip` | GeoIP location |
| `--robots` | robots.txt & sitemap |
| `--wordpress` | WordPress deep scan |
| `--php` | PHP file enumeration |

### Options

| Flag | Description |
|------|-------------|
| `-o NAME` | Custom output filename |
| `--timeout SEC` | Request timeout (default: 3s) |
| `--delay SEC` | Delay between requests (stealth) |
| `--silent` | Minimal output |
| `--json` | Also save JSON |
| `--no-ai` | Skip AI analysis |
| `--no-history` | Skip historical diff |
| `-f FILE` | Scan multiple targets from file |
| `--version` | Show version |

---

## 💡 Examples

```bash
# Full scan
python reconforge.py example.com --all

# Subdomains + Ports only
python reconforge.py example.com -s -p

# WHOIS + SSL + WAF
python reconforge.py example.com -w --ssl --waf

# Stealth (1s delay between requests)
python reconforge.py example.com --all --delay 1

# Silent + custom output name
python reconforge.py example.com --all --silent -o my_report

# Multiple targets from file
python reconforge.py -f targets.txt --all
```

---

## 🤖 AI Analysis Setup (Optional)

```bash
# Windows
set ANTHROPIC_API_KEY=your_key_here

# Linux / Mac
export ANTHROPIC_API_KEY=your_key_here
```

Then run normally — AI analysis activates automatically.

---

## 📊 Output

Every scan saves exactly **2 files**:

| File | Description |
|------|-------------|
| `reconforge_domain_date.txt` | Full detailed plain-text report |
| `reconforge_domain_date.html` | Professional dark-theme visual report |

---

## 🚀 What It Scans

| Module | Details |
|--------|---------|
| DNS Records | A, AAAA, MX, NS, TXT, CNAME, SOA |
| GeoIP | Country, city, ISP, ASN, hosting detection |
| WHOIS | Registrar, dates, nameservers |
| SSL/TLS | Validity, expiry countdown, weak ciphers, SANs |
| WAF | Cloudflare, Akamai, Sucuri, Imperva, F5, Barracuda... |
| Subdomains | 200+ wordlist DNS bruteforce with progress bar |
| Ports | 20 ports with service + risk rating (CRITICAL/HIGH/MEDIUM/LOW) |
| HTTP Headers | Security header audit + score % + cookie flags |
| robots.txt | Disallowed paths, interesting endpoints |
| WordPress | Version, theme, plugins, XML-RPC, user enum, exposed paths |
| PHP Files | 60+ files including shells, admin panels, configs |
| Directories | 100+ common directories |
| Risk Scoring | CVSS-inspired severity for every finding |
| AI Analysis | Claude-powered attack vector prioritization |
| History Diff | What changed since your last scan |

---

## ⚠️ Legal Disclaimer

For **authorized security assessments only**.
Only scan systems you **own** or have **explicit written permission** to test.

---

<p align="center">ReconForge v5.0 — Built for serious ethical security work 🔐</p>
=======
# ReconForge
Intelligent Attack Surface Mapper — Pentesting Tool
>>>>>>> 64e5805b78253ec2e54ef95d60170d2b4d4c690b
