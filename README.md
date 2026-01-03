<p align="center">
  <img src="ThirdEye.png" alt="ThirdEye Logo" width="400"/>
</p>

<h1 align="center">ThirdEye</h1>
<p align="center">
  Advanced OSINT & Google Dork Recon Tool for Bug Bounty Hunters
</p>

---

## About ThirdEye

ThirdEye is an advanced OSINT automation tool designed for penetration testers and bug bounty hunters to identify data exposure through indexed search engine results.

It performs:
- Search-based reconnaissance
- Sensitive file exposure detection
- Cloud & source code discovery
- Login/portal detection
- Subdomain enumeration via search
- Error & log exposure monitoring

ThirdEye automates the most powerful Google Dorks into categorized reconnaissance modules.

---

## Features

| Category | Capability |
|---------|------------|
| Git & Source Code | Detect public .git, repos, configuration leaks |
| Backup & Database | Search exposed `.sql`, `.bak`, `.zip`, `.gz` |
| Documents | Confidential HR/Finance docs indexed accidentally |
| Credentials | API keys, passwords, internal configs |
| Admin Panels | Dashboards, login portals, CMS access |
| Subdomains | Enumerate assets through search indexing |
| Errors & Misconfig | PHP, SQL, stack trace exposures |
| Cloud Buckets | AWS S3/GCP/Azure storage leaks |
| Monitoring Panels | Jenkins, Grafana, Kibana, etc. |
| Misc OSINT | LinkedIn employees, redirects, listings |

---

## Installation

### Requirements
- Python 3.8+
- `xnldorker`
- `tldextract`

### Setup

```bash
git clone https://github.com/BAHUBALISID/ThirdEye.git
cd ThirdEye
pip install -r requirements.txt
