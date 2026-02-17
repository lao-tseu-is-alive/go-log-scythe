# 🛡️ GoLogScythe
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=lao-tseu-is-alive_go-log-scythe&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=lao-tseu-is-alive_go-log-scythe)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=lao-tseu-is-alive_go-log-scythe&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=lao-tseu-is-alive_go-log-scythe)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=lao-tseu-is-alive_go-log-scythe&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=lao-tseu-is-alive_go-log-scythe)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=lao-tseu-is-alive_go-log-scythe&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=lao-tseu-is-alive_go-log-scythe)

[![cve-trivy-scan](https://github.com/lao-tseu-is-alive/go-log-scythe/actions/workflows/cve-trivy-scan.yml/badge.svg)](https://github.com/lao-tseu-is-alive/go-log-scythe/actions/workflows/cve-trivy-scan.yml)


**GoLogScythe** is a high-performance, zero-dependency intelligent real-time web log
security daemon written in Go. 
It harvests malicious IP addresses from your web server logs (Nginx/Apache) 
and banishes them to the kernel-level void using `nftables` Sets. 
It uses a configurable weighted threat scoring and binary probe detection.

Unlike legacy tools or shell scripts, **LogScythe** uses lookup tables, meaning it can ban 100,000 parasites with the same near-zero CPU impact as banning just one.

---

## ✨ Features

* **Zero Dependencies:** Pure Go standard library. No `tail` libraries, no bloat.
* **High Performance:** Leverages `nftables` Sets for constant-time packet filtering.
* **Thread-Safe:** LRU cache uses internal `RWMutex` — safe under concurrent access.
* **Weighted Scoring System:** Assign different threat levels to different URL patterns via `rules.conf`, with per-hit score clamping for safety.
* **Binary Probe Detection:** Automatically detects and instantly bans RDP, TLS, SMB protocol probes sent to web ports.
* **IPv6 Normalization:** Canonical IP representation prevents duplicate tracking of the same address.
* **Repeat Penalty:** Reduces score for repeated requests to the same path (attackers hammering one URL).
* **Safety First:** Automatic whitelisting of your current SSH session, localhost, and existing UFW rules.
* **Dual-Regex Fallback:** Intelligent parsing logic that supports Nginx and Apache formats out of the box.
* **Custom Log Format Support:** Override the default regex via `REGEX_OVERRIDE` to parse JSON, syslog, or any custom log format.
* **Nftables Range Pre-Check:** Automatically detects IPs already covered by broad CIDR ranges in your `nftables.conf`, skipping redundant kernel commands and warning about potential nftables service issues (v0.3.1+).
* **Persistence:** Bans survive reboots via a local state file and automatic kernel re-synchronization.
* **Preview Mode:** Test your configuration against live logs without actually triggering firewall actions.
* **Environment Driven:** Fully configurable via `.env` or system environment variables.

> See [CHANGELOG.md](CHANGELOG.md) for the full release history.

---
![](https://raw.githubusercontent.com/lao-tseu-is-alive/go-log-scythe/refs/heads/main/images/goLogScythe.jpg)

---

## 🎯 When to Use GoLogScythe (Threat Model)

GoLogScythe is purpose-built for a specific threat profile. Understanding **what it protects against** — and **what it doesn't** — is critical for effective use.

### ✅ GoLogScythe IS Designed For

| Threat | Description |
|--------|-------------|
| **Automated scanners** | Bots probing for `/wp-admin`, `.env`, `.git/`, `phpinfo.php`, etc. |
| **Vulnerability probers** | Requests attempting directory traversal (`../`), SQL injection, XSS, and shell uploads |
| **Binary protocol probes** | RDP, TLS, SMB probes sent to web ports (port 80/443) — instant ban |
| **Credential stuffers** | Bots hammering login endpoints generating 4xx errors |
| **Reconnaissance** | Automated enumeration of sensitive files (`/etc/passwd`, `.htpasswd`, backups) |

### ❌ GoLogScythe Is NOT Designed For

| Scenario | Why | Use Instead |
|----------|-----|-------------|
| **DDoS / volumetric attacks** | Attackers can overwhelm before being banned; log-based detection is too slow at volume | Cloudflare, AWS Shield, rate-limiting at the CDN/load-balancer level |
| **Application-layer exploits** | Exploits against valid endpoints returning 200 are invisible to log-based scoring | A Web Application Firewall (WAF) like ModSecurity |
| **Authenticated abuse** | Malicious actions from logged-in users don't generate 4xx errors | Application-level anomaly detection |
| **IP spoofing** | Attackers using spoofed source IPs could trigger bans on innocent IPs | Network-layer protections (BCP38, uRPF) |
| **Distributed botnets** | Thousands of IPs each sending a single request won't breach the threshold | Reputation-based blocklists (e.g., AbuseIPDB, Spamhaus) |

> [!IMPORTANT]
> GoLogScythe is a **supplement** to your security stack — not a replacement for a WAF, CDN, or IDS. Think of it as an automated, real-time `fail2ban` alternative with better performance and kernel-level blocking.

### Ideal Deployment

GoLogScythe works best as a **layer in a defense-in-depth** strategy:

```
Internet → CDN/DDoS Shield → Reverse Proxy (Nginx) → GoLogScythe → nftables kernel drop
```

---

## 🎯 Weighted Scoring System (v0.2.0+)

GoLogScythe uses an intelligent weighted scoring system instead of simple request counting.
All scores are **clamped to a maximum of 20.0 per hit** (v0.3.0+) to prevent misconfigured rules from causing instant bans:

| Threat Level | Score | Examples |
|--------------|-------|----------|
| **Low** | 0.1 | favicon.ico, robots.txt, fonts |
| **Default** | 1.0 | Unmatched paths (standard 404s) |
| **High** | 5.0 | .env, wp-config.php, .git/, phpinfo.php |
| **Critical** | 10.0 | Directory traversal, SQL injection, shell uploads |
| **Binary Probe** | 12.666 | RDP/TLS/SMB probes (empty HTTP method) |
| **Max per hit** | 20.0 | Clamped ceiling — no single hit exceeds this |

### Externalized Rules (`rules.conf`)

Define your threat detection patterns in `rules.conf`:

```conf
# Format: <score> <regex_pattern>
# Lines starting with # are comments
# Score determines threat level (higher = more dangerous)
# Patterns are matched against the requested URL path
# Unmatched paths receive a default score of 1.0

# ============================================
# LOW PRIORITY (0.1-0.5) - Common benign files
# ============================================
0.1   ^/favicon\.ico$
0.1   ^/robots\.txt$
0.2   ^/sitemap\.xml$
0.1   ^/apple-touch-icon
0.1   \.woff2?$
0.1   \.ttf$

# ============================================
# HIGH PRIORITY (5.0) - Sensitive files/paths
# ============================================
5.0   \.env$                 # Environment files with secrets
5.0   /wp-config\.php        # WordPress database credentials
5.0   /config\.php$          # Generic config files
5.0   /\.git/                # Git repository exposure
5.0   /\.svn/                # SVN repository exposure
5.0   /\.ssh/                # SSH key exposure
5.0   /\.htaccess$           # Apache access control
5.0   /\.htpasswd$           # Apache password files
5.0   /phpinfo\.php$         # PHP info exposure
5.0   /phpmyadmin            # Database admin panels
5.0   /adminer               # Alternative DB admin
5.0   /wp-admin/             # WordPress admin
5.0   /wp-includes/          # WordPress internals
5.0   /server-status$        # Apache server status
5.0   /\.DS_Store$           # macOS metadata leak
5.0   \.sql$                 # Database dumps
5.0   \.bak$                 # Backup files
5.0   \.old$                 # Old file copies
5.0   \.backup$              # Backup files
5.0   \.log$                 # Log file exposure

# ============================================
# CRITICAL PRIORITY (10.0) - Instant ban worthy
# ============================================
10.0  \.\./                  # Directory traversal (unix)
10.0  \.\.\\                 # Directory traversal (windows)
10.0  /etc/passwd            # Unix password file
10.0  /etc/shadow            # Unix shadow password
10.0  /proc/self             # Linux proc filesystem
10.0  /proc/version          # Linux version info
10.0  <script>               # XSS attempt in path
10.0  %3Cscript%3E           # URL-encoded XSS
10.0  UNION\+SELECT          # SQL injection
10.0  UNION%20SELECT         # URL-encoded SQL injection
10.0  /shell\.php            # Web shell
10.0  /cmd\.php              # Command execution
10.0  /eval-stdin\.php       # Eval shell
10.0  /c99\.php              # C99 web shell
10.0  /r57\.php              # R57 web shell
10.0  /alfa\.php             # Alfa web shell
10.0  /cgi-bin/.*\.sh$       # Shell script execution

# ============================================
# CUSTOM: Add your own patterns below
# ============================================
# API-specific examples:
# 5.0   /api/v1/admin         # Admin API endpoints
# 8.0   /api/.*\.\.           # API path traversal
# 3.0   /graphql$             # GraphQL endpoint probing

# CMS-specific examples:
# 5.0   /wp-json/wp/v2/users  # WordPress user enumeration
# 5.0   /xmlrpc\.php          # WordPress XML-RPC abuse
# 5.0   /administrator/       # Joomla admin
# 5.0   /user/login$          # Drupal login
```

---

## 🔐 Binary Probe Detection

Attackers often send binary protocol probes to web ports hoping to find exposed services:

| Probe Type | Pattern | Detection |
|------------|---------|-----------|
| **RDP** | `\x03\x00\x00/*\xE0...mstshash=Administr` | Instant ban |
| **TLS Handshake** | `\x16\x03\x01...` | Instant ban |
| **SMB** | `\x00\x00\x00\xFFSMB...` | Instant ban |

These requests result in 400 errors with empty/garbage HTTP methods. GoLogScythe automatically detects and bans them.

---

## 🚀 Quick Start

### 1. Prerequisites (nftables)

LogScythe requires a modern Linux system with `nftables`. 

Ensure your `/etc/nftables.conf` is set up to handle the `parasites` set:


### ⚠️ ⚠️ You must edit your own version of `/etc/nftables.conf`  

**this is VERY important if your are working on a remote server via SSH, ensure that your external IP is in the whitelist file before using this or you may ban yourself from accessing your remote server** 

*the code of goLogScythe will try to detect your own ssh session IP and add it to your WHITELIST file, but you are responsible of your choices, and this should be configured and double checked by you !*

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	# 1. Parasite Set for ipv4 (Used by  goLogScythe Tool)
	set parasites {
          type ipv4_addr
          flags interval
    }
    # 1. Parasite Set for ipv6 (Used by  goLogScythe Tool)
    set parasites6 {
        type ipv6_addr
        flags interval
    }
	chain input {
		type filter hook input priority 0; policy drop;
		# 2. Early Drop: Block parasites before anything else
	        ip saddr @parasites drop
	        ip6 saddr @parasites6 drop

        	# 3. Allow Loopback (essential)
	        iif "lo" accept

		# 4. Allow essential IPv4 + IPv6 ICMP (after loopback, before established)
		ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept
		icmpv6 type { echo-request, echo-reply, packet-too-big, destination-unreachable, time-exceeded, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept

        	# 5. Allow Established (Already connected traffic)
	        ct state established,related accept

        	# 6. ⚠️⚠️ Double check to add your own rules here !
	        tcp dport 22 ip saddr 192.168.50.7 accept comment "YOUR BASTION IP SSH"

        	tcp dport { 80, 443 } accept comment "for Nginx HTTP/S"

	}
	chain forward {
		type filter hook forward priority filter;
	}
	chain output {
		type filter hook output priority filter;
	}
}


```

*Check syntax and apply with:*

    sudo nft --check -f /etc/nftables.conf
    sudo nft -f /etc/nftables.conf

    

### 2. Installation

##### Option 1. Installation from source if you have Go installed
```bash
git clone https://github.com/lao-tseu-is-alive/go-log-scythe.git
cd go-log-scythe
go build -o goLogScythe ./cmd/goLogScythe/

```
##### Option 2. Installation from the releases pages

Navigate to  https://github.com/lao-tseu-is-alive/go-log-scythe/releases
and download the latest version for your Linux architecture.

### 3. Configuration

Create a `.env` file or export the variables:

```bash
# Log to monitor
LOG_PATH="/var/log/nginx/access.log"

# Rules configuration (weighted scoring)
RULES_PATH="./rules.conf"

# Thresholds
BAN_THRESHOLD=10        # Score threshold (not count!)
REPEAT_PENALTY=0.1      # 10% score for repeated path hits
BAN_WINDOW="15m"

# Security
PREVIEW_MODE=true  # Set to false once you verify matches

```

---

## 🔍 Preview Mode

Before going live, run LogScythe in **Preview Mode**. This will show you exactly which IPs would be banned based on your current log activity without modifying your firewall:

```bash
sudo PREVIEW_MODE=true SCAN_ALL_MODE=true ./goLogScythe

```

*Output:*
```
📋 Loaded 43 threat detection rules from ./rules.conf
📖 Scanning /var/log/nginx/access.log...
📊 Scan Results:
   Total lines: 686
   Parsed OK: 685
   4xx errors: 605
   IPs exceeding threshold (10.0): 17
👀 [PREVIEW] Would ban: 45.148.10.160 (score: 327.7)
👀 [PREVIEW] Would ban: 80.94.95.221 (score: 11.0)  ← RDP probe detected!
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_PATH` | `/var/log/nginx/access.log` | Path to the web log file to monitor |
| `WHITE_LIST_PATH` | `./whitelist.txt` | File containing IPs/CIDRs that should never be banned |
| `BANNED_FILE_PATH` | `./banned_ips.txt` | Persistence file for banned IPs |
| `RULES_PATH` | `""` | Path to `rules.conf` for weighted scoring (empty = backward compatible) |
| `BAN_THRESHOLD` | `10.0` | **Score** threshold before a ban is issued |
| `REPEAT_PENALTY` | `0.1` | Score multiplier for repeat requests to same path (10% = less spam score) |
| `BAN_WINDOW` | `15m` | Sliding window duration for score tracking |
| `NFT_SET_NAME` | `parasites` | The name of the nftables set for IPv4 |
| `NFT_SET_NAME_V6` | `parasites6` | The name of the nftables set for IPv6 |
| `NFTABLES_CONF_PATH` | `/etc/nftables.conf` | Path to nftables config for CIDR range pre-check (v0.3.1+) |
| `CACHE_CAPACITY` | `10000` | Maximum number of visitor IPs tracked simultaneously (v0.3.0+) |
| `REGEX_OVERRIDE` | `""` | Custom regex for log parsing (see [Custom Log Formats](#-custom-log-formats-regex_override)) |
| `PREVIEW_MODE` | `false` | If true, logs actions but skips firewall commands (clears banned map on start) |
| `SCAN_ALL_MODE` | `false` | If true, scans the entire log file at startup |

---

## 📝 Custom Log Formats (`REGEX_OVERRIDE`)

By default, GoLogScythe uses a regex designed for the **Combined Log Format** (Nginx / Apache):

```
192.168.1.1 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123
```

This default regex (`defaultLogRegex`) uses `(?s)` to gracefully handle binary garbage and malformed requests. However, if your web server uses a **custom log format** (JSON, syslog, or a custom template), you can override the parsing regex via the `REGEX_OVERRIDE` environment variable.

### Regex Requirements

Your custom regex **must** capture exactly **3 groups** in this order:

| Group | Content | Example |
|-------|---------|---------|
| **Group 1** | Client IP address | `192.168.1.50` |
| **Group 2** | Requested URL path | `/admin/login` |
| **Group 3** | HTTP status code | `404` |

> [!WARNING]
> If `REGEX_OVERRIDE` is set but produces an invalid regex, GoLogScythe will **exit with a fatal error** at startup. Always test your regex with `PREVIEW_MODE=true` first.

### Example: JSON Logs

If Nginx is configured with a JSON log format:

```nginx
log_format json_combined escape=json
  '{"remote_addr":"$remote_addr","request":"$request","status":$status}';
```

Producing lines like:

```json
{"remote_addr":"192.168.1.50","request":"GET /admin HTTP/1.1","status":404}
```

Use this override:

```bash
REGEX_OVERRIDE='"remote_addr":"([^"]+)".*?"request":"\\S+\\s+(\\S+)\\s+.*?"status":(\\d{3})'
```

### Example: Custom Nginx Fields

For a `log_format` using tab-separated fields like:

```
$remote_addr\t$status\t$request_uri\t$time_local
```

Producing: `192.168.1.50\t404\t/wp-admin\t16/Jan/2026:10:00:00`

```bash
REGEX_OVERRIDE='^(\\S+)\\t(\\d{3})\\t(\\S+)\\t'
```

> [!NOTE]
> In the tab-separated example above, the capture groups are `IP`, `status`, `path` — but GoLogScythe expects the order `IP`, `path`, `status`. You would need to reorder your log fields to match, or restructure to produce them in the right order.

### Example: Syslog-Prefixed Logs

If your logs have a syslog prefix before the standard combined format:

```
Jan 16 10:00:00 myserver nginx: 192.168.1.50 - - [16/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123
```

```bash
REGEX_OVERRIDE='nginx:\\s+(\\S+)\\s+-\\s+-\\s+\\[.*?\\]\\s+"\\S+\\s+(\\S+)\\s+.*?"\\s+(\\d{3})'
```

### Testing Your Override

Always test with Preview + Scan All mode first:

```bash
sudo REGEX_OVERRIDE='your_regex_here' PREVIEW_MODE=true SCAN_ALL_MODE=true ./goLogScythe
```

Check the output: if `Parsed OK` is 0, your regex doesn't match the log lines.

---


## 🛠️ Deployment (Systemd)

To run **LogScythe** as a background service on your VPS, create `/etc/systemd/system/go-log-scythe.service`:

```ini
[Unit]
Description=GoLogScythe - High-performance Log Security Daemon
After=network.target nftables.service

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/go-log-scythe
ExecStart=/usr/local/bin/goLogScythe-linux-amd64
Restart=always
RestartSec=5

# Load configuration
EnvironmentFile=/etc/go-log-scythe/config.env

# Hardening attributes
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
ReadOnlyPaths=/var/log/nginx/

[Install]
WantedBy=multi-user.target

```

```bash
sudo systemctl enable --now go-log-scythe

```

---

## 📊 Monitoring

To see the live list of banned parasites in your kernel:

```bash
sudo nft list set inet filter parasites

```

To see the service logs:

```bash
journalctl -u go-log-scythe -f

```

---

## 🤝 Contributing

Help us get rid of parasites! If you have a better regex for a specific web server, new threat patterns for `rules.conf`, or a performance tweak, feel free to open a PR.

**LogScythe** — *Clean logs. Fast servers. No parasites.*