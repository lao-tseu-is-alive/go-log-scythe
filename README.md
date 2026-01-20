# 🛡️ GoLogScythe

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
* **Weighted Scoring System:** Assign different threat levels to different URL patterns via `rules.conf`.
* **Binary Probe Detection:** Automatically detects and instantly bans RDP, TLS, SMB protocol probes sent to web ports.
* **Repeat Penalty:** Reduces score for repeated requests to the same path (attackers hammering one URL).
* **Safety First:** Automatic whitelisting of your current SSH session, localhost, and existing UFW rules.
* **Dual-Regex Fallback:** Intelligent parsing logic that supports Nginx and Apache formats out of the box.
* **Persistence:** Bans survive reboots via a local state file and automatic kernel re-synchronization.
* **Preview Mode:** Test your configuration against live logs without actually triggering firewall actions.
* **Environment Driven:** Fully configurable via `.env` or system environment variables.

---
![](https://raw.githubusercontent.com/lao-tseu-is-alive/go-log-scythe/refs/heads/main/images/goLogScythe.jpg)

## 🎯 Weighted Scoring System (v0.2.0+)

GoLogScythe uses an intelligent weighted scoring system instead of simple request counting:

| Threat Level | Score | Examples |
|--------------|-------|----------|
| **Low** | 0.1 | favicon.ico, robots.txt, fonts |
| **Default** | 1.0 | Unmatched paths (standard 404s) |
| **High** | 5.0 | .env, wp-config.php, .git/, phpinfo.php |
| **Critical** | 10.0 | Directory traversal, SQL injection, shell uploads |
| **Binary Probe** | 12.666 | RDP/TLS/SMB probes (empty HTTP method) |

### Externalized Rules (`rules.conf`)

Define your threat detection patterns in `rules.conf`:

```conf
# Format: <score> <regex_pattern>
# Low priority - benign files
0.1   ^/favicon\.ico$
0.1   ^/robots\.txt$

# High priority - sensitive files
5.0   \.env$
5.0   /wp-config\.php
5.0   /\.git/

# Critical - instant ban worthy
10.0  \.\./               # Directory traversal
10.0  /etc/passwd
10.0  UNION\+SELECT       # SQL injection
10.0  /shell\.php
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
| `REGEX_OVERRIDE` | `""` | Custom regex to use for log parsing |
| `PREVIEW_MODE` | `false` | If true, logs actions but skips firewall commands |
| `SCAN_ALL_MODE` | `false` | If true, scans the entire log file at startup |


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
EnvironmentFile=/var/lib/go-log-scythe/.env

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