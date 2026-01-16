# 🛡️ GoLogScythe

**GoLogScythe** is a high-performance, zero-dependency security daemon written in Go. It harvests malicious IP addresses from your web server logs (Nginx/Apache) and banishes them to the kernel-level void using `nftables` Sets.

Unlike legacy tools or shell scripts, **LogScythe** uses  lookup tables, meaning it can ban 100,000 parasites with the same near-zero CPU impact as banning just one.

---

## ✨ Features

* **Zero Dependencies:** Pure Go standard library. No `tail` libraries, no bloat.
* **High Performance:** Leverages `nftables` Sets for constant-time packet filtering.
* **Safety First:** Automatic whitelisting of your current SSH session, localhost, and existing UFW rules to prevent accidental lockouts.
* **Dual-Regex Fallback:** Intelligent parsing logic that supports Nginx and Apache formats out of the box.
* **Persistence:** Bans survive reboots via a local state file and automatic kernel re-synchronization.
* **Preview Mode:** Test your configuration against live logs without actually triggering firewall actions.
* **Environment Driven:** Fully configurable via `.env` or system environment variables.

---

## 🚀 Quick Start

### 1. Prerequisites (nftables)

LogScythe requires a modern Linux system with `nftables`. Ensure your `/etc/nftables.conf` is set up to handle the `parasites` set:

```nft
table inet filter {
    set parasites {
        type ipv4_addr
        flags interval
    }

    chain input {
        type filter hook input priority 0; policy accept;
        
        # Block parasites at the very front
        ip saddr @parasites drop
    }
}

```

*Apply with: `sudo nft -f /etc/nftables.conf*`

### 2. Installation

```bash
git clone https://github.com/your-username/logscythe.git
cd logscythe
go build -o logscythe main.go

```

### 3. Configuration

Create a `.env` file or export the variables:

```bash
# Log to monitor
LOG_PATH="/var/log/nginx/access.log"

# Thresholds
BAN_THRESHOLD=10
BAN_WINDOW="15m"

# Security
PREVIEW_MODE=true  # Set to false once you verify matches

```

---

## 🔍 Preview Mode

Before going live, run LogScythe in **Preview Mode**. This will show you exactly which IPs would be banned based on your current log activity without modifying your firewall:

```bash
sudo PREVIEW_MODE=true ./logscythe

```

*Output:*
`2026/01/16 12:00:00 👀 [PREVIEW] Would ban IP: 162.240.233.90 (10 hits detected)`

---

## ⚙️ Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `LOG_PATH` | `/var/log/nginx/access.log` | Path to the web log file to monitor. |
| `WHITE_LIST_PATH` | `./whitelist.txt` | File containing IPs/CIDRs that should never be banned. |
| `BANNED_FILE_PATH` | `./banned_ips.txt` | Persistence file for banned IPs. |
| `BAN_THRESHOLD` | `10` | Number of 4xx hits before a ban is issued. |
| `BAN_WINDOW` | `15m` | Sliding window duration for error counting. |
| `NFT_SET_NAME` | `parasites` | The name of the nftables set to target. |
| `REGEX_OVERRIDE` | `""` | Custom regex to use for log parsing. |
| `PREVIEW_MODE` | `false` | If true, logs actions but skips firewall commands. |

---

## 🛠️ Deployment (Systemd)

To run **LogScythe** as a background service on your VPS, create `/etc/systemd/system/logscythe.service`:

```ini
[Unit]
Description=LogScythe Parasite Cleaner
After=network.target nftables.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/logscythe
ExecStart=/opt/logscythe/logscythe
Restart=always
EnvironmentFile=/opt/logscythe/.env

[Install]
WantedBy=multi-user.target

```

```bash
sudo systemctl enable --now logscythe

```

---

## 📊 Monitoring

To see the live list of banned parasites in your kernel:

```bash
sudo nft list set inet filter parasites

```

To see the service logs:

```bash
journalctl -u logscythe -f

```

---

## 🤝 Contributing

Help us get rid of parasites! If you have a better regex for a specific web server or a performance tweak, feel free to open a PR.

**LogScythe** — *Clean logs. Fast servers. No parasites.*