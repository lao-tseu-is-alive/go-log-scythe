import re
import os
import glob

# Configuration
EVIDENCES_DIR = "./evidences"  # Directory to search for evidence files
OUTPUT_FILE = "global_blocklist.csv"

# Regex to capture the IP address and the request string
LOG_PATTERN = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"(.*?)"')

# Classification Heuristics
RULES = [
    # CRITICAL: Malware installation attempts, clear Remote Code Execution (RCE)
    ("CRITICAL", r"(wget|curl|chmod|Mozi|Mirai|/tmp/|\.sh|dlink\.mips)"),

    # HIGH: Known web exploits, binary probes, credential theft attempts
    ("HIGH", r"(\\x16\\x03|phpunit|thinkphp|eval-stdin|cgi-bin|\.env|\.git/config|jndi:)"),

    # MEDIUM: Generic scanners, background noise (often handled locally)
    ("MEDIUM", r"(xmlrpc\.php|wp-login|yealink|setup\.php|admin)"),
]

def classify_attack(request_line):
    """Returns the highest severity found for a given log line."""
    for severity, pattern in RULES:
        if re.search(pattern, request_line, re.IGNORECASE):
            return severity
    return "LOW"

def main():
    # 1. Automatic file gathering
    if not os.path.exists(EVIDENCES_DIR):
        print(f"⚠️  The directory '{EVIDENCES_DIR}' does not exist.")
        print(f"👉 Please create it and place your 'all_evidences.txt' files inside.")
        return

    files = glob.glob(os.path.join(EVIDENCES_DIR, "*.txt"))

    if not files:
        print(f"⚠️  No .txt files found inside '{EVIDENCES_DIR}'.")
        return

    print(f"📂 Analyzing {len(files)} files found in '{EVIDENCES_DIR}':")
    for f in files:
        print(f"  - {os.path.basename(f)}")

    banned_ips = {} # Structure: {ip: {'severity': level, 'count': n, 'sample': request}}

    # 2. Process logs
    for filename in files:
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = LOG_PATTERN.match(line)
                    if match:
                        ip = match.group(1)
                        request = match.group(2)
                        severity = classify_attack(request)

                        if severity == "LOW":
                            continue

                        # Initialize IP if new
                        if ip not in banned_ips:
                            banned_ips[ip] = {'severity': severity, 'count': 0, 'sample': request[:100]}

                        banned_ips[ip]['count'] += 1

                        # Upgrade severity if a more serious attack is detected later
                        current_sev = banned_ips[ip]['severity']
                        if severity == "CRITICAL":
                            banned_ips[ip]['severity'] = "CRITICAL"
                        elif severity == "HIGH" and current_sev == "MEDIUM":
                            banned_ips[ip]['severity'] = "HIGH"

        except Exception as e:
            print(f"❌ Error reading file {filename}: {e}")

    # 3. Write results (CRITICAL and HIGH only)
    print(f"\n💾 Generating {OUTPUT_FILE}...")

    # Sort order: CRITICAL > HIGH > MEDIUM
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

    # Sort by Severity, then by Attack Count (descending)
    sorted_ips = sorted(
        banned_ips.items(),
        key=lambda x: (priority_order.get(x[1]['severity'], 3), -x[1]['count'])
    )

    count = 0
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out:
        out.write("IP,SEVERITY,COUNT,SAMPLE_PAYLOAD\n")

        for ip, data in sorted_ips:
            # Filter to keep only the most dangerous IPs for global banning
            if data['severity'] in ["CRITICAL", "HIGH"]:
                # Clean payload for CSV (replace double quotes with single quotes)
                clean_sample = data['sample'].replace('"', "'")
                out.write(f"{ip},{data['severity']},{data['count']},\"{clean_sample}\"\n")
                count += 1

    print(f"✅ Done! {count} unique IPs (CRITICAL & HIGH) exported.")
    print(f"👉 You can now use this file to populate your firewalls.")

if __name__ == "__main__":
    main()