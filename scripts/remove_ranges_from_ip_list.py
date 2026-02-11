import ipaddress
import sys
import os

def load_ranges(range_file):
    networks = []
    if not os.path.exists(range_file):
        print(f"Error: Range file '{range_file}' not found.")
        sys.exit(1)

    with open(range_file, 'r') as f:
        for line in f:
            # Clean up whitespace, trailing commas, or list markers
            clean_line = line.strip().rstrip(',')
            if not clean_line:
                continue
            try:
                networks.append(ipaddress.ip_network(clean_line, strict=False))
            except ValueError:
                print(f"Skipping invalid range: {clean_line}")
    return networks

def filter_ips(ip_file, networks):
    if not os.path.exists(ip_file):
        print(f"Error: IP file '{ip_file}' not found.")
        sys.exit(1)

    survivors = []
    with open(ip_file, 'r') as f:
        for line in f:
            ip_str = line.strip()
            if not ip_str:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                # Check if this IP is covered by any of our broad ranges
                if not any(ip_obj in net for net in networks):
                    survivors.append(ip_str)
            except ValueError:
                print(f"Skipping invalid IP: {ip_str}")
    return survivors

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 optimize.py <ranges_file> <ips_file>")
        sys.exit(1)

    range_input = sys.argv[1]
    ip_input = sys.argv[2]

    # 1. Load the CIDR blocks
    banned_nets = load_ranges(range_input)
    print(f"Loaded {len(banned_nets)} network ranges.")

    # 2. Filter the individual IPs
    remaining = filter_ips(ip_input, banned_nets)

    # 3. Output results
    for ip in remaining:
        print(ip)

    # Optional: Print stats to stderr so it doesn't mess up redirected output
    print(f"\n# Done. Kept {len(remaining)} unique IPs.", file=sys.stderr)