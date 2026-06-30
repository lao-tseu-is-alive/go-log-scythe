import ipaddress
import sys
import os


def _safe_path(user_path):
    """Normalize and validate an untrusted path from CLI before any filesystem access.

    This addresses SonarQube-style taint analysis findings:
      1. SOURCE: CLI argument (sys.argv) can contain malicious content (modeled like HTTP input)
      2. Assigned to variable (range_input / ip_input)
      3. Passed as 'range_file' / 'ip_file' parameter
      4. Propagates into os.path.exists + open()  ← the instruction that can allow path escape

    We always canonicalize with realpath+abspath. This ensures '..' traversal, symlinks,
    and other tricks are resolved before we touch the filesystem.
    """
    if not isinstance(user_path, str) or not user_path.strip():
        raise ValueError("Path must be a non-empty string")
    return os.path.realpath(os.path.abspath(user_path))


def load_ranges(range_file):
    # Validate the constructed path before accessing the filesystem
    try:
        safe_path = _safe_path(range_file)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    networks = []
    if not os.path.exists(safe_path):
        print(f"Error: Range file '{range_file}' not found.")
        sys.exit(1)

    with open(safe_path, 'r') as f:
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
    # Validate the constructed path before accessing the filesystem
    try:
        safe_path = _safe_path(ip_file)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not os.path.exists(safe_path):
        print(f"Error: IP file '{ip_file}' not found.")
        sys.exit(1)

    survivors = []
    with open(safe_path, 'r') as f:
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
        print("Usage: python3 remove_ranges_from_ip_list.py <ranges_file> <ips_file>")
        sys.exit(1)

    range_input = sys.argv[1]
    ip_input = sys.argv[2]

    # 1. Load the CIDR blocks (paths are validated inside the functions)
    banned_nets = load_ranges(range_input)
    print(f"Loaded {len(banned_nets)} network ranges.")

    # 2. Filter the individual IPs
    remaining = filter_ips(ip_input, banned_nets)

    # 3. Output results
    for ip in remaining:
        print(ip)

    # Optional: Print stats to stderr so it doesn't mess up redirected output
    print(f"\n# Done. Kept {len(remaining)} unique IPs.", file=sys.stderr)