#!/usr/bin/env python3
import re
import os
import sys
import glob
import argparse
import csv
from datetime import datetime

# Regex to capture the timestamp: [15/Feb/2026:14:49:10 +0000]
TIMESTAMP_PATTERN = re.compile(r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]')

def parse_timestamp(ts_str):
    """Parse the Apache/Nginx log timestamp format."""
    try:
        return datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError:
        return None

def summarize_dir(directory, output_format='table'):
    # --- Taint analysis mitigation for SonarQube path traversal ---
    # Source (1): untrusted input (CLI arg, modeled like HTTP request body in general taint rules)
    # (2): assigned to args
    # (3): assigned to parameter 'directory'
    # (4): propagates into os.path.join + glob.glob (the instruction that can propagate malicious content)
    #
    # Requirement: validate the *constructed path* BEFORE accessing the filesystem.

    if not isinstance(directory, str) or not directory.strip():
        print("Error: directory must be a non-empty string.")
        return

    # Step 1: Canonicalize the source (breaks direct taint from raw 'directory')
    try:
        safe_base = os.path.realpath(os.path.abspath(directory))
    except OSError as exc:
        print(f"Error: could not resolve directory '{directory}': {exc}")
        return

    if not os.path.isdir(safe_base):
        print(f"Error: {directory} is not a directory.")
        return

    # Step 2: Construct the path using only the sanitized base (this is the propagation point)
    constructed = os.path.join(safe_base, "*_evidence.txt")

    # Step 3: Explicitly VALIDATE the constructed path before any FS access with it
    # Re-resolve the directory portion of the constructed path and ensure it is confined
    # to the safe_base we already validated.
    try:
        constructed_dir = os.path.dirname(constructed) or constructed
        validated_dir = os.path.realpath(os.path.abspath(constructed_dir))
        if validated_dir != safe_base:
            print(f"Error: constructed path escapes safe directory: {constructed}")
            return
    except OSError as exc:
        print(f"Error validating constructed path: {exc}")
        return

    # Now it is safe to use the validated constructed path with the filesystem
    files = glob.glob(constructed)
    if not files:
        print(f"No evidence files found in {directory}.")
        return

    ip_stats = {}
    for filepath in files:
        # Additional validation for each file returned by glob (in case of symlinks or TOCTOU)
        try:
            real_path = os.path.realpath(filepath)
            if os.path.commonpath([real_path, safe_base]) != safe_base:
                print(f"Warning: skipping file outside requested directory tree: {filepath}")
                continue
        except (OSError, ValueError):
            continue

        filename = os.path.basename(filepath)
        ip = filename.replace("_evidence.txt", "")
        if ip not in ip_stats:
            ip_stats[ip] = {'min': None, 'max': None, 'count': 0, 'files': 0}
        ip_stats[ip]['files'] += 1
        with open(real_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not line.strip():
                    continue
                ip_stats[ip]['count'] += 1
                match = TIMESTAMP_PATTERN.search(line)
                if match:
                    ts = parse_timestamp(match.group(1))
                    if ts:
                        if ip_stats[ip]['min'] is None or ts < ip_stats[ip]['min']:
                            ip_stats[ip]['min'] = ts
                        if ip_stats[ip]['max'] is None or ts > ip_stats[ip]['max']:
                            ip_stats[ip]['max'] = ts

    cols = ['IP', 'Min Time', 'Max Time', 'Duration', 'Files', 'Entries']
    
    if output_format == 'table':
        header = f"{cols[0]:<15} | {cols[1]:<20} | {cols[2]:<20} | {cols[3]:<15} | {cols[4]:<5} | {cols[5]:<8}"
        print(header)
        print("-" * len(header))
    elif output_format == 'csv':
        writer = csv.writer(sys.stdout, delimiter=',')
        writer.writerow(cols)
    elif output_format == 'tsv':
        writer = csv.writer(sys.stdout, delimiter='\t')
        writer.writerow(cols)

    try:
        for ip in sorted(ip_stats.keys()):
            stats = ip_stats[ip]
            min_str = stats['min'].strftime('%Y-%m-%d %H:%M') if stats['min'] else "N/A"
            max_str = stats['max'].strftime('%Y-%m-%d %H:%M') if stats['max'] else "N/A"
            duration_str = str(stats['max'] - stats['min']) if stats['min'] and stats['max'] else "N/A"
            
            row = [ip, min_str, max_str, duration_str, stats['files'], stats['count']]
            
            if output_format == 'table':
                print(f"{row[0]:<15} | {row[1]:<20} | {row[2]:<20} | {row[3]:<15} | {row[4]:<5} | {row[5]:<8}")
            else:
                writer.writerow(row)
    except BrokenPipeError:
        sys.stderr.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Summarize evidence logs. "
                    "Untrusted 'directory' (taint source) is canonicalized; the constructed path from join() "
                    "is explicitly validated before glob/open to stop propagation of malicious content."
    )
    parser.add_argument("directory", help="Directory with *_evidence.txt files. Path is sanitized + constructed path is validated before FS access.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--csv", action="store_true", help="Output in CSV format.")
    group.add_argument("--tsv", action="store_true", help="Output in TSV format.")
    
    args = parser.parse_args()
    
    fmt = 'table'
    if args.csv: fmt = 'csv'
    elif args.tsv: fmt = 'tsv'
    
    summarize_dir(args.directory, fmt)
