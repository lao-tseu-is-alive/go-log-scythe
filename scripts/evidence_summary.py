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
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a directory.")
        return

    files = glob.glob(os.path.join(directory, "*_evidence.txt"))
    if not files:
        print(f"No evidence files found in {directory}.")
        return

    ip_stats = {}
    for filepath in files:
        filename = os.path.basename(filepath)
        ip = filename.replace("_evidence.txt", "")
        if ip not in ip_stats:
            ip_stats[ip] = {'min': None, 'max': None, 'count': 0, 'files': 0}
        ip_stats[ip]['files'] += 1
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not line.strip(): continue
                ip_stats[ip]['count'] += 1
                match = TIMESTAMP_PATTERN.search(line)
                if match:
                    ts = parse_timestamp(match.group(1))
                    if ts:
                        if ip_stats[ip]['min'] is None or ts < ip_stats[ip]['min']: ip_stats[ip]['min'] = ts
                        if ip_stats[ip]['max'] is None or ts > ip_stats[ip]['max']: ip_stats[ip]['max'] = ts

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
    parser = argparse.ArgumentParser(description="Summarize evidence logs.")
    parser.add_argument("directory", help="Directory containing evidence files.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--csv", action="store_true", help="Output in CSV format.")
    group.add_argument("--tsv", action="store_true", help="Output in TSV format.")
    
    args = parser.parse_args()
    
    fmt = 'table'
    if args.csv: fmt = 'csv'
    elif args.tsv: fmt = 'tsv'
    
    summarize_dir(args.directory, fmt)
