#!/bin/bash
cd /root/evidences || exit
echo "## listing already gathered ip info"
find . -maxdepth 1 -name "*_evidence.txt" -exec basename {} _evidence.txt \; | sort -n > ip_list_done.txt
IP_LIST=/var/lib/go-log-scythe/banned_ips.txt
LOG_FILE=/var/log/nginx/access.log
echo "##  keeping lines unique to banned_ips.txt (not in ip_list_done.txt)."
comm -23 <(sort "$IP_LIST") <(sort ip_list_done.txt)|sort -n >missing_ip.txt
while IFS= read -r i; do
  [[ -z "$i" ]] && continue
  echo "#### gathering evidences for ip $i"
  grep "$i" "$LOG_FILE" > "${i}_evidence.txt"
done < missing_ip.txt
