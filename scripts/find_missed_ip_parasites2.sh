#!/bin/bash
# find_missed_ip_parasites.sh

THRESHOLD=5
BANNED_FILE="/var/lib/go-log-scythe/banned_ips.txt"
LOG_FILES="/var/log/nginx/*access.log"

echo "--------------------------------------------------------"
echo "🔍 Identifying IPs with hits >= $THRESHOLD (Status > 399) not in Firewall"
echo "--------------------------------------------------------"

# 1. Get stats: Status > 399 -> Unique (IP, URL) -> Count per IP
# We use 'sort -u' to ensure we only count an IP once for each specific URL it attacked
TEMP_STATS=$(gawk '$9 > 399 {print $1, $7}' $LOG_FILES | sort -u | awk '{print $1}' | sort | uniq -c)

# 2. Extract IPs that meet the threshold
IPS_TO_CHECK=$(echo "$TEMP_STATS" | gawk -v t=$THRESHOLD '$1 >= t {print $2}')

# 3. Get active nftables rules
ACTIVE_NFT_RULES=$(sudo nft list set inet filter parasites | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?')

for ip in $IPS_TO_CHECK; do
    # Skip if in persistence file
    if grep -q "^$ip$" "$BANNED_FILE" 2>/dev/null; then continue; fi

    # Check for subnet or direct match in nftables
    IS_BANNED=false
    for rule in $ACTIVE_NFT_RULES; do
        if [[ "$rule" == *"/"* ]]; then
            if python3 -c "import ipaddress; exit(0 if ipaddress.ip_address('$ip') in ipaddress.ip_network('$rule') else 1)" 2>/dev/null; then
                IS_BANNED=true; break
            fi
        elif [[ "$ip" == "$rule" ]]; then
            IS_BANNED=true; break
        fi
    done

    if [ "$IS_BANNED" = false ]; then
        # Extract the real count from our TEMP_STATS
        COUNT=$(echo "$TEMP_STATS" | grep " $ip$" | awk '{print $1}')
        echo "🚩 MISSING: $ip ($COUNT unique probe paths) is NOT in firewall!"
    fi
done