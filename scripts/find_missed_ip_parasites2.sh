#!/bin/bash
# find_missed_ip_parasites.sh (Fixed Version)

# 1. Match your daemon's threshold
THRESHOLD=5 
BANNED_FILE="/var/lib/go-log-scythe/banned_ips.txt"

echo "--------------------------------------------------------"
echo "🔍 Identifying IPs with hits >= $THRESHOLD that are NOT BANNED"
echo "--------------------------------------------------------"

# 2. Get high-count IPs from your existing script logic
# We scan all access logs exactly once
LOG_FILES="/var/log/nginx/*access.log"

# Create a temporary summary of IPs and their real counts
TEMP_STATS=$(gawk '$9 > 399 {print $1}' $LOG_FILES | sort | uniq -c)

# Extract only those meeting the threshold
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
        echo "🚩 MISSING: $ip ($COUNT real hits) is NOT in firewall sets!"
    fi
done
