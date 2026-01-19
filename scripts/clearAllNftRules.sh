#!/bin/bash
echo "allow everything again (temporary in case emergency)"
nft flush ruleset
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; }