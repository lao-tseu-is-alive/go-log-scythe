#!/bin/bash
echo "ip getting 404 looking for .env somewhere..."
gawk '$9 > 399 &&  $7 ~ /.env/ {print $1}' /var/log/nginx/access.log | sort -n >very_bad_ip.txt
gawk '$9 > 399 &&  $7 ~ /.env/ {print $1}' /var/log/nginx/access.log.1 | sort -n >>very_bad_ip.txt
sort -n very_bad_ip.txt >very_bad_ip_sorted.txt
uniq -c very_bad_ip_sorted.txt | gawk '{print $2,$1}'| sort -n
