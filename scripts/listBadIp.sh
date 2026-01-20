#!/bin/bash
gawk '$9 > 399 {print $1}' /var/log/nginx/access.log.1 | sort -n >bad_ip.txt
gawk '$9 > 399 {print $1}' /var/log/nginx/access.log | sort -n >>bad_ip.txt
sort -n bad_ip.txt |uniq -c|sort -n
