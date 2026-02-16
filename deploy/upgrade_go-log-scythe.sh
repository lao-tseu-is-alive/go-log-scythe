#!/bin/bash
cd /root/
rm goLogScythe-linux-amd64.tar.gz
wget https://github.com/lao-tseu-is-alive/go-log-scythe/releases/download/v0.3.1/goLogScythe-linux-amd64.tar.gz
tar xvfz goLogScythe-linux-amd64.tar.gz
mv goLogScythe-linux-amd64 /usr/local/bin/
systemctl restart nftables.service
systemctl restart go-log-scythe.service
journalctl -u go-log-scythe.service -n 30