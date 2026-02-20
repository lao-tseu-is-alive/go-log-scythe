#!/bin/bash
VERSION="v0.4.0"
cd /root/
if [ -f "goLogScythe-linux-amd64.tar.gz" ]; then
    echo "## will remove old goLogScythe-linux-amd64.tar.gz"
    rm goLogScythe-linux-amd64.tar.gz
fi
echo "## will retrieve goLogScythe release ${VERSION}"
wget https://github.com/lao-tseu-is-alive/go-log-scythe/releases/download/${VERSION}/goLogScythe-linux-amd64.tar.gz
echo "## will extract goLogScythe release ${VERSION}"
tar xvfz goLogScythe-linux-amd64.tar.gz
echo "## will move goLogScythe release ${VERSION} to /usr/local/bin/"
mv goLogScythe-linux-amd64 /usr/local/bin/
echo "## will restart nftables.service"
systemctl restart nftables.service
echo "## will restart go-log-scythe.service"
systemctl restart go-log-scythe.service
echo "## will check logs of go-log-scythe.service"
journalctl -u go-log-scythe.service -f
