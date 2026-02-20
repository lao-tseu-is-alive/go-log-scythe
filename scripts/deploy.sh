#!/bin/bash
cd deploy_goLogScythe || { echo "💥 💥 directory : deploy_goLogScythe  not found, will exit"; exit 1; }
TODAY=$(date -I)
echo "${TODAY}"
echo "## will create directories, if already exists, will jump to next"
if [ ! -d "/var/lib/go-log-scythe/" ]; then
    mkdir /var/lib/go-log-scythe/
fi
if [ ! -d "/etc/go-log-scythe/" ]; then
    mkdir /etc/go-log-scythe/
fi
echo "## will copy files if not already exists"
if [ ! -f "/etc/go-log-scythe/config.env" ]; then
    rsync -av config.env /etc/go-log-scythe/
fi
if [ ! -f "/etc/systemd/system/go-log-scythe.service" ]; then
    rsync -av go-log-scythe.service /etc/systemd/system/go-log-scythe.service
fi
if [ ! -f "/etc/nftables.conf" ]; then
    rsync -av nftables.conf /etc/
fi
if [ ! -f "/var/lib/go-log-scythe/go-log-scythe" ]; then
    rsync -av go-log-scythe /var/lib/
fi
ufw status
crontab -l
ufw status > "ufw_status_${TODAY}.txt"
ufw status |grep ALLOW > "ufw_status_ALLOW_${TODAY}.txt"
echo "## saved ufw allow to ufw_status_ALLOW_${TODAY}.txt"
echo "## will disable ufw"
ufw disable
systemctl stop ufw
systemctl disable ufw
echo "## will install nftables"
apt update
apt dist-upgrade
apt install nftables
systemctl enable nftables
echo "## will install nftables"
rsync -av nftables.conf /etc/
cat "ufw_status_ALLOW_${TODAY}.txt"
cat  /etc/hosts.allow
echo "## double check your own nftables"
vim /etc/nftables.conf
echo "## checking syntax of your own /etc/nftables.conf"
nft --check -f /etc/nftables.conf
systemctl restart nftables
echo "## checking disk usage of journalctl"
journalctl --disk-usage
echo "## adjust journalctl allowed disk usage (SystemMaxUse=1G)"
vim /etc/systemd/journald.conf
echo "## retrieving goLogScythe release"
wget https://github.com/lao-tseu-is-alive/go-log-scythe/releases/download/v0.4.0/goLogScythe-linux-amd64.tar.gz
tar xvfz goLogScythe-linux-amd64.tar.gz
mv goLogScythe-linux-amd64 /usr/local/bin/
systemctl daemon-reload
systemctl enable go-log-scythe.service
systemctl status go-log-scythe.service
systemctl start go-log-scythe.service
systemctl status go-log-scythe.service
journalctl -u go-log-scythe.service
journalctl -u go-log-scythe.service -f
vim /etc/go-log-scythe/config.env
systemctl restart nginx.service