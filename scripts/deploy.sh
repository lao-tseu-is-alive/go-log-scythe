#!/bin/bash
VERSION="v0.4.0"
echo "## will cd to deploy_goLogScythe directory if not found will exit"
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
echo "## will check ufw status if ufw is disable will jump to next section"
if [ "$(ufw status | grep "Status: active")" ]; then
    echo "## ufw is active"
    echo "## will check ufw status, and save to ufw_status_${TODAY}.txt"
    ufw status > "ufw_status_${TODAY}.txt"
    ufw status |grep ALLOW > "ufw_status_ALLOW_${TODAY}.txt"
    echo "## saved ufw allow to ufw_status_ALLOW_${TODAY}.txt"
    echo "## will disable ufw"
    ufw disable
    systemctl stop ufw
    systemctl disable ufw
else
    echo "## ufw is not active"
fi
echo "## will install nftables if not already installed"
if [ ! "$(dpkg -l | grep nftables)" ]; then
    apt update
    apt dist-upgrade
    apt install nftables
    systemctl enable nftables
else
    echo "## nftables is already installed"
fi
echo "## will copy nftables.conf if not already exists"
if [ ! -f "/etc/nftables.conf" ]; then
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
else
    echo "## nftables.conf already exists"
fi
echo "## retrieving goLogScythe release ${VERSION}"
if [ -f "goLogScythe-linux-amd64.tar.gz" ]; then
    echo "## goLogScythe-linux-amd64.tar.gz already exists (maybe od version) will clean up"
    rm goLogScythe-linux-amd64.tar.gz
fi
wget "https://github.com/lao-tseu-is-alive/go-log-scythe/releases/download/${VERSION}/goLogScythe-linux-amd64.tar.gz"
echo "## extracting goLogScythe-linux-amd64.tar.gz"
tar xvfz goLogScythe-linux-amd64.tar.gz
echo "## moving goLogScythe-linux-amd64 to /usr/local/bin/"
mv goLogScythe-linux-amd64 /usr/local/bin/
echo "## setting goLogScythe-linux-amd64 to executable"
chmod +x /usr/local/bin/goLogScythe-linux-amd64
echo "## double check your own config.env maybe update it to your needs"
vim /etc/go-log-scythe/config.env
echo "## restarting go-log-scythe.service"
systemctl restart go-log-scythe.service
echo "## daemon-reload"
systemctl daemon-reload
echo "## enabling go-log-scythe.service if not already enabled"
if [ ! "$(systemctl is-enabled go-log-scythe.service)" ]; then
    systemctl enable go-log-scythe.service
fi
echo "## re-starting go-log-scythe.service to apply changes"
systemctl restart go-log-scythe.service
echo "## checking status of go-log-scythe.service"
systemctl status go-log-scythe.service
echo "## checking logs of go-log-scythe.service"
journalctl -u go-log-scythe.service --since "1 hour ago"
