#!/bin/bash
sudo iptables -I INPUT -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -o lo -j NFQUEUE --queue-num 1
sudo iptables -I INPUT -i lo -j NFQUEUE --queue-num 1
echo "[*] iptables NFQUEUE rules applied."

