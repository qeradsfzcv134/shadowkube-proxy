#!/bin/bash

iptables -F

allowed_ports=(8079 2374 10249 31999 2378 30964 30962 30024 30022 30616 30614 30884 30882)

for port in "${allowed_ports[@]}"; do
    iptables -A INPUT -i lo -p tcp --dport "$port" -j ACCEPT
    iptables -A INPUT -p tcp --dport "$port" -j DROP
done
