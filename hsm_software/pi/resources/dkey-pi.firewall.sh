#!/bin/bash
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
#VERSION 2018-12-10-05

## Set system variables ##
IPT=/sbin/iptables
SYSCTL=/sbin/sysctl


### Dump old FW Rules if any exist ####
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -P INPUT ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD ACCEPT

### Turn on SYN Flooding protection ###
### should be place in /etc/sysctl.conf

$SYSCTL -w net/ipv4/tcp_syncookies=1

### Block all Inbound, outbound and forwarded packets first ###
$IPT -P INPUT DROP   # Drop any packets attempting to enter on eth0
$IPT -P OUTPUT DROP  # Drop any packets attempting to leave out on eth0
$IPT -P FORWARD DROP  # Drop any packets attempting to forward to system

### Allow full access to the loopback interface ###
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

$IPT -A INPUT -i eth0 -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT
$IPT -A OUTPUT -o eth0 -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT

$IPT -A INPUT -i eth0 -p tcp --dport 8080 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o eth0 -p tcp --sport 8080 -m state --state NEW,ESTABLISHED -j ACCEPT

$IPT -A INPUT -i eth0 -p tcp --dport 8081 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o eth0 -p tcp --sport 8081 -m state --state NEW,ESTABLISHED -j ACCEPT

$IPT -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

### Log Inbound and Outbound errors ###
$IPT -N LOGGING
$IPT -A INPUT -j LOGGING
$IPT -A OUTPUT -j LOGGING
$IPT -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "Firewall - Dropped" --log-level 4 
$IPT -A LOGGING -j DROP