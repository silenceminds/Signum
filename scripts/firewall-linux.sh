#!/usr/bin/env bash
set -euo pipefail

# Signum Linux/OCI Edge Firewall (iptables)
# Restricts unauthenticated access to :4443 (control) and rate-limits :80/:443.
# Usage: sudo ./firewall-linux.sh <AGENT_ALLOW_CIDR_OR_IP> [PUBLIC_CIDR]

AGENT_CIDR="${1:-0.0.0.0/0}"
PUBLIC_CIDR="${2:-0.0.0.0/0}"

echo "[signum-fw] Configuring iptables rules (agent_cidr=$AGENT_CIDR, public_cidr=$PUBLIC_CIDR)..."

# Flush or create dedicated SIGNUM_EDGE chain
iptables -N SIGNUM_EDGE 2>/dev/null || iptables -F SIGNUM_EDGE

# Allow established/related and loopback
iptables -A SIGNUM_EDGE -i lo -j ACCEPT
iptables -A SIGNUM_EDGE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop invalid packets and SYN floods
iptables -A SIGNUM_EDGE -m conntrack --ctstate INVALID -j DROP

# Control port (:4443): allow ONLY configured agent source CIDR, drop all others
iptables -A SIGNUM_EDGE -p tcp --dport 4443 -s "$AGENT_CIDR" -m conntrack --ctstate NEW -j ACCEPT
iptables -A SIGNUM_EDGE -p tcp --dport 4443 -j DROP

# Public HTTPS/HTTP (:443, :80): allow from PUBLIC_CIDR with per-IP connlimit
iptables -A SIGNUM_EDGE -p tcp --dport 443 -s "$PUBLIC_CIDR" -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP
iptables -A SIGNUM_EDGE -p tcp --dport 443 -s "$PUBLIC_CIDR" -j ACCEPT
iptables -A SIGNUM_EDGE -p tcp --dport 80 -s "$PUBLIC_CIDR" -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP
iptables -A SIGNUM_EDGE -p tcp --dport 80 -s "$PUBLIC_CIDR" -j ACCEPT

# Attach SIGNUM_EDGE to INPUT if not already attached
iptables -C INPUT -j SIGNUM_EDGE 2>/dev/null || iptables -I INPUT 1 -j SIGNUM_EDGE

echo "[signum-fw] Linux edge firewall active."
