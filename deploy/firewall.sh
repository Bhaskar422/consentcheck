#!/usr/bin/env bash
# Host firewall for audit containers. Run as root; idempotent.
# The consentcheck service runs this before every start (ExecStartPre), so the
# rules survive reboots and Docker restarts without iptables-persistent (which
# conflicts with ufw on Ubuntu 24.04).
#
# Second layer behind the egress guard: containers may not reach the cloud
# metadata service (169.254.169.254), the Vultr VPC (10.0.0.0/8) or carrier-grade
# NAT space. 172.16/12 and 192.168/16 are left alone because Docker allocates its
# own container networks from those ranges.
set -euo pipefail
iptables -L DOCKER-USER -n >/dev/null 2>&1 || iptables -N DOCKER-USER
for net in 169.254.0.0/16 10.0.0.0/8 100.64.0.0/10; do
  iptables -C DOCKER-USER -d "$net" -j DROP 2>/dev/null || iptables -I DOCKER-USER -d "$net" -j DROP
done
