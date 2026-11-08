#!/usr/bin/env bash
# One-shot setup for a fresh Vultr Cloud Compute instance (Ubuntu 24.04 LTS).
# Run as root from the repository root:   sudo bash deploy/setup_vultr.sh
#
# Installs Docker + gVisor (runsc), builds the sandbox image, installs the app
# as a systemd service behind Caddy on port 80, and adds host firewall rules so
# no container can reach the cloud metadata service or private networks.
set -euo pipefail

APP_DIR=/opt/consentcheck
APP_USER=consentcheck
ENV_FILE=/etc/consentcheck.env

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)."; exit 1; fi
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
IP=$(curl -s -4 https://ifconfig.me || hostname -I | awk '{print $1}')
# HTTPS needs a hostname. Pass your own with CC_DOMAIN=..., otherwise sslip.io
# maps <ip-with-dashes>.sslip.io to this VM for free.
DOMAIN=${CC_DOMAIN:-${IP//./-}.sslip.io}

echo "==> Base packages"
apt-get update -y
apt-get install -y ca-certificates curl gnupg python3-venv caddy ufw iptables-persistent

echo "==> Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

echo "==> gVisor (runsc)"
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -y && apt-get install -y runsc
fi
runsc install
# Containers on the default bridge (the egress guards of parallel scans) must not
# talk to each other. Merge "icc": false into daemon.json next to the runsc runtime.
python3 - <<'PY'
import json, pathlib
p = pathlib.Path("/etc/docker/daemon.json")
cfg = json.loads(p.read_text()) if p.exists() and p.read_text().strip() else {}
cfg["icc"] = False
p.write_text(json.dumps(cfg, indent=2))
PY
systemctl restart docker
docker run --rm --runtime=runsc hello-world >/dev/null && echo "    gVisor works"

echo "==> Host firewall: containers may not reach cloud metadata or the Vultr VPC (10.0.0.0/8)"
# Second layer behind the egress guard. 172.16/12 and 192.168/16 are left alone
# because Docker allocates its own container networks from those ranges.
for net in 169.254.0.0/16 10.0.0.0/8 100.64.0.0/10; do
  iptables -C DOCKER-USER -d "$net" -j DROP 2>/dev/null || iptables -I DOCKER-USER -d "$net" -j DROP
done
netfilter-persistent save
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable

echo "==> App user and code"
id -u $APP_USER >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin $APP_USER
usermod -aG docker $APP_USER
mkdir -p $APP_DIR
cp -r "$SRC_DIR"/app "$SRC_DIR"/proxy "$SRC_DIR"/sandbox "$SRC_DIR"/scripts "$SRC_DIR"/sites "$SRC_DIR"/requirements.txt $APP_DIR/
mkdir -p $APP_DIR/runs
python3 -m venv $APP_DIR/.venv
$APP_DIR/.venv/bin/pip install -q -r $APP_DIR/requirements.txt
# Code stays root-owned and read-only for the service; only runs/ is writable.
chown -R root:root $APP_DIR
chown -R $APP_USER:$APP_USER $APP_DIR/runs
chmod 750 $APP_DIR/runs

echo "==> Images"
docker pull mitmproxy/mitmproxy:11.0.2
docker build -t consentcheck-sandbox:latest $APP_DIR/sandbox

echo "==> Config"
if [[ ! -f $ENV_FILE ]]; then
  ADMIN_PW=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
  SESSION_SECRET=$(openssl rand -hex 32)
  cat > $ENV_FILE <<EOF
# Vultr Serverless Inference key (Console -> Serverless -> Inference). Stays on the host only.
VULTR_INFERENCE_API_KEY=
# Admin dashboard login (user "admin"). Change it here, then restart the service.
CC_ADMIN_USER=admin
CC_ADMIN_PASSWORD=$ADMIN_PW
CC_SESSION_SECRET=$SESSION_SECRET
CC_SANDBOX_RUNTIME=runsc
# The VM's own address and hostname: the egress guard refuses to let audited pages call it.
CC_SELF_HOSTS=$IP,$DOMAIN
# Set to 1 only if this VM is in an EU region (e.g. Frankfurt); see README.
CC_EU_VANTAGE=0
CC_AGENT_MODEL=glm-5.3-flash
CC_VERIFIER_MODEL=qwen3.8-27b
CC_REPORT_MODEL=glm-5.3
CC_MAX_CONCURRENT=2
EOF
  chmod 600 $ENV_FILE
fi

echo "==> Service"
install -m 644 "$SRC_DIR"/deploy/consentcheck.service /etc/systemd/system/consentcheck.service
sed "s/CC_DOMAIN/$DOMAIN/" "$SRC_DIR"/deploy/Caddyfile > /etc/caddy/Caddyfile
chmod 644 /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable --now consentcheck
systemctl restart caddy

echo
echo "Done. Open https://$DOMAIN/  (Caddy fetches the certificate on first start; give it a minute)"
echo "Admin dashboard: https://$DOMAIN/#/dashboard  (user and password are in $ENV_FILE)"
echo "Next: put your key in $ENV_FILE, then: systemctl restart consentcheck"
