#!/usr/bin/env bash
# Run INSIDE the Ubuntu 24.04 guest VM (not on Windows). Installs Docker CE and
# creates an egress-blocked internal network for the isolated pentest lab.
# Safe to re-run (idempotent-ish). Requires sudo.
set -euo pipefail

echo "[*] apt update + base packages"
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg git jq

echo "[*] add Docker's official apt repo"
sudo install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
fi
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[*] install Docker CE"
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "[*] add '$USER' to docker group (re-login to take effect)"
sudo usermod -aG docker "$USER"

echo "[*] verify Docker"
sudo docker run --rm hello-world | grep -q "working correctly" && echo "    docker OK"

echo "[*] create egress-blocked isolated network 'pentest-lab'"
# --internal => containers on this network have NO route to the outside world.
sudo docker network inspect pentest-lab >/dev/null 2>&1 || \
  sudo docker network create --internal --driver bridge pentest-lab
echo "    network 'pentest-lab' ready (internal, no egress)"

cat <<'EOF'

[DONE] Docker is installed and an isolated 'pentest-lab' network exists.
Next (manual, audit code first; keep each clone in its OWN empty dir):
  mkdir -p ~/labs/autopenbench && cd ~/labs/autopenbench && git clone <AutoPenBench repo> .
  mkdir -p ~/labs/cochise     && cd ~/labs/cochise     && git clone <Cochise repo> .
Run attack targets/agents ONLY attached to 'pentest-lab' (docker run --network pentest-lab ...).
Switch the VM's VirtualBox adapter to Host-only/Internal before live attack runs.
Re-login (or 'newgrp docker') so the docker group applies without sudo.
EOF
