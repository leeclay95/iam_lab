#!/usr/bin/env bash

# Force non-interactive frontend mode for apt packages
export DEBIAN_FRONTEND=noninteractive

# Exit immediately if a command exits with a non-zero status
set -e

echo "===================================================="
echo "Starting Floci IAM Abuse Lab Non-Interactive Install"
echo "===================================================="

# Create custom binary path early to ensure everything has a home
mkdir -p $HOME/.local/bin
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> $HOME/.bashrc
    export PATH="$HOME/.local/bin:$PATH"
fi

# 1. Update Package Indices
echo "[+] Updating apt repositories..."
sudo apt-get update -y -qq || echo "[-] Package update hit minor errors, moving forward..."

# 2. Install Core System Utilities
echo "[+] Installing prerequisite system tools..."
sudo apt-get install -y -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    apt-transport-https ca-certificates curl gnupg lsb-release wget zip python3 python3-pip jq git

# 3. Install Docker Engine & Compose v2
echo "[+] Installing Docker and Docker Compose..."
if ! command -v docker &> /dev/null; then
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null || \
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" | sudo tee /etc/apt/sources.list.d/docker.list
    
    sudo apt-get update -y -qq || true
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker $USER || true
else
    echo "[-] Docker is already installed."
fi

# 4. Robust Unattended Terraform Installation Loop
echo "[+] Installing HashiCorp Terraform..."
set +e # Allow commands to fail here so we can catch errors
if ! command -v terraform &> /dev/null; then
    # Strategy A: Standard lsb_release repo matching
    wget -O- https://apt.releases.hashicorp.com/gpg 2>/dev/null | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg --yes 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list > /dev/null
    sudo apt-get update -y &>/dev/null
    sudo apt-get install -y terraform &>/dev/null
    
    if [ $? -ne 0 ]; then
        # Strategy B: Force stable main Ubuntu release path (noble)
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com noble main" | sudo tee /etc/apt/sources.list.d/hashicorp.list > /dev/null
        sudo apt-get update -y &>/dev/null
        sudo apt-get install -y terraform &>/dev/null
        
        if [ $? -ne 0 ]; then
            # Strategy C: Raw Direct binary pull into user path using non-interactive flag (-o)
            TERRA_VERSION="1.9.5"
            curl -sSL -o terraform.zip "https://releases.hashicorp.com/terraform/${TERRA_VERSION}/terraform_${TERRA_VERSION}_linux_amd64.zip"
            unzip -o -q terraform.zip # -o forces overwrite without prompting for input
            mv -f terraform $HOME/.local/bin/
            rm -f terraform.zip
        fi
    fi
else
    echo "[-] Terraform is already installed."
fi
set -e # Re-enable strict error compliance

# 5. Install AWS CLI v2
echo "[+] Installing AWS CLI v2..."
if ! command -v aws &> /dev/null; then
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -o -q awscliv2.zip # -o forces overwrite if run multiple times
    sudo ./aws/install --update &>/dev/null
    rm -rf aws awscliv2.zip
else
    echo "[-] AWS CLI v2 is already installed."
fi

# 6. Install Open Policy Agent (OPA)
echo "[+] Downloading and configuring OPA..."
curl -sL -o $HOME/.local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x $HOME/.local/bin/opa

# 7. Install Conftest
echo "[+] Downloading and configuring Conftest..."
CONFTEST_VER="0.50.0"
wget -q "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VER}/conftest_${CONFTEST_VER}_Linux_x86_64.tar.gz"
tar -xzf "conftest_${CONFTEST_VER}_Linux_x86_64.tar.gz" conftest
mv -f conftest $HOME/.local/bin/
rm -f "conftest_${CONFTEST_VER}_Linux_x86_64.tar.gz"

# 8. Install tfsec
echo "[+] Installing tfsec scanner..."
set +e
sudo apt-get install -y -qq tfsec &>/dev/null
if [ $? -ne 0 ]; then
    curl -sL -o $HOME/.local/bin/tfsec https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64
    chmod +x $HOME/.local/bin/tfsec
fi
set -e

# 9. Install GitHub CLI (gh)
echo "[+] Installing GitHub CLI..."
if ! command -v gh &> /dev/null; then
    sudo mkdir -p -m 755 /etc/apt/keyrings
    wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
    sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    sudo apt-get update -y &>/dev/null && sudo apt-get install -y -qq gh &>/dev/null || echo "[-] Skipping non-essential GitHub client deployment..."
else
    echo "[-] GitHub CLI is already installed."
fi

# Clear terminal screen to cleanly present installation overview metrics
clear
echo "===================================================="
echo "      LAB DEPLOYMENT TOOLS VERSION DASHBOARD"
echo "===================================================="
echo ""

if command -v docker &> /dev/null; then echo -n "Docker:      "; docker --version; else echo "Docker:      MISSING"; fi
if command -v terraform &> /dev/null; then echo -n "Terraform:   "; terraform --version | head -n 1; else echo "Terraform:   MISSING"; fi
if command -v aws &> /dev/null; then echo -n "AWS CLI:     "; aws --version | cut -d' ' -f1-2; else echo "AWS CLI:     MISSING"; fi
if command -v opa &> /dev/null; then echo -n "OPA:         "; opa version | head -n 1; else echo "OPA:         MISSING"; fi
if command -v conftest &> /dev/null; then echo -n "Conftest:    "; conftest --version | head -n 1; else echo "Conftest:    MISSING"; fi
if command -v tfsec &> /dev/null; then echo -n "tfsec:       "; tfsec --version; else echo "tfsec:       MISSING"; fi
if command -v gh &> /dev/null; then echo -n "GitHub CLI:  "; gh --version | head -n 1; else echo "GitHub CLI:  NOT AVAILABLE"; fi

echo ""
echo "===================================================="
echo "[*] Run 'source ~/.bashrc' to finalize your user path updates."
echo "===================================================="
