#!/usr/bin/env bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

WITH_OLLAMA=false
for arg in "$@"; do
  [[ "$arg" == "--with-ollama" ]] && WITH_OLLAMA=true
done

# Check Linux
if [[ "$(uname -s)" != "Linux" ]]; then
  echo -e "${RED}Error: Ghost-Protocol requires Linux.${NC}"
  echo "Use a VirtualBox VM with Ubuntu 22.04+ on Windows/macOS."
  exit 1
fi

# Check Ubuntu/Debian
if ! command -v apt &>/dev/null; then
  echo -e "${RED}Error: This script requires apt (Ubuntu/Debian).${NC}"
  exit 1
fi

echo -e "${YELLOW}Installing system dependencies...${NC}"
sudo apt update && sudo apt install -y \
  build-essential pkg-config libssl-dev \
  clang llvm linux-headers-$(uname -r) \
  curl git

# Install Rust if not present
if ! command -v rustup &>/dev/null; then
  echo -e "${YELLOW}Installing Rust...${NC}"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- --default-toolchain stable --no-modify-path -y
  source "$HOME/.cargo/env"
else
  echo -e "${GREEN}Rust already installed.${NC}"
fi

echo -e "${YELLOW}Installing nightly toolchain + eBPF requirements...${NC}"
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

# Auto-detect default interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo -e "${GREEN}Detected network interface: $IFACE${NC}"
echo "Set interface = \"$IFACE\" in ghostd.toml"

# Optional ollama
if [[ "$WITH_OLLAMA" == true ]]; then
  echo -e "${YELLOW}Installing ollama...${NC}"
  curl -fsSL https://ollama.ai/install.sh | sh
  echo -e "${YELLOW}Waiting for ollama service to start...${NC}"
  for i in {1..10}; do
    if ollama list &>/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  echo -e "${YELLOW}Pulling phi3:mini model (~2GB)...${NC}"
  ollama pull phi3:mini
  echo -e "${GREEN}Ollama ready.${NC}"
else
  echo -e "${YELLOW}Skipping ollama. Re-run with --with-ollama to enable LLM personas.${NC}"
fi

# --- SECTION 1: TOTP Secret Generation ---

read -rp "Generate a TOTP secret now? (y/n): " gen_secret
if [[ "$gen_secret" == "y" ]]; then
  SECRET=$(openssl rand -hex 20 2>/dev/null | \
    python3 -c "import sys,base64; \
    print(base64.b32encode(bytes.fromhex(sys.stdin.read().strip())).decode())" \
    2>/dev/null)

  if [[ -z "$SECRET" ]]; then
    SECRET=$(python3 -c \
      "import base64,os; \
      print(base64.b32encode(os.urandom(20)).decode())" \
      2>/dev/null)
  fi

  if [[ -z "$SECRET" ]]; then
    echo -e "${RED}Could not generate secret. Install python3 or upgrade openssl.${NC}"
    exit 1
  fi
  echo ""
  echo -e "${GREEN}Your TOTP secret:${NC}"
  echo "  $SECRET"
  echo ""
  echo "Add this to ghostd.toml under [knock]:"
  echo "  secret = \"$SECRET\""
  echo ""
  # Save to a temp file for SSH config step below
  echo "$SECRET" > /tmp/ghost_secret.txt
fi

# --- SECTION 2: SSH Config Setup ---

if [[ -f /tmp/ghost_secret.txt ]]; then
  SECRET=$(cat /tmp/ghost_secret.txt)
  read -rp "Configure ~/.ssh/config for ghost-knock now? (y/n): " cfg_ssh
  if [[ "$cfg_ssh" == "y" ]]; then
    read -rp "Server IP or hostname: " SERVER_HOST
    read -rp "SSH username: " SSH_USER
    read -rp "Base port (default 10000): " BASE_PORT
    BASE_PORT=${BASE_PORT:-10000}
    read -rp "Port range (default 1000): " PORT_RANGE
    PORT_RANGE=${PORT_RANGE:-1000}

    # Ensure ~/.ssh directory exists
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh

    # Check if entry already exists
    if grep -q "Ghost-Protocol" ~/.ssh/config 2>/dev/null; then
      echo -e "${YELLOW}Ghost-Protocol entry already exists in ~/.ssh/config — skipping.${NC}"
    else
      cat >> ~/.ssh/config <<EOF

# Ghost-Protocol — added by setup.sh
Host ghost-server
    HostName $SERVER_HOST
    User $SSH_USER
    ProxyCommand $(pwd)/target/release/ghost-knock %h $BASE_PORT $PORT_RANGE "$SECRET"
EOF
      chmod 600 ~/.ssh/config
      echo -e "${GREEN}SSH config updated. Connect with: ssh ghost-server${NC}"
    fi
  fi
  rm -f /tmp/ghost_secret.txt
fi

# --- SECTION 3: Test the whole setup ---

echo -e "${YELLOW}Running self-test...${NC}"

# Test 1: cargo check
echo "  [1/3] cargo check --workspace"
cargo check --workspace --quiet && \
  echo -e "  ${GREEN}PASS${NC}" || \
  echo -e "  ${RED}FAIL — run: cargo check --workspace${NC}"

# Test 2: cargo clippy
echo "  [2/3] cargo clippy --workspace"
cargo clippy --workspace --quiet -- -D warnings && \
  echo -e "  ${GREEN}PASS${NC}" || \
  echo -e "  ${RED}FAIL — run: cargo clippy --workspace${NC}"

# Test 3: cargo test
echo "  [3/3] cargo test --workspace"
cargo test --workspace --quiet -- --test-threads=1 && \
  echo -e "  ${GREEN}PASS — all tests passing${NC}" || \
  echo -e "  ${RED}FAIL — run: cargo test --workspace${NC}"

echo -e "${GREEN}"
echo "================================================"
echo " Ghost-Protocol setup complete."
echo "================================================"
echo -e "${NC}"
