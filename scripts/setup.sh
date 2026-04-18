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

echo -e "${YELLOW}Installing nightly toolchain + eBPF target...${NC}"
rustup toolchain install nightly
rustup target add bpfel-unknown-none --toolchain nightly
cargo install bpf-linker

# Optional ollama
if [[ "$WITH_OLLAMA" == true ]]; then
  echo -e "${YELLOW}Installing ollama...${NC}"
  curl -fsSL https://ollama.ai/install.sh | sh
  echo -e "${YELLOW}Pulling phi3:mini model (~2GB)...${NC}"
  ollama pull phi3:mini
  echo -e "${GREEN}Ollama ready.${NC}"
else
  echo -e "${YELLOW}Skipping ollama. Re-run with --with-ollama to enable LLM personas.${NC}"
fi

echo -e "${GREEN}"
echo "================================================"
echo " Ghost-Protocol dependencies installed."
echo " Next steps:"
echo "   cargo build --release --workspace"
echo "   sudo ./target/release/ghostd --config ghostd.toml"
echo "================================================"
echo -e "${NC}"
