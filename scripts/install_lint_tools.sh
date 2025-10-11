#!/bin/bash

set -euo pipefail

echo "Installing lint tools required by lefthook..."

# This script supports only Debian-based systems (Debian, Ubuntu, etc.)
if ! command -v apt-get >/dev/null 2>&1; then
    echo "Error: This script requires apt-get (Debian-based systems only)"
    echo "Supported systems: Debian, Ubuntu, and derivatives"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

# Ensure ~/.local/bin directory exists
mkdir -p "${HOME}/.local/bin"

# Update package list once
echo "Updating package list..."
sudo apt-get update -qq

# lefthook
install_tool "lefthook" "go install github.com/evilmartians/lefthook@latest"

# yamllint
install_tool "yamllint" "sudo apt-get install -y yamllint"

# jq
install_tool "jq" "sudo apt-get install -y jq"

# dos2unix
install_tool "dos2unix" "sudo apt-get install -y dos2unix"

# clang-format
install_tool "clang-format" "sudo apt-get install -y clang-format"

# buf
install_tool "buf" "curl -sSL https://github.com/bufbuild/buf/releases/latest/download/buf-$(uname -s)-$(uname -m) | install -m 755 /dev/stdin ~/.local/bin/buf"

# golangci-lint
install_tool "golangci-lint" "go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"

# taplo (TOML linter)
install_tool "taplo" "curl -fsSL https://github.com/tamasfe/taplo/releases/latest/download/taplo-linux-x86_64.gz | gzip -d - | install -m 755 /dev/stdin ~/.local/bin/taplo"

echo ""
echo "✅ All lint tools have been installed successfully!"
echo ""
echo "You can now use lefthook for pre-commit hooks."
echo "Run 'lefthook install' to set up the git hooks."
