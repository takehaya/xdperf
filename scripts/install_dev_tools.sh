#!/bin/bash
# Install development tools
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

install_tool "goimports" "go install golang.org/x/tools/cmd/goimports@v0.38.0"
install_tool "nilaway" "go install go.uber.org/nilaway/cmd/nilaway@latest"

echo "✅ All development tools have been installed successfully!"
