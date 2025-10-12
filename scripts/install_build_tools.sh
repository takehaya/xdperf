#!/bin/bash
# Install build tools
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

install_tool "goreleaser" "go install github.com/goreleaser/goreleaser/v2@latest"
install_tool "tinygo" "wget https://github.com/tinygo-org/tinygo/releases/download/v0.39.0/tinygo_0.39.0_amd64.deb && sudo dpkg -i tinygo_0.39.0_amd64.deb && rm tinygo_0.39.0_amd64.deb"

echo "✅ All build tools have been installed successfully!"
