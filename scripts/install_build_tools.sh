#!/bin/bash
# Install build tools
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

install_tool "goreleaser" "go install github.com/goreleaser/goreleaser/v2@latest"

echo "✅ All build tools have been installed successfully!"
