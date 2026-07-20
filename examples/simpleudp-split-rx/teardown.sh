#!/bin/bash
# simpleudp-split-rx scenario: clean up
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

check_root
delete_netns "${NS_GEN}"
delete_netns "${NS_DUT}"
print_success "simpleudp-split-rx scenario cleaned up"
