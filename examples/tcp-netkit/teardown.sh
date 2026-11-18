#!/bin/bash
# tcp-netkit: remove namespaces and helper processes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

check_root
stop_nk_processes
delete_netns "${NS_TX}"
delete_netns "${NS_DUT}"
delete_netns "${NS_RX_L2}"
delete_netns "${NS_RX_L3}"
print_success "tcp-netkit topology removed"
