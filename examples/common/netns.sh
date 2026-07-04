#!/bin/bash
# examples/common/netns.sh
# Network namespace helpers (meant to be sourced)

# Create a namespace (recreated if it exists, for idempotency)
# Usage: create_netns <name>
create_netns() {
    local name="$1"
    if [ -z "$name" ]; then
        echo "Error: namespace name required"
        return 1
    fi

    ip netns del "$name" 2>/dev/null || true
    ip netns add "$name"
    ip netns exec "$name" ip link set lo up

    echo "Created namespace: $name"
}

# Usage: delete_netns <name>
delete_netns() {
    local name="$1"
    if [ -z "$name" ]; then
        echo "Error: namespace name required"
        return 1
    fi

    ip netns del "$name" 2>/dev/null || true
    echo "Deleted namespace: $name"
}
