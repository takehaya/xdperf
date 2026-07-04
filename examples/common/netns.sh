#!/bin/bash
# examples/common/netns.sh
# network namespace ユーティリティ (source して使う)

# namespace を作成 (既存なら作り直して冪等にする)
# Usage: create_netns <name>
create_netns() {
    local name="$1"
    if [ -z "$name" ]; then
        echo "Error: namespace 名が必要です"
        return 1
    fi

    ip netns del "$name" 2>/dev/null || true
    ip netns add "$name"
    ip netns exec "$name" ip link set lo up

    echo "Created namespace: $name"
}

# namespace を削除 (無ければ何もしない)
# Usage: delete_netns <name>
delete_netns() {
    local name="$1"
    if [ -z "$name" ]; then
        echo "Error: namespace 名が必要です"
        return 1
    fi

    ip netns del "$name" 2>/dev/null || true
    echo "Deleted namespace: $name"
}
