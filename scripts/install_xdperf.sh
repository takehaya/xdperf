#!/usr/bin/env bash
set -euo pipefail

REPO="takehaya/xdperf"
BIN_DIR="/usr/local/bin"
PLUGIN_DIR="/usr/local/share/xdperf/plugins"
STATE_FILE="/usr/local/share/xdperf/.installed-from-tag"

VERSION="${XDPERF_VERSION:-}"
if [ "${1:-}" = "--version" ] && [ -n "${2:-}" ]; then
  VERSION="$2"
  shift 2
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
  META_URL="https://api.github.com/repos/$REPO/releases/latest"
else
  META_URL="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
fi
JSON="$(curl -fsSL "$META_URL")"

BIN_URL="$(echo "$JSON" | jq -r --arg a "$ARCH" '
  .assets[]?.browser_download_url
  | select(test("/xdperf_.*_linux_" + $a + "$"))
' | head -n1)"
[ -n "$BIN_URL" ] || { echo "No binary asset matched for linux_${ARCH}"; exit 1; }

mapfile -t WASM_URLS < <(echo "$JSON" | jq -r --arg a "$ARCH" '
  .assets[]?.browser_download_url
  | select(test("/.*\\.wasm_.*_linux_" + $a + "$"))
')
TAG_NAME="$(echo "$JSON" | jq -r '.tag_name // empty')"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$BIN_DIR" "$PLUGIN_DIR"

# バイナリ取得
BIN_NAME="$(basename "$BIN_URL")"
curl -fsSL "$BIN_URL" -o "$TMP/$BIN_NAME"

# 実行属性を付けて配置
chmod +x "$TMP/$BIN_NAME"
install -m 0755 "$TMP/$BIN_NAME" "$BIN_DIR/xdperf"

# プラグイン配置（同名のみ上書き）
for U in "${WASM_URLS[@]}"; do
  W="$(basename "$U")"
  curl -fsSL "$U" -o "$TMP/$W"
  DEST_NAME="${W%%.wasm*}.wasm"
  install -m 0644 "$TMP/$W" "$PLUGIN_DIR/$DEST_NAME"
done

echo "${TAG_NAME:-${VERSION:-latest}}" > "$STATE_FILE"

echo "Installed xdperf"
echo "Binary   $BIN_DIR/xdperf"
echo "Plugins  $PLUGIN_DIR"
echo "Version  ${TAG_NAME:-${VERSION:-latest}}"
