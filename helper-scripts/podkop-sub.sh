#!/bin/sh
set -eu

SUB_URL="https://your-sub/abc"

SECTION="main"
HWID_FILE="/etc/podkop-sub/hwid"

SUPPORTED_RE='^(vless|ss|trojan|hysteria2|hy2|socks|socks5)://'

get_or_create_hwid() {
  if [ -s "$HWID_FILE" ]; then
    cat "$HWID_FILE"
    return
  fi

  mkdir -p "$(dirname "$HWID_FILE")"

  if [ -r /proc/sys/kernel/random/uuid ]; then
    HWID="$(cat /proc/sys/kernel/random/uuid)"
  else
    HWID="$(hexdump -n 16 -e '4/4 "%08x" 1 "\n"' /dev/urandom)"
  fi

  echo "$HWID" > "$HWID_FILE"
  chmod 600 "$HWID_FILE"

  echo "$HWID"
}

command -v curl >/dev/null 2>&1 || {
  echo "ERROR: curl not found"
  echo "Install: opkg update && opkg install curl"
  exit 1
}

command -v uci >/dev/null 2>&1 || {
  echo "ERROR: uci not found"
  exit 1
}

TMP_DIR="$(mktemp -d /tmp/podkop-sub.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

SUB_FILE="$TMP_DIR/sub.raw"
DECODED_FILE="$TMP_DIR/sub.decoded"

HWID="$(get_or_create_hwid)"

echo "Using HWID: $HWID"
echo "Fetching subscription..."

HTTP_CODE="$(curl -k -sS -L \
  -H "X-HWID: $HWID" \
  -w "%{http_code}" \
  -o "$SUB_FILE" \
  "$SUB_URL")"

if [ "$HTTP_CODE" != "200" ]; then
  echo "ERROR: subscription request failed"
  echo "HTTP status: $HTTP_CODE"
  echo "Response body:"
  cat "$SUB_FILE"
  echo
  exit 1
fi

# Plain text subscription
if tr -d '\r' < "$SUB_FILE" | grep -Eq "$SUPPORTED_RE"; then
  tr -d '\r' < "$SUB_FILE" > "$DECODED_FILE"

# Base64 subscription
else
  echo "No plain proxy URL found, trying base64 decode..."

  command -v base64 >/dev/null 2>&1 || {
    echo "ERROR: base64 not found"
    echo "Install: opkg update && opkg install coreutils-base64"
    exit 1
  }

  B64="$(tr -d '\r\n ' < "$SUB_FILE" | tr '_-' '/+')"

  MOD=$(( ${#B64} % 4 ))
  case "$MOD" in
    0) ;;
    2) B64="${B64}==" ;;
    3) B64="${B64}=" ;;
    *) echo "ERROR: invalid base64 subscription"; exit 1 ;;
  esac

  printf '%s' "$B64" | base64 -d > "$DECODED_FILE"
fi

PROXY_URL="$(grep -E "$SUPPORTED_RE" "$DECODED_FILE" | head -n 1 || true)"

if [ -z "$PROXY_URL" ]; then
  echo "ERROR: no supported proxy URL found"
  echo "Decoded subscription:"
  cat "$DECODED_FILE" || true
  echo
  exit 1
fi

echo "Selected proxy:"
echo "$PROXY_URL"

echo "Setting Podkop UCI..."

uci set "podkop.$SECTION.proxy_string=$PROXY_URL"
uci commit podkop


echo "Done."
echo "Current proxy_string:"
uci -q get "podkop.$SECTION.proxy_string"