#!/bin/sh
set -eu

ROOT="${ZK_SCRIBE_HOME:-$HOME/.zk-scribe}"
PACKAGE="${ZK_SCRIBE_PACKAGE:-https://github.com/brian-mwirigi/ZK-Scribe/archive/refs/heads/main.tar.gz}"
NODE_VERSION="v22.23.3"

node_major() {
  "$1" -p "process.versions.node.split('.')[0]"
}

if command -v node >/dev/null 2>&1; then
  MAJOR=$(node_major node || echo 0)
else
  MAJOR=0
fi

if [ "$MAJOR" -lt 22 ]; then
  OS=$(uname -s)
  ARCH=$(uname -m)
  case "$OS-$ARCH" in
    Linux-x86_64) ASSET="node-${NODE_VERSION}-linux-x64.tar.xz" ;;
    Linux-aarch64) ASSET="node-${NODE_VERSION}-linux-arm64.tar.xz" ;;
    Darwin-arm64) ASSET="node-${NODE_VERSION}-darwin-arm64.tar.gz" ;;
    Darwin-x86_64) ASSET="node-${NODE_VERSION}-darwin-x64.tar.gz" ;;
    *)
      echo "Install Node.js 22 or newer, then run this script again." >&2
      exit 1
      ;;
  esac
  mkdir -p "$ROOT"
  TMP=$(mktemp -d)
  URL="https://nodejs.org/dist/${NODE_VERSION}/${ASSET}"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$TMP/node.pkg"
  else
    wget -q -O "$TMP/node.pkg" "$URL"
  fi
  mkdir -p "$TMP/extract"
  tar -xf "$TMP/node.pkg" -C "$TMP/extract"
  rm -rf "$ROOT/node"
  mv "$TMP/extract"/node-* "$ROOT/node"
  rm -rf "$TMP"
fi

if [ -x "$ROOT/node/bin/node" ]; then
  PATH="$ROOT/node/bin:$PATH"
  export PATH
fi

mkdir -p "$ROOT"
npm install -g --prefix "$ROOT" "$PACKAGE"

mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/zk-scribe" <<EOF
#!/bin/sh
if [ -x "$ROOT/node/bin/node" ]; then
  PATH="$ROOT/node/bin:\$PATH"
  export PATH
fi
exec "$ROOT/bin/zk-scribe" "\$@"
EOF
chmod 755 "$HOME/.local/bin/zk-scribe"

echo "Installed zk-scribe."
echo "In the manuscript repository, run: zk-scribe init"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo "Add this to your shell profile: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
