#!/usr/bin/env bash
set -e

# SecretGuard 1-Line Universal Installer for macOS and Linux

REPO="hemanathk636/secretguard"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

echo "🛡️ Installing SecretGuard..."

# Detect OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64) TARGET="x86_64-apple-darwin" ;;
      arm64) TARGET="aarch64-apple-darwin" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS. For Windows, download the binary from GitHub Releases."
    exit 1
    ;;
esac

LATEST_TAG=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="v0.2.0"
fi

ARCHIVE="secretguard-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ARCHIVE}"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading SecretGuard (${TARGET}) ${LATEST_TAG}..."
curl -fsSL "$URL" -o "${TMP_DIR}/${ARCHIVE}"

tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"

if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/secretguard" "$INSTALL_DIR/secretguard"
else
  echo "Installing to $INSTALL_DIR requires sudo permissions:"
  sudo mv "${TMP_DIR}/secretguard" "$INSTALL_DIR/secretguard"
fi

chmod +x "$INSTALL_DIR/secretguard"
echo "✅ Installed secretguard binary to $INSTALL_DIR/secretguard"

# Automatically offer to add to .zshrc or .bashrc
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
  if ! grep -q "secretguard hook zsh" "$HOME/.zshrc" 2>/dev/null; then
    echo 'eval "$(secretguard hook zsh)"' >> "$HOME/.zshrc"
    echo "✅ Added SecretGuard hook to ~/.zshrc"
  fi
elif [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
  if ! grep -q "secretguard hook bash" "$HOME/.bashrc" 2>/dev/null; then
    echo 'eval "$(secretguard hook bash)"' >> "$HOME/.bashrc"
    echo "✅ Added SecretGuard hook to ~/.bashrc"
  fi
fi

echo ""
echo "🎉 SecretGuard is ready! Restart your terminal or run:"
echo "   source ~/.zshrc (or source ~/.bashrc)"
