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

LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="v1.0.0"
fi

if ! echo "$LATEST_TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.]+)?$'; then
  echo "❌ Security Error: Invalid release tag format '${LATEST_TAG}'. Aborting." >&2
  exit 1
fi

ARCHIVE="secretguard-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ARCHIVE}"
EXPECTED_WORKFLOW="${REPO}/.github/workflows/release.yml"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading SecretGuard (${TARGET}) ${LATEST_TAG}..."
curl -fsSL "$URL" -o "${TMP_DIR}/${ARCHIVE}"
curl -fsSL "${URL}.sha256" -o "${TMP_DIR}/${ARCHIVE}.sha256"

# 1. Integrity check (verifies download was not corrupted relative to release .sha256; NOT proof of authenticity)
echo "🔒 Verifying SHA-256 download integrity checksum..."
(
  cd "$TMP_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "${ARCHIVE}.sha256" || { echo "❌ Security Error: SHA-256 checksum verification failed! Aborting." >&2; exit 1; }
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "${ARCHIVE}.sha256" || { echo "❌ Security Error: SHA-256 checksum verification failed! Aborting." >&2; exit 1; }
  else
    echo "❌ Security Error: Neither sha256sum nor shasum is available. Cannot verify archive integrity!" >&2
    exit 1
  fi
)

# 2. Mandatory Authenticity & Provenance Verification (Fail-Closed: never skip)
AUTHENTICITY_VERIFIED=0

if [ -n "${SECRETGUARD_MINISIGN_PUBKEY:-}" ]; then
  if ! command -v minisign >/dev/null 2>&1; then
    echo "❌ Security Error: SECRETGUARD_MINISIGN_PUBKEY is set, but 'minisign' is not installed. Failing closed." >&2
    exit 1
  fi
  echo "🔏 Verifying Minisign cryptographic signature against pinned public key..."
  curl -fsSL "${URL}.minisig" -o "${TMP_DIR}/${ARCHIVE}.minisig" || {
    echo "❌ Security Error: Failed to download Minisign signature (${URL}.minisig). Unsigned release rejected." >&2
    exit 1
  }
  minisign -Vm "${TMP_DIR}/${ARCHIVE}" -P "$SECRETGUARD_MINISIGN_PUBKEY" || {
    echo "❌ Security Error: Minisign signature verification failed! Untrusted binary. Aborting." >&2
    exit 1
  }
  echo "✅ Minisign cryptographic signature verified."
  AUTHENTICITY_VERIFIED=1
fi

if command -v gh >/dev/null 2>&1; then
  echo "🔍 Verifying GitHub build provenance attestation (repo=${REPO}, workflow=${EXPECTED_WORKFLOW}, tag=${LATEST_TAG})..."
  gh attestation verify "${TMP_DIR}/${ARCHIVE}" \
    --repo "$REPO" \
    --signer-workflow "$EXPECTED_WORKFLOW" \
    --source-ref "refs/tags/${LATEST_TAG}" \
    --deny-self-hosted-runners || {
    echo "❌ Security Error: GitHub build provenance attestation verification failed! Untrusted or tampered release. Aborting." >&2
    exit 1
  }
  echo "✅ GitHub build provenance attestation verified."
  AUTHENTICITY_VERIFIED=1
elif [ "$AUTHENTICITY_VERIFIED" -ne 1 ]; then
  echo "❌ Security Error: Mandatory release authenticity verification cannot run because GitHub CLI ('gh') is not installed" >&2
  echo "   and no pinned Minisign public key (SECRETGUARD_MINISIGN_PUBKEY) was provided." >&2
  echo "   SHA-256 checksums alone do NOT prove release authenticity." >&2
  echo "   Install 'gh' (https://cli.github.com/) and re-run this installer. Failing closed." >&2
  exit 1
fi

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
