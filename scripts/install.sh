#!/usr/bin/env bash
# DIZGIN installer — macOS and Linux
# Installs dizgin and dizgind to the first writable directory already in PATH.
# Never modifies PATH.
#
# Usage (release):
#   curl -fsSL https://raw.githubusercontent.com/sungurerdim/dizgin/main/scripts/install.sh | sh
#
# Usage (local test — skips download/verify):
#   LOCAL_BINARY=./bin/dizgin ./scripts/install.sh
set -euo pipefail

REPO="sungurerdim/dizgin"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

# ── helpers ──────────────────────────────────────────────────────────────────

die() { echo "error: $*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not found in PATH"
}

# detect_platform sets GOOS and GOARCH in goreleaser naming convention.
detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$os" in
    linux)  GOOS="linux"  ;;
    darwin) GOOS="darwin" ;;
    *)      die "unsupported OS: $os" ;;
  esac
  case "$arch" in
    x86_64)         GOARCH="amd64" ;;
    aarch64|arm64)  GOARCH="arm64" ;;
    *)              die "unsupported architecture: $arch" ;;
  esac
}

# find_install_dir echoes the best writable directory from PATH.
# Preference: existing dizgin location → /usr/local/bin → ~/.local/bin → ~/bin → first writable.
find_install_dir() {
  # If DIZGIN is already installed, use the same directory (update-in-place).
  local existing
  existing=$(command -v "dizgin" 2>/dev/null || true)
  if [ -n "$existing" ]; then
    local dir
    dir=$(dirname "$existing")
    if [ -w "$dir" ]; then
      echo "$dir"; return
    fi
  fi

  # Prefer well-known directories if they are already in PATH and writable.
  local preferred=(/usr/local/bin "$HOME/.local/bin" "$HOME/bin")
  for dir in "${preferred[@]}"; do
    if [ -d "$dir" ] && [ -w "$dir" ] && _dir_in_path "$dir"; then
      echo "$dir"; return
    fi
  done

  # Fall back to first writable directory in PATH.
  IFS=':' read -ra path_dirs <<< "$PATH"
  for dir in "${path_dirs[@]}"; do
    [ -d "$dir" ] && [ -w "$dir" ] && echo "$dir" && return
  done

  return 1
}

_dir_in_path() {
  local target="$1"
  IFS=':' read -ra dirs <<< "$PATH"
  for d in "${dirs[@]}"; do [ "$d" = "$target" ] && return 0; done
  return 1
}

# checksum_verify verifies the SHA-256 of FILE against CHECKSUMS_FILE for ASSET_NAME.
checksum_verify() {
  local file="$1" checksums="$2" asset="$3"
  local expected
  expected=$(grep "[[:space:]]${asset}$" "$checksums" | awk '{print $1}')
  [ -n "$expected" ] || die "checksum entry not found for $asset"

  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    die "sha256sum or shasum required for checksum verification"
  fi

  [ "$actual" = "$expected" ] || die "checksum mismatch for $asset (got $actual, want $expected)"
}

# install_binary downloads, verifies, extracts, and installs a single binary.
install_binary() {
  local bin="$1" version_strip="$2" version="$3" install_dir="$4" tmp="$5" checksums_file="$6"
  local asset="${bin}_${version_strip}_${GOOS}_${GOARCH}.tar.gz"
  local asset_url="https://github.com/${REPO}/releases/download/${version}/${asset}"

  echo "  Downloading ${asset}..."
  curl -fsSL "$asset_url" -o "$tmp/$asset"

  checksum_verify "$tmp/$asset" "$checksums_file" "$asset"

  tar -xzf "$tmp/$asset" -C "$tmp" "$bin"
  install -m 755 "$tmp/$bin" "$install_dir/$bin"
  echo "  $bin -> $install_dir/$bin"
}

# ── main ─────────────────────────────────────────────────────────────────────

require curl

detect_platform

# Find install directory.
INSTALL_DIR=$(find_install_dir) || {
  echo "error: no writable directory found in PATH." >&2
  echo "" >&2
  echo "Directories in PATH (none are writable):" >&2
  IFS=':' read -ra dirs <<< "$PATH"
  for d in "${dirs[@]}"; do echo "  $d" >&2; done
  echo "" >&2
  echo "Add a writable directory to PATH first, then re-run this installer." >&2
  exit 1
}

# ── local test mode ───────────────────────────────────────────────────────────
if [ -n "${LOCAL_BINARY:-}" ]; then
  echo "Local binary: ${LOCAL_BINARY}"
  echo "Installing..."
  install -m 755 "$LOCAL_BINARY" "$INSTALL_DIR/dizgin"
  echo "  dizgin -> ${INSTALL_DIR}/dizgin"

  # Install dizgind if present alongside dizgin.
  local_dir=$(dirname "$LOCAL_BINARY")
  if [ -f "$local_dir/dizgind" ]; then
    install -m 755 "$local_dir/dizgind" "$INSTALL_DIR/dizgind"
    echo "  dizgind -> ${INSTALL_DIR}/dizgind"
  fi

  echo ""
  echo "DIZGIN (local build) installed -> ${INSTALL_DIR}"
  exit 0
fi

# ── release mode ─────────────────────────────────────────────────────────────
echo "Fetching latest release..."
RELEASE_JSON=$(curl -fsSL "$API_URL")
VERSION=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
[ -n "$VERSION" ] || die "could not determine latest version"
VERSION_STRIP="${VERSION#v}"

CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading checksums..."
curl -fsSL "$CHECKSUM_URL" -o "$TMP/checksums.txt"

echo "Installing..."
install_binary "dizgin"  "$VERSION_STRIP" "$VERSION" "$INSTALL_DIR" "$TMP" "$TMP/checksums.txt"
install_binary "dizgind" "$VERSION_STRIP" "$VERSION" "$INSTALL_DIR" "$TMP" "$TMP/checksums.txt"

echo ""
echo "DIZGIN ${VERSION} installed -> ${INSTALL_DIR}"
