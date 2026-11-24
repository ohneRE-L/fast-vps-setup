#!/bin/bash
set -euo pipefail

# Цвета для вывода в терминал
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Проверяем права суперпользователя (root)
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}" >&2
    exit 1
fi

# Проверяем, что система Debian / Ubuntu
if [ ! -f /etc/debian_version ] || ! command -v apt-get >/dev/null 2>&1; then
    echo -e "${RED}Error: This script is only intended for Debian / Ubuntu!${NC}" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Проверяем наличие curl и сертификатов (ca-certificates)
NEED_INSTALL=0
if ! command -v curl >/dev/null 2>&1; then
    NEED_INSTALL=1
fi
if ! dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null | grep -q "install ok installed"; then
    NEED_INSTALL=1
fi

if [ "$NEED_INSTALL" -eq 1 ]; then
    echo -e "${GREEN}>>> Installing curl and ca-certificates...${NC}"
    apt-get update -qq && apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold curl ca-certificates
fi

echo -e "${GREEN}>>> Detecting system architecture...${NC}"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        BIN_NAME="setup_server_amd64"
        ;;
    aarch64|arm64)
        BIN_NAME="setup_server_arm64"
        ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}" >&2
        exit 1
        ;;
esac

echo -e "${GREEN}>>> Downloading VPS Shielder (${BIN_NAME})...${NC}"

RELEASE_TAG="${FAST_VPS_VERSION:-latest}"
if [[ ! "$RELEASE_TAG" =~ ^(latest|v?[0-9A-Za-z._-]+)$ ]] || [[ "$RELEASE_TAG" == *".."* ]]; then
    echo -e "${RED}Error: Invalid FAST_VPS_VERSION format: $RELEASE_TAG${NC}" >&2
    exit 1
fi
REPO="ohneRE-L/fast-vps-setup"
TARGET="/usr/local/bin/setup_server"
TMP_DIR="$(mktemp -d -t fast-vps-setup.XXXXXXXXXX)"
TMP_BIN="${TMP_DIR}/${BIN_NAME}"
TMP_SUMS="${TMP_DIR}/checksums.txt"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Формирование URL для скачивания из GitHub Releases
if [ "$RELEASE_TAG" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BIN_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/latest/download/checksums.txt"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${BIN_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/checksums.txt"
fi

if ! curl -fsSL -L -o "$TMP_BIN" "$DOWNLOAD_URL"; then
    echo -e "${RED}Error: Failed to download binary for $ARCH from GitHub Releases.${NC}" >&2
    exit 1
fi

# Проверка контрольной суммы (fail-closed: обязательна для безопасности)
if ! curl -fsSL -L -o "$TMP_SUMS" "$CHECKSUM_URL"; then
    echo -e "${RED}Error: Failed to download checksums.txt from GitHub Releases.${NC}" >&2
    exit 1
fi

EXPECTED_HASH=$(grep -E "[[:space:]]${BIN_NAME}\$" "$TMP_SUMS" | awk '{print $1}' | head -n 1 || true)
EXPECTED_HASH="${EXPECTED_HASH,,}"
if [[ ! "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    echo -e "${RED}Error: Invalid or missing SHA-256 checksum for $BIN_NAME in checksums.txt!${NC}" >&2
    exit 1
fi

ACTUAL_HASH=$(sha256sum "$TMP_BIN" | awk '{print $1}')
ACTUAL_HASH="${ACTUAL_HASH,,}"
if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
    echo -e "${RED}Error: Checksum mismatch for $BIN_NAME!${NC}" >&2
    echo -e "${RED}Expected: $EXPECTED_HASH${NC}" >&2
    echo -e "${RED}Got:      $ACTUAL_HASH${NC}" >&2
    exit 1
fi
echo -e "${GREEN}>>> Checksum verified successfully.${NC}"

# Установка бинарника с правами на запуск
install -m 0755 "$TMP_BIN" "$TARGET"

echo -e "${GREEN}>>> Starting setup_server...${NC}\n"
cleanup
exec "$TARGET"
