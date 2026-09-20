#!/bin/bash
set -euo pipefail

# Цвета для вывода в терминал
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Проверяем права суперпользователя (root)
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}" >&2
    exit 1
fi

# Проверяем наличие curl и ca-certificates
if ! command -v curl &> /dev/null || ! command -v ca-certificates &> /dev/null; then
    echo -e "${GREEN}>>> Installing curl and ca-certificates...${NC}"
    apt-get update -qq && apt-get install -y -qq curl ca-certificates
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
REPO="ohneRE-L/fast-vps-setup"
TARGET="/usr/local/bin/setup_server"
TMP_BIN="/tmp/${BIN_NAME}.$$"
TMP_SUMS="/tmp/checksums.$$.txt"

cleanup() {
    rm -f "$TMP_BIN" "$TMP_SUMS"
}
trap cleanup EXIT

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

# Проверка контрольной суммы (если checksums.txt опубликован в релизе)
if curl -fsSL -L -o "$TMP_SUMS" "$CHECKSUM_URL" 2>/dev/null; then
    EXPECTED_HASH=$(grep -E "${BIN_NAME}\$" "$TMP_SUMS" | awk '{print $1}' | head -n 1 || true)
    if [ -n "$EXPECTED_HASH" ]; then
        ACTUAL_HASH=$(sha256sum "$TMP_BIN" | awk '{print $1}')
        if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
            echo -e "${RED}Error: Checksum mismatch for $BIN_NAME!${NC}" >&2
            echo -e "${RED}Expected: $EXPECTED_HASH${NC}" >&2
            echo -e "${RED}Got:      $ACTUAL_HASH${NC}" >&2
            exit 1
        fi
        echo -e "${GREEN}>>> Checksum verified successfully.${NC}"
    fi
fi

# Атомарная установка и права на запуск
mv "$TMP_BIN" "$TARGET"
chmod +x "$TARGET"

echo -e "${GREEN}>>> Starting setup_server...${NC}\n"
exec "$TARGET"