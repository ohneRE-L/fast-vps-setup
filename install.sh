#!/bin/bash
set -e

# Цвета для красоты
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Проверяем root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}"
    exit 1
fi

# Проверяем наличие curl и ca-certificates
if ! command -v curl &> /dev/null; then
    echo -e "${GREEN}>>> Installing curl and ca-certificates...${NC}"
    apt-get update -qq && apt-get install -y -qq curl ca-certificates
fi

echo -e "${GREEN}>>> Downloading VPS Shielder...${NC}"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        BIN_NAME="setup_server_amd64"
        ;;
    aarch64|arm64)
        BIN_NAME="setup_server_arm64"
        ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

RELEASE_URL="https://github.com/ohneRE-L/fast-vps-setup/releases/latest/download/${BIN_NAME}"
RAW_URL="https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/${BIN_NAME}"
FALLBACK_RAW_URL="https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/setup_server"

# Скачиваем бинарник: сначала из GitHub Releases, затем fallback на raw
if ! curl -fsSL -o /usr/local/bin/setup_server "$RELEASE_URL"; then
    if ! curl -fsSL -o /usr/local/bin/setup_server "$RAW_URL"; then
        if ! curl -fsSL -o /usr/local/bin/setup_server "$FALLBACK_RAW_URL"; then
            echo -e "${RED}Error: Failed to download binary for $ARCH${NC}"
            exit 1
        fi
    fi
fi

# Даем права на выполнение
chmod +x /usr/local/bin/setup_server

# Запускаем
exec /usr/local/bin/setup_server