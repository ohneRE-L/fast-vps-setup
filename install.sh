#!/bin/bash

# Цвета для красоты
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

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

# Скачиваем бинарник под нужную архитектуру (с fallback на setup_server)
if ! curl -sL -f -o /usr/local/bin/setup_server "https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/${BIN_NAME}"; then
    curl -sL -o /usr/local/bin/setup_server "https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/setup_server"
fi

# Даем права на выполнение
chmod +x /usr/local/bin/setup_server

# Запускаем
/usr/local/bin/setup_server