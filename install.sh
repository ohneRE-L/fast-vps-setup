#!/bin/bash

# Цвета для красоты
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> Downloading VPS Shielder...${NC}"

# Скачиваем бинарник во временную папку
curl -sL -o /usr/local/bin/setup_server "https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/setup_server"

# Даем права на выполнение
chmod +x /usr/local/bin/setup_server

# Запускаем
/usr/local/bin/setup_server