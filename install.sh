#!/bin/bash
# Скачиваем бинарник
curl -L -o /root/setup_server https://github.com/ВАШ_ЛОГИН/РЕПО/raw/main/setup_server
# Даем права
chmod +x /root/setup_server
# Запускаем
/root/setup_server