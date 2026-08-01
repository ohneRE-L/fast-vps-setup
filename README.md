# Fast VPS Setup [EN]

An automated **Go** script for fast and secure configuration of a new VPS server in one command.

**Multi-language support:** The script supports both **Russian** and **English** languages (selectable at startup).

## 🛠 What does this script do?

1.  **System Update (optional):** Runs `apt update && apt dist-upgrade -y && apt autoremove -y` to keep system updated along with the latest Linux kernels and clean up orphan packages (selectable as a menu option).
2.  **Optimization (ulimit):** Increases open files limit to `65535` for stable proxy performance under load.
3.  **SSH Port (optional):** Moves SSH to your chosen port (fully supporting Ubuntu 22.04/24.04 and `ssh.socket` mechanisms).
4.  **Firewall (UFW, optional):** Careful configuration with comments for convenience:
    *   **SSH**: `#SSH` — your current or new port.
    *   **443/tcp**: `#VPN` — for proxy traffic.
    *   **3/tcp**: `#PANEL` — for 3x-ui management.
    *   **10443/tcp**: `#SUBSCRIPTION` — for subscriptions.
    *   **8443/tcp**: For **telemt**.
5.  **Interactive Component Menu:** Choose exactly what to install using a startup menu (supports comma inputs, exit on `0`, and invalid input protection): **3x-ui**, **telemt**, **WARP watchdog**, **Fail2Ban**, **BBR**, **Cloudflare DNS**, and **full system/kernel updates**.
6.  **WARP Watchdog:** A script to monitor Cloudflare WARP on port 40000 with automatic restart upon failure.
7.  **BBR + BDP/TFO Acceleration:** Enables Google BBR, tunes TCP buffer sizes (BDP), enables TCP Fast Open (TFO), and enables MTU probing to maximize throughput and minimize latency for proxies.
8.  **Fail2Ban:** Protects SSH from brute-force attacks by automatically blocking suspicious IPs.
9.  **Maximum Security:** If 3x-ui is selected, the script generates a **random login**, **random password**, and a **random secret path** (Web Base Path).
10. **DNS (Cloudflare):** Setup of fast and reliable DNS server 1.1.1.1 (optional).
11. **SSH Key Setup:** Optional addition of your public SSH key for secure login and complete disablement of password authentication.
12. **SSH Socket Disabling (optional):** Disables systemd `ssh.socket` activation (introduced in Ubuntu 24.04) and switches to the classic, isolated `ssh.service` (sshd) for reliable port management.
---

## 🚀 Installation

Simply copy and paste this command into the terminal of your new server:

```bash
bash -c "$(curl -sL https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/install.sh)"
```

---

## 🔑 After Installation

Upon completion, the script will output a frame in the console with your login details:
*   **Full URL** (including the secret path)
*   **Login** (randomly generated)
*   **Password** (randomly generated)

> **WARNING:** If you try to access `http://IP:3` directly, the server will return a 404 error. This is intentional to hide the panel from scanners. Only use the full secret link!

---

# Fast VPS Setup

Автоматизированный скрипт на **Go** для быстрой и безопасной настройки нового VPS сервера за одну команду.

**Multi-language support:** Скрипт поддерживает **русский** и **английский** языки (выбор при запуске).

## 🛠 Что делает скрипт?

1.  **Обновление системы (опционально):** Выполняет `apt update && apt dist-upgrade -y && apt autoremove -y` (полное обновление системы и ядра Linux, а также удаление ненужного системного мусора). Теперь этот шаг можно запустить по выбору через меню.
2.  **Оптимизация (ulimit):** Увеличивает лимит открытых файлов до `65535` для стабильной работы прокси под нагрузкой.
3.  **Порт SSH (опционально):** Переносит SSH на выбранный вами порт (с полной поддержкой Ubuntu 22.04/24.04 и механизмов `ssh.socket`).
4.  **Firewall (UFW, опционально):** Тщательная настройка с комментариями для удобства:
    *   **SSH**: `#SSH` — ваш текущий или новый порт.
    *   **443/tcp**: `#VPN` — для трафика прокси.
    *   **3/tcp**: `#PANEL` — для управления 3x-ui.
    *   **10443/tcp**: `#SUBSCRIPTION` — для подписок.
    *   **8443/tcp**: Для работы **telemt**.
5.  **Интерактивное меню компонентов:** Удобный выбор на старте через номера (с выходом по `0` и валидацией ввода). Вы выбираете, ставить ли **3x-ui**, **telemt**, **WARP watchdog**, **Fail2Ban**, **BBR**, настраивать ли **Cloudflare DNS**, а также запускать ли **полное обновление пакетов и ядра**.
6.  **WARP Watchdog:** Скрипт для мониторинга Cloudflare WARP на порту 40000 с автоматическим перезапуском при сбоях.
7.  **Ускорение BBR + BDP/TFO:** Включает алгоритм Google BBR, оптимизирует буферы TCP (BDP), включает TCP Fast Open (TFO) и зондирование MTU для максимальной скорости и минимального пинга прокси.
8.  **Fail2Ban:** Защищает SSH от брутфорс-атак, автоматически блокируя подозрительные IP.
9.  **Максимальная защита:** Если выбран 3x-ui, скрипт сгенерирует **случайный логин**, **случайный пароль** и **случайный секретный путь** (Web Base Path).
10. **DNS (Cloudflare):** Настройка быстрого и надежного DNS-сервера 1.1.1.1 (опционально).
11. **Настройка SSH-ключа:** Опциональное добавление вашего публичного SSH-ключа для безопасного входа и полное отключение парольной авторизации.
12. **Отключение SSH Socket (опционально):** Полное отключение `ssh.socket` активации systemd (появившейся в Ubuntu 24.04) и возврат к классической изолированной службе `ssh.service` (sshd) для более надежной смены портов.
---

## 🚀 Установка

Просто скопируйте и вставьте эту команду в терминал вашего нового сервера:

```bash
bash -c "$(curl -sL https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/install.sh)"
```

---

## 🔑 После установки

По завершении работы скрипт выведет в консоль рамку с данными для входа:
*   **Полная ссылка** (включая секретный путь)
*   **Логин** (сгенерирован случайно)
*   **Пароль** (сгенерирован случайно)

> **ВНИМАНИЕ:** Если вы попробуете зайти просто по `http://IP:3`, сервер выдаст ошибку 404. Это сделано специально, чтобы скрыть панель от сканеров. Используйте только полную секретную ссылку!