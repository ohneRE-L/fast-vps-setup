# Fast VPS Setup [EN]

An automated **Go** script for fast and secure configuration of a new VPS server in one command.

**Multi-language support:** The script supports both **Russian** and **English** languages (selectable at startup).

## 🛠 What does this script do?

1.  **System Update (optional):** Runs `apt update && apt dist-upgrade -y && apt autoremove -y` to keep system updated along with the latest Linux kernels and clean up orphan packages (selectable as a menu option).
2.  **Optimization (ulimit):** Increases open files limit to `65535` for stable proxy performance under load.
3.  **SSH Port (optional):** Moves SSH to your chosen port (fully supporting Ubuntu 22.04/24.04 and `ssh.socket` mechanisms).
4.  **Firewall (UFW, optional):** Careful configuration with comments for convenience:
    *   **SSH**: `#SSH` — your current or new port.
    *   **443**: `#VPN` — for proxy/VPN traffic (TCP & UDP).
    *   **3/tcp**: `#PANEL` — for 3x-ui management.
    *   **10443/tcp**: `#SUBSCRIPTION` — for subscriptions.
    *   **8443/tcp**: For **telemt**.
5.  **Interactive Component Menu:** Choose exactly what to install using a startup menu (supports comma inputs, exit on `0`, and invalid input protection): **3x-ui**, **telemt**, **OpenFlux**, **WARP watchdog**, **Fail2Ban**, **BBR**, **DNS (Cloudflare + Google)**, and **full system/kernel updates**.
6.  **WARP Watchdog:** A script to monitor Cloudflare WARP on port 40000 with automatic restart upon failure (via cron).
7.  **BBR + BDP/TFO Acceleration:** Enables Google BBR, tunes TCP buffer sizes (BDP), enables TCP Fast Open (TFO), and enables MTU probing to maximize throughput and minimize latency for proxies.
8.  **Fail2Ban:** Protects SSH from brute-force attacks by automatically blocking suspicious IPs.
9.  **Maximum Security:** If 3x-ui is selected, the script generates a **random login**, **random password**, and a **random secret path** (Web Base Path).
10. **DNS (Cloudflare + Google):** Setup of fast and reliable DNS servers (1.1.1.1 and 8.8.8.8) (optional).
11. **SSH Key Setup:** Optional addition of your public SSH key for secure login with validation and complete disablement of password authentication.
12. **SSH Socket Disabling (optional):** Disables systemd `ssh.socket` activation (introduced in Ubuntu 24.04) and switches to the classic, isolated `ssh.service` (sshd) for reliable port management.
13. **Swap Setup (optional):** Creates a 2 GB swapfile with optimal swappiness tuning (`vm.swappiness=10`) — essential for budget VPS instances with 512MB–1GB RAM.
14. **Essential Utilities:** Installs core network and diagnostic tools (`curl`, `wget`, `htop`, `iftop`, `iotop`, `net-tools`, `dnsutils`, `jq`, `socat`, `tar`, `unzip`, `ca-certificates`).
15. **Safety & Protection:** Input validation for ports and SSH keys to prevent server lockout, plus Debian / Ubuntu OS verification.
16. **OpenFlux Exit Node:** Installs [OpenFlux](https://github.com/p1neappleXpress/OpenFlux), sets up high-performance L3 exit node over covert transports (Yandex.Docs, Mail.ru Docs, Cups.online, MAX/OneMe, Volga), enables Linux kernel packet forwarding, applies kernel RST-drop iptables rules, configures background `openflux.service` with auto-recovery, and provides convenient `openflux-mgr` CLI tool.
---

## 🚀 Installation

Simply copy and paste this command into the terminal of your new server:

```bash
bash -c "$(curl -sL https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/install.sh)"
```

---

## 🔑 After Installation

Upon completion, the script will output configuration frames for your chosen services:

### 3x-ui Panel (if installed)
*   **Full URL** (including the secret path)
*   **Login** (randomly generated)
*   **Password** (randomly generated)

> **WARNING:** If you try to access `http://IP:3` directly, the server will return a 404 error. This is intentional to hide the panel from scanners. Only use the full secret link!

### OpenFlux (if installed)
*   **Config file:** `/etc/openflux/openflux.conf`
*   **Secret key (optional):** `/etc/openflux/secret.key`
*   **Service management:** `openflux-mgr {status|logs|restart|start|stop|config}` or `systemctl status openflux`
*   **Client launch example:**
    *   **macOS (TUN):** `sudo openflux -r client -i tun -t <transport> -u "<doc_url>" [--encryption-key-file=secret.key]`
    *   **Windows / Linux (SOCKS5):** `openflux -r client -i socks5 -t <transport> -u "<doc_url>" -s :1080 [--encryption-key-file=secret.key]`

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
    *   **443**: `#VPN` — для трафика прокси/VPN (TCP и UDP).
    *   **3/tcp**: `#PANEL` — для управления 3x-ui.
    *   **10443/tcp**: `#SUBSCRIPTION` — для подписок.
    *   **8443/tcp**: Для работы **telemt**.
5.  **Интерактивное меню компонентов:** Удобный выбор на старте через номера (с выходом по `0` и валидацией ввода). Вы выбираете, ставить ли **3x-ui**, **telemt**, **OpenFlux**, **WARP watchdog**, **Fail2Ban**, **BBR**, настраивать ли **DNS (Cloudflare + Google)**, а также запускать ли **полное обновление пакетов и ядра**.
6.  **WARP Watchdog:** Скрипт для мониторинга Cloudflare WARP на порту 40000 с автоматическим перезапуском при сбоях (через cron).
7.  **Ускорение BBR + BDP/TFO:** Включает алгоритм Google BBR, оптимизирует буферы TCP (BDP), включает TCP Fast Open (TFO) и зондирование MTU для максимальной скорости и минимального пинга прокси.
8.  **Fail2Ban:** Защищает SSH от брутфорс-атак, автоматически блокируя подозрительные IP.
9.  **Максимальная защита:** Если выбран 3x-ui, скрипт сгенерирует **случайный логин**, **случайный пароль** и **случайный секретный путь** (Web Base Path).
10. **DNS (Cloudflare + Google):** Настройка быстрых и надежных DNS-серверов (1.1.1.1 и 8.8.8.8) (опционально).
11. **Настройка SSH-ключа:** Опциональное добавление вашего публичного SSH-ключа для безопасного входа (с валидацией формата) и полное отключение парольной авторизации.
12. **Отключение SSH Socket (опционально):** Полное отключение `ssh.socket` активации systemd (появившейся в Ubuntu 24.04) и возврат к классической изолированной службе `ssh.service` (sshd) для более надежной смены портов.
13. **Настройка Swap (опционально):** Создание файла подкачки на 2 ГБ с оптимизацией `vm.swappiness=10` — критично для стабильности слабых VPS с 512MB–1GB RAM.
14. **Базовый набор утилит:** Установка ключевых системных и сетевых инструментов (`curl`, `wget`, `htop`, `iftop`, `iotop`, `net-tools`, `dnsutils`, `jq`, `socat`, `tar`, `unzip`, `ca-certificates`).
15. **Защита от lockout:** Валидация вводимых портов и SSH-ключей перед применением настроек, а также проверка дистрибутива (Debian / Ubuntu).
16. **OpenFlux Exit Node:** Установка [OpenFlux](https://github.com/p1neappleXpress/OpenFlux), быстрая настройка L3 выходной ноды через covert-транспорты (Яндекс.Документы, Mail.ru Docs, Cups.online, MAX/OneMe, Volga), автоматическое включение IP-форвардинга ядра, блокировка RST-пакетов через iptables, служба автозапуска `openflux.service` и утилита управления `openflux-mgr`.
---

## 🚀 Установка

Просто скопируйте и вставьте эту команду в терминал вашего нового сервера:

```bash
bash -c "$(curl -sL https://raw.githubusercontent.com/ohneRE-L/fast-vps-setup/main/install.sh)"
```

---

## 🔑 После установки

По завершении работы скрипт выведет в консоль рамку с параметрами установленных сервисов:

### Панель 3x-ui (если выбрана)
*   **Полная ссылка** (включая секретный путь)
*   **Логин** (сгенерирован случайно)
*   **Пароль** (сгенерирован случайно)

> **ВНИМАНИЕ:** Если вы попробуете зайти просто по `http://IP:3`, сервер выдаст ошибку 404. Это сделано специально, чтобы скрыть панель от сканеров. Используйте только полную секретную ссылку!

### OpenFlux (если выбран)
*   **Файл конфигурации:** `/etc/openflux/openflux.conf`
*   **Файл ключа (при включении):** `/etc/openflux/secret.key`
*   **Управление службой:** `openflux-mgr {status|logs|restart|start|stop|config}` или `systemctl status openflux`
*   **Примеры запуска клиента:**
    *   **macOS (TUN):** `sudo openflux -r client -i tun -t <транспорт> -u "<ссылка_на_документ>" [--encryption-key-file=secret.key]`
    *   **Windows / Linux (SOCKS5):** `openflux -r client -i socks5 -t <транспорт> -u "<ссылка_на_документ>" -s :1080 [--encryption-key-file=secret.key]`