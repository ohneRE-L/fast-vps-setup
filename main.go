//go:build linux

package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Messages struct {
	LangSelect              string
	RootRequired            string
	DebianOnly              string
	SSHPortPrompt           string
	SSHPortEmpty            string
	InvalidSSHPort          string
	SSHPortConflict         string
	ChangeSSH               string
	SetupUFW                string
	Install3xUI             string
	InstallTelemt           string
	InstallWarp             string
	EnableBBR               string
	InstallF2B              string
	SystemUpdate            string
	InstallingTools         string
	Ulimits                 string
	InstallingSwap          string
	SSHChange               string
	UFWSetup                string
	Installing3x            string
	InstallingTelemt        string
	InstallingWarp          string
	WarpNotInstalled        string
	InstallingBBR           string
	InstallingF2B           string
	Finalizing              string
	Success                 string
	URL                     string
	Login                   string
	Password                string
	SSHPort                 string
	XUICommand              string
	SetupDNS                string
	InstallingDNS           string
	SetupSSHKey             string
	EnterSSHKey             string
	InstallingSSHKey        string
	SSHKeyEmpty             string
	InvalidSSHKey           string
	SelectComponents        string
	MenuHeader              string
	MenuOption1             string
	MenuOption2             string
	MenuOption3             string
	MenuOption4             string
	MenuOption5             string
	MenuOption6             string
	MenuOption7             string
	MenuOption8             string
	MenuOption9             string
	MenuOption10            string
	MenuOption11            string
	MenuOption12            string
	MenuOption13            string
	OpenFluxActionPrompt    string
	MenuOption0             string
	ExitMsg                 string
	DisablingSocket         string
	RebootNotice            string
	InstallOpenFluxPrompt   string
	OpenFluxTransportPrompt string
	OpenFluxURLPrompt       string
	OpenFluxURLEmpty        string
	OpenFluxCupsPrompt      string
	OpenFluxOneMeToken      string
	OpenFluxOneMeUID        string
	OpenFluxEncryptPrompt   string
	OpenFluxCodecPrompt     string
	OpenFluxURLCleanNotice  string
	OpenFluxInvalidDocID    string
	InstallingOpenFlux      string
	UninstallingOpenFlux    string
	OpenFluxUninstalled     string
	OpenFluxAlreadyInstalled string
	OpenFluxReinstallChoice string
	OpenFluxHeader          string
	OpenFluxTransport       string
	OpenFluxURL             string
	OpenFluxSecretKey       string
	OpenFluxKeyNotice       string
	OpenFluxCmdExample      string
	OpenFluxMgrCmd          string
}

var ruMsgs = Messages{
	LangSelect:       "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	RootRequired:     "Ошибка: запустите скрипт от имени root (sudo)",
	DebianOnly:       "Ошибка: Этот скрипт предназначен только для систем Debian / Ubuntu!",
	SSHPortPrompt:    "👉 Введите новый порт для SSH (например, 9049): ",
	SSHPortEmpty:     "Порт не может быть пустым",
	InvalidSSHPort:   "Некорректный номер порта. Введите число от 1 до 65535.",
	SSHPortConflict:  "Этот порт зарезервирован для системных служб или прокси. Выберите другой порт.",
	ChangeSSH:        "Изменить порт SSH?",
	SetupUFW:         "Настроить Firewall (UFW)?",
	Install3xUI:      "Установить 3x-ui?",
	InstallTelemt:    "Установить telemt?",
	InstallWarp:      "Установить WARP watchdog?",
	EnableBBR:        "Включить BBR (ускорение сети)?",
	InstallF2B:       "Установить Fail2Ban (защита от брутфорса)?",
	SystemUpdate:     "[1/6] 🛠 Обновление системы...",
	InstallingTools:  "[1.5/6] 🧰 Установка базовых сетевых утилит...",
	Ulimits:          "[2/6] 🚀 Настройка лимитов...",
	InstallingSwap:   "[2.7/6] 💾 Настройка файла подкачки Swap (2 GB)...",
	SSHChange:        "[3/6] 🔒 Смена порта SSH на ",
	UFWSetup:         "[4/6] 🧱 Настройка Firewall...",
	Installing3x:     "[5/6] 📥 Установка 3x-ui...",
	InstallingTelemt: "[5.5/6] 📥 Установка telemt...",
	InstallingWarp:   "[6.5/6] 🛡 Настройка WARP Watchdog...",
	WarpNotInstalled: "WARP (warp-svc) не установлен на сервере! Сначала установите Cloudflare WARP.",
	InstallingBBR:    "[2.5/6] ⚡️ Включение BBR...",
	InstallingF2B:    "[4.5/6] 🛡 Установка Fail2Ban...",
	Finalizing:       "[6/6] ⚙️ Финализация настроек...",
	Success:          "✅ УСТАНОВКА ЗАВЕРШЕНА!",
	URL:              "🌐 Ссылка",
	Login:            "👤 Логин",
	Password:         "🔑 Пароль",
	SSHPort:          "📡 SSH порт",
	XUICommand:       "Команда 'x-ui' доступна в консоли.",
	SetupDNS:         "Настроить DNS (Cloudflare + Google)?",
	InstallingDNS:    "[3.5/6] 🌐 Настройка DNS (Cloudflare + Google)...",
	SetupSSHKey:      "Добавить SSH-ключ (и отключить пароли)?",
	EnterSSHKey:      "👉 Если у вас нет ключа, откройте новый терминал на вашем ПК и введите 'ssh-keygen -t ed25519'.\n👉 Затем скопируйте содержимое файла (обычно ~/.ssh/id_ed25519.pub).\n👉 Введите ваш публичный SSH-ключ:\n",
	InstallingSSHKey: "[3.7/6] 🔑 Настройка SSH-ключа...",
	SSHKeyEmpty:      "SSH-ключ не может быть пустым",
	InvalidSSHKey:    "Некорректный формат публичного SSH-ключа (должен начинаться с ssh-ed25519, ssh-rsa, ecdsa-...)",
	SelectComponents: "Введите номера через запятую или диапазоны (например, 1-4,7,12) или 'all' для всего: ",
	MenuHeader:       "--- СПИСОК КОМПОНЕНТОВ ---",
	MenuOption1:      "1. Смена порта SSH",
	MenuOption2:      "2. Установка SSH-ключа (рекомендуется)",
	MenuOption3:      "3. Настройка Firewall (UFW)",
	MenuOption4:      "4. Установка 3x-ui",
	MenuOption5:      "5. Установка telemt",
	MenuOption6:      "6. Настройка WARP Watchdog",
	MenuOption7:      "7. Включение BBR + TCP BDP/TFO (ускорение сети)",
	MenuOption8:      "8. Установка Fail2Ban",
	MenuOption9:      "9. Настройка DNS (Cloudflare + Google)",
	MenuOption10:     "10. Отключить SSH Socket (включить классический SSH Service)",
	MenuOption11:     "11. Обновить пакеты и ядро",
	MenuOption12:            "12. Настройка Swap (2 GB)",
	MenuOption13:            "13. Установка, настройка или удаление OpenFlux (Exit Node)",
	OpenFluxActionPrompt:    "👉 Выберите действие для OpenFlux:\n  1. Установка и настройка (по умолчанию)\n  2. Удаление OpenFlux\nВаш выбор [1/2, Enter = 1]: ",
	MenuOption0:             "0. Выход",
	ExitMsg:                 "Выход из скрипта...",
	DisablingSocket:         "[3.1/6] ⚙️ Отключение SSH Socket и запуск классического SSH Service...",
	RebootNotice:            "⚠️ Рекомендуется перезагрузить сервер (команда 'reboot') для применения изменений ядра и BBR.",
	InstallOpenFluxPrompt:   "Установить OpenFlux?",
	OpenFluxTransportPrompt: "👉 Выберите транспорт для OpenFlux:\n  1. Yandex.Docs (WebSocket) [по умолчанию]\n  2. Mail.ru Docs (WebSocket)\n  3. Cups.online (Centrifugo комнаты)\n  4. MAX / OneMe (WebRTC)\n  5. Yandex Volga (HTTP relay + WS)\nВаш выбор [1-5, Enter = 1]: ",
	OpenFluxURLPrompt:       "👉 Введите URL документа / публичную ссылку (например, ссылка на документ в Яндекс.Документах или Mail.ru):\n",
	OpenFluxURLEmpty:        "URL не может быть пустым",
	OpenFluxCupsPrompt:      "👉 Введите ID комнаты Cups.online (или нажмите Enter для автоматической генерации комнат exit-нодой): ",
	OpenFluxOneMeToken:      "👉 Введите MAX Web token (--maxToken): ",
	OpenFluxOneMeUID:        "👉 Введите MAX Call User ID (--maxUid): ",
	OpenFluxEncryptPrompt:   "Включить сквозное шифрование AES-256-GCM (будет сгенерирован секретный ключ)?",
	OpenFluxCodecPrompt:     "👉 Выберите профиль кодека для OpenFlux:\n  1. Универсальный: Android + iOS + PC (--codec=legacy) [Рекомендуется]\n  2. High-Performance: Только PC (потоковый batched+zstd)\nВаш выбор [1/2, Enter = 1]: ",
	OpenFluxURLCleanNotice:  "✨ Ссылка очищена и приведена к формату OpenFlux:\n   ",
	OpenFluxInvalidDocID:    "Не удалось извлечь ID документа из ссылки. Проверьте формат ссылки.",
	InstallingOpenFlux:      "[5.7/6] 📥 Установка и настройка OpenFlux (Exit Node)...",
	UninstallingOpenFlux:    "[5.8/6] 🗑 Удаление OpenFlux...",
	OpenFluxUninstalled:     "✅ OpenFlux успешно и полностью удален из системы.",
	OpenFluxAlreadyInstalled: "OpenFlux уже установлен на этом сервере.",
	OpenFluxReinstallChoice: "Выберите действие:\n  1. Переустановить / изменить параметры (по умолчанию)\n  2. Удалить OpenFlux\nВаш выбор [1/2, Enter = 1]: ",
	OpenFluxHeader:          "🛡 OPENFLUX НАСТРОЕН И ЗАПУЩЕН",
	OpenFluxTransport:       "📡 Транспорт",
	OpenFluxURL:             "🔗 Документ/URL",
	OpenFluxSecretKey:       "🔑 Секретный ключ шифрования",
	OpenFluxKeyNotice:       "👉 Скопируйте этот ключ в файл secret.key на клиенте и добавьте параметр --encryption-key-file=secret.key",
	OpenFluxCmdExample:      "💻 Примеры подключения клиента",
	OpenFluxMgrCmd:          "Управление сервисом: 'openflux-mgr' (или 'systemctl status openflux')",
}

var enMsgs = Messages{
	LangSelect:       "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	RootRequired:     "Error: run the script as root (sudo)",
	DebianOnly:       "Error: This script is only intended for Debian / Ubuntu systems!",
	SSHPortPrompt:    "👉 Enter new SSH port (e.g., 9049): ",
	SSHPortEmpty:     "Port cannot be empty",
	InvalidSSHPort:   "Invalid port number. Enter a number between 1 and 65535.",
	SSHPortConflict:  "This port is reserved for system services or proxies. Choose another port.",
	ChangeSSH:        "Change SSH port?",
	SetupUFW:         "Configure Firewall (UFW)?",
	Install3xUI:      "Install 3x-ui?",
	InstallTelemt:    "Install telemt?",
	InstallWarp:      "Install WARP watchdog?",
	EnableBBR:        "Enable BBR (network optimization)?",
	InstallF2B:       "Install Fail2Ban (brute-force protection)?",
	SystemUpdate:     "[1/6] 🛠 System update...",
	InstallingTools:  "[1.5/6] 🧰 Installing essential network utilities...",
	Ulimits:          "[2/6] 🚀 Setting limits...",
	InstallingSwap:   "[2.7/6] 💾 Setting up Swap file (2 GB)...",
	SSHChange:        "[3/6] 🔒 Changing SSH port to ",
	UFWSetup:         "[4/6] 🧱 Configuring Firewall...",
	Installing3x:     "[5/6] 📥 Installing 3x-ui...",
	InstallingTelemt: "[5.5/6] 📥 Installing telemt...",
	InstallingWarp:   "[6.5/6] 🛡 Setting up WARP Watchdog...",
	WarpNotInstalled: "WARP (warp-svc) is not installed on this server! Please install Cloudflare WARP first.",
	InstallingBBR:    "[2.5/6] ⚡️ Enabling BBR...",
	InstallingF2B:    "[4.5/6] 🛡 Installing Fail2Ban...",
	Finalizing:       "[6/6] ⚙️ Finalizing settings...",
	Success:          "✅ INSTALLATION COMPLETED!",
	URL:              "🌐 URL",
	Login:            "👤 Login",
	Password:         "🔑 Password",
	SSHPort:          "📡 SSH Port",
	XUICommand:       "The 'x-ui' command is available in the console.",
	SetupDNS:         "Configure DNS (Cloudflare + Google)?",
	InstallingDNS:    "[3.5/6] 🌐 Configuring DNS (Cloudflare + Google)...",
	SetupSSHKey:      "Add SSH key (and disable passwords)?",
	EnterSSHKey:      "👉 If you don't have a key, open a new terminal on your PC and run 'ssh-keygen -t ed25519'.\n👉 Then copy the contents of the file (usually ~/.ssh/id_ed25519.pub).\n👉 Enter your public SSH key:\n",
	InstallingSSHKey: "[3.7/6] 🔑 Configuring SSH key...",
	SSHKeyEmpty:      "SSH key cannot be empty",
	InvalidSSHKey:    "Invalid SSH public key format (must start with ssh-ed25519, ssh-rsa, ecdsa-...)",
	SelectComponents: "Enter numbers separated by comma or ranges (e.g., 1-4,7,12) or 'all': ",
	MenuHeader:       "--- COMPONENT LIST ---",
	MenuOption1:      "1. Change SSH Port",
	MenuOption2:      "2. Setup SSH Key (Recommended)",
	MenuOption3:      "3. Configure Firewall (UFW)",
	MenuOption4:      "4. Install 3x-ui",
	MenuOption5:      "5. Install telemt",
	MenuOption6:      "6. Setup WARP Watchdog",
	MenuOption7:      "7. Enable BBR + TCP BDP/TFO (network optimization)",
	MenuOption8:      "8. Install Fail2Ban",
	MenuOption9:      "9. Configure DNS (Cloudflare + Google)",
	MenuOption10:     "10. Disable SSH Socket (enable classic SSH Service)",
	MenuOption11:     "11. Update packages and kernel",
	MenuOption12:            "12. Setup Swap (2 GB)",
	MenuOption13:            "13. Install, configure or uninstall OpenFlux (Exit Node)",
	OpenFluxActionPrompt:    "👉 Choose action for OpenFlux:\n  1. Install & configure (default)\n  2. Uninstall OpenFlux\nYour choice [1/2, Enter = 1]: ",
	MenuOption0:             "0. Exit",
	ExitMsg:                 "Exiting script...",
	DisablingSocket:         "[3.1/6] ⚙️ Disabling SSH Socket and starting classic SSH Service...",
	RebootNotice:            "⚠️ It is recommended to reboot the server ('reboot' command) to apply kernel and BBR changes.",
	InstallOpenFluxPrompt:   "Install OpenFlux?",
	OpenFluxTransportPrompt: "👉 Choose transport for OpenFlux:\n  1. Yandex.Docs (WebSocket) [default]\n  2. Mail.ru Docs (WebSocket)\n  3. Cups.online (Centrifugo rooms)\n  4. MAX / OneMe (WebRTC)\n  5. Yandex Volga (HTTP relay + WS)\nYour choice [1-5, Enter = 1]: ",
	OpenFluxURLPrompt:       "👉 Enter document URL / public link (e.g., Yandex Docs or Mail.ru document URL):\n",
	OpenFluxURLEmpty:        "URL cannot be empty",
	OpenFluxCupsPrompt:      "👉 Enter Cups.online room ID (or press Enter to auto-generate rooms on exit node): ",
	OpenFluxOneMeToken:      "👉 Enter MAX Web token (--maxToken): ",
	OpenFluxOneMeUID:        "👉 Enter MAX Call User ID (--maxUid): ",
	OpenFluxEncryptPrompt:   "Enable end-to-end AES-256-GCM encryption (a secret key will be generated)?",
	OpenFluxCodecPrompt:     "👉 Choose codec profile for OpenFlux:\n  1. Universal: Android + iOS + PC (--codec=legacy) [Recommended]\n  2. High-Performance: PC only (batched+zstd)\nYour choice [1/2, Enter = 1]: ",
	OpenFluxURLCleanNotice:  "✨ URL cleaned and formatted for OpenFlux:\n   ",
	OpenFluxInvalidDocID:    "Could not extract document ID from the URL. Please verify the format.",
	InstallingOpenFlux:      "[5.7/6] 📥 Installing and configuring OpenFlux (Exit Node)...",
	UninstallingOpenFlux:    "[5.8/6] 🗑 Uninstalling OpenFlux...",
	OpenFluxUninstalled:      "✅ OpenFlux has been completely uninstalled from the system.",
	OpenFluxAlreadyInstalled: "OpenFlux is already installed on this server.",
	OpenFluxReinstallChoice:  "Choose action:\n  1. Reinstall / update parameters (default)\n  2. Uninstall OpenFlux\nYour choice [1/2, Enter = 1]: ",
	OpenFluxHeader:          "🛡 OPENFLUX CONFIGURED & RUNNING",
	OpenFluxTransport:       "📡 Transport",
	OpenFluxURL:             "🔗 Document/URL",
	OpenFluxSecretKey:       "🔑 Encryption Secret Key",
	OpenFluxKeyNotice:       "👉 Copy this key to secret.key file on your client and use --encryption-key-file=secret.key",
	OpenFluxCmdExample:      "💻 Client connection examples",
	OpenFluxMgrCmd:          "Service management: 'openflux-mgr' (or 'systemctl status openflux')",
}

var T Messages

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, n)
	for i := range ret {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func getIP() string {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	for _, s := range services {
		out, err := exec.Command("curl", "-s", "--max-time", "3", s).Output()
		if err == nil {
			res := strings.TrimSpace(string(out))
			if res != "" {
				return res
			}
		}
	}
	return "<IP_SERVER>"
}

func isValidPort(p string) bool {
	port, err := strconv.Atoi(p)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}

func isValidSSHPublicKey(k string) bool {
	k = strings.TrimSpace(k)
	prefixes := []string{
		"ssh-rsa",
		"ssh-ed25519",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com",
		"sk-ecdsa-sha2-nistp256@openssh.com",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(k, prefix) {
			parts := strings.Fields(k)
			return len(parts) >= 2
		}
	}
	return false
}

func parseSelection(input string, maxOption int) (map[string]bool, bool) {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "0" || input == "" {
		return nil, false
	}
	res := make(map[string]bool)
	if input == "all" {
		for i := 1; i <= maxOption; i++ {
			res[fmt.Sprintf("%d", i)] = true
		}
		return res, true
	}

	tokens := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})

	for _, token := range tokens {
		if strings.Contains(token, "-") {
			parts := strings.Split(token, "-")
			if len(parts) != 2 {
				return nil, false
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || start > end || start < 1 || end > maxOption {
				return nil, false
			}
			for i := start; i <= end; i++ {
				res[fmt.Sprintf("%d", i)] = true
			}
		} else {
			val, err := strconv.Atoi(token)
			if err != nil || val < 1 || val > maxOption {
				return nil, false
			}
			res[fmt.Sprintf("%d", val)] = true
		}
	}

	if len(res) == 0 {
		return nil, false
	}
	return res, true
}

func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func askYesNo(prompt string, reader *bufio.Reader) bool {
	for {
		fmt.Printf("👉 %s (y/n): ", prompt)
		input, _ := reader.ReadString('\n')
		input = strings.ToLower(strings.TrimSpace(input))
		if input == "y" || input == "yes" {
			return true
		}
		if input == "n" || input == "no" {
			return false
		}
	}
}

func main() {
	if _, err := os.Stat("/etc/debian_version"); os.IsNotExist(err) {
		log.Fatalf("❌ Error: This script is only intended for Debian / Ubuntu! / Ошибка: Этот скрипт предназначен только для Debian / Ubuntu!")
	}
	if os.Getuid() != 0 {
		log.Fatalf("❌ Error: root required / Ошибка: требуется root (sudo)")
	}

	reader := bufio.NewReader(os.Stdin)

	// Language selection
	for {
		fmt.Print(ruMsgs.LangSelect)
		lang, _ := reader.ReadString('\n')
		lang = strings.TrimSpace(lang)
		if lang == "1" {
			T = ruMsgs
			break
		} else if lang == "2" {
			T = enMsgs
			break
		}
	}

	fmt.Println("\n" + T.MenuHeader)
	fmt.Println(T.MenuOption1)
	fmt.Println(T.MenuOption2)
	fmt.Println(T.MenuOption3)
	fmt.Println(T.MenuOption4)
	fmt.Println(T.MenuOption5)
	fmt.Println(T.MenuOption6)
	fmt.Println(T.MenuOption7)
	fmt.Println(T.MenuOption8)
	fmt.Println(T.MenuOption9)
	fmt.Println(T.MenuOption10)
	fmt.Println(T.MenuOption11)
	fmt.Println(T.MenuOption12)
	fmt.Println(T.MenuOption13)
	fmt.Println(T.MenuOption0)
	fmt.Print("\n" + T.SelectComponents)

	selection, _ := reader.ReadString('\n')
	chosen, ok := parseSelection(selection, 13)
	if !ok {
		fmt.Println(T.ExitMsg)
		os.Exit(0)
	}

	changeSSHPortChoice := chosen["1"]
	setupSSHKeyChoice := chosen["2"]
	configureUFWChoice := chosen["3"]
	install3xUI := chosen["4"]
	installTelemtChoice := chosen["5"]
	installWarpWatchdogChoice := chosen["6"]
	enableBBRChoice := chosen["7"]
	installFail2BanChoice := chosen["8"]
	setupDNSChoice := chosen["9"]
	disableSSHSocketChoice := chosen["10"]
	updateSystemChoice := chosen["11"]
	setupSwapChoice := chosen["12"]
	installOpenFluxChoice := chosen["13"]
	uninstallOpenFluxChoice := false

	sshPort := getCurrentSSHPort()
	if changeSSHPortChoice {
		for {
			fmt.Print(T.SSHPortPrompt)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "" {
				fmt.Println("⚠️ " + T.SSHPortEmpty)
				continue
			}
			if !isValidPort(input) {
				fmt.Println("⚠️ " + T.InvalidSSHPort)
				continue
			}
			if input == "3" || input == "443" || input == "8443" || input == "10443" || input == "40000" || input == "9000" {
				fmt.Printf("⚠️ %s (%s)\n", T.SSHPortConflict, input)
				continue
			}
			sshPort = input
			break
		}
	}

	sshKey := ""
	if setupSSHKeyChoice {
		for {
			fmt.Print(T.EnterSSHKey)
			input, _ := reader.ReadString('\n')
			sshKey = strings.TrimSpace(input)
			if sshKey == "" {
				fmt.Println("⚠️ " + T.SSHKeyEmpty)
				continue
			}
			if !isValidSSHPublicKey(sshKey) {
				fmt.Println("⚠️ " + T.InvalidSSHKey)
				continue
			}
			break
		}
	}

	ofluxTransport := "yandex"
	ofluxURL := ""
	ofluxCodec := "legacy"
	ofluxExtraFlags := ""
	ofluxKey := ""

	if installOpenFluxChoice {
		isOpenFluxInstalled := false
		if _, err := os.Stat("/etc/systemd/system/openflux.service"); err == nil {
			isOpenFluxInstalled = true
		} else if _, err := os.Stat("/usr/local/bin/openflux"); err == nil {
			isOpenFluxInstalled = true
		} else if _, err := os.Stat("/etc/openflux"); err == nil {
			isOpenFluxInstalled = true
		} else if _, err := os.Stat("/usr/local/bin/openflux-mgr"); err == nil {
			isOpenFluxInstalled = true
		}

		if isOpenFluxInstalled {
			fmt.Println("\nℹ️ " + T.OpenFluxAlreadyInstalled)
			fmt.Print(T.OpenFluxReinstallChoice)
			act, _ := reader.ReadString('\n')
			act = strings.TrimSpace(act)
			if act == "2" {
				uninstallOpenFluxChoice = true
				installOpenFluxChoice = false
			}
		} else if strings.ToLower(strings.TrimSpace(selection)) != "all" {
			fmt.Println("\n" + strings.Repeat("-", 40))
			fmt.Print(T.OpenFluxActionPrompt)
			act, _ := reader.ReadString('\n')
			act = strings.TrimSpace(act)
			if act == "2" {
				uninstallOpenFluxChoice = true
				installOpenFluxChoice = false
			}
		}
	}

	if installOpenFluxChoice {
		fmt.Println("\n" + strings.Repeat("-", 40))
		for {
			fmt.Print(T.OpenFluxTransportPrompt)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "" || input == "1" {
				ofluxTransport = "yandex"
				break
			} else if input == "2" {
				ofluxTransport = "mailru"
				break
			} else if input == "3" {
				ofluxTransport = "cupsonline"
				break
			} else if input == "4" {
				ofluxTransport = "oneme"
				break
			} else if input == "5" {
				ofluxTransport = "vyandex"
				break
			} else {
				fmt.Println("⚠️ Invalid selection / Неверный выбор")
			}
		}

		if ofluxTransport == "cupsonline" {
			fmt.Print(T.OpenFluxCupsPrompt)
			input, _ := reader.ReadString('\n')
			ofluxURL = strings.TrimSpace(input)
		} else if ofluxTransport == "oneme" {
			fmt.Print(T.OpenFluxOneMeToken)
			token, _ := reader.ReadString('\n')
			token = strings.TrimSpace(token)
			fmt.Print(T.OpenFluxOneMeUID)
			uid, _ := reader.ReadString('\n')
			uid = strings.TrimSpace(uid)
			if token != "" {
				ofluxExtraFlags += fmt.Sprintf(" --maxToken=%s", token)
			}
			if uid != "" {
				ofluxExtraFlags += fmt.Sprintf(" --maxUid=%s", uid)
			}
		} else {
			for {
				fmt.Print(T.OpenFluxURLPrompt)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input == "" {
					fmt.Println("⚠️ " + T.OpenFluxURLEmpty)
					continue
				}
				cleaned, err := cleanOpenFluxURL(ofluxTransport, input)
				if err != nil {
					fmt.Printf("⚠️ %s (%v)\n", T.OpenFluxInvalidDocID, err)
					continue
				}
				ofluxURL = cleaned
				if ofluxURL != input {
					fmt.Println(T.OpenFluxURLCleanNotice + ofluxURL)
				}
				break
			}
		}

		// Выбор профиля кодека (legacy vs batched)
		fmt.Print(T.OpenFluxCodecPrompt)
		codecChoice, _ := reader.ReadString('\n')
		codecChoice = strings.TrimSpace(codecChoice)
		if codecChoice == "2" {
			ofluxCodec = "batched"
		} else {
			ofluxCodec = "legacy"
		}

		if askYesNo(T.OpenFluxEncryptPrompt, reader) {
			ofluxKey = generateRandomString(32)
		}
	}

	secretPath := generateRandomString(12)
	adminUser := generateRandomString(8)
	adminPass := generateRandomString(14)

	if updateSystemChoice {
		fmt.Println("\n" + T.SystemUpdate)
		_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
		run("bash", "-c", "apt update && apt dist-upgrade -y && apt autoremove -y")
		fmt.Println("\n" + T.InstallingTools)
		installBasicUtilities()
	} else {
		if configureUFWChoice || installFail2BanChoice || setupDNSChoice || install3xUI || installTelemtChoice || setupSwapChoice || installOpenFluxChoice {
			_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
			run("apt", "update")
			fmt.Println("\n" + T.InstallingTools)
			installBasicUtilities()
		}
	}

	fmt.Println("\n" + T.Ulimits)
	setUlimits()

	if setupSwapChoice {
		fmt.Println("\n" + T.InstallingSwap)
		setupSwap()
	}

	if enableBBRChoice {
		fmt.Println("\n" + T.InstallingBBR)
		enableBBR()
	}

	if disableSSHSocketChoice {
		fmt.Println("\n" + T.DisablingSocket)
		disableSSHSocket()
	}

	if changeSSHPortChoice {
		fmt.Println("\n" + T.SSHChange + sshPort)
		applySSHPort(sshPort)
	}

	if setupSSHKeyChoice {
		fmt.Println("\n" + T.InstallingSSHKey)
		setupSSHKey(sshKey)
	}

	if setupDNSChoice {
		fmt.Println("\n" + T.InstallingDNS)
		setupDNS()
	}

	if configureUFWChoice {
		fmt.Println("\n" + T.UFWSetup)
		configureUFW(sshPort)
	}

	// Синхронизация времени для надежной работы TLS/VLESS/Reality
	run("systemctl", "enable", "--now", "systemd-timesyncd")

	if installFail2BanChoice {
		fmt.Println("\n" + T.InstallingF2B)
		installFail2Ban(sshPort)
	}

	if install3xUI {
		fmt.Println("\n" + T.Installing3x)
		install3xUIOfficial()
	}

	if installTelemtChoice {
		fmt.Println("\n" + T.InstallingTelemt)
		installTelemt()
	}

	if uninstallOpenFluxChoice {
		uninstallOpenFlux()
	}

	if installOpenFluxChoice {
		fmt.Println("\n" + T.InstallingOpenFlux)
		installOpenFlux(ofluxTransport, ofluxURL, ofluxCodec, ofluxKey, ofluxExtraFlags)
	}

	if install3xUI {
		fmt.Println("\n" + T.Finalizing)
		finalConfig(adminUser, adminPass, secretPath)
	}

	if installWarpWatchdogChoice {
		fmt.Println("\n" + T.InstallingWarp)
		setupWarpWatchdog()
	}

	ip := getIP()
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println(T.Success)
	fmt.Println(strings.Repeat("=", 50))
	if install3xUI {
		fmt.Printf("%s: http://%s:3/%s/\n", T.URL, ip, secretPath)
		fmt.Printf("%s:  %s\n", T.Login, adminUser)
		fmt.Printf("%s: %s\n", T.Password, adminPass)
		fmt.Println(strings.Repeat("-", 50))
	}
	if installOpenFluxChoice {
		fmt.Println(T.OpenFluxHeader)
		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("%s: %s\n", T.OpenFluxTransport, ofluxTransport)
		if ofluxURL != "" {
			fmt.Printf("%s: %s\n", T.OpenFluxURL, ofluxURL)
		}
		if ofluxKey != "" {
			fmt.Printf("%s: %s\n", T.OpenFluxSecretKey, ofluxKey)
			fmt.Println(T.OpenFluxKeyNotice)
		}
		fmt.Println(strings.Repeat("-", 50))
		fmt.Println(T.OpenFluxCmdExample + ":")
		codecFlag := ""
		if ofluxCodec == "legacy" {
			codecFlag = " -c legacy"
		}
		keyFlag := ""
		if ofluxKey != "" {
			keyFlag = " --encryption-key-file=secret.key"
		}
		urlArg := ""
		if ofluxURL != "" {
			urlArg = fmt.Sprintf(" -u \"%s\"", ofluxURL)
		}
		fmt.Printf(" macOS (TUN):   sudo openflux -r client -i tun -t %s%s%s%s\n", ofluxTransport, urlArg, codecFlag, keyFlag)
		fmt.Printf(" Win / Linux:   openflux -r client -i socks5 -t %s%s -s :1080%s%s\n", ofluxTransport, urlArg, codecFlag, keyFlag)
		if ofluxCodec == "legacy" {
			fmt.Println(" Android / iOS: Совместимо (профиль legacy включен)")
		} else {
			fmt.Println(" Android / iOS: Внимание: мобильные клиенты требуют профиль legacy (выбран batched)")
		}
		fmt.Println(T.OpenFluxMgrCmd)
		fmt.Println(strings.Repeat("-", 50))
	}
	fmt.Printf("%s: %s\n", T.SSHPort, sshPort)
	fmt.Println(strings.Repeat("=", 50))
	if install3xUI {
		fmt.Println(T.XUICommand)
	}

	if updateSystemChoice || enableBBRChoice {
		fmt.Println("\n" + T.RebootNotice)
	}
}

func installBasicUtilities() {
	_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	run("apt-get", "install", "-y", "curl", "wget", "htop", "iftop", "iotop", "net-tools", "dnsutils", "jq", "socat", "tar", "unzip", "ca-certificates")
}

func setupSwap() {
	out, _ := exec.Command("swapon", "--show").Output()
	if strings.TrimSpace(string(out)) != "" {
		return
	}
	if _, err := os.Stat("/swapfile"); err == nil {
		return
	}

	cmd := exec.Command("fallocate", "-l", "2G", "/swapfile")
	if err := cmd.Run(); err != nil {
		run("dd", "if=/dev/zero", "of=/swapfile", "bs=1M", "count=2048", "status=none")
	}
	run("chmod", "600", "/swapfile")
	run("mkswap", "/swapfile")
	run("swapon", "/swapfile")

	fstab, err := os.ReadFile("/etc/fstab")
	if err == nil && !strings.Contains(string(fstab), "/swapfile") {
		f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			_, _ = f.WriteString("\n/swapfile none swap sw 0 0\n")
			_ = f.Close()
		}
	}

	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	_ = os.WriteFile("/etc/sysctl.d/99-swap.conf", []byte("vm.swappiness=10\n"), 0644)
	run("sysctl", "-w", "vm.swappiness=10")
}

func setUlimits() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Max = 65535
		rLimit.Cur = 65535
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}

	// Session limits
	_ = os.MkdirAll("/etc/security/limits.d", 0755)
	content := "* soft nofile 65535\n* hard nofile 65535\nroot soft nofile 65535\nroot hard nofile 65535\n"
	_ = os.WriteFile("/etc/security/limits.d/99-custom.conf", []byte(content), 0644)

	// Systemd service limits
	_ = os.MkdirAll("/etc/systemd/system.conf.d", 0755)
	sysdContent := "[Manager]\nDefaultLimitNOFILE=65535:65535\n"
	_ = os.WriteFile("/etc/systemd/system.conf.d/99-limits.conf", []byte(sysdContent), 0644)
	run("systemctl", "daemon-reload")
}

func applySSHPort(port string) {
	cfg, err := os.ReadFile("/etc/ssh/sshd_config")
	if err == nil {
		re := regexp.MustCompile(`(?m)^#?Port\s+\d+`)
		newCfg := re.ReplaceAll(cfg, []byte("Port "+port))
		if !strings.Contains(string(newCfg), "Port "+port) {
			newCfg = append(newCfg, []byte("\nPort "+port+"\n")...)
		}
		_ = os.WriteFile("/etc/ssh/sshd_config", newCfg, 0644)
	}

	outActive, _ := exec.Command("systemctl", "is-active", "ssh.socket").Output()
	outEnabled, _ := exec.Command("systemctl", "is-enabled", "ssh.socket").Output()

	isSocket := strings.Contains(string(outActive), "active") || strings.Contains(string(outEnabled), "enabled")

	if isSocket {
		_ = os.MkdirAll("/etc/systemd/system/ssh.socket.d", 0755)
		data := fmt.Sprintf("[Socket]\nListenStream=\nListenStream=0.0.0.0:%s\nListenStream=[::]:%s\n", port, port)
		_ = os.WriteFile("/etc/systemd/system/ssh.socket.d/listen.conf", []byte(data), 0644)
		run("systemctl", "daemon-reload")
		run("systemctl", "restart", "ssh.socket")
		run("systemctl", "restart", "ssh")
	} else {
		if err := exec.Command("systemctl", "restart", "sshd").Run(); err != nil {
			run("systemctl", "restart", "ssh")
		}
	}
}

func configureUFW(sshPort string) {
	run("apt-get", "install", "-y", "ufw")
	run("ufw", "default", "deny", "incoming")
	run("ufw", "default", "allow", "outgoing")
	run("ufw", "allow", sshPort+"/tcp", "comment", "SSH")
	run("ufw", "allow", "443", "comment", "VPN")
	run("ufw", "allow", "3/tcp", "comment", "PANEL")
	run("ufw", "allow", "10443/tcp", "comment", "SUBSCRIPTION")
	run("ufw", "allow", "8443/tcp")
	run("ufw", "deny", "9000", "comment", "nginx")
	run("ufw", "deny", "40000", "comment", "warp")
	run("ufw", "--force", "enable")
	run("ufw", "reload")
}

func installTelemt() {
	cmd := `curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- --port 8443`
	run("bash", "-c", cmd)
}

func setupWarpWatchdog() {
	// Проверяем наличие warp-svc или warp-cli
	_, errPath := exec.LookPath("warp-cli")
	_, errStat := os.Stat("/usr/bin/warp-svc")
	if errPath != nil && os.IsNotExist(errStat) {
		fmt.Println("⚠️ " + T.WarpNotInstalled)
		return
	}

	script := `#!/bin/bash

LOG_FILE="/var/log/warp-watchdog.log"
WARP_PORT="40000"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Проверяем, слушает ли warp-svc порт 40000
if ss -lntp | grep -q ":$WARP_PORT.*warp-svc"; then
    # Порт слушается, WARP в порядке
    exit 0
else
    log "⚠️  Порт $WARP_PORT не слушается или процесс warp-svc не отвечает. Перезапускаем WARP..."

    # Перезапускаем сервис WARP
    systemctl restart warp-svc

    # Небольшая пауза, чтобы сервис успел запуститься
    sleep 10

    # Повторная проверка
    if ss -lntp | grep -q ":$WARP_PORT.*warp-svc"; then
        log "✅ После перезапуска WARP порт $WARP_PORT снова в порядке."
    else
        log "❌ Критическая ошибка: WARP не смог запуститься или порт $WARP_PORT не открылся."
    fi
fi
`
	_ = os.WriteFile("/usr/local/bin/warp-watchdog.sh", []byte(script), 0755)
	run("chmod", "+x", "/usr/local/bin/warp-watchdog.sh")

	cronJob := "* * * * * root /usr/local/bin/warp-watchdog.sh >/dev/null 2>&1\n"
	_ = os.WriteFile("/etc/cron.d/warp-watchdog", []byte(cronJob), 0644)

	// Настройка ротации логов для watchdog
	logrotateCfg := "/var/log/warp-watchdog.log {\n    weekly\n    rotate 4\n    compress\n    missingok\n    notifempty\n}\n"
	_ = os.WriteFile("/etc/logrotate.d/warp-watchdog", []byte(logrotateCfg), 0644)
}

func install3xUIOfficial() {
	installCmd := `bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)`
	answers := "n\n"
	cmd := exec.Command("bash", "-c", installCmd)
	cmd.Stdin = strings.NewReader(answers)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func finalConfig(user, pass, path string) {
	if !waitForFile("/usr/local/x-ui/x-ui", 30*time.Second) {
		log.Println("⚠️ /usr/local/x-ui/x-ui not found, retrying configuration...")
	}
	time.Sleep(2 * time.Second)

	fullPath := "/" + path + "/"
	_ = exec.Command("/usr/local/x-ui/x-ui", "setting", "-username", user, "-password", pass, "-port", "3", "-webBasePath", fullPath).Run()

	_ = os.Remove("/usr/bin/x-ui")
	_ = exec.Command("ln", "-s", "/usr/local/x-ui/x-ui.sh", "/usr/bin/x-ui").Run()

	run("systemctl", "restart", "x-ui")
	run("hash", "-r")
}

func enableBBR() {
	run("modprobe", "tcp_bbr")
	_ = os.MkdirAll("/etc/modules-load.d", 0755)
	_ = os.WriteFile("/etc/modules-load.d/bbr.conf", []byte("tcp_bbr\n"), 0644)

	sysctlSettings := `# Network BBR, BDP & TFO Optimizations
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
`
	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	_ = os.WriteFile("/etc/sysctl.d/99-bbr.conf", []byte(sysctlSettings), 0644)
	run("sysctl", "--system")
}

func installFail2Ban(sshPort string) {
	run("apt-get", "install", "-y", "fail2ban")
	_ = os.MkdirAll("/etc/fail2ban/jail.d", 0755)
	jailConfig := fmt.Sprintf("[sshd]\nenabled = true\nbackend = systemd\nport = %s\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n", sshPort)
	_ = os.WriteFile("/etc/fail2ban/jail.d/sshd.local", []byte(jailConfig), 0644)
	run("systemctl", "enable", "fail2ban")
	run("systemctl", "restart", "fail2ban")
}

func setupDNS() {
	run("apt-get", "install", "-y", "systemd-resolved")
	config := "[Resolve]\nDNS=1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844\nFallbackDNS=1.0.0.1 8.8.4.4\nDNSStubListener=yes\n"
	_ = os.MkdirAll("/etc/systemd/resolved.conf.d", 0755)
	_ = os.WriteFile("/etc/systemd/resolved.conf.d/dns.conf", []byte(config), 0644)
	run("systemctl", "enable", "--now", "systemd-resolved")
	run("systemctl", "restart", "systemd-resolved")
}

func getCurrentSSHPort() string {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "22"
	}
	re := regexp.MustCompile(`(?m)^Port\s+(\d+)`)
	match := re.FindStringSubmatch(string(data))
	if len(match) > 1 {
		return match[1]
	}
	return "22"
}

func setupSSHKey(key string) {
	_ = os.MkdirAll("/root/.ssh", 0700)
	authKeys, err := os.ReadFile("/root/.ssh/authorized_keys")
	if err != nil || !strings.Contains(string(authKeys), key) {
		f, err := os.OpenFile("/root/.ssh/authorized_keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = f.WriteString(key + "\n")
			_ = f.Close()
		}
	}

	// 1. Drop-in config for modern OpenSSH (Ubuntu 22.04+, Debian 12+)
	_ = os.MkdirAll("/etc/ssh/sshd_config.d", 0755)
	dropinCfg := "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
	_ = os.WriteFile("/etc/ssh/sshd_config.d/99-disable-passwords.conf", []byte(dropinCfg), 0644)

	// 2. Fallback in /etc/ssh/sshd_config for older systems
	cfg, err := os.ReadFile("/etc/ssh/sshd_config")
	if err == nil {
		re := regexp.MustCompile(`(?m)^#?PasswordAuthentication\s+(yes|no)`)
		newCfg := re.ReplaceAll(cfg, []byte("PasswordAuthentication no"))
		if !strings.Contains(string(newCfg), "PasswordAuthentication no") {
			newCfg = append(newCfg, []byte("\nPasswordAuthentication no\n")...)
		}
		_ = os.WriteFile("/etc/ssh/sshd_config", newCfg, 0644)
	}

	if err := exec.Command("systemctl", "restart", "sshd").Run(); err != nil {
		run("systemctl", "restart", "ssh")
	}
}

func disableSSHSocket() {
	run("systemctl", "stop", "ssh.socket")
	run("systemctl", "disable", "ssh.socket")
	if err := exec.Command("systemctl", "enable", "--now", "sshd").Run(); err != nil {
		run("systemctl", "enable", "--now", "ssh")
	}
}

func installOpenFlux(transport, docURL, codec, secretKey, extraFlags string) {
	arch := runtime.GOARCH
	var binName string
	switch arch {
	case "amd64":
		binName = "openflux-linux-amd64"
	case "arm64":
		binName = "openflux-linux-arm64"
	case "arm":
		binName = "openflux-linux-arm"
	default:
		binName = "openflux-linux-amd64"
	}

	targetPath := "/usr/local/bin/openflux"
	releaseURL := fmt.Sprintf("https://github.com/p1neappleXpress/OpenFlux/releases/latest/download/%s", binName)

	downloadCmd := fmt.Sprintf("curl -fsSL -L -o %s %s || curl -fsSL -L -o %s https://github.com/p1neappleXpress/OpenFlux/releases/download/0.0.3/%s", targetPath, releaseURL, targetPath, binName)
	run("bash", "-c", downloadCmd)

	if _, err := os.Stat(targetPath); err != nil {
		log.Printf("❌ Failed to download OpenFlux binary: %v\n", err)
		return
	}
	run("chmod", "+x", targetPath)

	_ = os.MkdirAll("/etc/openflux", 0755)

	totalFlags := strings.TrimSpace(extraFlags)
	if secretKey != "" {
		_ = os.WriteFile("/etc/openflux/secret.key", []byte(secretKey+"\n"), 0600)
		if totalFlags != "" {
			totalFlags += " "
		}
		totalFlags += "--encryption-key-file=/etc/openflux/secret.key"
	}

	urlParam := ""
	if docURL != "" {
		urlParam = fmt.Sprintf("URL=\"%s\"\n", docURL)
	} else {
		urlParam = "URL=\"\"\n"
	}

	confContent := fmt.Sprintf("# OpenFlux Exit Node Configuration\nROLE=exit\nMODE=l3\nCODEC=%s\nTRANSPORT=%s\n%sEXTRA_FLAGS=\"%s\"\n", codec, transport, urlParam, totalFlags)
	_ = os.WriteFile("/etc/openflux/openflux.conf", []byte(confContent), 0644)

	// Stop existing service if running to prevent file locks and command mismatch
	run("systemctl", "stop", "openflux")

	// Enable net.ipv4.ip_forward for L3 routing
	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	_ = os.WriteFile("/etc/sysctl.d/99-openflux.conf", []byte("net.ipv4.ip_forward=1\n"), 0644)
	run("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Ensure iptables is installed
	run("apt-get", "install", "-y", "iptables")

	// Create systemd service with isolated iptables RST-drop lifecycle
	serviceContent := `[Unit]
Description=OpenFlux Exit Node
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/openflux/openflux.conf
ExecStartPre=/bin/sh -c '/sbin/iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || /sbin/iptables -I OUTPUT 1 -p tcp --tcp-flags RST RST -j DROP'
ExecStart=/bin/sh -c 'CODEC_ARG="${CODEC:-legacy}"; URL_ARG=""; [ -n "$URL" ] && URL_ARG="--url=$URL"; exec /usr/local/bin/openflux --role=${ROLE:-exit} --mode=${MODE:-l3} --codec=$CODEC_ARG --transport=${TRANSPORT:-yandex} $URL_ARG ${EXTRA_FLAGS}'
ExecStopPost=/bin/sh -c '/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true'
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`
	_ = os.WriteFile("/etc/systemd/system/openflux.service", []byte(serviceContent), 0644)
	run("systemctl", "daemon-reload")
	run("systemctl", "enable", "openflux")
	run("systemctl", "restart", "openflux")

	// Create openflux-mgr helper script
	mgrContent := `#!/bin/bash
case "$1" in
    status)
        systemctl status openflux --no-pager
        ;;
    logs)
        journalctl -u openflux -f -n 100
        ;;
    restart)
        systemctl daemon-reload
        systemctl restart openflux
        systemctl status openflux --no-pager
        ;;
    start)
        systemctl daemon-reload
        systemctl start openflux
        systemctl status openflux --no-pager
        ;;
    stop)
        systemctl stop openflux
        ;;
    config)
        ${EDITOR:-nano} /etc/openflux/openflux.conf
        echo "Reloading systemd and restarting openflux service..."
        systemctl daemon-reload
        systemctl restart openflux
        systemctl status openflux --no-pager
        ;;
    uninstall)
        echo "Uninstalling OpenFlux..."
        systemctl stop openflux 2>/dev/null || true
        systemctl disable openflux 2>/dev/null || true
        rm -f /etc/systemd/system/openflux.service
        systemctl daemon-reload
        /sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true
        rm -f /etc/sysctl.d/99-openflux.conf
        rm -f /usr/local/bin/openflux
        rm -rf /etc/openflux
        rm -f /usr/local/bin/openflux-mgr
        echo "OpenFlux has been completely uninstalled."
        ;;
    *)
        echo "OpenFlux Exit Node Manager"
        echo "Usage: openflux-mgr {status|logs|restart|start|stop|config|uninstall}"
        ;;
esac
`
	_ = os.WriteFile("/usr/local/bin/openflux-mgr", []byte(mgrContent), 0755)
	run("chmod", "+x", "/usr/local/bin/openflux-mgr")
}

func cleanOpenFluxURL(transport, rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	switch transport {
	case "yandex", "vyandex":
		// Case 1: Raw document ID pasted directly
		if !strings.Contains(rawURL, "/") && len(rawURL) >= 8 {
			return fmt.Sprintf("https://docs.yandex.ru/edit/d/%s?from_public=1", rawURL), nil
		}

		// Case 2: URL containing /d/<DOC_ID>
		re := regexp.MustCompile(`/d/([a-zA-Z0-9_\-\.]+)`)
		match := re.FindStringSubmatch(rawURL)
		if len(match) > 1 {
			docID := match[1]
			return fmt.Sprintf("https://docs.yandex.ru/edit/d/%s?from_public=1", docID), nil
		}

		// Case 3: Other Yandex Docs URLs - strip tracking parameters and append from_public=1
		if strings.Contains(rawURL, "docs.yandex.") || strings.Contains(rawURL, "yandex.") {
			base := strings.Split(rawURL, "?")[0]
			return base + "?from_public=1", nil
		}
		return rawURL, nil

	case "mailru":
		base := strings.Split(rawURL, "?")[0]
		return strings.TrimRight(base, "/"), nil

	default:
		return rawURL, nil
	}
}

func uninstallOpenFlux() {
	fmt.Println("\n" + T.UninstallingOpenFlux)

	// Stop and disable systemd service
	run("systemctl", "stop", "openflux")
	run("systemctl", "disable", "openflux")
	_ = os.Remove("/etc/systemd/system/openflux.service")
	run("systemctl", "daemon-reload")

	// Remove kernel RST drop iptables rule
	run("bash", "-c", "/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true")

	// Remove sysctl config
	_ = os.Remove("/etc/sysctl.d/99-openflux.conf")

	// Remove binaries and scripts
	_ = os.Remove("/usr/local/bin/openflux")
	_ = os.Remove("/usr/local/bin/openflux-mgr")

	// Remove configuration directory
	_ = os.RemoveAll("/etc/openflux")

	fmt.Println(T.OpenFluxUninstalled)
}

