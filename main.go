//go:build linux

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Messages struct {
	LangSelect          string
	SSHPortPrompt       string
	SSHPortEmpty        string
	InvalidSSHPort      string
	SSHPortConflict     string
	SystemUpdate        string
	InstallingTools     string
	Ulimits             string
	InstallingSwap      string
	SSHChange           string
	UFWSetup            string
	Installing3x        string
	InstallingTelemt    string
	InstallingWarp      string
	WarpNotInstalled    string
	InstallingBBR       string
	InstallingF2B       string
	Finalizing          string
	Success             string
	URL                 string
	Login               string
	Password            string
	SSHPort             string
	XUICommand          string
	InstallingDNS       string
	EnterSSHKey         string
	InstallingSSHKey    string
	SSHKeyEmpty         string
	InvalidSSHKey       string
	SelectComponents    string
	MenuHeader          string
	MenuOption1         string
	MenuOption2         string
	MenuOption3         string
	MenuOption4         string
	MenuOption5         string
	MenuOption6         string
	MenuOption7         string
	MenuOption8         string
	MenuOption9         string
	MenuOption10        string
	MenuOption11        string
	MenuOption12        string
	MenuOption0         string
	ExitMsg             string
	DisablingSocket     string
	RebootNotice        string
	InvalidSelection    string
	SSHPortApplyFailed  string
	PanelSecurityNotice string
}

var ruMsgs = Messages{
	LangSelect:          "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	SSHPortPrompt:       "👉 Введите новый порт для SSH (например, 9049): ",
	SSHPortEmpty:        "Порт не может быть пустым",
	InvalidSSHPort:      "Некорректный номер порта. Введите число от 1 до 65535.",
	SSHPortConflict:     "Этот порт зарезервирован для системных служб или прокси. Выберите другой порт.",
	SystemUpdate:        "[1/6] 🛠 Обновление системы...",
	InstallingTools:     "[1.5/6] 🧰 Установка базовых сетевых утилит...",
	Ulimits:             "[2/6] 🚀 Настройка лимитов...",
	InstallingSwap:      "[2.7/6] 💾 Настройка файла подкачки Swap (2 GB)...",
	SSHChange:           "[3/6] 🔒 Смена порта SSH на ",
	UFWSetup:            "[4/6] 🧱 Настройка Firewall...",
	Installing3x:        "[5/6] 📥 Установка 3x-ui...",
	InstallingTelemt:    "[5.5/6] 📥 Установка telemt...",
	InstallingWarp:      "[6.5/6] 🛡 Настройка WARP Watchdog...",
	WarpNotInstalled:    "WARP (warp-svc) не установлен на сервере! Сначала установите Cloudflare WARP.",
	InstallingBBR:       "[2.5/6] ⚡️ Включение BBR...",
	InstallingF2B:       "[4.5/6] 🛡 Установка Fail2Ban...",
	Finalizing:          "[6/6] ⚙️ Финализация настроек...",
	Success:             "✅ УСТАНОВКА ЗАВЕРШЕНА!",
	URL:                 "🌐 Ссылка",
	Login:               "👤 Логин",
	Password:            "🔑 Пароль",
	SSHPort:             "📡 SSH порт",
	XUICommand:          "Команда 'x-ui' доступна в консоли.",
	InstallingDNS:       "[3.5/6] 🌐 Настройка DNS (Cloudflare + Google)...",
	EnterSSHKey:         "👉 Если у вас нет ключа, откройте новый терминал на вашем ПК и введите 'ssh-keygen -t ed25519'.\n👉 Затем скопируйте содержимое файла (обычно ~/.ssh/id_ed25519.pub).\n👉 Введите ваш публичный SSH-ключ:\n",
	InstallingSSHKey:    "[3.7/6] 🔑 Настройка SSH-ключа...",
	SSHKeyEmpty:         "SSH-ключ не может быть пустым",
	InvalidSSHKey:       "Некорректный формат публичного SSH-ключа (должен начинаться с ssh-ed25519, ssh-rsa, ecdsa-...)",
	SelectComponents:    "Введите номера через запятую или диапазоны (например, 1-4,7,12) или 'all' для всего: ",
	MenuHeader:          "--- СПИСОК КОМПОНЕНТОВ ---",
	MenuOption1:         "1. Смена порта SSH",
	MenuOption2:         "2. Установка SSH-ключа (рекомендуется)",
	MenuOption3:         "3. Настройка Firewall (UFW)",
	MenuOption4:         "4. Установка 3x-ui",
	MenuOption5:         "5. Установка telemt",
	MenuOption6:         "6. Настройка WARP Watchdog",
	MenuOption7:         "7. Включение BBR + TCP BDP/TFO (ускорение сети)",
	MenuOption8:         "8. Установка Fail2Ban",
	MenuOption9:         "9. Настройка DNS (Cloudflare + Google)",
	MenuOption10:        "10. Отключить SSH Socket (включить классический SSH Service)",
	MenuOption11:        "11. Обновить пакеты и ядро",
	MenuOption12:        "12. Настройка Swap (2 GB)",
	MenuOption0:         "0. Выход",
	ExitMsg:             "Выход из скрипта...",
	DisablingSocket:     "[3.1/6] ⚙️ Отключение SSH Socket и запуск классического SSH Service...",
	RebootNotice:        "⚠️ Рекомендуется перезагрузить сервер (команда 'reboot') для применения изменений ядра и BBR.",
	InvalidSelection:    "Некорректный выбор. Введите номера из меню (например, 1-4,7), 'all' или 0 для выхода.",
	SSHPortApplyFailed:  "Не удалось применить новый порт SSH, используется текущий порт",
	PanelSecurityNotice: "⚠️ Панель 3x-ui работает по HTTP на порту 3. Для защиты учётных данных настройте SSL/TLS в панели или используйте SSH-туннель (ssh -L 3:127.0.0.1:3 root@<IP>).",
}

var enMsgs = Messages{
	LangSelect:          "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	SSHPortPrompt:       "👉 Enter new SSH port (e.g., 9049): ",
	SSHPortEmpty:        "Port cannot be empty",
	InvalidSSHPort:      "Invalid port number. Enter a number between 1 and 65535.",
	SSHPortConflict:     "This port is reserved for system services or proxies. Choose another port.",
	SystemUpdate:        "[1/6] 🛠 System update...",
	InstallingTools:     "[1.5/6] 🧰 Installing essential network utilities...",
	Ulimits:             "[2/6] 🚀 Setting limits...",
	InstallingSwap:      "[2.7/6] 💾 Setting up Swap file (2 GB)...",
	SSHChange:           "[3/6] 🔒 Changing SSH port to ",
	UFWSetup:            "[4/6] 🧱 Configuring Firewall...",
	Installing3x:        "[5/6] 📥 Installing 3x-ui...",
	InstallingTelemt:    "[5.5/6] 📥 Installing telemt...",
	InstallingWarp:      "[6.5/6] 🛡 Setting up WARP Watchdog...",
	WarpNotInstalled:    "WARP (warp-svc) is not installed on this server! Please install Cloudflare WARP first.",
	InstallingBBR:       "[2.5/6] ⚡️ Enabling BBR...",
	InstallingF2B:       "[4.5/6] 🛡 Installing Fail2Ban...",
	Finalizing:          "[6/6] ⚙️ Finalizing settings...",
	Success:             "✅ INSTALLATION COMPLETED!",
	URL:                 "🌐 URL",
	Login:               "👤 Login",
	Password:            "🔑 Password",
	SSHPort:             "📡 SSH Port",
	XUICommand:          "The 'x-ui' command is available in the console.",
	InstallingDNS:       "[3.5/6] 🌐 Configuring DNS (Cloudflare + Google)...",
	EnterSSHKey:         "👉 If you don't have a key, open a new terminal on your PC and run 'ssh-keygen -t ed25519'.\n👉 Then copy the contents of the file (usually ~/.ssh/id_ed25519.pub).\n👉 Enter your public SSH key:\n",
	InstallingSSHKey:    "[3.7/6] 🔑 Configuring SSH key...",
	SSHKeyEmpty:         "SSH key cannot be empty",
	InvalidSSHKey:       "Invalid SSH public key format (must start with ssh-ed25519, ssh-rsa, ecdsa-...)",
	SelectComponents:    "Enter numbers separated by comma or ranges (e.g., 1-4,7,12) or 'all': ",
	MenuHeader:          "--- COMPONENT LIST ---",
	MenuOption1:         "1. Change SSH Port",
	MenuOption2:         "2. Setup SSH Key (Recommended)",
	MenuOption3:         "3. Configure Firewall (UFW)",
	MenuOption4:         "4. Install 3x-ui",
	MenuOption5:         "5. Install telemt",
	MenuOption6:         "6. Setup WARP Watchdog",
	MenuOption7:         "7. Enable BBR + TCP BDP/TFO (network optimization)",
	MenuOption8:         "8. Install Fail2Ban",
	MenuOption9:         "9. Configure DNS (Cloudflare + Google)",
	MenuOption10:        "10. Disable SSH Socket (enable classic SSH Service)",
	MenuOption11:        "11. Update packages and kernel",
	MenuOption12:        "12. Setup Swap (2 GB)",
	MenuOption0:         "0. Exit",
	ExitMsg:             "Exiting script...",
	DisablingSocket:     "[3.1/6] ⚙️ Disabling SSH Socket and starting classic SSH Service...",
	RebootNotice:        "⚠️ It is recommended to reboot the server ('reboot' command) to apply kernel and BBR changes.",
	InvalidSelection:    "Invalid selection. Enter menu numbers (e.g., 1-4,7), 'all', or 0 to exit.",
	SSHPortApplyFailed:  "Failed to apply new SSH port, keeping current port",
	PanelSecurityNotice: "⚠️ 3x-ui panel runs over plaintext HTTP on port 3. Configure SSL/TLS in the panel or use an SSH tunnel (ssh -L 3:127.0.0.1:3 root@<IP>) to protect credentials.",
}

var T Messages

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("⚠️ Command '%s %s' failed: %v\n", name, strings.Join(args, " "), err)
		return err
	}
	return nil
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
		lang, err := readLine(reader)
		if err != nil {
			fmt.Println("\n" + ruMsgs.ExitMsg)
			return
		}
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
	fmt.Println(T.MenuOption0)

	var chosen map[string]bool
	for {
		fmt.Print("\n" + T.SelectComponents)
		selection, err := readLine(reader)
		if err != nil {
			fmt.Println("\n" + T.ExitMsg)
			return
		}
		if strings.TrimSpace(selection) == "0" {
			fmt.Println(T.ExitMsg)
			return
		}
		var ok bool
		chosen, ok = parseSelection(selection, 12)
		if !ok {
			fmt.Println("⚠️ " + T.InvalidSelection)
			continue
		}
		break
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

	sshPort := getCurrentSSHPort()
	if changeSSHPortChoice {
		for {
			fmt.Print(T.SSHPortPrompt)
			input, err := readLine(reader)
			if err != nil {
				fmt.Println("\n" + T.ExitMsg)
				return
			}
			input = strings.TrimSpace(input)
			if input == "" {
				fmt.Println("⚠️ " + T.SSHPortEmpty)
				continue
			}
			if !isValidPort(input) {
				fmt.Println("⚠️ " + T.InvalidSSHPort)
				continue
			}
			portNum, _ := strconv.Atoi(input)
			normPort := strconv.Itoa(portNum)
			if normPort == "3" || normPort == "443" || normPort == "8443" || normPort == "10443" || normPort == "40000" || normPort == "9000" {
				fmt.Printf("⚠️ %s (%s)\n", T.SSHPortConflict, normPort)
				continue
			}
			sshPort = normPort
			break
		}
	}

	sshKey := ""
	if setupSSHKeyChoice {
		for {
			fmt.Print(T.EnterSSHKey)
			input, err := readLine(reader)
			if err != nil {
				fmt.Println("\n" + T.ExitMsg)
				return
			}
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

	secretPath, err := generateRandomString(12)
	if err != nil {
		log.Fatalf("❌ Failed to generate secret path: %v", err)
	}
	adminUser, err := generateRandomString(8)
	if err != nil {
		log.Fatalf("❌ Failed to generate admin username: %v", err)
	}
	adminPass, err := generateRandomString(14)
	if err != nil {
		log.Fatalf("❌ Failed to generate admin password: %v", err)
	}

	if updateSystemChoice {
		fmt.Println("\n" + T.SystemUpdate)
		_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
		_ = run("bash", "-c", "apt-get update && apt-get dist-upgrade -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold && apt-get autoremove -y")
		fmt.Println("\n" + T.InstallingTools)
		installBasicUtilities()
	} else {
		if configureUFWChoice || installFail2BanChoice || setupDNSChoice || install3xUI || installTelemtChoice || setupSwapChoice {
			_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
			_ = run("apt-get", "update")
			fmt.Println("\n" + T.InstallingTools)
			installBasicUtilities()
		}
	}

	if enableBBRChoice || install3xUI || installTelemtChoice {
		fmt.Println("\n" + T.Ulimits)
		setUlimits()
	}

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
		if err := applySSHPort(sshPort); err != nil {
			log.Printf("⚠️ %s: %v\n", T.SSHPortApplyFailed, err)
			sshPort = getCurrentSSHPort()
		}
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

	if install3xUI || installTelemtChoice {
		// Синхронизация времени для надежной работы TLS/VLESS/Reality
		_ = exec.Command("systemctl", "enable", "--now", "systemd-timesyncd").Run()
	}

	if installFail2BanChoice {
		fmt.Println("\n" + T.InstallingF2B)
		installFail2Ban(sshPort)
	}

	xuiDownloadOK := false
	if install3xUI {
		fmt.Println("\n" + T.Installing3x)
		if err := install3xUIOfficial(); err != nil {
			log.Printf("❌ 3x-ui installation failed: %v\n", err)
		} else {
			xuiDownloadOK = true
		}
	}

	if installTelemtChoice {
		fmt.Println("\n" + T.InstallingTelemt)
		if err := installTelemt(); err != nil {
			log.Printf("❌ telemt installation failed: %v\n", err)
		}
	}

	xuiConfiguredOK := false
	if install3xUI && xuiDownloadOK {
		fmt.Println("\n" + T.Finalizing)
		if err := finalConfig(adminUser, adminPass, secretPath); err != nil {
			log.Printf("❌ 3x-ui configuration failed: %v\n", err)
		} else {
			xuiConfiguredOK = true
		}
	}

	if installWarpWatchdogChoice {
		fmt.Println("\n" + T.InstallingWarp)
		setupWarpWatchdog()
	}

	if configureUFWChoice || enableBBRChoice || install3xUI || installTelemtChoice {
		// Оптимизация conntrack, если модуль активен (UFW, Docker, Wireguard, nat)
		tuneConntrack()
	}

	ip := getIP()
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println(T.Success)
	fmt.Println(strings.Repeat("=", 50))
	if xuiConfiguredOK {
		fmt.Printf("%s: %s\n", T.URL, formatPanelURL(ip, secretPath))
		fmt.Printf("%s:  %s\n", T.Login, adminUser)
		fmt.Printf("%s: %s\n", T.Password, adminPass)
		fmt.Println(strings.Repeat("-", 50))
	}
	fmt.Printf("%s: %s\n", T.SSHPort, sshPort)
	fmt.Println(strings.Repeat("=", 50))
	if xuiConfiguredOK {
		fmt.Println(T.XUICommand)
		fmt.Println(T.PanelSecurityNotice)
	}

	if updateSystemChoice || enableBBRChoice {
		fmt.Println("\n" + T.RebootNotice)
	}
}

func installBasicUtilities() {
	_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	_ = run("apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
		"curl", "wget", "htop", "iftop", "iotop", "net-tools", "dnsutils", "jq", "socat", "tar", "unzip", "ca-certificates")
}

func hasZram() bool {
	if data, err := os.ReadFile("/proc/swaps"); err == nil {
		return hasZramContent(string(data))
	}
	if out, err := exec.Command("swapon", "--show").Output(); err == nil {
		return hasZramContent(string(out))
	}
	return false
}

func applySwappiness(val int) {
	if err := os.MkdirAll("/etc/sysctl.d", 0755); err != nil {
		log.Printf("⚠️ Failed to create /etc/sysctl.d: %v\n", err)
		return
	}
	content := fmt.Sprintf("vm.swappiness=%d\n", val)
	if err := os.WriteFile("/etc/sysctl.d/99-swap.conf", []byte(content), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/sysctl.d/99-swap.conf: %v\n", err)
	} else {
		_ = run("sysctl", "-w", fmt.Sprintf("vm.swappiness=%d", val))
	}
}

func ensureFstabSwap() {
	fstab, err := os.ReadFile("/etc/fstab")
	if err != nil && !os.IsNotExist(err) {
		log.Printf("⚠️ Failed to read /etc/fstab: %v\n", err)
		return
	}
	if hasFstabSwapEntry(string(fstab)) {
		return
	}
	f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("⚠️ Failed to open /etc/fstab for writing: %v\n", err)
		return
	}
	prefix := ""
	if len(fstab) > 0 && !strings.HasSuffix(string(fstab), "\n") {
		prefix = "\n"
	}
	if _, err := f.WriteString(prefix + "/swapfile none swap sw 0 0\n"); err != nil {
		log.Printf("⚠️ Failed to write to /etc/fstab: %v\n", err)
	}
	_ = f.Close()
}

func precreateSwapfile() error {
	f, err := os.OpenFile("/swapfile", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove("/swapfile")
		return err
	}
	if err := os.Chmod("/swapfile", 0600); err != nil {
		_ = os.Remove("/swapfile")
		return err
	}
	return nil
}

func activateNewSwapfile() error {
	if err := os.Chmod("/swapfile", 0600); err != nil {
		return fmt.Errorf("chmod 0600 failed: %w", err)
	}
	if err := exec.Command("mkswap", "/swapfile").Run(); err != nil {
		return fmt.Errorf("mkswap failed: %w", err)
	}
	if err := exec.Command("swapon", "/swapfile").Run(); err != nil {
		return fmt.Errorf("swapon failed: %w", err)
	}
	return nil
}

func setupSwap() {
	if hasZram() {
		return // Do not override swappiness or add disk swap on zram-enabled systems
	}

	out, _ := exec.Command("swapon", "--show").Output()
	if strings.TrimSpace(string(out)) != "" {
		applySwappiness(10)
		return
	}
	if fi, err := os.Lstat("/swapfile"); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			log.Println("⚠️ /swapfile is a symlink, refusing to use or overwrite it")
			return
		}
		if fi.IsDir() {
			log.Println("⚠️ /swapfile is a directory, cannot use or create swapfile at this path")
			return
		}
		if err := exec.Command("swapon", "/swapfile").Run(); err != nil {
			log.Printf("⚠️ Existing /swapfile cannot be activated (%v), recreating...\n", err)
			_ = os.Remove("/swapfile")
		} else {
			ensureFstabSwap()
			applySwappiness(10)
			return
		}
	}

	if err := precreateSwapfile(); err != nil {
		log.Printf("⚠️ Failed to pre-create /swapfile: %v\n", err)
		return
	}

	created := false
	if err := exec.Command("fallocate", "-l", "2G", "/swapfile").Run(); err == nil {
		if err := activateNewSwapfile(); err == nil {
			created = true
		} else {
			log.Printf("⚠️ Swap activation after fallocate failed (%v), retrying with dd...\n", err)
			_ = os.Remove("/swapfile")
		}
	} else {
		_ = os.Remove("/swapfile")
	}

	if !created {
		if err := precreateSwapfile(); err != nil {
			log.Printf("⚠️ Failed to pre-create /swapfile for dd: %v\n", err)
			return
		}
		if err := run("dd", "if=/dev/zero", "of=/swapfile", "bs=1M", "count=2048", "status=none"); err != nil {
			log.Printf("⚠️ dd failed to create /swapfile: %v\n", err)
			_ = os.Remove("/swapfile")
			return
		}
		if err := activateNewSwapfile(); err != nil {
			log.Printf("⚠️ Failed to activate /swapfile: %v\n", err)
			_ = os.Remove("/swapfile")
			return
		}
	}

	ensureFstabSwap()
	applySwappiness(10)
}

func setUlimits() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		if rLimit.Cur < 65535 {
			rLimit.Cur = 65535
		}
		if rLimit.Max < 524288 {
			rLimit.Max = 524288
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
			log.Printf("⚠️ Failed to set RLIMIT_NOFILE: %v\n", err)
		}
	}

	// Session limits
	if err := os.MkdirAll("/etc/security/limits.d", 0755); err != nil {
		log.Printf("⚠️ Failed to create /etc/security/limits.d: %v\n", err)
	} else {
		content := "* soft nofile 65535\n* hard nofile 524288\nroot soft nofile 65535\nroot hard nofile 524288\n"
		if err := os.WriteFile("/etc/security/limits.d/99-custom.conf", []byte(content), 0644); err != nil {
			log.Printf("⚠️ Failed to write /etc/security/limits.d/99-custom.conf: %v\n", err)
		}
	}

	// Systemd service limits
	if err := os.MkdirAll("/etc/systemd/system.conf.d", 0755); err != nil {
		log.Printf("⚠️ Failed to create /etc/systemd/system.conf.d: %v\n", err)
	} else {
		sysdContent := "[Manager]\nDefaultLimitNOFILE=65535:524288\n"
		if err := os.WriteFile("/etc/systemd/system.conf.d/99-limits.conf", []byte(sysdContent), 0644); err != nil {
			log.Printf("⚠️ Failed to write /etc/systemd/system.conf.d/99-limits.conf: %v\n", err)
		}
	}
	_ = run("systemctl", "daemon-reload")
}

func applySSHPort(port string) error {
	// 1. Если на сервере уже активен UFW, сначала открываем новый порт во избежание lockout
	ufwCmd := exec.Command("ufw", "status")
	ufwCmd.Env = append(os.Environ(), "LC_ALL=C")
	if ufwStatus, err := ufwCmd.Output(); err == nil && strings.Contains(string(ufwStatus), "Status: active") {
		if err := run("ufw", "prepend", "allow", port+"/tcp", "comment", "SSH"); err != nil {
			_ = run("ufw", "allow", port+"/tcp", "comment", "SSH")
		}
		_ = run("ufw", "reload")
	}

	// 2. Записываем порт в drop-in конфиг (00- для гарантированного приоритета)
	if err := os.MkdirAll("/etc/ssh/sshd_config.d", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/ssh/sshd_config.d: %w", err)
	}
	dropInPath := "/etc/ssh/sshd_config.d/00-port.conf"
	prevDropIn, prevDropInErr := os.ReadFile(dropInPath)
	if err := os.WriteFile(dropInPath, []byte("Port "+port+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", dropInPath, err)
	}
	_ = os.Remove("/etc/ssh/sshd_config.d/99-port.conf")

	var prevMainCfg []byte
	mainCfgModified := false
	rollback := func() {
		if prevDropInErr == nil {
			_ = os.WriteFile(dropInPath, prevDropIn, 0644)
		} else {
			_ = os.Remove(dropInPath)
		}
		if mainCfgModified {
			_ = os.WriteFile("/etc/ssh/sshd_config", prevMainCfg, 0644)
		}
	}

	if cfg, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		prevMainCfg = cfg
		cfgStr := string(cfg)

		if hasActiveSSHDInclude(cfgStr) {
			// Комментируем активные директивы Port, чтобы OpenSSH не слушал оба порта
			if newCfg, changed := commentActivePorts(cfgStr); changed {
				if err := os.WriteFile("/etc/ssh/sshd_config", []byte(newCfg), 0644); err != nil {
					rollback()
					return fmt.Errorf("failed to comment out old Port in /etc/ssh/sshd_config: %w", err)
				}
				mainCfgModified = true
			}
		} else {
			// Старые системы без Include: меняем директиву прямо в основном конфиге (до Match-блока)
			newCfg := updateSSHDConfigPort(cfgStr, port)
			if newCfg != cfgStr {
				if err := os.WriteFile("/etc/ssh/sshd_config", []byte(newCfg), 0644); err != nil {
					rollback()
					return fmt.Errorf("failed to write /etc/ssh/sshd_config: %w", err)
				}
				mainCfgModified = true
			}
		}
	}

	// 3. Валидируем конфигурацию перед перезапуском демона
	_ = os.MkdirAll("/run/sshd", 0755)
	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("sshd -t failed, changes rolled back: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// 4. Перезапускаем ssh.socket / sshd
	outActive, _ := exec.Command("systemctl", "is-active", "ssh.socket").Output()
	outEnabled, _ := exec.Command("systemctl", "is-enabled", "ssh.socket").Output()

	if isSSHSocketActive(string(outActive), string(outEnabled)) {
		if err := os.MkdirAll("/etc/systemd/system/ssh.socket.d", 0755); err != nil {
			return fmt.Errorf("failed to create ssh.socket.d: %w", err)
		}
		_ = os.Remove("/etc/systemd/system/ssh.socket.d/override.conf")
		data := fmt.Sprintf("[Socket]\nListenStream=\nListenStream=%s\n", port)
		if err := os.WriteFile("/etc/systemd/system/ssh.socket.d/listen.conf", []byte(data), 0644); err != nil {
			return fmt.Errorf("failed to write ssh.socket listen.conf: %w", err)
		}
		if err := run("systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload failed: %w", err)
		}
		if err := run("systemctl", "restart", "ssh.socket"); err != nil {
			return fmt.Errorf("systemctl restart ssh.socket failed: %w", err)
		}
		_ = run("systemctl", "restart", "ssh")
	} else {
		if err := exec.Command("systemctl", "restart", "sshd").Run(); err != nil {
			if err := run("systemctl", "restart", "ssh"); err != nil {
				return fmt.Errorf("failed to restart sshd/ssh: %w", err)
			}
		}
	}
	return nil
}

func tuneConntrack() {
	conntrackPath := "/proc/sys/net/netfilter/nf_conntrack_max"
	data, err := os.ReadFile(conntrackPath)
	if err != nil {
		return
	}

	curMax, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || curMax <= 0 {
		return
	}

	targetMax := curMax
	if curMax < 65536 {
		targetMax = 65536
	}

	hashsize := targetMax / 4

	_ = os.MkdirAll("/etc/modules-load.d", 0755)
	if err := os.WriteFile("/etc/modules-load.d/conntrack.conf", []byte("nf_conntrack\n"), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/modules-load.d/conntrack.conf: %v\n", err)
	}

	_ = os.MkdirAll("/etc/modprobe.d", 0755)
	if err := os.WriteFile("/etc/modprobe.d/conntrack.conf", []byte(fmt.Sprintf("options nf_conntrack hashsize=%d\n", hashsize)), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/modprobe.d/conntrack.conf: %v\n", err)
	}

	// Моментальное применение hashsize в работающее ядро
	_ = os.WriteFile("/sys/module/nf_conntrack/parameters/hashsize", []byte(strconv.Itoa(hashsize)+"\n"), 0644)

	conntrackCfg := fmt.Sprintf(`# Stateful firewall conntrack optimizations
net.netfilter.nf_conntrack_max = %d
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
`, targetMax)

	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	if err := os.WriteFile("/etc/sysctl.d/99-conntrack.conf", []byte(conntrackCfg), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/sysctl.d/99-conntrack.conf: %v\n", err)
		return
	}
	_ = run("sysctl", "-p", "/etc/sysctl.d/99-conntrack.conf")
}

func configureUFW(sshPort string) {
	_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	if err := run("apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "ufw"); err != nil {
		log.Printf("⚠️ Failed to install ufw: %v\n", err)
		return
	}
	if err := run("ufw", "default", "deny", "incoming"); err != nil {
		log.Printf("⚠️ Failed to set ufw default deny incoming: %v\n", err)
		return
	}
	if err := run("ufw", "default", "allow", "outgoing"); err != nil {
		log.Printf("⚠️ Failed to set ufw default allow outgoing: %v\n", err)
		return
	}

	// Критично: открываем SSH-порт первым (prepend), чтобы существующие deny-правила не вызвали lockout
	if err := run("ufw", "prepend", "allow", sshPort+"/tcp", "comment", "SSH"); err != nil {
		if err := run("ufw", "allow", sshPort+"/tcp", "comment", "SSH"); err != nil {
			log.Printf("❌ Failed to allow SSH port %s in UFW: %v. Aborting UFW activation to prevent lockout!\n", sshPort, err)
			return
		}
	}

	_ = run("ufw", "allow", "443", "comment", "VPN")
	_ = run("ufw", "allow", "3/tcp", "comment", "PANEL")
	_ = run("ufw", "allow", "10443/tcp", "comment", "SUBSCRIPTION")
	_ = run("ufw", "allow", "8443/tcp", "comment", "telemt")
	_ = run("ufw", "deny", "9000", "comment", "nginx")
	_ = run("ufw", "deny", "40000", "comment", "warp")
	if err := run("ufw", "--force", "enable"); err != nil {
		log.Printf("⚠️ Failed to enable UFW: %v\n", err)
		return
	}
	_ = run("ufw", "reload")
}

func downloadScriptToTemp(rawURL string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, rawURL)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", fmt.Errorf("failed reading script body: %w", err)
	}
	if !isValidScriptContent(data) {
		return "", fmt.Errorf("downloaded content from %s is empty or not a valid shell script", rawURL)
	}

	tmpFile, err := os.CreateTemp("", "fast-vps-script-*.sh")
	if err != nil {
		return "", fmt.Errorf("failed creating temp script: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Chmod(0700); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed setting permissions on temp script: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed writing temp script: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed closing temp script: %w", err)
	}
	return tmpPath, nil
}

func installTelemt() error {
	tmpPath, err := downloadScriptToTemp("https://raw.githubusercontent.com/telemt/telemt/main/install.sh")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()
	return run("sh", tmpPath, "--port", "8443")
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
set -u

LOG_FILE="/var/log/warp-watchdog.log"
WARP_PORT="40000"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Проверяем, слушает ли warp-svc порт 40000
if ss -lntp | grep -qE ":${WARP_PORT}[[:space:]].*warp-svc"; then
    # Порт слушается, WARP в порядке
    exit 0
else
    log "⚠️  Порт $WARP_PORT не слушается или процесс warp-svc не отвечает. Перезапускаем WARP..."

    # Перезапускаем сервис WARP
    systemctl restart warp-svc

    # Небольшая пауза, чтобы сервис успел запуститься
    sleep 10

    # Повторная проверка
    if ss -lntp | grep -qE ":${WARP_PORT}[[:space:]].*warp-svc"; then
        log "✅ После перезапуска WARP порт $WARP_PORT снова в порядке."
    else
        log "❌ Критическая ошибка: WARP не смог запуститься или порт $WARP_PORT не открылся."
    fi
fi
`
	if err := os.WriteFile("/usr/local/bin/warp-watchdog.sh", []byte(script), 0755); err != nil {
		log.Printf("⚠️ Failed to write /usr/local/bin/warp-watchdog.sh: %v\n", err)
		return
	}
	if err := os.Chmod("/usr/local/bin/warp-watchdog.sh", 0755); err != nil {
		log.Printf("⚠️ Failed to chmod /usr/local/bin/warp-watchdog.sh: %v\n", err)
		return
	}

	cronJob := "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n* * * * * root flock -n /run/warp-watchdog.lock /usr/local/bin/warp-watchdog.sh >/dev/null 2>&1\n"
	if err := os.WriteFile("/etc/cron.d/warp-watchdog", []byte(cronJob), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/cron.d/warp-watchdog: %v\n", err)
	}

	// Настройка ротации логов для watchdog
	logrotateCfg := "/var/log/warp-watchdog.log {\n    weekly\n    rotate 4\n    compress\n    missingok\n    notifempty\n}\n"
	if err := os.WriteFile("/etc/logrotate.d/warp-watchdog", []byte(logrotateCfg), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/logrotate.d/warp-watchdog: %v\n", err)
	}
}

func install3xUIOfficial() error {
	tmpPath, err := downloadScriptToTemp("https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()

	cmd := exec.Command("bash", tmpPath)
	cmd.Stdin = strings.NewReader("n\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func finalConfig(user, pass, path string) error {
	if !waitForFile("/usr/local/x-ui/x-ui", 30*time.Second) {
		return fmt.Errorf("/usr/local/x-ui/x-ui not found after installation")
	}
	time.Sleep(2 * time.Second)

	fullPath := "/" + path + "/"
	// Upstream x-ui CLI only accepts credentials via command-line flags (-username/-password)
	if err := exec.Command("/usr/local/x-ui/x-ui", "setting", "-username", user, "-password", pass, "-port", "3", "-webBasePath", fullPath).Run(); err != nil {
		return fmt.Errorf("x-ui setting command failed: %w", err)
	}

	if fi, err := os.Stat("/usr/local/x-ui/x-ui.sh"); err != nil || fi.IsDir() {
		return fmt.Errorf("/usr/local/x-ui/x-ui.sh not found: %w", err)
	}
	_ = os.Remove("/usr/bin/x-ui")
	if err := os.Symlink("/usr/local/x-ui/x-ui.sh", "/usr/bin/x-ui"); err != nil {
		return fmt.Errorf("failed to create /usr/bin/x-ui symlink: %w", err)
	}

	return run("systemctl", "restart", "x-ui")
}

func getOptimalTCPBufferMax() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 8388608
	}
	return parseOptimalTCPBuffer(string(data))
}

func enableBBR() {
	if err := run("modprobe", "tcp_bbr"); err != nil {
		log.Printf("⚠️ modprobe tcp_bbr failed (kernel may lack tcp_bbr or run inside container): %v\n", err)
	}
	_ = os.MkdirAll("/etc/modules-load.d", 0755)
	if err := os.WriteFile("/etc/modules-load.d/bbr.conf", []byte("tcp_bbr\n"), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/modules-load.d/bbr.conf: %v\n", err)
	}

	maxBuf := getOptimalTCPBufferMax()

	sysctlSettings := fmt.Sprintf(`# Network BBR, BDP & TFO Optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = %d
net.core.wmem_max = %d
net.ipv4.tcp_rmem = 4096 87380 %d
net.ipv4.tcp_wmem = 4096 65536 %d
net.ipv4.tcp_mtu_probing = 1

# Socket reuse and connection queues
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096

# Keepalive for idle tunnels and long sessions
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3
`, maxBuf, maxBuf, maxBuf, maxBuf)

	if err := os.MkdirAll("/etc/sysctl.d", 0755); err != nil {
		log.Printf("⚠️ Failed to create /etc/sysctl.d: %v\n", err)
		return
	}
	if err := os.WriteFile("/etc/sysctl.d/99-bbr.conf", []byte(sysctlSettings), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/sysctl.d/99-bbr.conf: %v\n", err)
		return
	}
	if err := run("sysctl", "--system"); err != nil {
		log.Printf("⚠️ sysctl --system failed; BBR may not be supported on this kernel: %v\n", err)
	}
	if avail, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control"); err == nil {
		if !strings.Contains(string(avail), "bbr") {
			log.Printf("⚠️ Kernel does not list 'bbr' in tcp_available_congestion_control (%s)\n", strings.TrimSpace(string(avail)))
		}
	}
}

func installFail2Ban(sshPort string) {
	_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	if err := run("apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "fail2ban", "python3-systemd"); err != nil {
		log.Printf("⚠️ Failed to install fail2ban: %v\n", err)
		return
	}
	if err := os.MkdirAll("/etc/fail2ban/jail.d", 0755); err != nil {
		log.Printf("⚠️ Failed to create /etc/fail2ban/jail.d: %v\n", err)
		return
	}
	jailConfig := fmt.Sprintf("[sshd]\nenabled = true\nbackend = systemd\nport = %s\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n", sshPort)
	if err := os.WriteFile("/etc/fail2ban/jail.d/sshd.local", []byte(jailConfig), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/fail2ban/jail.d/sshd.local: %v\n", err)
		return
	}
	if err := run("systemctl", "enable", "fail2ban"); err != nil {
		log.Printf("⚠️ Failed to enable fail2ban: %v\n", err)
	}
	if err := run("systemctl", "restart", "fail2ban"); err != nil {
		log.Printf("⚠️ Failed to restart fail2ban: %v\n", err)
	}
}

func setupDNS() {
	_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	if err := exec.Command("systemctl", "cat", "systemd-resolved.service").Run(); err != nil {
		if err := run("apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "systemd-resolved"); err != nil {
			log.Printf("⚠️ Failed to install systemd-resolved: %v\n", err)
			return
		}
	}
	config := "[Resolve]\nDNS=1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844\nFallbackDNS=1.0.0.1 8.8.4.4\nDNSStubListener=yes\n"
	if err := os.MkdirAll("/etc/systemd/resolved.conf.d", 0755); err != nil {
		log.Printf("⚠️ Failed to create /etc/systemd/resolved.conf.d: %v\n", err)
		return
	}
	if err := os.WriteFile("/etc/systemd/resolved.conf.d/dns.conf", []byte(config), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/systemd/resolved.conf.d/dns.conf: %v\n", err)
		return
	}
	if err := run("systemctl", "enable", "--now", "systemd-resolved"); err != nil {
		log.Printf("⚠️ Failed to enable systemd-resolved: %v\n", err)
		return
	}
	if err := run("systemctl", "restart", "systemd-resolved"); err != nil {
		log.Printf("⚠️ Failed to restart systemd-resolved: %v\n", err)
		return
	}
	if fi, err := os.Stat("/run/systemd/resolve/stub-resolv.conf"); err == nil && !fi.IsDir() {
		tmpLink := "/etc/resolv.conf.fast-vps-tmp"
		_ = os.Remove(tmpLink)
		if err := os.Symlink("/run/systemd/resolve/stub-resolv.conf", tmpLink); err != nil {
			log.Printf("⚠️ Failed to create temp symlink for /etc/resolv.conf: %v\n", err)
			return
		}
		if err := os.Rename(tmpLink, "/etc/resolv.conf"); err != nil {
			_ = os.Remove(tmpLink)
			log.Printf("⚠️ Failed to update /etc/resolv.conf symlink: %v\n", err)
		}
	}
}

func getCurrentSSHPort() string {
	outActive, _ := exec.Command("systemctl", "is-active", "ssh.socket").Output()
	outEnabled, _ := exec.Command("systemctl", "is-enabled", "ssh.socket").Output()
	if isSSHSocketActive(string(outActive), string(outEnabled)) {
		if listenOut, err := exec.Command("systemctl", "show", "-p", "Listen", "--value", "ssh.socket").Output(); err == nil {
			if port := parseSSHSocketListenPort(string(listenOut)); port != "" {
				return port
			}
		}
		if matches, err := filepath.Glob("/etc/systemd/system/ssh.socket.d/*.conf"); err == nil {
			sort.Strings(matches)
			var combined strings.Builder
			for _, m := range matches {
				if data, err := os.ReadFile(m); err == nil {
					combined.Write(data)
					combined.WriteByte('\n')
				}
			}
			if port := parseSSHSocketDropInPort(combined.String()); port != "" {
				return port
			}
		}
	}

	_ = os.MkdirAll("/run/sshd", 0755)
	if out, err := exec.Command("sshd", "-T").Output(); err == nil {
		if port := parseSSHPortFromConfig(string(out)); port != "" {
			return port
		}
	}

	dropIns := []string{
		"/etc/ssh/sshd_config.d/00-port.conf",
		"/etc/ssh/sshd_config.d/99-port.conf",
	}
	for _, p := range dropIns {
		if dropData, err := os.ReadFile(p); err == nil {
			if port := parseSSHPortFromConfig(string(dropData)); port != "" {
				return port
			}
		}
	}

	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "22"
	}
	if port := parseSSHPortFromConfig(string(data)); port != "" {
		return port
	}
	return "22"
}

func setupSSHKey(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}

	if err := os.MkdirAll("/root/.ssh", 0700); err != nil {
		log.Printf("❌ Failed to create /root/.ssh: %v\n", err)
		return
	}
	if err := os.Chmod("/root/.ssh", 0700); err != nil {
		log.Printf("❌ Failed to set permissions on /root/.ssh: %v\n", err)
		return
	}

	authKeys, err := os.ReadFile("/root/.ssh/authorized_keys")
	if err != nil && !os.IsNotExist(err) {
		log.Printf("❌ Failed to read /root/.ssh/authorized_keys: %v\n", err)
		return
	}
	keyExists := err == nil && hasAuthorizedKey(string(authKeys), key)

	if !keyExists {
		f, err := os.OpenFile("/root/.ssh/authorized_keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Printf("❌ Failed to open /root/.ssh/authorized_keys: %v\n", err)
			return
		}
		prefix := ""
		if len(authKeys) > 0 && !strings.HasSuffix(string(authKeys), "\n") {
			prefix = "\n"
		}
		if _, err := f.WriteString(prefix + key + "\n"); err != nil {
			_ = f.Close()
			log.Printf("❌ Failed to write to /root/.ssh/authorized_keys: %v. Password auth will NOT be disabled!\n", err)
			return
		}
		_ = f.Close()
	}

	if err := os.Chmod("/root/.ssh/authorized_keys", 0600); err != nil {
		log.Printf("❌ Failed to set permissions on /root/.ssh/authorized_keys: %v. Password auth will NOT be disabled!\n", err)
		return
	}

	// 1. Drop-in config для OpenSSH (00- для приоритета над 50-cloud-init.conf)
	if err := os.MkdirAll("/etc/ssh/sshd_config.d", 0755); err != nil {
		log.Printf("⚠️ Failed to create /etc/ssh/sshd_config.d: %v\n", err)
		return
	}
	dropinPath := "/etc/ssh/sshd_config.d/00-disable-passwords.conf"
	prevDropin, prevDropinErr := os.ReadFile(dropinPath)
	dropinCfg := "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
	if err := os.WriteFile(dropinPath, []byte(dropinCfg), 0644); err != nil {
		log.Printf("⚠️ Failed to write %s: %v\n", dropinPath, err)
		return
	}
	_ = os.Remove("/etc/ssh/sshd_config.d/99-disable-passwords.conf")

	// 2. Fallback для старых OpenSSH без Include или если PasswordAuthentication yes предшествует Include
	var prevMainCfg []byte
	mainCfgModified := false
	needMainCfgUpdate := false
	if cfg, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		prevMainCfg = cfg
		cfgStr := string(cfg)
		if !hasActiveSSHDInclude(cfgStr) || hasPasswordAuthBeforeInclude(cfgStr) {
			needMainCfgUpdate = true
			newCfg := updateLegacySSHDPasswordAuth(cfgStr, true)
			if newCfg != cfgStr {
				if err := os.WriteFile("/etc/ssh/sshd_config", []byte(newCfg), 0644); err != nil {
					log.Printf("⚠️ Failed to write /etc/ssh/sshd_config: %v\n", err)
				} else {
					mainCfgModified = true
				}
			}
		}
	}

	// 3. Валидируем конфигурацию через sshd -t перед перезапуском демона
	_ = os.MkdirAll("/run/sshd", 0755)
	out, valErr := exec.Command("sshd", "-t").CombinedOutput()
	if valErr != nil && strings.Contains(string(out), "KbdInteractiveAuthentication") {
		// Fallback для Debian 11 / OpenSSH < 8.7 (опция KbdInteractiveAuthentication не поддерживается)
		log.Printf("⚠️ sshd -t rejected KbdInteractiveAuthentication, retrying with ChallengeResponseAuthentication...\n")
		dropinCfgFallback := "PasswordAuthentication no\nChallengeResponseAuthentication no\n"
		if err := os.WriteFile(dropinPath, []byte(dropinCfgFallback), 0644); err != nil {
			log.Printf("⚠️ Failed to rewrite %s: %v\n", dropinPath, err)
		}
		if needMainCfgUpdate {
			fallbackMain := updateLegacySSHDPasswordAuth(string(prevMainCfg), false)
			if fallbackMain != string(prevMainCfg) {
				if err := os.WriteFile("/etc/ssh/sshd_config", []byte(fallbackMain), 0644); err != nil {
					log.Printf("⚠️ Failed to rewrite /etc/ssh/sshd_config: %v\n", err)
				} else {
					mainCfgModified = true
				}
			}
		}
		out, valErr = exec.Command("sshd", "-t").CombinedOutput()
	}

	if valErr != nil {
		if prevDropinErr == nil {
			_ = os.WriteFile(dropinPath, prevDropin, 0644)
		} else {
			_ = os.Remove(dropinPath)
		}
		if mainCfgModified {
			_ = os.WriteFile("/etc/ssh/sshd_config", prevMainCfg, 0644)
		}
		log.Printf("❌ sshd -t failed, changes rolled back: %v (%s)\n", valErr, strings.TrimSpace(string(out)))
		return
	}

	if err := exec.Command("systemctl", "restart", "sshd").Run(); err != nil {
		_ = run("systemctl", "restart", "ssh")
	}
}

func disableSSHSocket() {
	_ = os.Remove("/etc/systemd/system/ssh.socket.d/listen.conf")
	_ = os.Remove("/etc/systemd/system/ssh.socket.d/override.conf")
	_ = run("systemctl", "daemon-reload")
	_ = run("systemctl", "stop", "ssh.socket")
	_ = run("systemctl", "disable", "ssh.socket")
	_ = run("systemctl", "daemon-reload")
	if err := exec.Command("systemctl", "enable", "--now", "sshd").Run(); err == nil {
		_ = run("systemctl", "restart", "sshd")
	} else {
		_ = run("systemctl", "enable", "--now", "ssh")
		_ = run("systemctl", "restart", "ssh")
	}
}
