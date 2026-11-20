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
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Messages struct {
	LangSelect              string
	SSHPortPrompt           string
	SSHPortEmpty            string
	InvalidSSHPort          string
	SSHPortConflict         string
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
	InstallingDNS           string
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
	MenuOption0             string
	ExitMsg                 string
	DisablingSocket         string
	RebootNotice            string
}

var ruMsgs = Messages{
	LangSelect:       "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	SSHPortPrompt:    "👉 Введите новый порт для SSH (например, 9049): ",
	SSHPortEmpty:     "Порт не может быть пустым",
	InvalidSSHPort:   "Некорректный номер порта. Введите число от 1 до 65535.",
	SSHPortConflict:  "Этот порт зарезервирован для системных служб или прокси. Выберите другой порт.",
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
	InstallingDNS:    "[3.5/6] 🌐 Настройка DNS (Cloudflare + Google)...",
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
	MenuOption0:             "0. Выход",
	ExitMsg:                 "Выход из скрипта...",
	DisablingSocket:         "[3.1/6] ⚙️ Отключение SSH Socket и запуск классического SSH Service...",
	RebootNotice:            "⚠️ Рекомендуется перезагрузить сервер (команда 'reboot') для применения изменений ядра и BBR.",
}

var enMsgs = Messages{
	LangSelect:       "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	SSHPortPrompt:    "👉 Enter new SSH port (e.g., 9049): ",
	SSHPortEmpty:     "Port cannot be empty",
	InvalidSSHPort:   "Invalid port number. Enter a number between 1 and 65535.",
	SSHPortConflict:  "This port is reserved for system services or proxies. Choose another port.",
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
	InstallingDNS:    "[3.5/6] 🌐 Configuring DNS (Cloudflare + Google)...",
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
	MenuOption0:             "0. Exit",
	ExitMsg:                 "Exiting script...",
	DisablingSocket:         "[3.1/6] ⚙️ Disabling SSH Socket and starting classic SSH Service...",
	RebootNotice:            "⚠️ It is recommended to reboot the server ('reboot' command) to apply kernel and BBR changes.",
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
	fmt.Println(T.MenuOption0)
	fmt.Print("\n" + T.SelectComponents)

	selection, _ := reader.ReadString('\n')
	chosen, ok := parseSelection(selection, 12)
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
		if configureUFWChoice || installFail2BanChoice || setupDNSChoice || install3xUI || installTelemtChoice || setupSwapChoice {
			_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
			run("apt", "update")
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

	if install3xUI || installTelemtChoice {
		// Синхронизация времени для надежной работы TLS/VLESS/Reality
		_ = exec.Command("systemctl", "enable", "--now", "systemd-timesyncd").Run()
	}

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

	if install3xUI {
		fmt.Println("\n" + T.Finalizing)
		finalConfig(adminUser, adminPass, secretPath)
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
	if install3xUI {
		fmt.Printf("%s: http://%s:3/%s/\n", T.URL, ip, secretPath)
		fmt.Printf("%s:  %s\n", T.Login, adminUser)
		fmt.Printf("%s: %s\n", T.Password, adminPass)
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

func hasZram() bool {
	if data, err := os.ReadFile("/proc/swaps"); err == nil {
		return strings.Contains(string(data), "zram")
	}
	if out, err := exec.Command("swapon", "--show").Output(); err == nil {
		return strings.Contains(string(out), "zram")
	}
	return false
}

func applySwappiness(val int) {
	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	content := fmt.Sprintf("vm.swappiness=%d\n", val)
	if err := os.WriteFile("/etc/sysctl.d/99-swap.conf", []byte(content), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/sysctl.d/99-swap.conf: %v\n", err)
	} else {
		_ = run("sysctl", "-w", fmt.Sprintf("vm.swappiness=%d", val))
	}
}

func ensureFstabSwap() {
	fstab, err := os.ReadFile("/etc/fstab")
	if err == nil && !strings.Contains(string(fstab), "/swapfile") {
		f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("⚠️ Failed to open /etc/fstab for writing: %v\n", err)
		} else {
			if _, err := f.WriteString("\n/swapfile none swap sw 0 0\n"); err != nil {
				log.Printf("⚠️ Failed to write to /etc/fstab: %v\n", err)
			}
			_ = f.Close()
		}
	}
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
	if fi, err := os.Stat("/swapfile"); err == nil {
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

	cmd := exec.Command("fallocate", "-l", "2G", "/swapfile")
	if err := cmd.Run(); err != nil {
		_ = os.Remove("/swapfile")
		if err := run("dd", "if=/dev/zero", "of=/swapfile", "bs=1M", "count=2048", "status=none"); err != nil {
			log.Printf("⚠️ dd failed to create /swapfile: %v\n", err)
			_ = os.Remove("/swapfile")
			return
		}
	}
	_ = run("chmod", "600", "/swapfile")
	if err := exec.Command("mkswap", "/swapfile").Run(); err != nil {
		log.Printf("⚠️ mkswap failed: %v\n", err)
		_ = os.Remove("/swapfile")
		return
	}
	if err := exec.Command("swapon", "/swapfile").Run(); err != nil {
		log.Printf("⚠️ swapon failed: %v\n", err)
		_ = os.Remove("/swapfile")
		return
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
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}

	// Session limits
	_ = os.MkdirAll("/etc/security/limits.d", 0755)
	content := "* soft nofile 65535\n* hard nofile 524288\nroot soft nofile 65535\nroot hard nofile 524288\n"
	_ = os.WriteFile("/etc/security/limits.d/99-custom.conf", []byte(content), 0644)

	// Systemd service limits
	_ = os.MkdirAll("/etc/systemd/system.conf.d", 0755)
	sysdContent := "[Manager]\nDefaultLimitNOFILE=65535:524288\n"
	_ = os.WriteFile("/etc/systemd/system.conf.d/99-limits.conf", []byte(sysdContent), 0644)
	run("systemctl", "daemon-reload")
}

func applySSHPort(port string) {
	// 1. Если на сервере уже активен UFW, сначала открываем новый порт во избежание lockout
	ufwStatus, err := exec.Command("ufw", "status").Output()
	if err == nil && strings.Contains(string(ufwStatus), "Status: active") {
		run("ufw", "allow", port+"/tcp", "comment", "SSH")
		run("ufw", "reload")
	}

	// 2. Записываем порт в drop-in конфиг (00- для гарантированного приоритета)
	_ = os.MkdirAll("/etc/ssh/sshd_config.d", 0755)
	dropInPath := "/etc/ssh/sshd_config.d/00-port.conf"
	prevDropIn, prevDropInErr := os.ReadFile(dropInPath)
	if err := os.WriteFile(dropInPath, []byte("Port "+port+"\n"), 0644); err != nil {
		log.Printf("⚠️ Failed to write %s: %v\n", dropInPath, err)
		return
	}
	_ = os.Remove("/etc/ssh/sshd_config.d/99-port.conf")

	var prevMainCfg []byte
	mainCfgModified := false
	if cfg, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		prevMainCfg = cfg
		cfgStr := string(cfg)
		hasInclude := strings.Contains(cfgStr, "sshd_config.d")

		if hasInclude {
			// Комментируем активные директивы Port, чтобы OpenSSH не слушал оба порта
			reActivePort := regexp.MustCompile(`(?m)^[\t ]*Port\b.*$`)
			if reActivePort.Match(cfg) {
				newCfg := reActivePort.ReplaceAllStringFunc(cfgStr, func(line string) string {
					return "#" + line
				})
				if err := os.WriteFile("/etc/ssh/sshd_config", []byte(newCfg), 0644); err != nil {
					log.Printf("⚠️ Failed to comment out old Port in /etc/ssh/sshd_config: %v\n", err)
				} else {
					mainCfgModified = true
				}
			}
		} else {
			// Старые системы без Include: меняем директиву прямо в основном конфиге
			re := regexp.MustCompile(`(?m)^#?Port\s+\d+`)
			newCfg := re.ReplaceAll(cfg, []byte("Port "+port))
			if !strings.Contains(string(newCfg), "Port "+port) {
				newCfg = append(newCfg, []byte("\nPort "+port+"\n")...)
			}
			if err := os.WriteFile("/etc/ssh/sshd_config", newCfg, 0644); err != nil {
				log.Printf("⚠️ Failed to write /etc/ssh/sshd_config: %v\n", err)
			} else {
				mainCfgModified = true
			}
		}
	}

	// 3. Валидируем конфигурацию перед перезапуском демона
	_ = os.MkdirAll("/run/sshd", 0755)
	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		if prevDropInErr == nil {
			_ = os.WriteFile(dropInPath, prevDropIn, 0644)
		} else {
			_ = os.Remove(dropInPath)
		}
		if mainCfgModified {
			_ = os.WriteFile("/etc/ssh/sshd_config", prevMainCfg, 0644)
		}
		log.Printf("❌ sshd -t failed, changes rolled back: %v (%s)\n", err, strings.TrimSpace(string(out)))
		return
	}

	// 4. Перезапускаем ssh.socket / sshd
	outActive, _ := exec.Command("systemctl", "is-active", "ssh.socket").Output()
	outEnabled, _ := exec.Command("systemctl", "is-enabled", "ssh.socket").Output()

	isSocket := strings.Contains(string(outActive), "active") || strings.Contains(string(outEnabled), "enabled")

	if isSocket {
		_ = os.MkdirAll("/etc/systemd/system/ssh.socket.d", 0755)
		_ = os.Remove("/etc/systemd/system/ssh.socket.d/override.conf")
		data := fmt.Sprintf("[Socket]\nListenStream=\nListenStream=%s\n", port)
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
	run("sysctl", "-p", "/etc/sysctl.d/99-conntrack.conf")
}

func configureUFW(sshPort string) {
	if err := run("apt-get", "install", "-y", "ufw"); err != nil {
		log.Printf("⚠️ Failed to install ufw: %v\n", err)
		return
	}
	_ = run("ufw", "default", "deny", "incoming")
	_ = run("ufw", "default", "allow", "outgoing")

	// Критично: открываем SSH-порт перед включением фаервола во избежание lockout
	if err := run("ufw", "allow", sshPort+"/tcp", "comment", "SSH"); err != nil {
		log.Printf("❌ Failed to allow SSH port %s in UFW: %v. Aborting UFW activation to prevent lockout!\n", sshPort, err)
		return
	}

	_ = run("ufw", "allow", "443", "comment", "VPN")
	_ = run("ufw", "allow", "3/tcp", "comment", "PANEL")
	_ = run("ufw", "allow", "10443/tcp", "comment", "SUBSCRIPTION")
	_ = run("ufw", "allow", "8443/tcp")
	_ = run("ufw", "deny", "9000", "comment", "nginx")
	_ = run("ufw", "deny", "40000", "comment", "warp")
	_ = run("ufw", "--force", "enable")
	_ = run("ufw", "reload")
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
	if err := exec.Command("/usr/local/x-ui/x-ui", "setting", "-username", user, "-password", pass, "-port", "3", "-webBasePath", fullPath).Run(); err != nil {
		log.Printf("⚠️ x-ui setting command failed: %v\n", err)
	}

	_ = os.Remove("/usr/bin/x-ui")
	_ = exec.Command("ln", "-s", "/usr/local/x-ui/x-ui.sh", "/usr/bin/x-ui").Run()

	run("systemctl", "restart", "x-ui")
}

func parseOptimalTCPBuffer(meminfoContent string) int {
	var memTotalKB int64
	for _, line := range strings.Split(meminfoContent, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memTotalKB, _ = strconv.ParseInt(fields[1], 10, 64)
			}
			break
		}
	}

	memTotalMB := memTotalKB / 1024
	if memTotalMB <= 0 {
		return 8388608
	}
	switch {
	case memTotalMB <= 512:
		return 8388608
	case memTotalMB <= 1024:
		return 16777216
	case memTotalMB <= 2048:
		return 33554432
	default:
		return 67108864
	}
}

func getOptimalTCPBufferMax() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 8388608
	}
	return parseOptimalTCPBuffer(string(data))
}

func enableBBR() {
	run("modprobe", "tcp_bbr")
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

	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	if err := os.WriteFile("/etc/sysctl.d/99-bbr.conf", []byte(sysctlSettings), 0644); err != nil {
		log.Printf("⚠️ Failed to write /etc/sysctl.d/99-bbr.conf: %v\n", err)
		return
	}
	run("sysctl", "--system")
}

func installFail2Ban(sshPort string) {
	run("apt-get", "install", "-y", "fail2ban", "python3-systemd")
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
	if out, err := exec.Command("sshd", "-T").Output(); err == nil {
		reT := regexp.MustCompile(`(?m)^port\s+(\d+)`)
		if match := reT.FindStringSubmatch(string(out)); len(match) > 1 {
			return match[1]
		}
	}

	re := regexp.MustCompile(`(?m)^Port\s+(\d+)`)
	dropIns := []string{
		"/etc/ssh/sshd_config.d/00-port.conf",
		"/etc/ssh/sshd_config.d/99-port.conf",
	}
	for _, p := range dropIns {
		if dropData, err := os.ReadFile(p); err == nil {
			if match := re.FindStringSubmatch(string(dropData)); len(match) > 1 {
				return match[1]
			}
		}
	}

	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "22"
	}
	match := re.FindStringSubmatch(string(data))
	if len(match) > 1 {
		return match[1]
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

	authKeys, err := os.ReadFile("/root/.ssh/authorized_keys")
	keyExists := err == nil && strings.Contains(string(authKeys), key)

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

	// 1. Drop-in config для OpenSSH (00- для приоритета над 50-cloud-init.conf)
	_ = os.MkdirAll("/etc/ssh/sshd_config.d", 0755)
	dropinPath := "/etc/ssh/sshd_config.d/00-disable-passwords.conf"
	prevDropin, prevDropinErr := os.ReadFile(dropinPath)
	dropinCfg := "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
	if err := os.WriteFile(dropinPath, []byte(dropinCfg), 0644); err != nil {
		log.Printf("⚠️ Failed to write %s: %v\n", dropinPath, err)
		return
	}
	_ = os.Remove("/etc/ssh/sshd_config.d/99-disable-passwords.conf")

	// 2. Fallback для старых OpenSSH без Include
	var prevMainCfg []byte
	mainCfgModified := false
	if cfg, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil && !strings.Contains(string(cfg), "sshd_config.d") {
		prevMainCfg = cfg
		re := regexp.MustCompile(`(?m)^#?PasswordAuthentication\s+(yes|no)`)
		newCfg := re.ReplaceAll(cfg, []byte("PasswordAuthentication no"))
		if !strings.Contains(string(newCfg), "PasswordAuthentication no") {
			newCfg = append(newCfg, []byte("\nPasswordAuthentication no\n")...)
		}
		if err := os.WriteFile("/etc/ssh/sshd_config", newCfg, 0644); err != nil {
			log.Printf("⚠️ Failed to write /etc/ssh/sshd_config: %v\n", err)
		} else {
			mainCfgModified = true
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
		run("systemctl", "restart", "ssh")
	}
}

func disableSSHSocket() {
	_ = os.Remove("/etc/systemd/system/ssh.socket.d/listen.conf")
	_ = os.Remove("/etc/systemd/system/ssh.socket.d/override.conf")
	run("systemctl", "daemon-reload")
	run("systemctl", "stop", "ssh.socket")
	run("systemctl", "disable", "ssh.socket")
	if err := exec.Command("systemctl", "enable", "--now", "sshd").Run(); err != nil {
		run("systemctl", "enable", "--now", "ssh")
	}
}

