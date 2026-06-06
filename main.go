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
	"strings"
	"syscall"
	"time"
)

type Messages struct {
	LangSelect       string
	RootRequired     string
	SSHPortPrompt    string
	SSHPortEmpty     string
	ChangeSSH        string
	SetupUFW         string
	Install3xUI      string
	InstallTelemt    string
	InstallWarp      string
	EnableBBR        string
	InstallF2B       string
	SystemUpdate     string
	Ulimits          string
	SSHChange        string
	UFWSetup         string
	Installing3x     string
	InstallingTelemt string
	InstallingWarp   string
	InstallingBBR    string
	InstallingF2B    string
	Finalizing       string
	Success          string
	URL              string
	Login            string
	Password         string
	SSHPort          string
	XUICommand       string
	SetupDNS         string
	InstallingDNS    string
	SetupSSHKey      string
	EnterSSHKey      string
	InstallingSSHKey string
	SSHKeyEmpty      string
}

var ruMsgs = Messages{
	LangSelect:       "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	RootRequired:     "Ошибка: запустите скрипт от имени root (sudo)",
	SSHPortPrompt:    "👉 Введите новый порт для SSH (например, 9049): ",
	SSHPortEmpty:     "Порт не может быть пустым",
	ChangeSSH:        "Изменить порт SSH?",
	SetupUFW:         "Настроить Firewall (UFW)?",
	Install3xUI:      "Установить 3x-ui?",
	InstallTelemt:    "Установить telemt?",
	InstallWarp:      "Установить WARP watchdog?",
	EnableBBR:        "Включить BBR (ускорение сети)?",
	InstallF2B:       "Установить Fail2Ban (защита от брутфорса)?",
	SystemUpdate:     "[1/6] 🛠 Обновление системы...",
	Ulimits:          "[2/6] 🚀 Настройка лимитов...",
	SSHChange:        "[3/6] 🔒 Смена порта SSH на ",
	UFWSetup:         "[4/6] 🧱 Настройка Firewall...",
	Installing3x:     "[5/6] 📥 Установка 3x-ui...",
	InstallingTelemt: "[5.5/6] 📥 Установка telemt...",
	InstallingWarp:   "[6.5/6] 🛡 Настройка WARP Watchdog...",
	InstallingBBR:    "[2.5/6] ⚡️ Включение BBR...",
	InstallingF2B:    "[4.5/6] 🛡 Установка Fail2Ban...",
	Finalizing:       "[6/6] ⚙️ Финализация настроек...",
	Success:          "✅ УСТАНОВКА ЗАВЕРШЕНА!",
	URL:              "🌐 Ссылка",
	Login:            "👤 Логин",
	Password:         "🔑 Пароль",
	SSHPort:          "📡 SSH порт",
	XUICommand:       "Команда 'x-ui' доступна в консоли.",
	SetupDNS:         "Настроить DNS (Cloudflare 1.1.1.1)?",
	InstallingDNS:    "[3.5/6] 🌐 Настройка DNS (Cloudflare)...",
	SetupSSHKey:      "Добавить SSH-ключ (и отключить пароли)?",
	EnterSSHKey:      "👉 Если у вас нет ключа, откройте новый терминал на вашем ПК и введите 'ssh-keygen -t ed25519'.\n👉 Затем скопируйте содержимое файла (обычно ~/.ssh/id_ed25519.pub).\n👉 Введите ваш публичный SSH-ключ:\n",
	InstallingSSHKey: "[3.7/6] 🔑 Настройка SSH-ключа...",
	SSHKeyEmpty:      "SSH-ключ не может быть пустым",
}

var enMsgs = Messages{
	LangSelect:       "👉 Выберите язык / Select language (1: RU, 2: EN): ",
	RootRequired:     "Error: run the script as root (sudo)",
	SSHPortPrompt:    "👉 Enter new SSH port (e.g., 9049): ",
	SSHPortEmpty:     "Port cannot be empty",
	ChangeSSH:        "Change SSH port?",
	SetupUFW:         "Configure Firewall (UFW)?",
	Install3xUI:      "Install 3x-ui?",
	InstallTelemt:    "Install telemt?",
	InstallWarp:      "Install WARP watchdog?",
	EnableBBR:        "Enable BBR (network optimization)?",
	InstallF2B:       "Install Fail2Ban (brute-force protection)?",
	SystemUpdate:     "[1/6] 🛠 System update...",
	Ulimits:          "[2/6] 🚀 Setting limits...",
	SSHChange:        "[3/6] 🔒 Changing SSH port to ",
	UFWSetup:         "[4/6] 🧱 Configuring Firewall...",
	Installing3x:     "[5/6] 📥 Installing 3x-ui...",
	InstallingTelemt: "[5.5/6] 📥 Installing telemt...",
	InstallingWarp:   "[6.5/6] 🛡 Setting up WARP Watchdog...",
	InstallingBBR:    "[2.5/6] ⚡️ Enabling BBR...",
	InstallingF2B:    "[4.5/6] 🛡 Installing Fail2Ban...",
	Finalizing:       "[6/6] ⚙️ Finalizing settings...",
	Success:          "✅ INSTALLATION COMPLETED!",
	URL:              "🌐 URL",
	Login:            "👤 Login",
	Password:         "🔑 Password",
	SSHPort:          "📡 SSH Port",
	XUICommand:       "The 'x-ui' command is available in the console.",
	SetupDNS:         "Configure DNS (Cloudflare 1.1.1.1)?",
	InstallingDNS:    "[3.5/6] 🌐 Configuring DNS (Cloudflare)...",
	SetupSSHKey:      "Add SSH key (and disable passwords)?",
	EnterSSHKey:      "👉 If you don't have a key, open a new terminal on your PC and run 'ssh-keygen -t ed25519'.\n👉 Then copy the contents of the file (usually ~/.ssh/id_ed25519.pub).\n👉 Enter your public SSH key:\n",
	InstallingSSHKey: "[3.7/6] 🔑 Configuring SSH key...",
	SSHKeyEmpty:      "SSH key cannot be empty",
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
	out, _ := exec.Command("curl", "-s", "https://api.ipify.org").Output()
	res := strings.TrimSpace(string(out))
	if res == "" {
		return "<IP_SERVER>"
	}
	return res
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
	if os.Getuid() != 0 {
		log.Fatalf("Error: root required")
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

	changeSSHPortChoice := askYesNo(T.ChangeSSH, reader)
	sshPort := getCurrentSSHPort()
	if changeSSHPortChoice {
		fmt.Print(T.SSHPortPrompt)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			sshPort = input
		}
	}

	setupSSHKeyChoice := askYesNo(T.SetupSSHKey, reader)
	sshKey := ""
	if setupSSHKeyChoice {
		fmt.Print(T.EnterSSHKey)
		input, _ := reader.ReadString('\n')
		sshKey = strings.TrimSpace(input)
		if sshKey == "" {
			log.Fatal(T.SSHKeyEmpty)
		}
	}

	configureUFWChoice := askYesNo(T.SetupUFW, reader)
	install3xUI := askYesNo(T.Install3xUI, reader)
	installTelemtChoice := askYesNo(T.InstallTelemt, reader)
	installWarpWatchdogChoice := askYesNo(T.InstallWarp, reader)
	enableBBRChoice := askYesNo(T.EnableBBR, reader)
	installFail2BanChoice := askYesNo(T.InstallF2B, reader)
	setupDNSChoice := askYesNo(T.SetupDNS, reader)

	secretPath := generateRandomString(12)
	adminUser := generateRandomString(8)
	adminPass := generateRandomString(14)

	fmt.Println("\n" + T.SystemUpdate)
	err := os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	if err != nil {
		return
	}
	run("apt-get", "update")
	run("apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade")

	fmt.Println("\n" + T.Ulimits)
	setUlimits()

	if enableBBRChoice {
		fmt.Println("\n" + T.InstallingBBR)
		enableBBR()
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

	if installFail2BanChoice {
		fmt.Println("\n" + T.InstallingF2B)
		installFail2Ban()
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
}

func setUlimits() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Max = 65535
		rLimit.Cur = 65535
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}
	content := "\n* soft nofile 65535\n* hard nofile 65535\nroot soft nofile 65535\nroot hard nofile 65535\n"
	f, _ := os.OpenFile("/etc/security/limits.conf", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if f != nil {
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {

			}
		}(f)
		_, _ = f.WriteString(content)
	}
}

func applySSHPort(port string) {
	cfg, err := os.ReadFile("/etc/ssh/sshd_config")
	if err == nil {
		re := regexp.MustCompile(`(?m)^#?Port\s+\d+`)
		newCfg := re.ReplaceAll(cfg, []byte("Port "+port))
		_ = os.WriteFile("/etc/ssh/sshd_config", newCfg, 0644)
	}

	out, _ := exec.Command("systemctl", "list-unit-files", "ssh.socket").Output()
	if strings.Contains(string(out), "ssh.socket") {
		_ = os.MkdirAll("/etc/systemd/system/ssh.socket.d", 0755)
		data := fmt.Sprintf("[Socket]\nListenStream=\nListenStream=%s\n", port)
		_ = os.WriteFile("/etc/systemd/system/ssh.socket.d/listen.conf", []byte(data), 0644)
		run("systemctl", "daemon-reload")
		run("systemctl", "restart", "ssh.socket")
	}

	if err := exec.Command("systemctl", "restart", "sshd").Run(); err != nil {
		run("systemctl", "restart", "ssh")
	}
}

func configureUFW(sshPort string) {
	run("apt-get", "install", "-y", "ufw")
	run("ufw", "allow", sshPort+"/tcp", "comment", "SSH")
	run("ufw", "allow", "443/tcp", "comment", "VPN")
	run("ufw", "allow", "3/tcp", "comment", "PANEL")
	run("ufw", "allow", "10443/tcp", "comment", "SUBSCRIPTION")
	run("ufw", "allow", "8443/tcp")
	run("ufw", "deny", "9000", "comment", "nginx")
	run("ufw", "deny", "40000", "comment", "warp")
	run("ufw", "--force", "enable")
}

func installTelemt() {
	cmd := `curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- --port 8443`
	run("bash", "-c", cmd)
}

func setupWarpWatchdog() {
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
	time.Sleep(5 * time.Second)
	fullPath := "/" + path + "/"
	_ = exec.Command("/usr/local/x-ui/x-ui", "setting", "-username", user, "-password", pass, "-port", "3", "-webBasePath", fullPath).Run()

	_ = os.Remove("/usr/bin/x-ui")
	_ = exec.Command("ln", "-s", "/usr/local/x-ui/x-ui.sh", "/usr/bin/x-ui").Run()

	run("systemctl", "restart", "x-ui")
	run("hash", "-r")
}

func enableBBR() {
	f, _ := os.OpenFile("/etc/sysctl.conf", os.O_APPEND|os.O_WRONLY, 0644)
	if f != nil {
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {

			}
		}(f)
		_, _ = f.WriteString("\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n")
	}
	run("sysctl", "-p")
}

func installFail2Ban() {
	run("apt-get", "install", "-y", "fail2ban")
	run("systemctl", "enable", "fail2ban")
	run("systemctl", "start", "fail2ban")
}

func setupDNS() {
	config := "[Resolve]\nDNS=1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001\nFallbackDNS=8.8.8.8 8.8.4.4\nDNSStubListener=yes\n"
	_ = os.MkdirAll("/etc/systemd/resolved.conf.d", 0755)
	_ = os.WriteFile("/etc/systemd/resolved.conf.d/dns.conf", []byte(config), 0644)
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
	f, err := os.OpenFile("/root/.ssh/authorized_keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.WriteString(key + "\n")
		f.Close()
	}

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
