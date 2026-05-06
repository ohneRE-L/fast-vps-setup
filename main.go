//go:build linux
// +build linux

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
		return "<IP_СЕРВЕРА>"
	}
	return res
}

func main() {
	if os.Getuid() != 0 {
		log.Fatalf("Ошибка: запустите скрипт от имени root (sudo)")
	}

	reader := bufio.NewReader(os.Stdin)
	changeSSHPortChoice := askYesNo("Изменить порт SSH?", reader)
	sshPort := "22"
	if changeSSHPortChoice {
		fmt.Print("👉 Введите новый порт для SSH (например, 9049): ")
		input, _ := reader.ReadString('\n')
		sshPort = strings.TrimSpace(input)
		if sshPort == "" {
			log.Fatal("Порт не может быть пустым")
		}
	}

	configureUFWChoice := askYesNo("Настроить Firewall (UFW)?", reader)
	install3xUI := askYesNo("Установить 3x-ui?", reader)
	installTelemtChoice := askYesNo("Установить telemt?", reader)
	installWarpWatchdogChoice := askYesNo("Установить WARP watchdog?", reader)
	enableBBRChoice := askYesNo("Включить BBR (ускорение сети)?", reader)
	installFail2BanChoice := askYesNo("Установить Fail2Ban (защита от брутфорса)?", reader)

	secretPath := generateRandomString(12)
	adminUser := generateRandomString(8)
	adminPass := generateRandomString(14)

	fmt.Println("\n[1/6] 🛠 Обновление системы...")
	os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	run("apt-get", "update")
	run("apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade")

	fmt.Println("\n[2/6] 🚀 Настройка лимитов...")
	setUlimits()

	if enableBBRChoice {
		fmt.Println("\n[2.5/6] ⚡️ Включение BBR...")
		enableBBR()
	}

	if changeSSHPortChoice {
		fmt.Println("\n[3/6] 🔒 Смена порта SSH на", sshPort)
		applySSHPort(sshPort)
	}

	if configureUFWChoice {
		fmt.Println("\n[4/6] 🧱 Настройка Firewall...")
		configureUFW(sshPort)
	}

	if installFail2BanChoice {
		fmt.Println("\n[4.5/6] 🛡 Установка Fail2Ban...")
		installFail2Ban()
	}

	if install3xUI {
		fmt.Println("\n[5/6] 📥 Установка 3x-ui...")
		install3xUIOfficial()
	}

	if installTelemtChoice {
		fmt.Println("\n[5.5/6] 📥 Установка telemt...")
		installTelemt()
	}

	if install3xUI {
		fmt.Println("\n[6/6] ⚙️ Финализация настроек...")
		finalConfig(adminUser, adminPass, secretPath)
	}

	if installWarpWatchdogChoice {
		fmt.Println("\n[6.5/6] 🛡 Настройка WARP Watchdog...")
		setupWarpWatchdog()
	}

	ip := getIP()
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("✅ УСТАНОВКА ЗАВЕРШЕНА!")
	fmt.Println(strings.Repeat("=", 50))
	if install3xUI {
		fmt.Printf("🌐 Ссылка: http://%s:3/%s/\n", ip, secretPath)
		fmt.Printf("👤 Логин:  %s\n", adminUser)
		fmt.Printf("🔑 Пароль: %s\n", adminPass)
		fmt.Println(strings.Repeat("-", 50))
	}
	fmt.Printf("📡 SSH порт: %s\n", sshPort)
	fmt.Println(strings.Repeat("=", 50))
	if install3xUI {
		fmt.Println("Команда 'x-ui' доступна в консоли.")
	}
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
		fmt.Println("Пожалуйста, введите 'y' или 'n'")
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
		defer f.Close()
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
	run("ufw", "deny", "9000")
	run("ufw", "deny", "40000")
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
		defer f.Close()
		_, _ = f.WriteString("\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n")
	}
	run("sysctl", "-p")
}

func installFail2Ban() {
	run("apt-get", "install", "-y", "fail2ban")
	run("systemctl", "enable", "fail2ban")
	run("systemctl", "start", "fail2ban")
}
