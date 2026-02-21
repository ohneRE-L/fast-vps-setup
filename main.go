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

// === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

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

// === ОСНОВНЫЕ ШАГИ ===

func main() {
	if os.Getuid() != 0 {
		log.Fatalf("Ошибка: запустите скрипт от имени root (sudo)")
	}

	// 1. Запрос порта SSH
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("👉 Введите новый порт для SSH (например, 9049): ")
	sshPort, _ := reader.ReadString('\n')
	sshPort = strings.TrimSpace(sshPort)
	if sshPort == "" {
		log.Fatal("Порт не может быть пустым")
	}

	// Данные для безопасности
	secretPath := generateRandomString(12)
	adminUser := generateRandomString(8)
	adminPass := generateRandomString(14)

	fmt.Println("\n[1/6] 🛠 Обновление системы (apt update & upgrade)...")
	os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	run("apt-get", "update")
	run("apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade")

	fmt.Println("\n[2/6] 🚀 Настройка лимитов (ulimit -n 65535)...")
	setUlimits()

	fmt.Println("\n[3/6] 🔒 Смена порта SSH на", sshPort)
	applySSHPort(sshPort)

	fmt.Println("\n[4/6] 🧱 Настройка Firewall (UFW)...")
	configureUFW(sshPort)

	fmt.Println("\n[5/6] 📥 Установка 3x-ui через официальный скрипт...")
	install3xUIOfficial(adminUser, adminPass, secretPath)

	fmt.Println("\n[6/6] ⚙️ Финализация настроек...")
	finalConfig(adminUser, adminPass, secretPath)

	// ВЫВОД РЕЗУЛЬТАТОВ
	ip := getIP()
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("✅ УСТАНОВКА ЗАВЕРШЕНА!")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("🌐 Ссылка: http://%s:3/%s/\n", ip, secretPath)
	fmt.Printf("👤 Логин:  %s\n", adminUser)
	fmt.Printf("🔑 Пароль: %s\n", adminPass)
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("📡 Новый SSH порт: %s\n", sshPort)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("⚠️ Заходить ТОЛЬКО по полной ссылке!")
	fmt.Println("Команда 'x-ui' доступна в консоли.")
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

	// Ubuntu 22.10+ (ssh.socket)
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
	run("ufw", "allow", sshPort+"/tcp")
	run("ufw", "allow", "3/tcp")
	run("ufw", "allow", "80/tcp")
	run("ufw", "allow", "443/tcp")
	run("ufw", "allow", "2053/tcp")
	run("ufw", "--force", "enable")
}

func install3xUIOfficial(user, pass, path string) {
	// Официальная команда, которую вы просили.
	// Мы передаем ответы через Stdin:
	// y (customize) -> user -> pass -> 3 (port) -> /path/ (web base path)
	installCmd := `bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)`

	// Подготовка ответов для скрипта (y - да, кастомизировать)
	answers := fmt.Sprintf("y\n%s\n%s\n3\n/%s/\n", user, pass, path)

	cmd := exec.Command("bash", "-c", installCmd)
	cmd.Stdin = strings.NewReader(answers)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func finalConfig(user, pass, path string) {
	// На случай, если официальный скрипт проигнорировал Stdin (бывает в новых версиях),
	// принудительно выставляем настройки через CLI утилиту x-ui.
	time.Sleep(2 * time.Second)
	fullPath := "/" + path + "/"
	_ = exec.Command("/usr/local/x-ui/x-ui", "setting", "-username", user, "-password", pass, "-port", "3", "-webBasePath", fullPath).Run()

	// Создаем симлинк для команды x-ui, если скрипт его не создал
	_ = os.Remove("/usr/bin/x-ui")
	_ = runCommand("ln", "-s", "/usr/local/x-ui/x-ui.sh", "/usr/bin/x-ui")

	run("systemctl", "restart", "x-ui")
	run("hash", "-r")
}

func runCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
