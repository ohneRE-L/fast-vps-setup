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
	out, err := exec.Command("curl", "-s", "https://api.ipify.org").Output()
	if err != nil {
		return "<IP_СЕРВЕРА>"
	}
	return strings.TrimSpace(string(out))
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

	// Генерация данных для панели
	secretPath := generateRandomString(12)
	adminUser := generateRandomString(8)
	adminPass := generateRandomString(14)

	fmt.Println("\n[1/7] 🛠 Обновление системы (apt update & upgrade)...")
	os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	run("apt-get", "update")
	run("apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade")

	fmt.Println("\n[2/7] 🚀 Настройка лимитов (ulimit -n 65535)...")
	setUlimits()

	fmt.Println("\n[3/7] 🔒 Смена порта SSH на", sshPort)
	applySSHPort(sshPort)

	fmt.Println("\n[4/7] 🧱 Настройка Firewall (UFW)...")
	configureUFW(sshPort)

	fmt.Println("\n[5/7] 📥 Установка 3x-ui (прямая загрузка)...")
	install3xUI()

	fmt.Println("\n[6/7] ⚙️ Применение случайных настроек безопасности...")
	applyPanelSettings(secretPath, adminUser, adminPass)

	fmt.Println("\n[7/7] 🧹 Финальная проверка путей...")
	finalSymlinks()

	// ВЫВОД РЕЗУЛЬТАТОВ
	ip := getIP()
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("✅ УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("🌐 Ссылка: http://%s:3/%s/\n", ip, secretPath)
	fmt.Printf("👤 Логин:  %s\n", adminUser)
	fmt.Printf("🔑 Пароль: %s\n", adminPass)
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("📡 Новый SSH порт: %s\n", sshPort)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("⚠️ Заходить ТОЛЬКО по полной ссылке (иначе 404)!")
	fmt.Println("Команда 'x-ui' теперь доступна в консоли.")
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
	defer f.Close()
	_, _ = f.WriteString(content)
}

func applySSHPort(port string) {
	// Редактируем стандартный конфиг
	cfg, _ := os.ReadFile("/etc/ssh/sshd_config")
	re := regexp.MustCompile(`(?m)^#?Port\s+\d+`)
	newCfg := re.ReplaceAll(cfg, []byte("Port "+port))
	_ = os.WriteFile("/etc/ssh/sshd_config", newCfg, 0644)

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

func install3xUI() {
	// Получаем архитектуру и версию
	cmd := exec.Command("bash", "-c", `curl -s https://api.github.com/repos/mhsanaei/3x-ui/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'`)
	tagOut, _ := cmd.Output()
	tag := strings.TrimSpace(string(tagOut))
	if tag == "" {
		tag = "v2.4.3"
	}

	arch := "amd64"
	uOut, _ := exec.Command("uname", "-m").Output()
	if strings.Contains(string(uOut), "arm") || strings.Contains(string(uOut), "aarch64") {
		arch = "arm64"
	}

	url := fmt.Sprintf("https://github.com/mhsanaei/3x-ui/releases/download/%s/x-ui-linux-%s.tar.gz", tag, arch)
	run("curl", "-L", "-o", "/tmp/x-ui.tar.gz", url)
	run("rm", "-rf", "/usr/local/x-ui")
	run("tar", "-zxf", "/tmp/x-ui.tar.gz", "-C", "/usr/local/")

	run("chmod", "+x", "/usr/local/x-ui/x-ui", "/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/x-ui.sh")
	run("cp", "-f", "/usr/local/x-ui/x-ui.service.debian", "/etc/systemd/system/x-ui.service")
	run("systemctl", "daemon-reload")
	run("systemctl", "enable", "x-ui")
	run("systemctl", "start", "x-ui")
}

func applyPanelSettings(path, user, pass string) {
	time.Sleep(3 * time.Second)
	fullPath := "/" + path + "/"
	// Используем внутренний CLI x-ui для настройки
	_ = exec.Command("/usr/local/x-ui/x-ui", "setting", "-username", user, "-password", pass, "-port", "3", "-webBasePath", fullPath).Run()
	run("systemctl", "restart", "x-ui")
}

func finalSymlinks() {
	// Создаем ссылки, чтобы команда x-ui работала везде
	_ = os.Remove("/usr/bin/x-ui")
	_ = os.Remove("/usr/local/bin/x-ui")
	run("ln", "-s", "/usr/local/x-ui/x-ui.sh", "/usr/bin/x-ui")
	run("ln", "-s", "/usr/local/x-ui/x-ui.sh", "/usr/local/bin/x-ui")
	run("hash", "-r")
}
