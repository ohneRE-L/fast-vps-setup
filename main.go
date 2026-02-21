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

// ensureSelfExecutable устанавливает права chmod +x на сам файл скрипта
func ensureSelfExecutable() {
	filePath := "/root/setup_server"
	if _, err := os.Stat(filePath); err == nil {
		_ = os.Chmod(filePath, 0755)
	}
}

// Генерация случайной строки заданной длины
func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, n)
	for i := range ret {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func main() {
	if os.Getuid() != 0 {
		log.Fatalf("Ошибка: Скрипт должен быть запущен с правами root (sudo)")
	}

	ensureSelfExecutable()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введите новый порт для SSH (например, 2222): ")
	sshPortStr, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Ошибка при вводе порта: %v", err)
	}
	sshPortStr = strings.TrimSpace(sshPortStr)
	if sshPortStr == "" {
		log.Fatalf("Ошибка: Порт не может быть пустым")
	}

	// Генерируем все случайные данные для безопасности
	secretPath := generateRandomString(12) // Секретный путь URL
	adminUser := generateRandomString(8)   // Рандомный логин
	adminPass := generateRandomString(14)  // Рандомный пароль

	fmt.Printf("\n[1/6] Обновление системы (apt update && upgrade)...\n")
	updateSystem()

	fmt.Printf("\n[2/6] Настройка лимитов открытых файлов (65535)...\n")
	setUlimit()

	fmt.Printf("\n[3/6] Смена порта SSH на %s...\n", sshPortStr)
	changeSSHPort(sshPortStr)

	fmt.Printf("\n[4/6] Настройка Firewall (UFW) + порты 3, 80, 443, 2053...\n")
	setupFirewall(sshPortStr)

	fmt.Printf("\n[5/6] Прямая установка панели 3x-ui...\n")
	install3xUIManual()

	fmt.Printf("\n[6/6] Установка секретных настроек (порт 3, логин, пароль, путь)...\n")
	configure3xUI(secretPath, adminUser, adminPass)

	serverIP := getIP()
	fmt.Println("\n✅ Все операции абсолютно успешно завершены!")
	fmt.Printf("\n--------------------------------------------------\n")
	fmt.Printf("🚀 ДАННЫЕ ДЛЯ ВХОДА В ПАНЕЛЬ:\n")
	fmt.Printf("--------------------------------------------------\n")
	fmt.Printf("🔗 Ссылка: http%s//%s:3/%s/\n", ":", serverIP, secretPath)
	fmt.Printf("👤 Логин:  %s\n", adminUser)
	fmt.Printf("🔑 Пароль: %s\n", adminPass)
	fmt.Printf("--------------------------------------------------\n")
	fmt.Printf("\n⚠️ ВНИМАНИЕ: Обязательно сохраните эти данные!\n")
	fmt.Printf("⚠️ Просто по http://%s:3 зайти нельзя (будет 404).\n", serverIP)
	fmt.Printf("⚠️ Новый SSH порт: %s\n\n", sshPortStr)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func getIP() string {
	out, err := exec.Command("curl", "-s", "https://api.ipify.org").Output()
	if err != nil {
		return "<IP_сервера>"
	}
	return strings.TrimSpace(string(out))
}

func updateSystem() {
	_ = runCommand("apt-get", "update")
	cmd := exec.Command("apt-get", "upgrade", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	_ = cmd.Run()
}

func setUlimit() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Max = 65535
		rLimit.Cur = 65535
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}
	f, err := os.OpenFile("/etc/security/limits.conf", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString("\n* soft nofile 65535\n* hard nofile 65535\nroot soft nofile 65535\nroot hard nofile 65535\n")
	}
}

func changeSSHPort(port string) {
	config, err := os.ReadFile("/etc/ssh/sshd_config")
	if err == nil {
		re := regexp.MustCompile(`(?m)^#?Port\s+\d+`)
		newConfig := re.ReplaceAll(config, []byte("Port "+port))
		_ = os.WriteFile("/etc/ssh/sshd_config", newConfig, 0644)
	}
	out, _ := exec.Command("systemctl", "list-unit-files", "ssh.socket").Output()
	if strings.Contains(string(out), "ssh.socket") {
		_ = os.MkdirAll("/etc/systemd/system/ssh.socket.d", 0755)
		override := fmt.Sprintf("[Socket]\nListenStream=\nListenStream=%s\n", port)
		_ = os.WriteFile("/etc/systemd/system/ssh.socket.d/listen.conf", []byte(override), 0644)
		_ = runCommand("systemctl", "daemon-reload")
		_ = runCommand("systemctl", "restart", "ssh.socket")
	}
	if err := runCommand("systemctl", "restart", "sshd"); err != nil {
		_ = runCommand("systemctl", "restart", "ssh")
	}
}

func setupFirewall(sshPort string) {
	_ = runCommand("apt-get", "install", "-y", "ufw")
	_ = runCommand("ufw", "allow", sshPort+"/tcp")
	_ = runCommand("ufw", "allow", "3/tcp")
	_ = runCommand("ufw", "allow", "80/tcp")
	_ = runCommand("ufw", "allow", "443/tcp")
	_ = runCommand("ufw", "allow", "2053/tcp")
	_ = exec.Command("ufw", "--force", "enable").Run()
}

func install3xUIManual() {
	cmd := exec.Command("bash", "-c", `curl -s https://api.github.com/repos/mhsanaei/3x-ui/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'`)
	out, _ := cmd.Output()
	tag := strings.TrimSpace(string(out))
	if tag == "" {
		tag = "v2.4.3"
	}

	url := fmt.Sprintf("https://github.com/mhsanaei/3x-ui/releases/download/%s/x-ui-linux-amd64.tar.gz", tag)
	_ = runCommand("curl", "-L", "-o", "/tmp/x-ui.tar.gz", url)
	_ = runCommand("rm", "-rf", "/usr/local/x-ui")
	_ = runCommand("tar", "-zxf", "/tmp/x-ui.tar.gz", "-C", "/usr/local/")

	_ = runCommand("chmod", "+x", "/usr/local/x-ui/x-ui", "/usr/local/x-ui/bin/xray-linux-amd64")
	_ = runCommand("cp", "/usr/local/x-ui/x-ui.service.debian", "/etc/systemd/system/x-ui.service")
	_ = runCommand("systemctl", "daemon-reload")
	_ = runCommand("systemctl", "enable", "x-ui")
	_ = runCommand("systemctl", "start", "x-ui")
}

func configure3xUI(path, user, pass string) {
	time.Sleep(3 * time.Second)
	fullPath := "/" + path + "/"
	// Установка случайных пользователя, пароля и пути
	_ = runCommand("/usr/local/x-ui/x-ui", "setting", "-username", user, "-password", pass, "-port", "3", "-webBasePath", fullPath)
	_ = runCommand("systemctl", "restart", "x-ui")
}
