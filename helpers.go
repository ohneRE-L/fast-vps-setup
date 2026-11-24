package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reActiveSSHDInclude      = regexp.MustCompile(`(?im)^[\t ]*Include\b.*sshd_config\.d`)
	reActivePortDirective    = regexp.MustCompile(`(?im)^[\t ]*Port\b.*$`)
	reAnyPortDirective       = regexp.MustCompile(`(?im)^[\t ]*#?[\t ]*Port\s+\d+\b.*$`)
	reActivePortValue        = regexp.MustCompile(`(?im)^[\t ]*Port\s+(\d+)\b`)
	reMatchBlock             = regexp.MustCompile(`(?im)^[\t ]*Match\b`)
	reDashWithSpaces         = regexp.MustCompile(`\s*-\s*`)
	reActivePasswordAuthYes  = regexp.MustCompile(`(?im)^[\t ]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication)\s+yes\b`)
	reSSHSocketListenPortEnd = regexp.MustCompile(`(?:^|:)(\d+)$`)
)

var validSSHKeyTypes = map[string]bool{
	"ssh-rsa":                            true,
	"ssh-ed25519":                        true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

func isSSHSocketActive(activeOut, enabledOut string) bool {
	isActive := strings.TrimSpace(activeOut) == "active"
	enState := strings.TrimSpace(enabledOut)
	return isActive || enState == "enabled" || enState == "enabled-runtime"
}

func hasActiveSSHDInclude(cfg string) bool {
	globalPart, _, _ := splitAtFirstMatch(cfg)
	return reActiveSSHDInclude.MatchString(globalPart)
}

func splitAtFirstMatch(cfg string) (globalPart, matchPart string, hasMatch bool) {
	loc := reMatchBlock.FindStringIndex(cfg)
	if loc == nil {
		return cfg, "", false
	}
	return cfg[:loc[0]], cfg[loc[0]:], true
}

func appendGlobalDirective(globalPart, directiveLine string) string {
	if globalPart == "" {
		return directiveLine + "\n"
	}
	if !strings.HasSuffix(globalPart, "\n") {
		globalPart += "\n"
	}
	return globalPart + directiveLine + "\n"
}

func commentActivePorts(cfg string) (string, bool) {
	if !reActivePortDirective.MatchString(cfg) {
		return cfg, false
	}
	updated := reActivePortDirective.ReplaceAllStringFunc(cfg, func(line string) string {
		return "#" + line
	})
	return updated, updated != cfg
}

func updateSSHDConfigPort(cfg, port string) string {
	globalPart, matchPart, hasMatch := splitAtFirstMatch(cfg)

	reActive := regexp.MustCompile(`(?im)^[\t ]*Port\s+\d+\b.*$`)
	if reActive.MatchString(globalPart) {
		replaced := false
		globalPart = reActive.ReplaceAllStringFunc(globalPart, func(line string) string {
			if !replaced {
				replaced = true
				return "Port " + port
			}
			return "#" + line
		})
	} else if reAnyPortDirective.MatchString(globalPart) {
		replaced := false
		globalPart = reAnyPortDirective.ReplaceAllStringFunc(globalPart, func(line string) string {
			if !replaced {
				replaced = true
				return "Port " + port
			}
			return line
		})
	} else {
		globalPart = appendGlobalDirective(globalPart, "Port "+port)
	}

	if hasMatch {
		if globalPart != "" && !strings.HasSuffix(globalPart, "\n") {
			globalPart += "\n"
		}
		return globalPart + matchPart
	}
	return globalPart
}

func setGlobalDirectiveNo(globalPart, directive string) string {
	reActive := regexp.MustCompile(`(?im)^[\t ]*` + regexp.QuoteMeta(directive) + `\s+(?:yes|no)\b.*$`)
	if reActive.MatchString(globalPart) {
		replaced := false
		return reActive.ReplaceAllStringFunc(globalPart, func(line string) string {
			if !replaced {
				replaced = true
				return directive + " no"
			}
			return "#" + line
		})
	}

	reAny := regexp.MustCompile(`(?im)^[\t ]*#?[\t ]*` + regexp.QuoteMeta(directive) + `\s+(?:yes|no)\b.*$`)
	if reAny.MatchString(globalPart) {
		replaced := false
		return reAny.ReplaceAllStringFunc(globalPart, func(line string) string {
			if !replaced {
				replaced = true
				return directive + " no"
			}
			return line
		})
	}

	return appendGlobalDirective(globalPart, directive+" no")
}

func updateLegacySSHDPasswordAuth(cfg string, useKbdInteractive bool) string {
	globalPart, matchPart, hasMatch := splitAtFirstMatch(cfg)

	globalPart = setGlobalDirectiveNo(globalPart, "PasswordAuthentication")
	if useKbdInteractive {
		globalPart = setGlobalDirectiveNo(globalPart, "KbdInteractiveAuthentication")
		reActiveChallenge := regexp.MustCompile(`(?im)^[\t ]*ChallengeResponseAuthentication\s+yes\b.*$`)
		globalPart = reActiveChallenge.ReplaceAllString(globalPart, "ChallengeResponseAuthentication no")
	} else {
		reActiveKbd := regexp.MustCompile(`(?im)^[\t ]*KbdInteractiveAuthentication\b.*$`)
		globalPart = reActiveKbd.ReplaceAllStringFunc(globalPart, func(line string) string {
			return "#" + line
		})
		globalPart = setGlobalDirectiveNo(globalPart, "ChallengeResponseAuthentication")
	}

	if hasMatch {
		if globalPart != "" && !strings.HasSuffix(globalPart, "\n") {
			globalPart += "\n"
		}
		return globalPart + matchPart
	}
	return globalPart
}

func hasPasswordAuthBeforeInclude(cfg string) bool {
	globalPart, _, _ := splitAtFirstMatch(cfg)
	includeLoc := reActiveSSHDInclude.FindStringIndex(globalPart)
	if includeLoc == nil {
		return false
	}
	beforeInclude := globalPart[:includeLoc[0]]
	return reActivePasswordAuthYes.MatchString(beforeInclude)
}

func parseSSHPortFromConfig(cfg string) string {
	if match := reActivePortValue.FindStringSubmatch(cfg); len(match) > 1 {
		if isValidPort(match[1]) {
			port, _ := strconv.Atoi(match[1])
			return strconv.Itoa(port)
		}
	}
	return ""
}

func parseSSHSocketListenPort(showOutput string) string {
	for _, line := range strings.Split(showOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		for _, field := range fields {
			if match := reSSHSocketListenPortEnd.FindStringSubmatch(field); len(match) > 1 {
				if isValidPort(match[1]) {
					port, _ := strconv.Atoi(match[1])
					return strconv.Itoa(port)
				}
			}
		}
	}
	return ""
}

func parseSSHSocketDropInPort(confContent string) string {
	port := ""
	for _, rawLine := range strings.Split(confContent, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eqIdx])
		if !strings.EqualFold(key, "ListenStream") {
			continue
		}
		val := strings.TrimSpace(line[eqIdx+1:])
		if val == "" {
			port = ""
			continue
		}
		if idx := strings.LastIndexByte(val, ':'); idx >= 0 {
			val = val[idx+1:]
		}
		if isValidPort(val) {
			p, _ := strconv.Atoi(val)
			port = strconv.Itoa(p)
		}
	}
	return port
}

func generateRandomString(n int) (string, error) {
	if n < 0 {
		return "", fmt.Errorf("invalid random string length: %d", n)
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	max := big.NewInt(int64(len(letters)))
	ret := make([]byte, n)
	for i := range ret {
		num, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("crypto/rand failed: %w", err)
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret), nil
}

func getIP() string {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	client := &http.Client{Timeout: 3 * time.Second}
	for _, s := range services {
		resp, err := client.Get(s)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		res := strings.TrimSpace(string(body))
		if ip := net.ParseIP(res); ip != nil {
			return ip.String()
		}
	}
	return "<IP_SERVER>"
}

func formatPanelURL(ip, secretPath string) string {
	return fmt.Sprintf("http://%s/%s/", net.JoinHostPort(ip, "3"), secretPath)
}

func isValidPort(p string) bool {
	if p == "" {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}

func isValidSSHPublicKey(k string) bool {
	k = strings.Trim(k, " \t")
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		b := k[i]
		if b == '\r' || b == '\n' || (b < 0x20 && b != '\t') || b == 0x7f {
			return false
		}
	}

	parts := strings.Fields(k)
	if len(parts) < 2 {
		return false
	}
	keyType := parts[0]
	if !validSSHKeyTypes[keyType] {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(decoded) < 4 {
		return false
	}

	algoLen := int(binary.BigEndian.Uint32(decoded[:4]))
	if algoLen <= 0 || uint64(algoLen) >= uint64(len(decoded)-4) {
		return false
	}
	return string(decoded[4:4+algoLen]) == keyType
}

func hasAuthorizedKey(authKeysContent, key string) bool {
	targetParts := strings.Fields(strings.TrimSpace(key))
	if len(targetParts) < 2 || !validSSHKeyTypes[targetParts[0]] {
		return false
	}
	targetType, targetBlob := targetParts[0], targetParts[1]

	for _, rawLine := range strings.Split(authKeysContent, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == targetType && fields[1] == targetBlob {
			return true
		}
	}
	return false
}

func parsePositiveIntASCII(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseSelection(input string, maxOption int) (map[string]bool, bool) {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "0" || input == "" {
		return nil, false
	}
	res := make(map[string]bool)
	if input == "all" {
		for i := 1; i <= maxOption; i++ {
			res[strconv.Itoa(i)] = true
		}
		return res, true
	}

	normalized := reDashWithSpaces.ReplaceAllString(input, "-")
	tokens := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})

	for _, token := range tokens {
		if strings.Contains(token, "-") {
			parts := strings.Split(token, "-")
			if len(parts) != 2 {
				return nil, false
			}
			start, ok1 := parsePositiveIntASCII(parts[0])
			end, ok2 := parsePositiveIntASCII(parts[1])
			if !ok1 || !ok2 || start > end || start < 1 || end > maxOption {
				return nil, false
			}
			for i := start; i <= end; i++ {
				res[strconv.Itoa(i)] = true
			}
		} else {
			val, ok := parsePositiveIntASCII(token)
			if !ok || val < 1 || val > maxOption {
				return nil, false
			}
			res[strconv.Itoa(val)] = true
		}
	}

	if len(res) == 0 {
		return nil, false
	}
	return res, true
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF && len(line) > 0 {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func hasZramContent(content string) bool {
	return strings.Contains(content, "/dev/zram")
}

func hasFstabSwapEntry(fstabContent string) bool {
	for _, rawLine := range strings.Split(fstabContent, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] == "/swapfile" {
			return true
		}
	}
	return false
}

func ensureFstabSwapContent(fstabContent string) (string, bool) {
	if hasFstabSwapEntry(fstabContent) {
		return fstabContent, false
	}
	if fstabContent != "" && !strings.HasSuffix(fstabContent, "\n") {
		fstabContent += "\n"
	}
	return fstabContent + "/swapfile none swap sw 0 0\n", true
}

func isValidScriptContent(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && bytes.HasPrefix(trimmed, []byte("#!"))
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
