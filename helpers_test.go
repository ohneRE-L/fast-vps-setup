package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func makeWireSSHKey(wireAlgo, textType, comment string, payload []byte) string {
	var raw []byte
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(wireAlgo)))
	raw = append(raw, lenBuf...)
	raw = append(raw, []byte(wireAlgo)...)
	raw = append(raw, payload...)
	b64 := base64.StdEncoding.EncodeToString(raw)
	if comment != "" {
		return textType + " " + b64 + " " + comment
	}
	return textType + " " + b64
}

func TestIsSSHSocketActive(t *testing.T) {
	tests := []struct {
		name       string
		activeOut  string
		enabledOut string
		want       bool
	}{
		{"inactive and disabled", "inactive\n", "disabled\n", false},
		{"inactive and static", "inactive\n", "static\n", false},
		{"activating only", "activating\n", "disabled\n", false},
		{"active", "active\n", "disabled\n", true},
		{"enabled", "inactive\n", "enabled\n", true},
		{"enabled-runtime", "inactive\n", "enabled-runtime\n", true},
		{"both active and enabled", "active\n", "enabled\n", true},
		{"empty outputs", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSSHSocketActive(tt.activeOut, tt.enabledOut); got != tt.want {
				t.Fatalf("isSSHSocketActive(%q, %q) = %v, want %v", tt.activeOut, tt.enabledOut, got, tt.want)
			}
		})
	}
}

func TestHasActiveSSHDInclude(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		want bool
	}{
		{"active include", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n", true},
		{"indented lowercase include", "  include /etc/ssh/sshd_config.d/*.conf\n", true},
		{"commented include", "#Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n", false},
		{"spaced commented include", "  # Include /etc/ssh/sshd_config.d/*.conf\n", false},
		{"no include", "Port 22\nPasswordAuthentication yes\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasActiveSSHDInclude(tt.cfg); got != tt.want {
				t.Fatalf("hasActiveSSHDInclude() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommentActivePorts(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        string
		wantChanged bool
	}{
		{
			name:        "standard Port 22",
			input:       "Port 22\nPasswordAuthentication yes\n",
			want:        "#Port 22\nPasswordAuthentication yes\n",
			wantChanged: true,
		},
		{
			name:        "Port with tabs and spaces and lowercase",
			input:       "\tport  22\n#Port 2222\n",
			want:        "#\tport  22\n#Port 2222\n",
			wantChanged: true,
		},
		{
			name:        "already commented Port only",
			input:       "#Port 22\n# Port 22\n",
			want:        "#Port 22\n# Port 22\n",
			wantChanged: false,
		},
		{
			name:        "PortForwarding untouched",
			input:       "PortForwarding yes\n",
			want:        "PortForwarding yes\n",
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := commentActivePorts(tt.input)
			if changed != tt.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, tt.wantChanged)
			}
			if got != tt.want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestUpdateSSHDConfigPort(t *testing.T) {
	tests := []struct {
		name  string
		input string
		port  string
		want  string
	}{
		{
			name:  "commented Port replaced",
			input: "#Port 22\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
			port:  "2222",
			want:  "Port 2222\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
		},
		{
			name:  "Port 222 replaced with 2222 without substring bug",
			input: "Port 222\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
			port:  "2222",
			want:  "Port 2222\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
		},
		{
			name:  "multiple active ports replaces first and comments second",
			input: "Port 22\nPort 222\n",
			port:  "9049",
			want:  "Port 9049\n#Port 222\n",
		},
		{
			name:  "missing Port inserted before Match block",
			input: "PermitRootLogin yes\nMatch User deploy\n\tX11Forwarding no\n",
			port:  "2222",
			want:  "PermitRootLogin yes\nPort 2222\nMatch User deploy\n\tX11Forwarding no\n",
		},
		{
			name:  "missing Port appended when no Match block",
			input: "PermitRootLogin yes\n",
			port:  "2222",
			want:  "PermitRootLogin yes\nPort 2222\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := updateSSHDConfigPort(tt.input, tt.port)
			if got != tt.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, tt.want)
			}
		})
	}
}

func TestUpdateLegacySSHDPasswordAuth(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		useKbdInteractive bool
		wantContains      []string
		wantNotContains   []string
		checkBeforeMatch  bool
	}{
		{
			name:              "commented and active directives before Match",
			input:             "# PasswordAuthentication yes\nChallengeResponseAuthentication yes\nMatch User deploy\n\tPasswordAuthentication yes\n",
			useKbdInteractive: true,
			wantContains:      []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no", "ChallengeResponseAuthentication no"},
			checkBeforeMatch:  true,
		},
		{
			name:              "Debian 11 ChallengeResponseAuthentication fallback",
			input:             "PasswordAuthentication yes\nKbdInteractiveAuthentication no\n",
			useKbdInteractive: false,
			wantContains:      []string{"PasswordAuthentication no", "ChallengeResponseAuthentication no", "#KbdInteractiveAuthentication no"},
		},
		{
			name:              "appends before Match when missing",
			input:             "Port 2222\nMatch Address 10.0.0.0/8\n\tPasswordAuthentication yes\n",
			useKbdInteractive: true,
			wantContains:      []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no"},
			checkBeforeMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := updateLegacySSHDPasswordAuth(tt.input, tt.useKbdInteractive)
			for _, sub := range tt.wantContains {
				if !strings.Contains(got, sub) {
					t.Fatalf("expected %q in:\n%s", sub, got)
				}
			}
			for _, sub := range tt.wantNotContains {
				if strings.Contains(got, sub) {
					t.Fatalf("unexpected %q in:\n%s", sub, got)
				}
			}
			if tt.checkBeforeMatch {
				globalPart, _, hasMatch := splitAtFirstMatch(got)
				if !hasMatch {
					t.Fatalf("expected Match block in:\n%s", got)
				}
				if !strings.Contains(globalPart, "PasswordAuthentication no") {
					t.Fatalf("PasswordAuthentication no was not placed before Match:\n%s", got)
				}
			}
		})
	}
}

func TestHasPasswordAuthBeforeInclude(t *testing.T) {
	if !hasPasswordAuthBeforeInclude("PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n") {
		t.Fatal("expected true when PasswordAuthentication yes precedes Include")
	}
	if hasPasswordAuthBeforeInclude("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n") {
		t.Fatal("expected false when Include precedes PasswordAuthentication yes")
	}
	if hasPasswordAuthBeforeInclude("#PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n") {
		t.Fatal("expected false for commented PasswordAuthentication yes")
	}
}

func TestIsValidSSHPublicKey(t *testing.T) {
	validEd25519 := makeWireSSHKey("ssh-ed25519", "ssh-ed25519", "user@host", make([]byte, 36))
	validRSA := makeWireSSHKey("ssh-rsa", "ssh-rsa", "", make([]byte, 64))
	validSK := makeWireSSHKey("sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519@openssh.com", "yubikey", make([]byte, 40))
	mismatchedWire := makeWireSSHKey("ssh-rsa", "ssh-ed25519", "user@host", make([]byte, 36))
	noPayloadWire := makeWireSSHKey("ssh-ed25519", "ssh-ed25519", "", nil)

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"valid ed25519", validEd25519, true},
		{"valid rsa without comment", validRSA, true},
		{"valid sk-ssh-ed25519", validSK, true},
		{"empty", "", false},
		{"prefix bypass ssh-ed25519foo", "ssh-ed25519foo " + strings.Fields(validEd25519)[1], false},
		{"non-base64 body", "ssh-ed25519 not-base64!!!", false},
		{"wire algorithm mismatch", mismatchedWire, false},
		{"wire header only without key payload", noPayloadWire, false},
		{"newline injection", validEd25519 + "\ncommand=\"id\" " + validRSA, false},
		{"carriage return injection", validEd25519 + "\r", false},
		{"control char injection", validEd25519 + "\x00", false},
		{"missing base64 part", "ssh-ed25519", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidSSHPublicKey(tt.key); got != tt.want {
				t.Fatalf("isValidSSHPublicKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestHasAuthorizedKey(t *testing.T) {
	key1 := makeWireSSHKey("ssh-ed25519", "ssh-ed25519", "laptop", make([]byte, 36))
	key1OtherComment := makeWireSSHKey("ssh-ed25519", "ssh-ed25519", "desktop", make([]byte, 36))

	tests := []struct {
		name    string
		content string
		key     string
		want    bool
	}{
		{"commented out key does not match", "# " + key1 + "\n", key1, false},
		{"restricted command= key does not match", `command="/bin/false" ` + key1 + "\n", key1, false},
		{"unrestricted key matches regardless of comment", key1OtherComment + "\n", key1, true},
		{"empty authorized_keys", "", key1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasAuthorizedKey(tt.content, tt.key); got != tt.want {
				t.Fatalf("hasAuthorizedKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		port string
		want bool
	}{
		{"22", true},
		{"1", true},
		{"65535", true},
		{"0443", true},
		{"0", false},
		{"65536", false},
		{"+22", false},
		{"-22", false},
		{" 22", false},
		{"22 ", false},
		{"abc", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isValidPort(tt.port); got != tt.want {
			t.Errorf("isValidPort(%q) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestParseSelection(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantOK bool
		want   []string
	}{
		{"single", "3", true, []string{"3"}},
		{"comma and range with spaces around dash", "1 - 4, 7, 12", true, []string{"1", "2", "3", "4", "7", "12"}},
		{"all", "ALL", true, []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"}},
		{"exit 0", "0", false, nil},
		{"empty", "   ", false, nil},
		{"out of range", "13", false, nil},
		{"reversed range", "5-2", false, nil},
		{"plus prefix rejected", "+2", false, nil},
		{"trailing dash rejected", "1-", false, nil},
		{"garbage", "abc", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseSelection(tt.input, 12)
			if ok != tt.wantOK {
				t.Fatalf("parseSelection(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok {
				if len(got) != len(tt.want) {
					t.Fatalf("len(got) = %d, want %d (%v)", len(got), len(tt.want), got)
				}
				for _, k := range tt.want {
					if !got[k] {
						t.Fatalf("missing key %q in %v", k, got)
					}
				}
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	s1, err := generateRandomString(14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s1) != 14 {
		t.Fatalf("expected length 14, got %d", len(s1))
	}
	s2, err := generateRandomString(14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s1 == s2 {
		t.Fatalf("expected distinct random strings, got %q twice", s1)
	}
	if _, err := generateRandomString(-1); err == nil {
		t.Fatal("expected error for negative length")
	}
}

func TestFormatPanelURL(t *testing.T) {
	if got := formatPanelURL("203.0.113.10", "abc123"); got != "http://203.0.113.10:3/abc123/" {
		t.Fatalf("unexpected IPv4 URL: %s", got)
	}
	if got := formatPanelURL("2001:db8::1", "abc123"); got != "http://[2001:db8::1]:3/abc123/" {
		t.Fatalf("unexpected IPv6 URL: %s", got)
	}
	if got := formatPanelURL("<IP_SERVER>", "abc123"); got != "http://<IP_SERVER>:3/abc123/" {
		t.Fatalf("unexpected placeholder URL: %s", got)
	}
}

func TestEnsureFstabSwapContent(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantChanged bool
	}{
		{"empty fstab", "", true},
		{"commented /swapfile still adds entry", "# /swapfile none swap sw 0 0\nUUID=123 / ext4 defaults 0 1\n", true},
		{"active /swapfile skips", "UUID=123 / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, changed := ensureFstabSwapContent(tt.input)
			if changed != tt.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, tt.wantChanged)
			}
			if tt.wantChanged && !hasFstabSwapEntry(out) {
				t.Fatalf("expected active /swapfile entry in:\n%s", out)
			}
		})
	}
}

func TestHasZramContent(t *testing.T) {
	if !hasZramContent("Filename\tType\n/dev/zram0\tpartition\n") {
		t.Fatal("expected true for /dev/zram0")
	}
	if hasZramContent("Filename\tType\n/swapfile\tfile\n") {
		t.Fatal("expected false for /swapfile")
	}
	if hasZramContent("/my-zram-backup file\n") {
		t.Fatal("expected false for non-/dev/zram substring")
	}
}

func TestReadLineEOF(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("first\r\nlast_without_newline"))
	line1, err := readLine(r)
	if err != nil || line1 != "first" {
		t.Fatalf("line1 = (%q, %v), want (%q, nil)", line1, err, "first")
	}
	line2, err := readLine(r)
	if err != nil || line2 != "last_without_newline" {
		t.Fatalf("line2 = (%q, %v), want (%q, nil)", line2, err, "last_without_newline")
	}
	line3, err := readLine(r)
	if err != io.EOF || line3 != "" {
		t.Fatalf("line3 = (%q, %v), want (%q, io.EOF)", line3, err, "")
	}
}

func TestParseSSHSocketListenPort(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ipv6 wildcard stream", "[::]:2222 (Stream)\n", "2222"},
		{"ipv4 stream", "0.0.0.0:9049 (Stream)\n", "9049"},
		{"specific ipv6 literal", "[2001:db8::1]:2222 (Stream)\n", "2222"},
		{"bare port", "2222 (Stream)\n", "2222"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSSHSocketListenPort(tt.input); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSSHSocketDropInPort(t *testing.T) {
	conf := "[Socket]\nListenStream=\nListenStream=2222\n"
	if got := parseSSHSocketDropInPort(conf); got != "2222" {
		t.Fatalf("got %q, want 2222", got)
	}
	resetOnly := "[Socket]\nListenStream=\n"
	if got := parseSSHSocketDropInPort(resetOnly); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestIsValidScriptContent(t *testing.T) {
	if !isValidScriptContent([]byte("#!/bin/bash\necho ok\n")) {
		t.Fatal("expected valid bash script to pass")
	}
	if isValidScriptContent([]byte("<html><body>404 Not Found</body></html>")) {
		t.Fatal("expected HTML error page to fail")
	}
	if isValidScriptContent([]byte("   \n\t")) {
		t.Fatal("expected empty content to fail")
	}
}

func TestOptimalTCPBufferMax(t *testing.T) {
	tests := []struct {
		name     string
		meminfo  string
		expected int
	}{
		{"256MB RAM", "MemTotal:         262144 kB\nMemFree:           50000 kB\n", 8388608},
		{"512MB RAM", "MemTotal:         524288 kB\nMemFree:          100000 kB\n", 8388608},
		{"1GB RAM", "MemTotal:        1048576 kB\nMemFree:          200000 kB\n", 16777216},
		{"2GB RAM", "MemTotal:        2097152 kB\nMemFree:          500000 kB\n", 33554432},
		{"4GB RAM", "MemTotal:        4194304 kB\nMemFree:         1000000 kB\n", 67108864},
		{"corrupt or empty meminfo fallback", "garbage data without MemTotal", 8388608},
		{"zero MemTotal fallback", "MemTotal:              0 kB\n", 8388608},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOptimalTCPBuffer(tt.meminfo)
			if result != tt.expected {
				t.Fatalf("expected buffer=%d, got %d", tt.expected, result)
			}
		})
	}
}
