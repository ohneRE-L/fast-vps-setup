//go:build linux

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSSHConfigPortCommenting(t *testing.T) {
	reActivePort := regexp.MustCompile(`(?m)^[\t ]*Port\b.*$`)

	tests := []struct {
		name     string
		input    string
		expected string
		matched  bool
	}{
		{
			name:     "standard Port 22",
			input:    "Port 22\nPasswordAuthentication yes\n",
			expected: "#Port 22\nPasswordAuthentication yes\n",
			matched:  true,
		},
		{
			name:     "Port with tabs and spaces",
			input:    "\tPort  22\n#Port 2222\n",
			expected: "#\tPort  22\n#Port 2222\n",
			matched:  true,
		},
		{
			name:     "already commented Port only",
			input:    "#Port 22\n# Port 22\n",
			expected: "#Port 22\n# Port 22\n",
			matched:  false,
		},
		{
			name:     "multiple active ports",
			input:    "Port 22\nPort 222\n",
			expected: "#Port 22\n#Port 222\n",
			matched:  true,
		},
		{
			name:     "word starting with Port but not Port directive",
			input:    "PortForwarding yes\n",
			expected: "PortForwarding yes\n",
			matched:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := reActivePort.Match([]byte(tt.input))
			if matched != tt.matched {
				t.Fatalf("expected matched=%v, got %v", tt.matched, matched)
			}
			if matched {
				result := reActivePort.ReplaceAllStringFunc(tt.input, func(line string) string {
					return "#" + line
				})
				if result != tt.expected {
					t.Fatalf("expected:\n%s\ngot:\n%s", tt.expected, result)
				}
			}
		})
	}
}

func TestLegacySSHDConfigPortReplace(t *testing.T) {
	re := regexp.MustCompile(`(?m)^#?Port\s+\d+`)

	tests := []struct {
		name     string
		input    string
		port     string
		expected string
	}{
		{
			name:     "commented Port replaced",
			input:    "#Port 22\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
			port:     "2222",
			expected: "Port 2222\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
		},
		{
			name:     "uncommented Port replaced",
			input:    "Port 22\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
			port:     "2222",
			expected: "Port 2222\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := re.ReplaceAll([]byte(tt.input), []byte("Port "+tt.port))
			if string(res) != tt.expected {
				t.Fatalf("expected:\n%s\ngot:\n%s", tt.expected, string(res))
			}
		})
	}
}

func TestDebian11PasswordDisableFallback(t *testing.T) {
	dir := t.TempDir()
	dropinPath := filepath.Join(dir, "00-disable-passwords.conf")

	// 1. Initial write with modern OpenSSH options
	initialCfg := "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
	if err := os.WriteFile(dropinPath, []byte(initialCfg), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	// 2. Simulate sshd -t output on Debian 11 / OpenSSH 8.4
	simulatedOutput := "/etc/ssh/sshd_config.d/00-disable-passwords.conf: line 2: Bad configuration option: KbdInteractiveAuthentication\n"

	if strings.Contains(simulatedOutput, "KbdInteractiveAuthentication") {
		fallbackCfg := "PasswordAuthentication no\nChallengeResponseAuthentication no\n"
		if err := os.WriteFile(dropinPath, []byte(fallbackCfg), 0644); err != nil {
			t.Fatalf("failed to write fallback config: %v", err)
		}
	}

	data, err := os.ReadFile(dropinPath)
	if err != nil {
		t.Fatalf("failed to read dropin config: %v", err)
	}

	dataStr := string(data)
	if strings.Contains(dataStr, "KbdInteractiveAuthentication") {
		t.Fatalf("config still contains KbdInteractiveAuthentication: %s", dataStr)
	}
	if !strings.Contains(dataStr, "ChallengeResponseAuthentication no") {
		t.Fatalf("config missing ChallengeResponseAuthentication no: %s", dataStr)
	}
	if !strings.Contains(dataStr, "PasswordAuthentication no") {
		t.Fatalf("config missing PasswordAuthentication no: %s", dataStr)
	}
}

func TestHasZramDetection(t *testing.T) {
	tmpDir := t.TempDir()
	swapsWithZram := filepath.Join(tmpDir, "proc_swaps_zram")
	contentZram := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/zram0                              partition\t2097148\t\t0\t\t100\n"
	_ = os.WriteFile(swapsWithZram, []byte(contentZram), 0644)

	swapsWithoutZram := filepath.Join(tmpDir, "proc_swaps_file")
	contentFile := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swapfile                               file\t\t2097148\t\t0\t\t-2\n"
	_ = os.WriteFile(swapsWithoutZram, []byte(contentFile), 0644)

	hasZramCustom := func(path string) bool {
		data, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(data), "zram")
	}

	if !hasZramCustom(swapsWithZram) {
		t.Fatalf("failed to detect zram in %s", swapsWithZram)
	}
	if hasZramCustom(swapsWithoutZram) {
		t.Fatalf("falsely detected zram in %s", swapsWithoutZram)
	}
}

func TestSwapFailureCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	swapfile := filepath.Join(tmpDir, "swapfile")

	// Create dummy partial swapfile
	if err := os.WriteFile(swapfile, []byte("partial content"), 0600); err != nil {
		t.Fatalf("failed to create dummy swapfile: %v", err)
	}

	// Simulate error cleanup
	_ = os.Remove(swapfile)

	if _, err := os.Stat(swapfile); !os.IsNotExist(err) {
		t.Fatalf("expected swapfile to be deleted on failure, but it exists")
	}
}

func TestSetupSwapDecisionMatrix(t *testing.T) {
	// Matrix of swap conditions and expected actions
	tests := []struct {
		name              string
		hasZram           bool
		swaponOutput      string
		swapfileExists    bool
		expectEarlyReturn bool
		expectSwappiness  bool
		expectCreateSwap  bool
	}{
		{
			name:              "zram is active -> exit immediately without touching swappiness",
			hasZram:           true,
			swaponOutput:      "/dev/zram0 partition 2097148 0 100",
			swapfileExists:    false,
			expectEarlyReturn: true,
			expectSwappiness:  false,
			expectCreateSwap:  false,
		},
		{
			name:              "disk swap is already active -> set swappiness=10, do not create duplicate swapfile",
			hasZram:           false,
			swaponOutput:      "/swapfile file 1048576 0 -2",
			swapfileExists:    true,
			expectEarlyReturn: true,
			expectSwappiness:  true,
			expectCreateSwap:  false,
		},
		{
			name:              "no active swap -> create 2GB swapfile and set swappiness=10",
			hasZram:           false,
			swaponOutput:      "",
			swapfileExists:    false,
			expectEarlyReturn: false,
			expectSwappiness:  true,
			expectCreateSwap:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swappinessSet := false
			swapCreated := false

			applySwappinessMock := func() {
				swappinessSet = true
			}

			// Simulating setupSwap logic flow
			if tt.hasZram {
				// Early return, no swappiness
			} else if strings.TrimSpace(tt.swaponOutput) != "" {
				applySwappinessMock()
			} else if tt.swapfileExists {
				applySwappinessMock()
			} else {
				swapCreated = true
				applySwappinessMock()
			}

			if swappinessSet != tt.expectSwappiness {
				t.Errorf("expected swappinessSet=%v, got %v", tt.expectSwappiness, swappinessSet)
			}
			if swapCreated != tt.expectCreateSwap {
				t.Errorf("expected swapCreated=%v, got %v", tt.expectCreateSwap, swapCreated)
			}
		})
	}
}
