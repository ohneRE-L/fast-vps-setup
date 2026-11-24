//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxSSHConfigHelpersEndToEnd(t *testing.T) {
	// Verify real production helpers chained together as used by applySSHPort & setupSSHKey
	cfg := "Port 22\nPasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n"
	if !hasActiveSSHDInclude(cfg) {
		t.Fatal("expected active Include to be detected")
	}
	if !hasPasswordAuthBeforeInclude(cfg) {
		t.Fatal("expected PasswordAuthentication yes before Include to be detected")
	}

	commented, changed := commentActivePorts(cfg)
	if !changed {
		t.Fatal("expected Port 22 to be commented")
	}
	if parseSSHPortFromConfig(commented) != "" {
		t.Fatalf("expected no active Port after commenting, got %q", parseSSHPortFromConfig(commented))
	}

	secured := updateLegacySSHDPasswordAuth(commented, true)
	if hasPasswordAuthBeforeInclude(secured) {
		t.Fatalf("PasswordAuthentication yes still active before Include:\n%s", secured)
	}
}

func TestLinuxWaitForFile(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "ready.flag")

	if waitForFile(target, 50*time.Millisecond) {
		t.Fatal("expected waitForFile to return false for missing file")
	}

	if err := os.WriteFile(target, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if !waitForFile(target, 500*time.Millisecond) {
		t.Fatal("expected waitForFile to return true for existing file")
	}
	if waitForFile(tmpDir, 50*time.Millisecond) {
		t.Fatal("expected waitForFile to return false for directory")
	}
}

func TestLinuxParseSSHPortFromConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		want string
	}{
		{"sshd -T lowercase", "port 2222\naddressfamily any\n", "2222"},
		{"indented Port", "  Port 9049\n", "9049"},
		{"commented Port ignored", "#Port 2222\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSSHPortFromConfig(tt.cfg); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
