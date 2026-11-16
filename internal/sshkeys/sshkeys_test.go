package sshkeys

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl gc"

func TestLine(t *testing.T) {
	l, err := Line(pub, netip.MustParseAddr("10.8.0.1"), 100042)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(l, `from="10.8.0.1",no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA`) || !strings.HasSuffix(l, " gatecontrol-agent:100042") {
		t.Fatal(l)
	}
	if _, err := Line("ssh-rsa AAAA", netip.MustParseAddr("10.8.0.1"), 1); err == nil {
		t.Fatal("rsa accepted")
	}
	if _, err := Line(pub+"\ncommand=\"x\"", netip.Addr{}, 1); err == nil {
		t.Fatal("no hub accepted")
	}
}

func TestMerge(t *testing.T) {
	old := "ssh-ed25519 AAAAown me@laptop\nfrom=\"10.8.0.1\" ssh-ed25519 OLD gatecontrol-agent:7\n\n"
	got := Merge(old, "NEW gatecontrol-agent:8")
	if got != "ssh-ed25519 AAAAown me@laptop\nNEW gatecontrol-agent:8\n" {
		t.Fatalf("%q", got)
	}
	if Merge(got, "") != "ssh-ed25519 AAAAown me@laptop\n" {
		t.Fatal("remove failed")
	}
	if Merge("", "") != "" {
		t.Fatal("empty")
	}
}

func TestInstallRefusesSymlink(t *testing.T) {
	home := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	a := &Account{Name: "x", UID: os.Getuid(), GID: os.Getgid(), Home: home}
	if err := Install(a, "L gatecontrol-agent:1"); err == nil {
		t.Fatal("symlinked ~/.ssh accepted")
	}
}

func TestInstallWritesAndRemoves(t *testing.T) {
	home := t.TempDir()
	a := &Account{Name: "x", UID: os.Getuid(), GID: os.Getgid(), Home: home}
	if err := Install(a, "L gatecontrol-agent:1"); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(home, ".ssh", "authorized_keys")
	b, _ := os.ReadFile(f)
	fi, _ := os.Stat(f)
	if string(b) != "L gatecontrol-agent:1\n" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%q %v", b, fi.Mode())
	}
	if err := Install(a, ""); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(f)
	if len(b) != 0 {
		t.Fatalf("%q", b)
	}
}
