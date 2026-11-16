package detect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// a real ed25519 public key and its fingerprint (ssh-keygen -lf)
const edPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example"

func write(t *testing.T, root, p, content string) {
	t.Helper()
	f := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fake(t *testing.T) (*System, string) {
	root := t.TempDir()
	return &System{Root: root, LookPath: func(string) (string, error) { return "", errors.New("none") }}, root
}

func TestParsePublicKey(t *testing.T) {
	k, err := ParsePublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	if k.Alg != "ssh-ed25519" || len(k.SHA256) != 43 {
		t.Fatalf("%+v", k)
	}
	if _, err := ParsePublicKey("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"); err == nil {
		t.Fatal("type mismatch accepted")
	}
	if _, err := ParsePublicKey("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestHostKeyOf(t *testing.T) {
	s, root := fake(t)
	if _, err := s.HostKeyOf(); err == nil {
		t.Fatal("no key expected")
	}
	write(t, root, "etc/ssh/ssh_host_ed25519_key.pub", edPub+"\n")
	k, err := s.HostKeyOf()
	if err != nil || k.Alg != "ssh-ed25519" {
		t.Fatalf("%+v %v", k, err)
	}
}

func TestTmux(t *testing.T) {
	s, _ := fake(t)
	if s.TmuxOf(context.Background()).Available {
		t.Fatal("tmux without binary")
	}
	s.LookPath = func(string) (string, error) { return "/usr/bin/tmux", nil }
	s.Output = func(context.Context, string, ...string) ([]byte, error) { return []byte("tmux 3.3a\n"), nil }
	if tm := s.TmuxOf(context.Background()); !tm.Available || tm.Version != "3.3a" {
		t.Fatalf("%+v", tm)
	}
}

func TestDesktopWayvncOnPi(t *testing.T) {
	s, root := fake(t)
	write(t, root, "proc/812/comm", "wayvnc\n")
	write(t, root, "proc/1/comm", "systemd\n")
	write(t, root, "usr/sbin/xrdp", "")
	write(t, root, "run/user/1000/wayland-0", "")
	// 5900 listening (0x170C), state 0A
	write(t, root, "proc/net/tcp", "  sl  local_address rem_address   st\n   0: 00000000:170C 00000000:0000 0A 00000000:00000000\n")
	d := s.DesktopOf("", 0)
	if d.Kind != WayVNC || d.Protocol != "vnc" || d.Port != 5900 || !d.Running || !d.Ready || d.Session != "wayland" {
		t.Fatalf("%+v", d)
	}
	if len(d.Installed) != 2 {
		t.Fatalf("installed %v", d.Installed)
	}
	x := s.DesktopOf(XRDP, 0)
	if x.Kind != XRDP || x.Running || x.Ready || x.Protocol != "rdp" {
		t.Fatalf("%+v", x)
	}
}

func TestDesktopNone(t *testing.T) {
	s, _ := fake(t)
	if d := s.DesktopOf("", 0); d.Kind != "" || d.Ready {
		t.Fatalf("%+v", d)
	}
}

func TestListeningIPv6AndNotListen(t *testing.T) {
	s, root := fake(t)
	write(t, root, "proc/net/tcp", "h\n 0: 0100007F:0D3D 00000000:0000 01 x\n")
	write(t, root, "proc/net/tcp6", "h\n 0: 00000000000000000000000000000000:0D3D 00000000000000000000000000000000:0000 0A x\n")
	if !s.Listening(3389) || s.Listening(22) {
		t.Fatal("listening detection wrong")
	}
}

func TestOSAndUFW(t *testing.T) {
	s, root := fake(t)
	write(t, root, "etc/os-release", "ID=raspbian\nVERSION_ID=\"12\"\n")
	if o := s.OSOf(); o.ID != "raspbian" || o.Version != "12" {
		t.Fatalf("%+v", o)
	}
	write(t, root, "etc/ufw/ufw.conf", "ENABLED=yes\n")
	if !s.UFWActive() {
		t.Fatal("ufw")
	}
}

func TestSessionFromLogind(t *testing.T) {
	s, _ := fake(t)
	s.LookPath = func(n string) (string, error) {
		if n == "loginctl" {
			return "/usr/bin/loginctl", nil
		}
		return "", errors.New("none")
	}
	s.Output = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "list-sessions" {
			return []byte("  3 1000 pi seat0 tty7\n c1 0 root\n"), nil
		}
		if args[1] == "3" {
			return []byte("wayland\n"), nil
		}
		return []byte("tty\n"), nil
	}
	if d := s.DesktopOf("", 0); d.Session != "wayland" {
		t.Fatalf("%+v", d)
	}
}
