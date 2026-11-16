// Package detect finds out what this device offers: the SSH host key, tmux, the desktop's
// remote desktop server (KRdp, GNOME Remote Desktop, wayvnc, xrdp, x11vnc), whether it
// listens, the session type and the distribution. Everything reads files below Root
// (default "/") and runs only fixed programs, so tests can fake a system.
package detect

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// System is the device seen through a root directory.
type System struct {
	Root     string
	LookPath func(string) (string, error)
	Output   func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Host is the real system.
func Host() *System {
	return &System{Root: "/", LookPath: exec.LookPath, Output: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output() // #nosec G204 -- fixed programs (tmux -V, loginctl)
	}}
}

func (s *System) path(p string) string { return filepath.Join(s.Root, p) }

// HostKey is the SSH host key as the plugin pins it.
type HostKey struct {
	Alg    string `json:"alg"`
	SHA256 string `json:"sha256"`
}

// HostKeyOf the sshd: ed25519 first, then ecdsa, then rsa (public files only).
func (s *System) HostKeyOf() (*HostKey, error) {
	for _, f := range []string{"ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub", "ssh_host_rsa_key.pub"} {
		b, err := os.ReadFile(s.path(filepath.Join("etc/ssh", f)))
		if err != nil {
			continue
		}
		if k, err := ParsePublicKey(string(b)); err == nil {
			return k, nil
		}
	}
	return nil, errors.New("no SSH host key found (is openssh-server installed?)")
}

// ParsePublicKey reads "<alg> <base64> [comment]" and returns the alg and the SHA-256
// fingerprint as ssh-keygen -l prints it after "SHA256:" (43 characters).
func ParsePublicKey(line string) (*HostKey, error) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return nil, errors.New("not a public key")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(raw) < 11 {
		return nil, errors.New("not a public key")
	}
	// the blob starts with the algorithm name (uint32 length + name)
	n := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if n <= 0 || 4+n > len(raw) || string(raw[4:4+n]) != f[0] {
		return nil, errors.New("key type does not match")
	}
	sum := sha256.Sum256(raw)
	return &HostKey{Alg: f[0], SHA256: base64.RawStdEncoding.EncodeToString(sum[:])}, nil
}

// Tmux is the tmux of the device.
type Tmux struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
}

var tmuxVersionRE = regexp.MustCompile(`^tmux ([0-9][0-9A-Za-z.\-]{0,15})`)

// TmuxOf runs `tmux -V`.
func (s *System) TmuxOf(ctx context.Context) Tmux {
	p, err := s.LookPath("tmux")
	if err != nil {
		return Tmux{}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := s.Output(ctx, p, "-V")
	if err != nil {
		return Tmux{Available: true}
	}
	m := tmuxVersionRE.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return Tmux{Available: true}
	}
	return Tmux{Available: true, Version: m[1]}
}

// OS of the device.
type OS struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Arch    string `json:"arch"`
}

// OSOf reads /etc/os-release.
func (s *System) OSOf() OS {
	o := OS{ID: "linux", Arch: runtime.GOARCH}
	f, err := os.Open(s.path("etc/os-release"))
	if err != nil {
		return o
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = clip(strings.Trim(v, `"'`), 40)
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_ID":
			o.Version = v
		}
	}
	return o
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Desktop server kinds.
const (
	KRdp    = "krdp"
	GnomeRD = "gnome-remote-desktop"
	WayVNC  = "wayvnc"
	XRDP    = "xrdp"
	X11VNC  = "x11vnc"
)

// Kinds in the order of preference.
var Kinds = []string{KRdp, GnomeRD, WayVNC, XRDP, X11VNC}

type kindInfo struct {
	protocol string
	port     int
	procs    []string
	bins     []string
}

var kinds = map[string]kindInfo{
	KRdp:    {"rdp", 3389, []string{"krdpserver"}, []string{"usr/bin/krdpserver"}},
	GnomeRD: {"rdp", 3389, []string{"gnome-remote-de"}, []string{"usr/libexec/gnome-remote-desktop-daemon", "usr/lib/gnome-remote-desktop-daemon", "usr/bin/grdctl"}},
	WayVNC:  {"vnc", 5900, []string{"wayvnc"}, []string{"usr/bin/wayvnc"}},
	XRDP:    {"rdp", 3389, []string{"xrdp"}, []string{"usr/sbin/xrdp"}},
	X11VNC:  {"vnc", 5900, []string{"x11vnc"}, []string{"usr/bin/x11vnc"}},
}

// ProtocolOf a kind ("" unknown).
func ProtocolOf(kind string) (string, int) {
	k, ok := kinds[kind]
	if !ok {
		return "", 0
	}
	return k.protocol, k.port
}

// Desktop is what the device offers for a desktop session.
type Desktop struct {
	Kind      string   `json:"kind,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	Port      int      `json:"port,omitempty"`
	Running   bool     `json:"running"`
	Ready     bool     `json:"ready"`
	Session   string   `json:"session,omitempty"` // wayland | x11
	Installed []string `json:"installed,omitempty"`
}

// DesktopOf finds the desktop server; want/port pin a kind or port (empty/0: detect).
func (s *System) DesktopOf(want string, port int) Desktop {
	procs := s.processes()
	d := Desktop{Session: s.sessionType(context.Background())}
	var running, installed []string
	for _, k := range Kinds {
		info := kinds[k]
		run := false
		for _, p := range info.procs {
			if procs[p] {
				run = true
			}
		}
		inst := run
		for _, b := range info.bins {
			if _, err := os.Stat(s.path(b)); err == nil {
				inst = true
			}
		}
		if run {
			running = append(running, k)
		}
		if inst {
			installed = append(installed, k)
		}
	}
	d.Installed = installed
	pick := ""
	switch {
	case want != "":
		if _, ok := kinds[want]; ok {
			pick = want
		}
	case len(running) > 0:
		pick = running[0]
	case len(installed) > 0:
		pick = installed[0]
	}
	if pick == "" {
		return d
	}
	d.Kind = pick
	d.Protocol, d.Port = ProtocolOf(pick)
	if port > 0 {
		d.Port = port
	}
	for _, r := range running {
		if r == pick {
			d.Running = true
		}
	}
	d.Ready = s.Listening(d.Port)
	return d
}

// processes: the names (comm, ≤ 15 characters) of the running processes.
func (s *System) processes() map[string]bool {
	out := map[string]bool{}
	ents, err := os.ReadDir(s.path("proc"))
	if err != nil {
		return out
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(s.path(filepath.Join("proc", e.Name(), "comm")))
		if err == nil {
			out[strings.TrimSpace(string(b))] = true
		}
	}
	return out
}

// sessionType of the graphical session: logind first (the service cannot look into
// /run/user or the shared /tmp), then the sockets (the CLI as root).
func (s *System) sessionType(ctx context.Context) string {
	if t := s.logindType(ctx); t != "" {
		return t
	}
	if m, _ := filepath.Glob(s.path("run/user/*/wayland-[0-9]")); len(m) > 0 {
		return "wayland"
	}
	if m, _ := filepath.Glob(s.path("tmp/.X11-unix/X*")); len(m) > 0 {
		return "x11"
	}
	return ""
}

var sessionIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func (s *System) logindType(ctx context.Context) string {
	if s.Output == nil || s.LookPath == nil {
		return ""
	}
	lc, err := s.LookPath("loginctl")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := s.Output(ctx, lc, "list-sessions", "--no-legend")
	if err != nil {
		return ""
	}
	found := ""
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || !sessionIDRE.MatchString(f[0]) {
			continue
		}
		t, err := s.Output(ctx, lc, "show-session", f[0], "-p", "Type", "--value")
		if err != nil {
			continue
		}
		switch strings.TrimSpace(string(t)) {
		case "wayland":
			return "wayland"
		case "x11":
			found = "x11"
		}
	}
	return found
}

// Listening: something listens on TCP port (IPv4 or IPv6).
func (s *System) Listening(port int) bool {
	if port <= 0 {
		return false
	}
	for _, f := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		if listensIn(s.path(f), port) {
			return true
		}
	}
	return false
}

func listensIn(file string, port int) bool {
	f, err := os.Open(file) // #nosec G304 -- /proc/net/tcp below the root
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 4 || fs[3] != "0A" { // 0A = LISTEN
			continue
		}
		_, ph, ok := strings.Cut(fs[1], ":")
		if !ok {
			continue
		}
		if p, err := strconv.ParseInt(ph, 16, 32); err == nil && int(p) == port {
			return true
		}
	}
	return false
}

// UFWActive: ufw is switched on (its drop would win over the agent's accept).
func (s *System) UFWActive() bool {
	b, err := os.ReadFile(s.path("etc/ufw/ufw.conf"))
	return err == nil && regexp.MustCompile(`(?m)^ENABLED=yes`).Match(b)
}
