// Package sshkeys writes the one authorized_keys line of GateControl for a shared account:
//
//	from="10.8.0.1",no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA… gatecontrol-agent:<deviceId>
//
// Only GateControl's server (the hub address) may use the key. Other lines stay untouched,
// an old line of the agent is replaced. Runs as root (sudo gatecontrol-agent share ssh):
// it never follows a symbolic link in the account's ~/.ssh and hands the files to the account.
package sshkeys

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/detect"
)

// Marker starts the comment of the agent's line.
const Marker = "gatecontrol-agent"

// Line renders the restricted line.
func Line(publicKey string, from netip.Addr, deviceID int) (string, error) {
	f := strings.Fields(publicKey)
	if len(f) < 2 || f[0] != "ssh-ed25519" {
		return "", errors.New("sshkeys: GateControl's key must be ssh-ed25519")
	}
	if _, err := detect.ParsePublicKey(f[0] + " " + f[1]); err != nil {
		return "", fmt.Errorf("sshkeys: %w", err)
	}
	if !from.IsValid() || !from.Is4() {
		return "", errors.New("sshkeys: invalid hub address")
	}
	return fmt.Sprintf(`from="%s",no-agent-forwarding,no-X11-forwarding,no-port-forwarding %s %s %s:%d`, from, f[0], f[1], Marker, deviceID), nil
}

// Merge returns the content with the agent's line replaced (line == "": removed).
func Merge(old, line string) string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(old))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if isOurs(l) {
			continue
		}
		out = append(out, l)
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if line != "" {
		out = append(out, line)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

func isOurs(l string) bool {
	f := strings.Fields(l)
	return len(f) > 0 && strings.HasPrefix(f[len(f)-1], Marker+":")
}

// Account is a local account that may be shared.
type Account struct {
	Name string
	UID  int
	GID  int
	Home string
}

// Lookup finds the account; root and system accounts without a home are refused.
func Lookup(name string) (*Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: no account %q", name)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 {
		return nil, errors.New("sshkeys: root cannot be shared — name a normal account")
	}
	if u.HomeDir == "" || u.HomeDir == "/" || u.HomeDir == "/nonexistent" {
		return nil, fmt.Errorf("sshkeys: account %q has no home directory", name)
	}
	return &Account{Name: u.Username, UID: uid, GID: gid, Home: u.HomeDir}, nil
}

// Install writes (line != "") or removes (line == "") the agent's line for the account.
func Install(a *Account, line string) error {
	home, err := os.Lstat(a.Home)
	if err != nil || !home.IsDir() {
		return fmt.Errorf("sshkeys: home of %s missing", a.Name)
	}
	dir := filepath.Join(a.Home, ".ssh")
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if line == "" {
			return nil
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		if err := os.Lchown(dir, a.UID, a.GID); err != nil {
			return err
		}
	case err != nil:
		return err
	case fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir():
		return errors.New("sshkeys: ~/.ssh is not a plain directory — refusing")
	default:
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != a.UID {
			return errors.New("sshkeys: ~/.ssh belongs to another account — refusing")
		}
	}
	file := filepath.Join(dir, "authorized_keys")
	old := ""
	if fi, err := os.Lstat(file); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return errors.New("sshkeys: authorized_keys is not a plain file — refusing")
		}
		f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- checked above
		if err != nil {
			return err
		}
		b, err := readAll(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		old = string(b)
	} else if line == "" {
		return nil
	}
	next := Merge(old, line)
	tmp, err := os.CreateTemp(dir, ".authorized_keys.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chown(a.UID, a.GID); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(next); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, file)
}

func readAll(f *os.File) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, errors.New("sshkeys: authorized_keys too large")
	}
	return b, nil
}

const maxFile = 4 << 20
