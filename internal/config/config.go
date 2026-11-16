// Package config keeps what the agent stores on disk:
//
//	/etc/gatecontrol-agent/agent.json     settings (server, name, shares, confirm, network) root:gatecontrol 0640
//	/var/lib/gatecontrol-agent/token      the app token, nothing else                       gatecontrol 0600
//	/var/lib/gatecontrol-agent/wg.json    WireGuard: private key, address, peer, hash       gatecontrol 0600
//	/var/lib/gatecontrol-agent/state.json device id, peer id, last report (no secret)       gatecontrol 0600
//
// Paths can be moved with GATECONTROL_AGENT_ETC / GATECONTROL_AGENT_STATE (tests, packaging checks).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Paths of the agent.
type Paths struct {
	Etc   string
	State string
	Run   string
}

// DefaultPaths honours the environment overrides.
func DefaultPaths() Paths {
	p := Paths{Etc: "/etc/gatecontrol-agent", State: "/var/lib/gatecontrol-agent", Run: "/run/gatecontrol-agent"}
	if v := os.Getenv("GATECONTROL_AGENT_ETC"); v != "" {
		p.Etc = v
	}
	if v := os.Getenv("GATECONTROL_AGENT_STATE"); v != "" {
		p.State = v
	}
	if v := os.Getenv("GATECONTROL_AGENT_RUN"); v != "" {
		p.Run = v
	}
	return p
}

func (p Paths) AgentFile() string { return filepath.Join(p.Etc, "agent.json") }
func (p Paths) TokenFile() string { return filepath.Join(p.State, "token") }
func (p Paths) WGFile() string    { return filepath.Join(p.State, "wg.json") }
func (p Paths) StateFile() string { return filepath.Join(p.State, "state.json") }
func (p Paths) Socket() string    { return filepath.Join(p.Run, "agent.sock") }

// WG modes.
const (
	WGNetlink = "netlink"
	WGQuick   = "wg-quick"
)

// Confirm modes of a request at this device.
const (
	ConfirmCode = "code" // a redeemed code is the consent
	ConfirmAsk  = "ask"  // `gatecontrol-agent allow|deny <id>` within 30 s
)

// SSHShare is the SSH share of this device.
type SSHShare struct {
	Enabled bool   `json:"enabled"`
	User    string `json:"user,omitempty"`
	Port    int    `json:"port,omitempty"`
	Tmux    bool   `json:"tmux"`
}

// DesktopShare is the desktop share of this device.
type DesktopShare struct {
	Enabled bool   `json:"enabled"`
	Kind    string `json:"kind,omitempty"` // empty: detect
	Port    int    `json:"port,omitempty"` // 0: the kind's default
}

// Agent is agent.json.
type Agent struct {
	Server    string       `json:"server"`
	Name      string       `json:"name"`
	WGMode    string       `json:"wgMode"`
	Interface string       `json:"interface"`
	Subnet    string       `json:"subnet,omitempty"`
	Hub       string       `json:"hub,omitempty"`
	ShareMode string       `json:"shareMode"` // code | open
	Confirm   string       `json:"confirm"`
	SSH       SSHShare     `json:"ssh"`
	Desktop   DesktopShare `json:"desktop"`
}

// Defaults fills empty fields.
func (a *Agent) Defaults() {
	if a.WGMode == "" {
		a.WGMode = WGNetlink
	}
	if a.Interface == "" {
		a.Interface = "wg-gc"
	}
	if a.ShareMode == "" {
		a.ShareMode = "code"
	}
	if a.Confirm == "" {
		a.Confirm = ConfirmCode
	}
	if a.SSH.Port == 0 {
		a.SSH.Port = 22
	}
}

// Validate checks the settings.
func (a *Agent) Validate() error {
	if err := CheckServer(a.Server); err != nil {
		return err
	}
	if a.WGMode != WGNetlink && a.WGMode != WGQuick {
		return fmt.Errorf("wgMode must be %q or %q", WGNetlink, WGQuick)
	}
	if a.ShareMode != "code" && a.ShareMode != "open" {
		return errors.New("shareMode must be code or open")
	}
	if a.Confirm != ConfirmCode && a.Confirm != ConfirmAsk {
		return errors.New("confirm must be code or ask")
	}
	if a.SSH.Port < 1 || a.SSH.Port > 65535 || a.Desktop.Port < 0 || a.Desktop.Port > 65535 {
		return errors.New("port out of range")
	}
	if !ValidInterface(a.Interface) {
		return errors.New("invalid interface name")
	}
	return nil
}

// ValidInterface: 1–15 of a-z 0-9 - _ (what nft and ip accept without quoting trouble).
func ValidInterface(s string) bool {
	if len(s) == 0 || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// CheckServer: an https URL without user info, path, query or fragment.
func CheckServer(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the server must be an https:// address without a path")
	}
	return nil
}

// NormalizeServer returns scheme://host[:port].
func NormalizeServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	if err := CheckServer(s); err != nil {
		return "", err
	}
	u, _ := url.Parse(s)
	return u.Scheme + "://" + u.Host, nil
}

// WG is wg.json — the WireGuard settings of this device.
type WG struct {
	PrivateKey   string `json:"privateKey"`
	Address      string `json:"address"` // 10.8.0.41/32
	PeerKey      string `json:"peerPublicKey"`
	PresharedKey string `json:"presharedKey,omitempty"`
	Endpoint     string `json:"endpoint"`
	AllowedIPs   string `json:"allowedIps"` // the VPN subnet only
	Keepalive    int    `json:"keepalive"`
	MTU          int    `json:"mtu,omitempty"`
	Hash         string `json:"hash"`
}

// State is state.json (no secret).
type State struct {
	PeerID   int    `json:"peerId"`
	PeerName string `json:"peerName,omitempty"`
	DeviceID int    `json:"deviceId,omitempty"`
	LastSeq  int64  `json:"lastSeq,omitempty"`
}

// ErrNotEnrolled: no token on disk.
var ErrNotEnrolled = errors.New("not_enrolled")

// Store reads and writes the files.
type Store struct{ P Paths }

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed paths of the agent
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// WriteFileAtomic writes via a temp file in the same directory and renames it.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(b, '\n'), mode)
}

// LoadAgent reads agent.json (with defaults).
func (s Store) LoadAgent() (*Agent, error) {
	a := &Agent{}
	if err := readJSON(s.P.AgentFile(), a); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotEnrolled
		}
		return nil, err
	}
	a.Defaults()
	return a, a.Validate()
}

// SaveAgent writes agent.json (0640: the service's group reads it).
func (s Store) SaveAgent(a *Agent) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return writeJSON(s.P.AgentFile(), a, 0o640)
}

// LoadToken reads the token.
func (s Store) LoadToken() (string, error) {
	b, err := os.ReadFile(s.P.TokenFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotEnrolled
		}
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", ErrNotEnrolled
	}
	return t, nil
}

// SaveToken writes the token (0600).
func (s Store) SaveToken(t string) error {
	return WriteFileAtomic(s.P.TokenFile(), []byte(t+"\n"), 0o600)
}

// LoadWG reads wg.json.
func (s Store) LoadWG() (*WG, error) {
	w := &WG{}
	if err := readJSON(s.P.WGFile(), w); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotEnrolled
		}
		return nil, err
	}
	return w, nil
}

// SaveWG writes wg.json (0600).
func (s Store) SaveWG(w *WG) error { return writeJSON(s.P.WGFile(), w, 0o600) }

// LoadState reads state.json (missing → empty).
func (s Store) LoadState() (*State, error) {
	st := &State{}
	if err := readJSON(s.P.StateFile(), st); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return st, nil
}

// SaveState writes state.json (0600).
func (s Store) SaveState(st *State) error { return writeJSON(s.P.StateFile(), st, 0o600) }

// RemoveAll removes token, wg.json, state.json and agent.json.
func (s Store) RemoveAll() error {
	var errs []error
	for _, f := range []string{s.P.TokenFile(), s.P.WGFile(), s.P.StateFile(), s.P.AgentFile()} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
