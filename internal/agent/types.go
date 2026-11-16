// Package agent is the service gatecontrol-agent: it holds the WireGuard tunnel, registers
// the device with the plugin "Fernzugriff" (host/register with platform linux), beats every
// 60 s (host/state), keeps the code of the device, answers requests, opens and closes the
// firewall per session on the plugin's signals (push stream) and answers the CLI on the
// control socket.
package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/api"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/detect"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/wg"
)

// API is what the agent needs of GateControl (api.Client; tests fake it).
type API interface {
	Plugin(ctx context.Context, method, path string, body, out any) error
	ConfigCheck(ctx context.Context, peerID int, hash string) (*api.ConfigAnswer, error)
	Stream(ctx context.Context, lastSeq int64, fn func(api.Notification)) error
	Ack(ctx context.Context, seqs []int64) error
}

// Tunnel is the WireGuard side (wg package; tests fake it).
type Tunnel interface {
	Apply(iface string, w *config.WG) error
	Read(iface string) wg.Status
	Remove(iface string) error
}

// SSHInfo of host/register and host/state.
type SSHInfo struct {
	Offered bool            `json:"offered"`
	User    string          `json:"user,omitempty"`
	Port    int             `json:"port"`
	Tmux    detect.Tmux     `json:"tmux"`
	HostKey *detect.HostKey `json:"hostKey,omitempty"`
}

// DesktopInfo of host/register and host/state.
type DesktopInfo struct {
	Offered  bool   `json:"offered"`
	Kind     string `json:"kind,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
	Ready    bool   `json:"ready"`
	Session  string `json:"session,omitempty"`
}

// Register is the body of host/register (and, without name, of host/state).
type Register struct {
	Platform   string      `json:"platform"`
	Name       string      `json:"name,omitempty"`
	AppVersion string      `json:"appVersion"`
	OS         detect.OS   `json:"os"`
	SSH        SSHInfo     `json:"ssh"`
	Desktop    DesktopInfo `json:"desktop"`
	ShareMode  string      `json:"shareMode,omitempty"`
	Online     bool        `json:"online,omitempty"`
}

// HostAnswer of host/register.
type HostAnswer struct {
	Host struct {
		DeviceID  int    `json:"deviceId"`
		Platform  string `json:"platform"`
		ShareMode string `json:"shareMode"`
		AllowOpen bool   `json:"allowOpen"`
		State     string `json:"state"`
		SSH       *struct {
			Offered   bool   `json:"offered"`
			User      string `json:"user"`
			PublicKey string `json:"publicKey"`
			From      string `json:"from"`
		} `json:"ssh"`
		Desktop *struct {
			Offered  bool   `json:"offered"`
			Protocol string `json:"protocol"`
			Port     int    `json:"port"`
		} `json:"desktop"`
	} `json:"host"`
	CodeRequired bool `json:"codeRequired"`
}

// Request of a helper as the signal and the heartbeat hand it.
type Request struct {
	RequestID string `json:"requestId"`
	From      struct {
		UserID int    `json:"userId"`
		Name   string `json:"name"`
	} `json:"from"`
	Mode      string `json:"mode"`
	Via       string `json:"via"`
	Kind      string `json:"kind"`
	ExpiresAt string `json:"expiresAt"`
}

// StateAnswer of host/state.
type StateAnswer struct {
	ShareMode string    `json:"shareMode"`
	AllowOpen bool      `json:"allowOpen"`
	Pending   []Request `json:"pending"`
}

// Signal of the plugin (data of a silent push).
type Signal struct {
	Type       string          `json:"type"`
	RequestID  string          `json:"requestId,omitempty"`
	SessionKey string          `json:"sessionKey,omitempty"`
	Allow      string          `json:"allow,omitempty"`
	Port       int             `json:"port,omitempty"`
	Until      string          `json:"until,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

// Code of the device.
type Code struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Status for `gatecontrol-agent status`.
type Status struct {
	Version     string        `json:"version"`
	Since       time.Time     `json:"since"`
	Server      string        `json:"server"`
	Name        string        `json:"name"`
	DeviceID    int           `json:"deviceId,omitempty"`
	Registered  bool          `json:"registered"`
	State       string        `json:"state,omitempty"`
	Problem     string        `json:"problem,omitempty"`
	ShareMode   string        `json:"shareMode"`
	AllowOpen   bool          `json:"allowOpen"`
	Confirm     string        `json:"confirm"`
	VPN         VPNStatus     `json:"vpn"`
	SSH         SSHInfo       `json:"ssh"`
	Desktop     DesktopInfo   `json:"desktop"`
	Code        *Code         `json:"code,omitempty"`
	Sessions    int           `json:"sessions"`
	Requests    []PendingView `json:"requests,omitempty"`
	LastContact time.Time     `json:"lastContact,omitempty"`
	Push        string        `json:"push"`
}

// VPNStatus of the tunnel.
type VPNStatus struct {
	Interface     string    `json:"interface"`
	Mode          string    `json:"mode"`
	Up            bool      `json:"up"`
	Address       string    `json:"address,omitempty"`
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
}

// PendingView of a request waiting at this device (confirm ask).
type PendingView struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	Mode      string    `json:"mode"`
	Kind      string    `json:"kind"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ReloadAnswer of the control op reload (the CLI writes authorized_keys from it).
type ReloadAnswer struct {
	DeviceID     int    `json:"deviceId"`
	SSHUser      string `json:"sshUser,omitempty"`
	SSHPublicKey string `json:"sshPublicKey,omitempty"`
	SSHFrom      string `json:"sshFrom,omitempty"`
	State        string `json:"state,omitempty"`
	ShareMode    string `json:"shareMode"`
}

// Decision of the control ops allow / deny.
type Decision struct {
	ID   string `json:"id"`
	View bool   `json:"view,omitempty"`
}
