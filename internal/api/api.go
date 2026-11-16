// Package api talks to GateControl: the enrollment (POST /api/v1/client/enroll), the
// WireGuard config check, the app API of the plugin "Fernzugriff"
// (/api/v1/client/plugins/gatecontrol-remote/api/<path>) and the push stream
// (GET /api/v1/client/push, Server-Sent Events) with its acknowledgements.
//
// Every request carries X-API-Token, X-Client-Platform: linux, X-Client-Version,
// X-Machine-Fingerprint and the agent's User-Agent. TLS is always verified.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/version"
)

// PluginID of "Fernzugriff".
const PluginID = "gatecontrol-remote"

// Error is an answer of GateControl that is not ok.
type Error struct {
	Status int
	Code   string
	Text   string
}

func (e *Error) Error() string {
	if e.Text != "" && e.Text != e.Code {
		return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Text)
	}
	return fmt.Sprintf("%s (%d)", e.Code, e.Status)
}

// CodeOf returns the code of an *Error ("" otherwise).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Client of one GateControl server.
type Client struct {
	Server      string // https://host[:port]
	Token       string
	Fingerprint string
	HTTP        *http.Client
	StreamHTTP  *http.Client // no overall timeout (SSE)
}

// New makes a client; token may be empty (enroll).
func New(server, token, fingerprint string) *Client {
	return &Client{Server: strings.TrimRight(server, "/"), Token: token, Fingerprint: fingerprint,
		HTTP: &http.Client{Timeout: 20 * time.Second}, StreamHTTP: &http.Client{}}
}

// Fingerprint of this machine: SHA-256 of /etc/machine-id with a fixed salt (64 hex).
func Fingerprint(machineIDFile string) string {
	b, err := os.ReadFile(machineIDFile) // #nosec G304 -- fixed path
	id := strings.TrimSpace(string(b))
	if err != nil || id == "" {
		h, _ := os.Hostname()
		id = "host:" + h
	}
	sum := sha256.Sum256([]byte("gatecontrol-agent:" + id))
	return hex.EncodeToString(sum[:])
}

func (c *Client) headers(h http.Header) {
	h.Set("User-Agent", version.UserAgent())
	h.Set("X-Client-Platform", "linux")
	h.Set("X-Client-Version", version.Version)
	if c.Fingerprint != "" {
		h.Set("X-Machine-Fingerprint", c.Fingerprint)
	}
	if c.Token != "" {
		h.Set("X-API-Token", c.Token)
	}
}

// Do sends a JSON request and decodes a JSON answer into out (may be nil).
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Server+path, rd)
	if err != nil {
		return err
	}
	c.headers(req.Header)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	var env struct {
		OK    *bool  `json:"ok"`
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	if res.StatusCode >= 300 || (env.OK != nil && !*env.OK) {
		code := env.Code
		if code == "" {
			code = env.Error
		}
		if code == "" || strings.Contains(code, " ") {
			code = fmt.Sprintf("http_%d", res.StatusCode)
		}
		return &Error{Status: res.StatusCode, Code: code, Text: env.Error}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("api: unexpected answer from %s: %w", path, err)
		}
	}
	return nil
}

// EnrollRequest is the body of POST /api/v1/client/enroll.
type EnrollRequest struct {
	Code          string `json:"code"`
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	ClientVersion string `json:"clientVersion"`
}

// VPN is the network of GateControl (enroll answer, since the Linux agent's server PR).
type VPN struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
}

// EnrollResult is the answer of the enrollment.
type EnrollResult struct {
	Token    string   `json:"token"`
	PeerID   int      `json:"peerId"`
	PeerName string   `json:"peerName"`
	Config   string   `json:"config"`
	Hash     string   `json:"hash"`
	Scopes   []string `json:"scopes"`
	VPN      *VPN     `json:"vpn"`
}

// Enroll trades a setup code for a token and the WireGuard config.
func (c *Client) Enroll(ctx context.Context, code, hostname string) (*EnrollResult, error) {
	var r EnrollResult
	err := c.Do(ctx, http.MethodPost, "/api/v1/client/enroll", EnrollRequest{Code: code, Hostname: hostname, Platform: "linux", ClientVersion: version.Version}, &r)
	if err != nil {
		return nil, err
	}
	if r.Token == "" || r.Config == "" || r.PeerID == 0 {
		return nil, errors.New("api: the server handed no device (a token code without a peer cannot set up the agent)")
	}
	return &r, nil
}

// InternalDNS of the config answer (server = the hub address).
type InternalDNS struct {
	Server string `json:"server"`
}

// ConfigAnswer of GET /api/v1/client/config and /config/check.
type ConfigAnswer struct {
	Updated     bool         `json:"updated"`
	Config      string       `json:"config"`
	Hash        string       `json:"hash"`
	InternalDNS *InternalDNS `json:"internalDns"`
	VPN         *VPN         `json:"vpn"`
}

// Config fetches the WireGuard config of the peer.
func (c *Client) Config(ctx context.Context, peerID int) (*ConfigAnswer, error) {
	var r ConfigAnswer
	err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/client/config?peerId=%d", peerID), nil, &r)
	r.Updated = true
	return &r, err
}

// ConfigCheck asks whether the config changed.
func (c *Client) ConfigCheck(ctx context.Context, peerID int, hash string) (*ConfigAnswer, error) {
	var r ConfigAnswer
	err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/client/config/check?peerId=%d&hash=%s", peerID, url.QueryEscape(hash)), nil, &r)
	return &r, err
}

// Plugin calls the app API of "Fernzugriff".
func (c *Client) Plugin(ctx context.Context, method, path string, body, out any) error {
	return c.Do(ctx, method, "/api/v1/client/plugins/"+PluginID+"/api/"+strings.TrimLeft(path, "/"), body, out)
}

// Ack confirms push deliveries.
func (c *Client) Ack(ctx context.Context, seqs []int64) error {
	return c.Do(ctx, http.MethodPost, "/api/v1/client/push/ack", map[string]any{"seqs": seqs, "state": "delivered"}, nil)
}
