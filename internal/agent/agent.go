package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/api"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/ctl"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/detect"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/fw"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/version"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/wg"
)

// Timing of the service (tests make it shorter).
type Timing struct {
	Heartbeat   time.Duration
	ConfigCheck time.Duration
	RequestWait time.Duration
	RetryMin    time.Duration
	RetryMax    time.Duration
	PluginRetry time.Duration
}

// DefaultTiming as in the contract.
var DefaultTiming = Timing{Heartbeat: 60 * time.Second, ConfigCheck: 5 * time.Minute, RequestWait: 30 * time.Second,
	RetryMin: time.Second, RetryMax: 5 * time.Minute, PluginRetry: time.Hour}

// unavailable: the plugin is missing, stopped or too old — keep the VPN, try again later.
var unavailable = map[string]bool{"not_found": true, "not_running": true, "offline": true, "http_404": true, "http_503": true, "plugin_not_found": true}

type pending struct {
	req     Request
	expires time.Time
}

// Agent is the running service.
type Agent struct {
	Store  config.Store
	API    API
	Tunnel Tunnel
	FW     *fw.Firewall
	Sys    *detect.System
	Log    *slog.Logger
	Timing Timing
	Now    func() time.Time

	mu         sync.Mutex
	cfg        *config.Agent
	wgc        *config.WG
	st         *config.State
	since      time.Time
	registered bool
	host       HostAnswer
	shareMode  string
	allowOpen  bool
	code       *Code
	problem    string
	lastOK     time.Time
	push       string
	waiting    map[string]pending
	reports    SSHInfo
	desk       DesktopInfo
	acks       []int64
	codeTimer  *time.Timer
}

// New makes the agent from what is on disk.
func New(store config.Store, a API, t Tunnel, f *fw.Firewall, sys *detect.System, log *slog.Logger) (*Agent, error) {
	cfg, err := store.LoadAgent()
	if err != nil {
		return nil, err
	}
	w, err := store.LoadWG()
	if err != nil {
		return nil, err
	}
	st, err := store.LoadState()
	if err != nil {
		return nil, err
	}
	return &Agent{Store: store, API: a, Tunnel: t, FW: f, Sys: sys, Log: log, Timing: DefaultTiming, Now: time.Now,
		cfg: cfg, wgc: w, st: st, waiting: map[string]pending{}, shareMode: cfg.ShareMode, push: "starting"}, nil
}

func (a *Agent) now() time.Time { return a.Now() }

// Run is the service until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	a.since = a.now()
	a.mu.Unlock()
	if err := a.tunnelUp(); err != nil {
		a.Log.Error("WireGuard not up", "interface", a.cfg.Interface, "err", err)
	}
	if err := a.firewallSetup(ctx); err != nil {
		a.Log.Error("firewall not set up", "err", err)
	}
	var wgDone sync.WaitGroup
	start := func(fn func(context.Context)) {
		wgDone.Add(1)
		go func() { defer wgDone.Done(); fn(ctx) }()
	}
	start(a.registerLoop)
	start(a.pushLoop)
	start(a.configLoop)
	start(func(ctx context.Context) {
		if err := ctl.Serve(ctx, a.Store.P.Socket(), a.handle); err != nil {
			a.Log.Error("control socket failed", "err", err)
		}
	})
	<-ctx.Done()
	a.mu.Lock()
	if a.codeTimer != nil {
		a.codeTimer.Stop()
	}
	a.mu.Unlock()
	wgDone.Wait()
	return nil
}

func (a *Agent) tunnelUp() error {
	a.mu.Lock()
	cfg, w := a.cfg, a.wgc
	a.mu.Unlock()
	if cfg.WGMode != config.WGNetlink {
		return nil // wg-quick@<iface> holds the tunnel
	}
	return a.Tunnel.Apply(cfg.Interface, w)
}

// spec of the firewall from the settings.
func (a *Agent) spec() fw.Spec {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := fw.Spec{Interface: a.cfg.Interface, SSHPort: a.cfg.SSH.Port, Desktop: []int{3389, 5900}}
	if p, err := netip.ParsePrefix(a.wgc.AllowedIPs); err == nil {
		s.Subnet = p
	}
	if a.cfg.Desktop.Enabled && a.desk.Port > 0 {
		s.Desktop = append(s.Desktop, a.desk.Port)
	}
	if a.cfg.SSH.Enabled {
		from := a.cfg.Hub
		if a.host.Host.SSH != nil && a.host.Host.SSH.From != "" {
			from = a.host.Host.SSH.From
		}
		if ip, err := netip.ParseAddr(from); err == nil && ip.Is4() {
			s.SSHFrom = ip
		}
	}
	return s
}

func (a *Agent) firewallSetup(ctx context.Context) error {
	a.detectNow(ctx)
	return a.FW.Setup(ctx, a.spec())
}

// detectNow refreshes what the device offers.
func (a *Agent) detectNow(ctx context.Context) {
	a.mu.Lock()
	cfg := *a.cfg
	a.mu.Unlock()
	ssh := SSHInfo{Offered: cfg.SSH.Enabled, User: cfg.SSH.User, Port: cfg.SSH.Port, Tmux: a.Sys.TmuxOf(ctx)}
	if k, err := a.Sys.HostKeyOf(); err == nil {
		ssh.HostKey = k
	} else if cfg.SSH.Enabled {
		a.Log.Warn("SSH shared, but no host key", "err", err)
	}
	if !cfg.SSH.Tmux {
		ssh.Tmux = detect.Tmux{}
	}
	d := a.Sys.DesktopOf(cfg.Desktop.Kind, cfg.Desktop.Port)
	desk := DesktopInfo{Offered: cfg.Desktop.Enabled && d.Kind != "", Kind: d.Kind, Protocol: d.Protocol, Port: d.Port, Ready: d.Ready, Session: d.Session}
	a.mu.Lock()
	a.reports, a.desk = ssh, desk
	a.mu.Unlock()
}

// body of host/register (withName) or host/state. shareMode only goes with a change of the CLI (share open|code):
// a switch in the portal stays when the service restarts.
func (a *Agent) body(withName bool) Register {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := Register{Platform: "linux", AppVersion: version.Version, OS: a.Sys.OSOf(), SSH: a.reports, Desktop: a.desk}
	if withName {
		r.Name = a.cfg.Name
	} else {
		r.Online = true
	}
	return r
}

// register once → nil or the error of the plugin.
func (a *Agent) register(ctx context.Context) error {
	a.detectNow(ctx)
	var ans HostAnswer
	if err := a.API.Plugin(ctx, http.MethodPost, "host/register", a.body(true), &ans); err != nil {
		a.mu.Lock()
		a.registered = false
		a.problem = api.CodeOf(err)
		if a.problem == "" {
			a.problem = "unreachable"
		}
		a.mu.Unlock()
		return err
	}
	a.mu.Lock()
	a.registered, a.host, a.problem, a.lastOK = true, ans, "", a.now()
	a.shareMode, a.allowOpen = ans.Host.ShareMode, ans.Host.AllowOpen
	if a.st.DeviceID != ans.Host.DeviceID {
		a.st.DeviceID = ans.Host.DeviceID
		_ = a.Store.SaveState(a.st)
	}
	a.mu.Unlock()
	a.Log.Info("registered with Fernzugriff", "device", ans.Host.DeviceID, "state", ans.Host.State, "shareMode", ans.Host.ShareMode)
	// the hub may only be known now: SSH from it
	if err := a.FW.Setup(ctx, a.spec()); err != nil {
		a.Log.Error("firewall not set up", "err", err)
	}
	a.restoreRules(ctx)
	a.refreshCode(ctx)
	return nil
}

func (a *Agent) backoff(n int) time.Duration {
	d := a.Timing.RetryMin << min(n, 20)
	if d > a.Timing.RetryMax || d <= 0 {
		d = a.Timing.RetryMax
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1)) // #nosec G404 -- jitter only
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// registerLoop registers, then beats; it registers again when the plugin forgets the device.
func (a *Agent) registerLoop(ctx context.Context) {
	fails := 0
	for ctx.Err() == nil {
		err := a.register(ctx)
		if err != nil {
			code := api.CodeOf(err)
			wait := a.backoff(fails)
			fails++
			if unavailable[code] {
				wait = a.Timing.PluginRetry
				a.Log.Warn("plugin Fernzugriff not available — only the VPN runs", "code", code)
			} else {
				a.Log.Warn("registering failed", "code", code, "err", err)
			}
			if !sleep(ctx, wait) {
				return
			}
			continue
		}
		fails = 0
		for ctx.Err() == nil {
			if !sleep(ctx, a.Timing.Heartbeat) {
				return
			}
			if err := a.heartbeat(ctx); err != nil {
				if c := api.CodeOf(err); c == "not_found" || unavailable[c] {
					break // register again
				}
				a.Log.Warn("heartbeat failed", "code", api.CodeOf(err), "err", err)
			}
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context) error {
	a.detectNow(ctx)
	var ans StateAnswer
	if err := a.API.Plugin(ctx, http.MethodPost, "host/state", a.body(false), &ans); err != nil {
		return err
	}
	a.mu.Lock()
	a.lastOK = a.now()
	a.shareMode, a.allowOpen = ans.ShareMode, ans.AllowOpen
	a.mu.Unlock()
	for _, r := range ans.Pending {
		a.onRequest(ctx, r)
	}
	a.expireWaiting()
	a.mu.Lock()
	needCode := a.code == nil || !a.code.ExpiresAt.After(a.now())
	a.mu.Unlock()
	if needCode {
		a.refreshCode(ctx)
	}
	return nil
}

// shared: something is offered (else no code is needed).
func (a *Agent) shared() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.registered && (a.cfg.SSH.Enabled || a.cfg.Desktop.Enabled)
}

// refreshCode fetches a new code (the plugin replaces the old one) and plans the next.
func (a *Agent) refreshCode(ctx context.Context) {
	if !a.shared() {
		return
	}
	var c struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := a.API.Plugin(ctx, http.MethodPost, "host/code", nil, &c); err != nil {
		a.Log.Warn("no new code", "code", api.CodeOf(err))
		return
	}
	exp, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil {
		exp = a.now().Add(10 * time.Minute)
	}
	a.mu.Lock()
	a.code = &Code{Code: c.Code, ExpiresAt: exp}
	if a.codeTimer != nil {
		a.codeTimer.Stop()
	}
	d := exp.Sub(a.now()) + time.Second
	if d < time.Second {
		d = time.Second
	}
	a.codeTimer = time.AfterFunc(d, func() {
		if ctx.Err() == nil {
			a.refreshCode(ctx)
		}
	})
	a.mu.Unlock()
	a.Log.Info("new code ready", "until", exp.Format(time.RFC3339))
}

// configLoop applies a changed WireGuard config (key rotation).
func (a *Agent) configLoop(ctx context.Context) {
	for sleep(ctx, a.Timing.ConfigCheck) {
		a.mu.Lock()
		peer, hash, subnet := a.st.PeerID, a.wgc.Hash, a.cfg.Subnet
		a.mu.Unlock()
		ans, err := a.API.ConfigCheck(ctx, peer, hash)
		if err != nil {
			a.Log.Debug("config check failed", "code", api.CodeOf(err))
			continue
		}
		if !ans.Updated || ans.Config == "" {
			continue
		}
		w, _, err := wg.Parse(ans.Config, subnet, ans.Hash)
		if err != nil {
			a.Log.Warn("new WireGuard config not usable", "err", err)
			continue
		}
		if err := a.Store.SaveWG(w); err != nil {
			a.Log.Error("WireGuard config not stored", "err", err)
			continue
		}
		a.mu.Lock()
		a.wgc = w
		mode := a.cfg.WGMode
		a.mu.Unlock()
		if mode == config.WGQuick {
			a.Log.Warn("WireGuard config changed — run: sudo gatecontrol-agent wg-sync")
			continue
		}
		if err := a.tunnelUp(); err != nil {
			a.Log.Error("WireGuard not updated", "err", err)
		} else {
			a.Log.Info("WireGuard config updated")
		}
	}
}

// pushLoop keeps the push stream open.
func (a *Agent) pushLoop(ctx context.Context) {
	fails := 0
	for ctx.Err() == nil {
		a.mu.Lock()
		last := a.st.LastSeq
		a.push = "connecting"
		a.mu.Unlock()
		opened := a.now()
		err := a.API.Stream(ctx, last, func(n api.Notification) { a.onNotification(ctx, n) })
		if ctx.Err() != nil {
			return
		}
		code := api.CodeOf(err)
		a.mu.Lock()
		a.push = "disconnected"
		if code != "" {
			a.push = code
		}
		a.mu.Unlock()
		if a.now().Sub(opened) > time.Minute {
			fails = 0
		}
		wait := a.backoff(fails)
		fails++
		switch code {
		case "http_404", "push_disabled", "direct_not_allowed":
			wait = a.Timing.PluginRetry
			a.Log.Warn("push stream not available — signals come with the heartbeat", "code", code)
		case "http_401", "token_required", "invalid_token":
			wait = a.Timing.PluginRetry
			a.Log.Error("the server refused the token — set the device up again (gatecontrol-agent enroll)")
		default:
			a.Log.Debug("push stream ended", "code", code, "err", err)
		}
		if !sleep(ctx, wait) {
			return
		}
	}
}

func (a *Agent) onNotification(ctx context.Context, n api.Notification) {
	a.mu.Lock()
	a.push = "connected"
	if n.Seq > 0 {
		a.acks = append(a.acks, n.Seq)
	}
	fresh := n.Seq == 0 || n.Seq > a.st.LastSeq
	if fresh && n.Seq > 0 {
		a.st.LastSeq = n.Seq
		_ = a.Store.SaveState(a.st)
	}
	acks := a.acks
	a.acks = nil
	a.mu.Unlock()
	if len(acks) > 0 {
		go func() {
			if err := a.API.Ack(ctx, acks); err != nil {
				a.Log.Debug("push ack failed", "code", api.CodeOf(err))
			}
		}()
	}
	if !fresh || n.Kind != "data" || n.Topic != api.SignalTopic || len(n.Data) == 0 {
		return
	}
	var s Signal
	if err := json.Unmarshal(n.Data, &s); err != nil {
		return
	}
	s.Raw = n.Data
	a.onSignal(ctx, s)
}

// onSignal handles one signal of the plugin.
func (a *Agent) onSignal(ctx context.Context, s Signal) {
	switch s.Type {
	case "remote.request":
		var r Request
		if json.Unmarshal(s.Raw, &r) == nil {
			a.onRequest(ctx, r)
		}
	case "remote.request.cancel":
		a.mu.Lock()
		delete(a.waiting, s.RequestID)
		a.mu.Unlock()
	case "remote.firewall.open":
		a.openRule(ctx, s.SessionKey, s.Allow, s.Port, s.Until)
	case "remote.firewall.close":
		a.closeRule(ctx, s.SessionKey, true)
	case "remote.code.void":
		a.refreshCode(ctx)
	}
}

func (a *Agent) onRequest(ctx context.Context, r Request) {
	if r.RequestID == "" || len(r.RequestID) > 64 {
		return
	}
	exp, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil {
		exp = a.now().Add(a.Timing.RequestWait)
	}
	a.mu.Lock()
	confirm := a.cfg.Confirm
	_, known := a.waiting[r.RequestID]
	if !known {
		a.waiting[r.RequestID] = pending{req: r, expires: exp}
	}
	a.mu.Unlock()
	if known {
		return
	}
	a.Log.Info("request", "id", r.RequestID, "from", r.From.Name, "kind", r.Kind, "mode", r.Mode, "via", r.Via)
	if confirm != config.ConfirmCode {
		// the default: the person at the device confirms within 30 s
		a.Log.Warn("request waits for confirmation — run: sudo gatecontrol-agent allow "+r.RequestID+" (or deny)", "from", r.From.Name, "kind", r.Kind)
		return
	}
	// confirm "code", set on purpose: the person here handed out the code — the consent for this one session
	if err := a.decide(ctx, r.RequestID, "allow", r.Mode); err != nil {
		a.Log.Warn("request not answered", "id", r.RequestID, "code", api.CodeOf(err))
	}
}

func (a *Agent) decide(ctx context.Context, id, decision, mode string) error {
	a.mu.Lock()
	p, ok := a.waiting[id]
	delete(a.waiting, id)
	a.mu.Unlock()
	if !ok {
		return errors.New("request_expired")
	}
	body := map[string]string{"decision": decision}
	if decision == "allow" {
		if mode != "view" {
			mode = p.req.Mode
		}
		if mode != "" {
			body["mode"] = mode
		}
	}
	err := a.API.Plugin(ctx, http.MethodPost, "host/requests/"+id, body, nil)
	if err == nil {
		a.Log.Info("request answered", "id", id, "decision", decision, "mode", body["mode"])
	}
	return err
}

func (a *Agent) expireWaiting() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, p := range a.waiting {
		if !p.expires.After(a.now()) {
			delete(a.waiting, id)
		}
	}
}

func (a *Agent) report(ctx context.Context, key, state, reason string) {
	body := map[string]string{"sessionKey": key, "state": state}
	if reason != "" {
		body["reason"] = reason
	}
	if err := a.API.Plugin(ctx, http.MethodPost, "host/firewall", body, nil); err != nil {
		a.Log.Warn("firewall state not reported", "state", state, "code", api.CodeOf(err))
	}
}

func (a *Agent) openRule(ctx context.Context, key, allow string, port int, until string) {
	if !fw.SessionKeyRE.MatchString(key) {
		return
	}
	a.mu.Lock()
	deskOn, deskPort := a.cfg.Desktop.Enabled && a.desk.Offered, a.desk.Port
	a.mu.Unlock()
	if !deskOn || port != deskPort {
		a.report(ctx, key, "failed", "port_not_shared")
		return
	}
	u, err := time.Parse(time.RFC3339Nano, until)
	if err != nil {
		u = a.now().Add(fw.MaxRule)
	}
	if err := a.FW.Open(ctx, key, allow, port, u); err != nil {
		reason := "nft"
		if errors.Is(err, fw.ErrInvalid) {
			reason = "invalid"
		}
		a.Log.Warn("rule not opened", "reason", reason, "err", err)
		a.report(ctx, key, "failed", reason)
		return
	}
	a.Log.Info("desktop open for one session", "allow", allow, "port", port)
	a.report(ctx, key, "open", "")
}

func (a *Agent) closeRule(ctx context.Context, key string, report bool) {
	if !fw.SessionKeyRE.MatchString(key) {
		return
	}
	_ = a.FW.Close(ctx, key)
	if report {
		a.report(ctx, key, "closed", "")
		// the session is over: a new code
		a.refreshCode(ctx)
	}
}

// restoreRules: the rules the plugin still wants after a start (the table was emptied).
func (a *Agent) restoreRules(ctx context.Context) {
	var ans struct {
		Open []struct {
			SessionKey string `json:"sessionKey"`
			Allow      string `json:"allow"`
			Port       int    `json:"port"`
			Until      string `json:"until"`
		} `json:"open"`
	}
	if err := a.API.Plugin(ctx, http.MethodGet, "host/firewall", nil, &ans); err != nil {
		return
	}
	for _, r := range ans.Open {
		a.openRule(ctx, r.SessionKey, r.Allow, r.Port, r.Until)
	}
}

// Status for the CLI.
func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Status{Version: version.Version, Since: a.since, Server: a.cfg.Server, Name: a.cfg.Name, DeviceID: a.st.DeviceID, Registered: a.registered,
		State: a.host.Host.State, Problem: a.problem, ShareMode: a.shareMode, AllowOpen: a.allowOpen, Confirm: a.cfg.Confirm,
		SSH: a.reports, Desktop: a.desk, Sessions: len(a.FW.Keys()), LastContact: a.lastOK, Push: a.push,
		VPN: VPNStatus{Interface: a.cfg.Interface, Mode: a.cfg.WGMode}}
	if a.code != nil && a.code.ExpiresAt.After(a.now()) {
		c := *a.code
		s.Code = &c
	}
	t := a.Tunnel.Read(a.cfg.Interface)
	s.VPN.Up, s.VPN.Address = t.Up, t.Address
	if t.LastHandshake > 0 {
		s.VPN.LastHandshake = time.Unix(t.LastHandshake, 0)
	}
	s.Requests = a.pendingLocked()
	return s
}

func (a *Agent) pendingLocked() []PendingView {
	out := []PendingView{}
	for id, p := range a.waiting {
		if p.expires.After(a.now()) {
			out = append(out, PendingView{ID: id, From: p.req.From.Name, Mode: p.req.Mode, Kind: p.req.Kind, ExpiresAt: p.expires})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

// handle answers the CLI.
func (a *Agent) handle(ctx context.Context, req ctl.Request, _ bool) (any, error) {
	switch req.Op {
	case "status":
		return a.Status(), nil
	case "code":
		s := a.Status()
		if s.Code == nil {
			if !a.shared() {
				return nil, errors.New("nothing_shared")
			}
			a.refreshCode(ctx)
			s = a.Status()
			if s.Code == nil {
				return nil, errors.New("no_code")
			}
		}
		return s.Code, nil
	case "requests":
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.pendingLocked(), nil
	case "allow", "deny":
		var d Decision
		if err := json.Unmarshal(req.Args, &d); err != nil || d.ID == "" {
			return nil, errors.New("invalid")
		}
		mode := ""
		if d.View {
			mode = "view"
		}
		if err := a.decide(ctx, d.ID, req.Op, mode); err != nil {
			return nil, err
		}
		return map[string]bool{"done": true}, nil
	case "reload":
		var o struct {
			SetShare bool `json:"setShare"`
		}
		if len(req.Args) > 0 {
			_ = json.Unmarshal(req.Args, &o)
		}
		return a.reload(ctx, o.SetShare)
	case "unregister":
		err := a.API.Plugin(ctx, http.MethodDelete, "host", nil, nil)
		a.mu.Lock()
		a.registered = false
		a.mu.Unlock()
		_ = a.FW.Teardown(ctx)
		return map[string]bool{"removed": err == nil}, err
	}
	return nil, fmt.Errorf("unknown op %q", req.Op)
}

// reload: the CLI changed agent.json — read it, set up the firewall, register again; setShare: the CLI
// switched "share open|code" (else a choice made in the portal stays).
func (a *Agent) reload(ctx context.Context, setShare bool) (*ReloadAnswer, error) {
	cfg, err := a.Store.LoadAgent()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	if err := a.register(ctx); err != nil {
		return nil, err
	}
	if setShare && cfg.ShareMode != a.shareModeNow() {
		if err := a.API.Plugin(ctx, http.MethodPut, "host/share", map[string]string{"shareMode": cfg.ShareMode}, nil); err != nil {
			return nil, err
		}
		a.mu.Lock()
		a.shareMode = cfg.ShareMode
		a.mu.Unlock()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r := &ReloadAnswer{DeviceID: a.host.Host.DeviceID, State: a.host.Host.State, ShareMode: a.shareMode}
	if h := a.host.Host.SSH; h != nil && h.Offered {
		r.SSHUser, r.SSHPublicKey, r.SSHFrom = h.User, h.PublicKey, h.From
	}
	return r, nil
}

func (a *Agent) shareModeNow() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.shareMode
}
