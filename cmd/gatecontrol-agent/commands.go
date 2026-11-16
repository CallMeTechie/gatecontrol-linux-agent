package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/agent"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/api"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/detect"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/fw"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/logx"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/sshkeys"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/version"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/wg"
)

// ServiceAccount runs the service.
const ServiceAccount = "gatecontrol"

// system is what the commands do to the machine (tests replace it).
type system interface {
	ServiceUser() (uid, gid int, ok bool)
	Systemctl(ctx context.Context, args ...string) error
	InstallTmux(ctx context.Context) error
	Hostname() string
	Detect() *detect.System
	RemoveInterface(iface string) error
	QuickFile(iface string) string
}

type hostSystem struct{}

func (hostSystem) ServiceUser() (int, int, bool) {
	u, err := user.Lookup(ServiceAccount)
	if err != nil {
		return 0, 0, false
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, true
}

func (hostSystem) Systemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...) // #nosec G204 -- fixed program, fixed arguments
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
}

func (hostSystem) InstallTmux(ctx context.Context) error {
	var cmd *exec.Cmd
	switch {
	case have("apt-get"):
		cmd = exec.CommandContext(ctx, "apt-get", "install", "-y", "tmux")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	case have("pacman"):
		cmd = exec.CommandContext(ctx, "pacman", "-S", "--noconfirm", "--needed", "tmux")
	case have("dnf"):
		cmd = exec.CommandContext(ctx, "dnf", "install", "-y", "tmux")
	default:
		return errors.New("no apt-get, pacman or dnf")
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func have(p string) bool { _, err := exec.LookPath(p); return err == nil }

func (hostSystem) Hostname() string { h, _ := os.Hostname(); return h }

func (hostSystem) Detect() *detect.System { return detect.Host() }

func (hostSystem) RemoveInterface(iface string) error { return wg.Remove(iface) }

func (hostSystem) QuickFile(iface string) string { return "/etc/wireguard/" + iface + ".conf" }

// normalizeCode accepts the setup code as typed (lower case, spaces, no dashes).
func normalizeCode(s string) (string, bool) {
	h := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			return r
		case r >= 'a' && r <= 'f':
			return r - 32
		}
		return -1
	}, s)
	if len(h) != 16 {
		return "", false
	}
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16], true
}

// chownService hands a file of the state directory to the service account.
func (a *app) chownService(paths ...string) {
	uid, gid, ok := a.sys.ServiceUser()
	if !ok {
		return
	}
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
}

func (a *app) chgrpService(p string) {
	if _, gid, ok := a.sys.ServiceUser(); ok {
		_ = os.Chown(p, 0, gid)
	}
}

func (a *app) line(label, value string) {
	dots := 18 - len([]rune(label))
	if dots < 2 {
		dots = 2
	}
	fmt.Fprintf(a.out, "  %s %s %s\n", label, strings.Repeat(".", dots), value)
}

// ── enroll ──

func (a *app) enroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(a.errw)
	name := fs.String("name", "", "device name")
	mode := fs.String("wg", config.WGNetlink, "netlink | wg-quick")
	iface := fs.String("interface", "wg-gc", "WireGuard interface")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return fail(exitUsage, "")
	}
	if len(pos) != 2 {
		return fail(exitUsage, a.t("Aufruf: sudo gatecontrol-agent enroll <server> <code>", "Usage: sudo gatecontrol-agent enroll <server> <code>"))
	}
	if err := a.needRoot(); err != nil {
		return err
	}
	server, err := config.NormalizeServer(pos[0])
	if err != nil {
		return fail(exitUsage, a.t("Der Server muss eine https://-Adresse sein.", "The server must be an https:// address."))
	}
	code, ok := normalizeCode(pos[1])
	if !ok {
		return fail(exitUsage, a.t("Der Code hat die Form XXXX-XXXX-XXXX-XXXX.", "The code looks like XXXX-XXXX-XXXX-XXXX."))
	}
	if *mode != config.WGNetlink && *mode != config.WGQuick {
		return fail(exitUsage, "--wg netlink|wg-quick")
	}
	if !config.ValidInterface(*iface) {
		return fail(exitUsage, "--interface")
	}
	host := *name
	if host == "" {
		host = a.sys.Hostname()
	}
	for _, d := range []string{a.store.P.Etc, a.store.P.State} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	a.chgrpService(a.store.P.Etc)
	a.chownService(a.store.P.State)
	c := api.New(server, "", api.Fingerprint("/etc/machine-id"))
	ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := c.Enroll(ectx, code, host)
	if err != nil {
		if api.CodeOf(err) == "" {
			return fail(exitNetwork, a.t("Server nicht erreichbar: ", "Server not reachable: ")+err.Error())
		}
		return a.explain(err)
	}
	a.line("Server", strings.TrimPrefix(server, "https://")+"  ok")
	subnet, hub := "", ""
	if res.VPN != nil {
		subnet, hub = res.VPN.Subnet, res.VPN.Gateway
	}
	c.Token = res.Token
	if hub == "" {
		if ca, err := c.Config(ectx, res.PeerID); err == nil && ca.InternalDNS != nil {
			hub = ca.InternalDNS.Server
		}
	}
	w, fallback, err := wg.Parse(res.Config, subnet, res.Hash)
	if err != nil {
		return fail(exitRejected, err.Error())
	}
	if fallback {
		fmt.Fprintln(a.errw, a.t("Hinweis: der Server nennt sein VPN-Netz nicht – nehme "+w.AllowedIPs+".", "Note: the server does not name its VPN network — using "+w.AllowedIPs+"."))
	}
	if hub == "" {
		p, _ := netip.ParsePrefix(w.AllowedIPs)
		hub = p.Addr().Next().String()
	}
	old, _ := a.store.LoadAgent()
	cfg := &config.Agent{Server: server, Name: host, WGMode: *mode, Interface: *iface, Subnet: w.AllowedIPs, Hub: hub}
	if old != nil && old.Server == server {
		cfg.SSH, cfg.Desktop, cfg.ShareMode, cfg.Confirm = old.SSH, old.Desktop, old.ShareMode, old.Confirm
	}
	cfg.Defaults()
	if err := a.store.SaveToken(res.Token); err != nil {
		return err
	}
	if err := a.store.SaveWG(w); err != nil {
		return err
	}
	if err := a.store.SaveState(&config.State{PeerID: res.PeerID, PeerName: res.PeerName}); err != nil {
		return err
	}
	if err := a.store.SaveAgent(cfg); err != nil {
		return err
	}
	a.chownService(a.store.P.TokenFile(), a.store.P.WGFile(), a.store.P.StateFile())
	a.chgrpService(a.store.P.AgentFile())
	a.line(a.t("Gerätename", "Device name"), host)
	addr := strings.TrimSuffix(w.Address, "/32")
	if *mode == config.WGQuick {
		if err := a.writeQuick(ctx, cfg.Interface, w); err != nil {
			return fail(exitUsage, "WireGuard (wg-quick): "+err.Error())
		}
	}
	if err := a.sys.Systemctl(ctx, "enable", "gatecontrol-agent.service"); err == nil {
		_ = a.sys.Systemctl(ctx, "restart", "gatecontrol-agent.service")
	}
	a.line("WireGuard", cfg.Interface+" "+addr+"  ("+*mode+")")
	if k, err := a.sys.Detect().HostKeyOf(); err == nil {
		a.line(a.t("Host-Schlüssel", "Host key"), k.Alg+" SHA256:"+k.SHA256[:6]+"…  "+a.t("wird gemeldet", "reported"))
	} else {
		a.line(a.t("Host-Schlüssel", "Host key"), a.t("keiner (openssh-server fehlt?)", "none (openssh-server missing?)"))
	}
	fmt.Fprintln(a.out, a.t("\nWeiter: sudo gatecontrol-agent share ssh --as <konto> --tmux   und/oder   sudo gatecontrol-agent share desktop",
		"\nNext: sudo gatecontrol-agent share ssh --as <account> --tmux   and/or   sudo gatecontrol-agent share desktop"))
	return nil
}

func (a *app) writeQuick(ctx context.Context, iface string, w *config.WG) error {
	f := a.sys.QuickFile(iface)
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(f, []byte(wg.Quick(w)), 0o600); err != nil {
		return err
	}
	if err := a.sys.Systemctl(ctx, "enable", "wg-quick@"+iface+".service"); err != nil {
		return err
	}
	return a.sys.Systemctl(ctx, "restart", "wg-quick@"+iface+".service")
}

// parseInterspersed lets flags follow the positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// ── status / code / requests ──

func (a *app) status(ctx context.Context, args []string) error {
	asJSON := len(args) > 0 && args[0] == "--json"
	var s agent.Status
	if err := a.call(ctx, "status", nil, &s); err != nil {
		if _, err2 := a.store.LoadToken(); errors.Is(err2, config.ErrNotEnrolled) {
			return a.explain(config.ErrNotEnrolled)
		}
		return err
	}
	if asJSON {
		e := json.NewEncoder(a.out)
		e.SetIndent("", "  ")
		return e.Encode(s)
	}
	a.renderStatus(s, time.Now())
	return nil
}

func ago(d time.Duration, de bool) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		if de {
			return fmt.Sprintf("%d Std.", int(d.Hours()))
		}
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	if de {
		return fmt.Sprintf("%d Tagen", int(d.Hours()/24))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func (a *app) onOff(b bool) string {
	if b {
		return a.t("an", "on")
	}
	return a.t("aus", "off")
}

func (a *app) renderStatus(s agent.Status, now time.Time) {
	de := a.lang == "de"
	fmt.Fprintf(a.out, "  gatecontrol-agent %s · %s %s · %s\n", s.Version, a.t("läuft seit", "running for"), ago(now.Sub(s.Since), de), s.Name)
	vpn := a.t("nicht verbunden", "not connected")
	if s.VPN.Up {
		vpn = a.t("verbunden", "connected") + " · " + s.VPN.Address
		if !s.VPN.LastHandshake.IsZero() {
			vpn += " · " + a.t("Handshake vor ", "handshake ") + ago(now.Sub(s.VPN.LastHandshake), de) + a.t("", " ago")
		}
	}
	a.line("VPN", vpn)
	srv := a.t("nicht erreichbar", "not reachable")
	if s.Registered {
		srv = a.t("erreichbar", "reachable") + " · Fernzugriff · " + a.t("Gerät ", "device ") + strconv.Itoa(s.DeviceID)
	} else if s.Problem != "" {
		srv += " (" + s.Problem + ")"
	}
	a.line("Server", srv)
	fmt.Fprintln(a.out, a.t("\n  Freigaben", "\n  Shares"))
	mode := a.t("nur mit Code", "code only")
	if s.ShareMode == "open" {
		mode = a.t("ohne Code für Berechtigte", "no code for permitted people")
	}
	ssh := a.onOff(s.SSH.Offered)
	if s.SSH.Offered {
		ssh += " · " + a.t("als ", "as ") + s.SSH.User
		if s.SSH.Tmux.Available {
			ssh += " · tmux " + s.SSH.Tmux.Version
		} else {
			ssh += " · " + a.t("ohne tmux", "without tmux")
		}
		ssh += " · " + mode
	}
	a.line("  SSH", ssh)
	desk := a.onOff(s.Desktop.Offered)
	if s.Desktop.Offered {
		desk += " · " + s.Desktop.Kind + " · " + s.Desktop.Protocol + " " + strconv.Itoa(s.Desktop.Port)
		if !s.Desktop.Ready {
			desk += " · " + a.t("lauscht nicht", "not listening")
		}
		desk += " · " + mode
	} else if s.Desktop.Kind != "" {
		desk += " · " + a.t("gefunden: ", "found: ") + s.Desktop.Kind
	}
	a.line("  Desktop", desk)
	a.line(a.t("  Bestätigung", "  Confirmation"), map[string]string{"code": a.t("der Code genügt (ohne Rückfrage)", "the code is enough (no question)"), "ask": a.t("am Gerät (allow/deny)", "at the device (allow/deny)")}[s.Confirm])
	a.line(a.t("  Sitzungen", "  Sessions"), strconv.Itoa(s.Sessions))
	if s.Code != nil {
		left := int(s.Code.ExpiresAt.Sub(now).Minutes())
		fmt.Fprintf(a.out, "\n  %s  %s  (%s)\n", a.t("Code:", "Code:"), spaced(s.Code.Code), a.t(fmt.Sprintf("noch %d Min., einmalig", left), fmt.Sprintf("%d min left, single use", left)))
	}
	for _, r := range s.Requests {
		fmt.Fprintf(a.out, "  %s %s: %s %s (%s) – sudo gatecontrol-agent allow %s\n", a.t("Anfrage", "Request"), r.ID, r.From, r.Kind, r.Mode, r.ID)
	}
}

// spaced shows 482-913-075 as 482 913 075.
func spaced(c string) string { return strings.ReplaceAll(c, "-", " ") }

func (a *app) code(ctx context.Context) error {
	var c agent.Code
	if err := a.call(ctx, "code", nil, &c); err != nil {
		return err
	}
	left := int(time.Until(c.ExpiresAt).Minutes())
	fmt.Fprintf(a.out, "%s\n%s\n", spaced(c.Code), a.t(
		fmt.Sprintf("Nenne diesen Code der Person, die dir helfen soll. Er gilt noch %d Minuten und nur einmal.", left),
		fmt.Sprintf("Give this code to the person helping you. It is valid for %d more minutes and only once.", left)))
	var s agent.Status
	if a.call(ctx, "status", nil, &s) == nil && s.Confirm != config.ConfirmCode {
		fmt.Fprintln(a.out, a.t("Danach am Gerät bestätigen: sudo gatecontrol-agent allow <id> (gatecontrol-agent requests zeigt die Anfrage).",
			"Then confirm at the device: sudo gatecontrol-agent allow <id> (gatecontrol-agent requests shows the request)."))
	}
	return nil
}

func (a *app) requests(ctx context.Context) error {
	var rs []agent.PendingView
	if err := a.call(ctx, "requests", nil, &rs); err != nil {
		return err
	}
	if len(rs) == 0 {
		fmt.Fprintln(a.out, a.t("Keine wartende Anfrage.", "No waiting request."))
		return nil
	}
	for _, r := range rs {
		fmt.Fprintf(a.out, "%s  %s  %s  %s  %s\n", r.ID, r.From, r.Kind, r.Mode, a.t("bis ", "until ")+r.ExpiresAt.Local().Format("15:04:05"))
	}
	return nil
}

func (a *app) decide(ctx context.Context, op string, args []string) error {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	fs.SetOutput(a.errw)
	view := fs.Bool("view", false, "only view")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) != 1 {
		return fail(exitUsage, "gatecontrol-agent "+op+" <id>")
	}
	if err := a.needRoot(); err != nil {
		return err
	}
	if err := a.call(ctx, op, agent.Decision{ID: pos[0], View: *view}, nil); err != nil {
		return err
	}
	fmt.Fprintln(a.out, map[string]string{"allow": a.t("Erlaubt.", "Allowed."), "deny": a.t("Abgelehnt.", "Declined.")}[op])
	return nil
}

// ── share / confirm ──

func (a *app) share(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail(exitUsage, "gatecontrol-agent share ssh|desktop|open|code …")
	}
	if err := a.needRoot(); err != nil {
		return err
	}
	cfg, err := a.store.LoadAgent()
	if err != nil {
		return a.explain(err)
	}
	what, rest := args[0], args[1:]
	off := len(rest) > 0 && rest[0] == "off"
	prevUser := cfg.SSH.User
	switch what {
	case "ssh":
		if off {
			cfg.SSH.Enabled = false
			break
		}
		fs := flag.NewFlagSet("share ssh", flag.ContinueOnError)
		fs.SetOutput(a.errw)
		as := fs.String("as", "", "account")
		tm := fs.Bool("tmux", true, "use tmux")
		install := fs.Bool("install-tmux", false, "install tmux when missing")
		if err := fs.Parse(rest); err != nil {
			return fail(exitUsage, "")
		}
		if *as == "" {
			return fail(exitUsage, a.t("Welches Konto? --as <konto>", "Which account? --as <account>"))
		}
		if _, err := sshkeys.Lookup(*as); err != nil {
			return fail(exitUsage, err.Error())
		}
		if *install && !a.sys.Detect().TmuxOf(ctx).Available {
			if err := a.sys.InstallTmux(ctx); err != nil {
				fmt.Fprintln(a.errw, a.t("tmux nicht installiert: ", "tmux not installed: ")+err.Error())
			}
		}
		cfg.SSH = config.SSHShare{Enabled: true, User: *as, Port: cfg.SSH.Port, Tmux: *tm}
	case "desktop":
		if off {
			cfg.Desktop.Enabled = false
			break
		}
		fs := flag.NewFlagSet("share desktop", flag.ContinueOnError)
		fs.SetOutput(a.errw)
		kind := fs.String("kind", "", strings.Join(detect.Kinds, " | "))
		port := fs.Int("port", 0, "port")
		if err := fs.Parse(rest); err != nil {
			return fail(exitUsage, "")
		}
		if *kind != "" {
			if p, _ := detect.ProtocolOf(*kind); p == "" {
				return fail(exitUsage, "--kind "+strings.Join(detect.Kinds, "|"))
			}
		}
		if *port < 0 || *port > 65535 || *port == cfg.SSH.Port {
			return fail(exitUsage, "--port")
		}
		d := a.sys.Detect().DesktopOf(*kind, *port)
		if d.Kind == "" {
			return fail(exitUsage, a.t("Kein Desktop-Server gefunden (KRdp, GNOME Remote Desktop, wayvnc, xrdp, x11vnc). Ohne Desktop gibt es nur SSH.",
				"No desktop server found (KRdp, GNOME Remote Desktop, wayvnc, xrdp, x11vnc). Without a desktop there is SSH only."))
		}
		cfg.Desktop = config.DesktopShare{Enabled: true, Kind: *kind, Port: *port}
	case "open":
		cfg.ShareMode = "open"
	case "code":
		cfg.ShareMode = "code"
	default:
		return fail(exitUsage, "gatecontrol-agent share ssh|desktop|open|code …")
	}
	if err := a.store.SaveAgent(cfg); err != nil {
		return err
	}
	a.chgrpService(a.store.P.AgentFile())
	var r agent.ReloadAnswer
	if err := a.call(ctx, "reload", map[string]bool{"setShare": what == "open" || what == "code"}, &r); err != nil {
		return err
	}
	switch what {
	case "ssh":
		return a.applySSH(cfg, prevUser, r)
	case "desktop":
		if off {
			fmt.Fprintln(a.out, a.t("Desktop nicht mehr freigegeben.", "Desktop no longer shared."))
			return nil
		}
		var s agent.Status
		_ = a.call(ctx, "status", nil, &s)
		ready := a.t("bereit", "ready")
		if !s.Desktop.Ready {
			ready = a.t("lauscht noch nicht – Desktop-Server einschalten", "not listening yet — switch the desktop server on")
		}
		sess := s.Desktop.Session
		if sess == "" {
			sess = "-"
		}
		fmt.Fprintf(a.out, "  Desktop: %s (%s) · %s %d %s  %s\n", s.Desktop.Kind, sess, s.Desktop.Protocol, s.Desktop.Port, a.t("nur im VPN", "VPN only"), ready)
		if a.sys.Detect().UFWActive() {
			fmt.Fprintln(a.errw, a.t("Hinweis: ufw ist aktiv – erlaube eingehend auf "+cfg.Interface+" (ufw allow in on "+cfg.Interface+").",
				"Note: ufw is active — allow incoming on "+cfg.Interface+" (ufw allow in on "+cfg.Interface+")."))
		}
	case "open":
		fmt.Fprintln(a.out, a.t("Ohne Code für Berechtigte.", "No code for permitted people."))
	case "code":
		fmt.Fprintln(a.out, a.t("Nur mit Code.", "Code only."))
	}
	return nil
}

func (a *app) applySSH(cfg *config.Agent, prevUser string, r agent.ReloadAnswer) error {
	// a previous account loses GateControl's key
	if prevUser != "" && (prevUser != cfg.SSH.User || !cfg.SSH.Enabled) {
		if acc, err := sshkeys.Lookup(prevUser); err == nil {
			_ = sshkeys.Install(acc, "")
		}
	}
	if !cfg.SSH.Enabled {
		fmt.Fprintln(a.out, a.t("SSH nicht mehr freigegeben, Schlüssel von GateControl entfernt.", "SSH no longer shared, GateControl's key removed."))
		return nil
	}
	if r.SSHPublicKey == "" {
		return fail(exitRejected, a.t("Der Server hat keinen SSH-Schlüssel geliefert (Plugin „Fernzugriff“ ab 1.6.0?).", "The server handed no SSH key (plugin “Remote access” 1.6.0 or later?)."))
	}
	from, err := netip.ParseAddr(r.SSHFrom)
	if err != nil {
		from, err = netip.ParseAddr(cfg.Hub)
		if err != nil {
			return fail(exitRejected, "hub address")
		}
	}
	line, err := sshkeys.Line(r.SSHPublicKey, from, r.DeviceID)
	if err != nil {
		return fail(exitRejected, err.Error())
	}
	acc, err := sshkeys.Lookup(cfg.SSH.User)
	if err != nil {
		return fail(exitUsage, err.Error())
	}
	if err := sshkeys.Install(acc, line); err != nil {
		return fail(exitUsage, err.Error())
	}
	tm := a.sys.Detect().TmuxOf(context.Background())
	tmux := a.t("tmux fehlt (sudo gatecontrol-agent share ssh --as "+cfg.SSH.User+" --install-tmux)", "tmux missing (sudo gatecontrol-agent share ssh --as "+cfg.SSH.User+" --install-tmux)")
	if !cfg.SSH.Tmux {
		tmux = a.t("ohne tmux", "without tmux")
	} else if tm.Available {
		tmux = "tmux " + tm.Version + a.t(" gefunden", " found")
	}
	fmt.Fprintf(a.out, "  %s %s · %s · %s\n", a.t("SSH freigegeben für", "SSH shared for"), cfg.SSH.User, a.t("Schlüssel von GateControl eingetragen", "GateControl's key added"), tmux)
	return nil
}

func (a *app) confirm(ctx context.Context, args []string) error {
	if len(args) != 1 || (args[0] != config.ConfirmCode && args[0] != config.ConfirmAsk) {
		return fail(exitUsage, "gatecontrol-agent confirm code|ask")
	}
	if err := a.needRoot(); err != nil {
		return err
	}
	cfg, err := a.store.LoadAgent()
	if err != nil {
		return a.explain(err)
	}
	cfg.Confirm = args[0]
	if err := a.store.SaveAgent(cfg); err != nil {
		return err
	}
	a.chgrpService(a.store.P.AgentFile())
	if err := a.call(ctx, "reload", nil, nil); err != nil {
		return err
	}
	if cfg.Confirm == config.ConfirmCode {
		fmt.Fprintln(a.errw, a.t(
			"ACHTUNG: Ab jetzt genügt der Code. Wer ihn hat, verbindet sich ohne Rückfrage am Gerät. Nur für Geräte ohne Bildschirm, an denen niemand sitzt. Zurück: sudo gatecontrol-agent confirm ask",
			"WARNING: From now on the code is enough. Whoever has it connects without being asked at the device. Only for devices without a screen and nobody at them. Back: sudo gatecontrol-agent confirm ask"))
	} else {
		fmt.Fprintln(a.out, a.t("Jede Anfrage wird am Gerät bestätigt (gatecontrol-agent requests, allow, deny).", "Every request is confirmed at the device (gatecontrol-agent requests, allow, deny)."))
	}
	return nil
}

// ── unenroll / wg-sync ──

func (a *app) unenroll(ctx context.Context, _ []string) error {
	if err := a.needRoot(); err != nil {
		return err
	}
	cfg, err := a.store.LoadAgent()
	if err != nil {
		return a.explain(err)
	}
	if err := a.call(ctx, "unregister", nil, nil); err != nil {
		fmt.Fprintln(a.errw, a.t("Abmelden beim Plugin nicht möglich: ", "Could not sign off at the plugin: ")+err.Error())
	}
	_ = a.sys.Systemctl(ctx, "disable", "--now", "gatecontrol-agent.service")
	if cfg.SSH.User != "" {
		if acc, err := sshkeys.Lookup(cfg.SSH.User); err == nil {
			_ = sshkeys.Install(acc, "")
		}
	}
	if cfg.WGMode == config.WGQuick {
		_ = a.sys.Systemctl(ctx, "disable", "--now", "wg-quick@"+cfg.Interface+".service")
		_ = os.Remove(a.sys.QuickFile(cfg.Interface))
	}
	_ = a.sys.RemoveInterface(cfg.Interface)
	_ = fw.New(nil).Teardown(ctx)
	if err := a.store.RemoveAll(); err != nil {
		return err
	}
	fmt.Fprintln(a.out, a.t("Abgemeldet. Sperre das Gerät zusätzlich unter „Meine Geräte“, damit sein Token ungültig wird.",
		"Signed off. Also lock the device under “My devices” so its token becomes invalid."))
	return nil
}

func (a *app) wgSync(ctx context.Context) error {
	if err := a.needRoot(); err != nil {
		return err
	}
	cfg, err := a.store.LoadAgent()
	if err != nil {
		return a.explain(err)
	}
	if cfg.WGMode != config.WGQuick {
		return fail(exitUsage, a.t("Nur im Modus wg-quick nötig.", "Only needed in wg-quick mode."))
	}
	w, err := a.store.LoadWG()
	if err != nil {
		return a.explain(err)
	}
	return a.writeQuick(ctx, cfg.Interface, w)
}

// ── run (the service) ──

func (a *app) run(ctx context.Context) error {
	log := logx.New(a.errw, levelOf(os.Getenv("GATECONTROL_AGENT_LOG")), os.Getenv("JOURNAL_STREAM") != "")
	token, err := a.store.LoadToken()
	if err != nil {
		log.Error("not set up — run: sudo gatecontrol-agent enroll <server> <code>")
		return fail(exitNotEnrolled, "")
	}
	cfg, err := a.store.LoadAgent()
	if err != nil {
		log.Error("settings not readable", "err", err)
		return fail(exitNotEnrolled, "")
	}
	c := api.New(cfg.Server, token, api.Fingerprint("/etc/machine-id"))
	ag, err := agent.New(a.store, c, wg.Netlink{}, fw.New(nil), detect.Host(), log)
	if err != nil {
		log.Error("not set up", "err", err)
		return fail(exitNotEnrolled, "")
	}
	log.Info("gatecontrol-agent starting", "version", version.Version, "server", cfg.Server, "interface", cfg.Interface, "wg", cfg.WGMode)
	return ag.Run(ctx)
}

func levelOf(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	}
	return slog.LevelInfo
}
