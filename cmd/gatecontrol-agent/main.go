// Command gatecontrol-agent is the Linux agent of GateControl's "Fernzugriff":
//
//	sudo gatecontrol-agent enroll https://gate.example.org 7F3A-91C2-0B5D-E448
//	sudo gatecontrol-agent share ssh --as pi --tmux
//	sudo gatecontrol-agent share desktop
//	gatecontrol-agent status | code | requests
//	sudo gatecontrol-agent allow <id> [--view] | deny <id>
//	sudo gatecontrol-agent unenroll
//	gatecontrol-agent run          (the systemd service)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/api"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/ctl"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/version"
)

// Exit codes (contract stage 4, section 10).
const (
	exitOK          = 0
	exitUsage       = 1
	exitRejected    = 2
	exitNetwork     = 3
	exitNotEnrolled = 4
	exitDaemon      = 5
)

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, msg string) error { return &exitError{code, msg} }

// app holds what the commands share (tests replace it).
type app struct {
	out, errw io.Writer
	store     config.Store
	lang      string
	uid       int
	sys       system
}

func main() {
	a := &app{out: os.Stdout, errw: os.Stderr, store: config.Store{P: config.DefaultPaths()}, lang: langOf(os.Getenv), uid: os.Getuid(), sys: hostSystem{}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := a.main(ctx, os.Args[1:])
	stop()
	os.Exit(a.exitCode(err))
}

func (a *app) exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	var e *exitError
	if errors.As(err, &e) {
		if e.msg != "" {
			fmt.Fprintln(a.errw, e.msg)
		}
		return e.code
	}
	fmt.Fprintln(a.errw, err)
	return exitUsage
}

func langOf(getenv func(string) string) string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := getenv(k); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "de") {
				return "de"
			}
			return "en"
		}
	}
	return "en"
}

// t picks the German or English text.
func (a *app) t(de, en string) string {
	if a.lang == "de" {
		return de
	}
	return en
}

func (a *app) usage() string {
	return a.t(`gatecontrol-agent – GateControl-Fernzugriff für Linux

  sudo gatecontrol-agent enroll <server> <code> [--name NAME] [--wg netlink|wg-quick]
  sudo gatecontrol-agent share ssh --as KONTO [--tmux] [--install-tmux] | share ssh off
  sudo gatecontrol-agent share desktop [--kind KIND] [--port PORT] | share desktop off
  sudo gatecontrol-agent share open | share code      (ohne Code für Berechtigte / nur mit Code)
  sudo gatecontrol-agent confirm ask|code             (Standard ask: jede Anfrage am Gerät bestätigen)
       gatecontrol-agent status [--json] | code | requests
  sudo gatecontrol-agent allow <id> [--view] | deny <id>
  sudo gatecontrol-agent wg-sync | unenroll
       gatecontrol-agent run | version`,
		`gatecontrol-agent – GateControl remote access for Linux

  sudo gatecontrol-agent enroll <server> <code> [--name NAME] [--wg netlink|wg-quick]
  sudo gatecontrol-agent share ssh --as ACCOUNT [--tmux] [--install-tmux] | share ssh off
  sudo gatecontrol-agent share desktop [--kind KIND] [--port PORT] | share desktop off
  sudo gatecontrol-agent share open | share code      (no code for permitted people / code only)
  sudo gatecontrol-agent confirm ask|code             (default ask: confirm every request at the device)
       gatecontrol-agent status [--json] | code | requests
  sudo gatecontrol-agent allow <id> [--view] | deny <id>
  sudo gatecontrol-agent wg-sync | unenroll
       gatecontrol-agent run | version`)
}

func (a *app) main(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(a.errw, a.usage())
		return fail(exitUsage, "")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "enroll":
		return a.enroll(ctx, rest)
	case "status":
		return a.status(ctx, rest)
	case "share":
		return a.share(ctx, rest)
	case "confirm":
		return a.confirm(ctx, rest)
	case "code":
		return a.code(ctx)
	case "requests":
		return a.requests(ctx)
	case "allow", "deny":
		return a.decide(ctx, cmd, rest)
	case "unenroll":
		return a.unenroll(ctx, rest)
	case "wg-sync":
		return a.wgSync(ctx)
	case "run":
		return a.run(ctx)
	case "version", "--version", "-v":
		fmt.Fprintln(a.out, "gatecontrol-agent", version.Version)
		return nil
	case "help", "--help", "-h":
		fmt.Fprintln(a.out, a.usage())
		return nil
	}
	fmt.Fprintln(a.errw, a.usage())
	return fail(exitUsage, "")
}

func (a *app) needRoot() error {
	if a.uid != 0 {
		return fail(exitUsage, a.t("Dafür braucht es root: sudo gatecontrol-agent …", "This needs root: sudo gatecontrol-agent …"))
	}
	return nil
}

// call talks to the service.
func (a *app) call(ctx context.Context, op string, args, out any) error {
	err := ctl.Call(ctx, a.store.P.Socket(), op, args, out)
	if errors.Is(err, ctl.ErrUnreachable) {
		return fail(exitDaemon, a.t("Der Dienst gatecontrol-agent antwortet nicht (systemctl status gatecontrol-agent).",
			"The service gatecontrol-agent does not answer (systemctl status gatecontrol-agent)."))
	}
	if err != nil {
		return a.explain(err)
	}
	return nil
}

// explain turns a code of the server or the service into a sentence.
func (a *app) explain(err error) error {
	code := api.CodeOf(err)
	if code == "" {
		code = err.Error()
	}
	texts := map[string][2]string{
		"invalid_or_expired":   {"Der Code stimmt nicht, ist abgelaufen oder wurde schon benutzt. Erzeuge unter „Meine Geräte › Gerät hinzufügen“ einen neuen.", "The code is wrong, expired or already used. Create a new one under “My devices › Add device”."},
		"fingerprint_required": {"Der Server verlangt eine Gerätebindung, die nicht passt.", "The server requires a device binding that does not match."},
		"user_disabled":        {"Dein Konto ist deaktiviert.", "Your account is disabled."},
		"limit_reached":        {"Die Lizenz erlaubt keine weiteren Geräte.", "The licence allows no more devices."},
		"no_valid_scopes":      {"Der Code gibt keine App-Rechte.", "The code grants no app rights."},
		"no_share_right":       {"Du darfst keine eigenen Geräte freigeben (Recht „Eigene Geräte freigeben“ beim Admin).", "You may not share own devices (ask an administrator for “Share own devices”)."},
		"no_vpn":               {"Das Gerät hat keine VPN-Adresse (Token ohne Peer).", "The device has no VPN address (token without a peer)."},
		"not_allowed":          {"Der Admin hat „Ohne Code“ für dieses Gerät gesperrt.", "An administrator locked “no code” for this device."},
		"not_root":             {"Dafür braucht es root: sudo gatecontrol-agent …", "This needs root: sudo gatecontrol-agent …"},
		"request_expired":      {"Die Anfrage ist abgelaufen.", "The request has expired."},
		"nothing_shared":       {"Nichts freigegeben: erst „share ssh“ oder „share desktop“.", "Nothing shared: run “share ssh” or “share desktop” first."},
		"http_404":             {"Das Plugin „Fernzugriff“ ist auf dem Server nicht installiert oder zu alt (ab 1.6.0).", "The plugin “Remote access” is not installed on the server or too old (1.6.0 or later)."},
		"not_running":          {"Das Plugin „Fernzugriff“ läuft nicht.", "The plugin “Remote access” is not running."},
		"not_enrolled":         {"Nicht eingerichtet: sudo gatecontrol-agent enroll <server> <code>", "Not set up: sudo gatecontrol-agent enroll <server> <code>"},
	}
	if t, ok := texts[code]; ok {
		c := exitRejected
		switch code {
		case "not_enrolled":
			c = exitNotEnrolled
		case "not_root":
			c = exitUsage
		}
		return fail(c, a.t(t[0], t[1])+" ("+code+")")
	}
	var e *api.Error
	if errors.As(err, &e) {
		return fail(exitRejected, a.t("Vom Server abgelehnt: ", "Refused by the server: ")+e.Error())
	}
	return fail(exitRejected, err.Error())
}
