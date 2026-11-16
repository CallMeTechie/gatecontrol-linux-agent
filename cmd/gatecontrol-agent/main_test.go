package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/agent"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/api"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
)

func testApp(t *testing.T, lang string, uid int) (*app, *bytes.Buffer, *bytes.Buffer) {
	d := t.TempDir()
	var o, e bytes.Buffer
	return &app{out: &o, errw: &e, store: config.Store{P: config.Paths{Etc: d, State: d, Run: d}}, lang: lang, uid: uid, sys: hostSystem{}}, &o, &e
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{"7f3a 91c2 0b5d e448": "7F3A-91C2-0B5D-E448", "7F3A-91C2-0B5D-E448": "7F3A-91C2-0B5D-E448", "7f3a91c20b5de448": "7F3A-91C2-0B5D-E448"} {
		if got, ok := normalizeCode(in); !ok || got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
	if _, ok := normalizeCode("7F3A-91C2"); ok {
		t.Error("short code accepted")
	}
}

func TestLang(t *testing.T) {
	env := map[string]string{"LANG": "de_DE.UTF-8"}
	if langOf(func(k string) string { return env[k] }) != "de" {
		t.Fatal("de")
	}
	env = map[string]string{"LC_ALL": "C", "LANG": "de_DE.UTF-8"}
	if langOf(func(k string) string { return env[k] }) != "en" {
		t.Fatal("LC_ALL wins")
	}
}

func TestNeedsRootAndUsage(t *testing.T) {
	a, _, _ := testApp(t, "de", 1000)
	if code := a.exitCode(a.main(context.Background(), []string{"share", "open"})); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if code := a.exitCode(a.main(context.Background(), []string{"enroll", "https://g.example", "7F3A-91C2-0B5D-E448"})); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if code := a.exitCode(a.main(context.Background(), []string{"bogus"})); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
}

func TestStatusWithoutDaemon(t *testing.T) {
	a, _, e := testApp(t, "en", 1000)
	if code := a.exitCode(a.main(context.Background(), []string{"status"})); code != exitNotEnrolled {
		t.Fatalf("exit %d (%s)", code, e.String())
	}
	_ = a.store.SaveToken("x")
	if code := a.exitCode(a.main(context.Background(), []string{"status"})); code != exitDaemon {
		t.Fatalf("exit %d", code)
	}
}

func TestExplain(t *testing.T) {
	a, _, _ := testApp(t, "de", 0)
	err := a.explain(&api.Error{Status: 403, Code: "no_share_right"})
	var x *exitError
	if !errors.As(err, &x) || x.code != exitRejected || !strings.Contains(x.msg, "freigeben") {
		t.Fatalf("%v", err)
	}
}

func TestRenderStatus(t *testing.T) {
	a, o, _ := testApp(t, "de", 0)
	now := time.Now()
	s := agent.Status{Version: "1.0.0", Since: now.Add(-12 * 24 * time.Hour), Name: "pi-garten", DeviceID: 100007, Registered: true, ShareMode: "code", Confirm: "code",
		VPN: agent.VPNStatus{Up: true, Address: "10.8.0.41", LastHandshake: now.Add(-38 * time.Second)},
		SSH: agent.SSHInfo{Offered: true, User: "pi"}, Desktop: agent.DesktopInfo{Offered: true, Kind: "wayvnc", Protocol: "vnc", Port: 5900, Ready: true},
		Code: &agent.Code{Code: "228-610-975", ExpiresAt: now.Add(9*time.Minute + 30*time.Second)}}
	s.SSH.Tmux.Available, s.SSH.Tmux.Version = true, "3.3a"
	a.renderStatus(s, now)
	out := o.String()
	for _, want := range []string{"läuft seit 12 Tagen", "verbunden · 10.8.0.41 · Handshake vor 38 s", "als pi · tmux 3.3a · nur mit Code", "wayvnc · vnc 5900", "228 610 975", "noch 9 Min., einmalig"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
