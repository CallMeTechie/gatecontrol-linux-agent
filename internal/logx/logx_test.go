package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactsSecrets(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, slog.LevelDebug, true)
	l.Info("enrolled", "token", "gc_abcdef", "server", "https://gate.example.org",
		slog.Group("wg", "privateKey", "AAAA", "address", "10.8.0.41"), "shareCode", "482913075")
	l.With("apiToken", "x1").Warn("later", "Fingerprint", "f00")
	out := b.String()
	for _, s := range []string{"gc_abcdef", "AAAA", "482913075", "x1", "f00"} {
		if strings.Contains(out, s) {
			t.Fatalf("secret %q in log: %s", s, out)
		}
	}
	for _, s := range []string{"gate.example.org", "10.8.0.41", Redacted} {
		if !strings.Contains(out, s) {
			t.Fatalf("missing %q in log: %s", s, out)
		}
	}
	if strings.Contains(out, "time=") {
		t.Fatalf("quiet logger wrote a time: %s", out)
	}
}

func TestIsSecretKey(t *testing.T) {
	for k, want := range map[string]bool{"token": true, "hostKey": true, "server": false, "deviceId": false, "CODE": true} {
		if IsSecretKey(k) != want {
			t.Errorf("IsSecretKey(%q) = %v", k, !want)
		}
	}
}
