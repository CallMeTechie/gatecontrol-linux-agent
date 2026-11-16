package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeadersAndEnroll(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Client-Platform") != "linux" || !strings.HasPrefix(r.Header.Get("User-Agent"), "gatecontrol-agent/") || r.Header.Get("X-Machine-Fingerprint") != "fp" {
			t.Errorf("headers %v", r.Header)
		}
		var b EnrollRequest
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Platform != "linux" || b.Code != "7F3A-91C2-0B5D-E448" {
			t.Errorf("body %+v", b)
		}
		_, _ = w.Write([]byte(`{"ok":true,"token":"tok","peerId":4,"peerName":"pi","config":"[Interface]","hash":"h","vpn":{"subnet":"10.8.0.0/24","gateway":"10.8.0.1"}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "", "fp")
	c.HTTP = srv.Client()
	r, err := c.Enroll(context.Background(), "7F3A-91C2-0B5D-E448", "pi")
	if err != nil || r.Token != "tok" || r.VPN.Gateway != "10.8.0.1" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Token") != "tok" {
			t.Error("token missing")
		}
		switch r.URL.Path {
		case "/api/v1/client/plugins/gatecontrol-remote/api/host/register":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"ok":false,"code":"no_share_right","error":"Du darfst keine Geräte freigeben."}`))
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_or_expired"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "tok", "")
	err := c.Plugin(context.Background(), "POST", "host/register", map[string]any{}, nil)
	if CodeOf(err) != "no_share_right" {
		t.Fatalf("%v", err)
	}
	_, err = c.Enroll(context.Background(), "x", "y")
	if CodeOf(err) != "invalid_or_expired" {
		t.Fatalf("%v", err)
	}
}

func TestParseSSE(t *testing.T) {
	in := ": hi\n\nevent: hello\ndata: {\"keepalive_s\":25}\n\nid: 7\nevent: notification\ndata: {\"topic\":\"" + SignalTopic + "\",\n" +
		"data: \"kind\":\"data\",\"data\":{\"type\":\"remote.code.void\"}}\n\n"
	var got []Event
	if err := ParseSSE(strings.NewReader(in), func(e Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].Name != "hello" || got[2].ID != "7" || !strings.Contains(got[2].Data, "remote.code.void") {
		t.Fatalf("%+v", got)
	}
}

func TestStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Last-Event-ID") != "5" {
			t.Errorf("last event id %q", r.Header.Get("Last-Event-ID"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: hello\ndata: {\"keepalive_s\":25}\n\n")
		fmt.Fprintf(w, "id: 6\nevent: notification\ndata: {\"topic\":%q,\"kind\":\"data\",\"data\":{\"type\":\"remote.code.void\"}}\n\n", SignalTopic)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok", "")
	var ns []Notification
	err := c.Stream(context.Background(), 5, func(n Notification) { ns = append(ns, n) })
	if err == nil || len(ns) != 1 || ns[0].Seq != 6 || ns[0].Topic != SignalTopic {
		t.Fatalf("%v %+v", err, ns)
	}
}

func TestFingerprint(t *testing.T) {
	f := t.TempDir() + "/machine-id"
	_ = writeFile(f, "abc\n")
	a, b := Fingerprint(f), Fingerprint(f)
	if a != b || len(a) != 64 {
		t.Fatal(a)
	}
}
