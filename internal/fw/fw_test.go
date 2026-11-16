package fw

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type rec struct {
	mu      sync.Mutex
	scripts []string
}

func (r *rec) Run(_ context.Context, s string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scripts = append(r.scripts, s)
	return nil
}

func (r *rec) last() string { r.mu.Lock(); defer r.mu.Unlock(); return r.scripts[len(r.scripts)-1] }

func spec() Spec {
	return Spec{Interface: "wg-gc", SSHPort: 22, Desktop: []int{5900, 3389}, SSHFrom: netip.MustParseAddr("10.8.0.1"), Subnet: netip.MustParsePrefix("10.8.0.0/24")}
}

func TestRuleset(t *testing.T) {
	r := Ruleset(spec())
	for _, want := range []string{`iifname != "wg-gc" accept`, "tcp dport 22 ip saddr @ssh_from accept", "ip saddr . tcp dport @allow accept",
		"tcp dport { 22, 3389, 5900 } drop", "add element inet gatecontrol ssh_from { 10.8.0.1 }", "delete table inet gatecontrol", "flags timeout"} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q in\n%s", want, r)
		}
	}
	s := spec()
	s.SSHFrom = netip.Addr{}
	if strings.Contains(Ruleset(s), "add element") {
		t.Error("ssh_from filled without SSH share")
	}
}

func TestOpenClose(t *testing.T) {
	r := &rec{}
	f := New(r)
	ctx := context.Background()
	if err := f.Setup(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	if err := f.Open(ctx, "fw_aaaaaaaaaaaa", "10.8.0.1", 3389, until); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.last(), "add element inet gatecontrol allow { 10.8.0.1 . 3389 timeout ") {
		t.Fatal(r.last())
	}
	if err := f.Open(ctx, "fw_bbbbbbbbbbbb", "10.8.0.1", 3389, until); err != nil {
		t.Fatal(err)
	}
	n := len(r.scripts)
	if err := f.Close(ctx, "fw_aaaaaaaaaaaa"); err != nil || len(r.scripts) != n {
		t.Fatal("closing one of two sessions with the same pair must keep the element")
	}
	_ = f.Close(ctx, "fw_bbbbbbbbbbbb")
	if !strings.HasPrefix(r.last(), "delete element inet gatecontrol allow { 10.8.0.1 . 3389 }") {
		t.Fatal(r.last())
	}
	if len(f.Keys()) != 0 {
		t.Fatal("keys left")
	}
}

func TestOpenRejects(t *testing.T) {
	f := New(&rec{})
	ctx := context.Background()
	_ = f.Setup(ctx, spec())
	cases := []struct {
		key, ip string
		port    int
		want    error
	}{
		{"bad key", "10.8.0.1", 3389, ErrInvalid},
		{"fw_aaaaaaaaaaaa", "192.168.1.2", 3389, ErrInvalid},
		{"fw_aaaaaaaaaaaa", "10.8.0.1; flush ruleset", 3389, ErrInvalid},
		{"fw_aaaaaaaaaaaa", "fe80::1", 3389, ErrInvalid},
		{"fw_aaaaaaaaaaaa", "10.8.0.1", 22, ErrPort},
	}
	for _, c := range cases {
		if err := f.Open(ctx, c.key, c.ip, c.port, time.Now().Add(time.Hour)); err != c.want {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

func TestTimeoutCapped(t *testing.T) {
	r := &rec{}
	f := New(r)
	ctx := context.Background()
	_ = f.Setup(ctx, spec())
	_ = f.Open(ctx, "fw_aaaaaaaaaaaa", "10.8.0.7", 5900, time.Now().Add(48*time.Hour))
	if !strings.Contains(r.last(), "timeout 28800s") {
		t.Fatal(r.last())
	}
}
