package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/api"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/detect"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/fw"
	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/wg"
)

type call struct {
	method, path string
	body         map[string]any
}

type fakeAPI struct {
	mu     sync.Mutex
	calls  []call
	answer map[string]string // "METHOD path" → JSON
	errs   map[string]error
}

func (f *fakeAPI) Plugin(_ context.Context, method, path string, body, out any) error {
	var b map[string]any
	if body != nil {
		raw, _ := json.Marshal(body)
		_ = json.Unmarshal(raw, &b)
	}
	f.mu.Lock()
	f.calls = append(f.calls, call{method, path, b})
	key := method + " " + path
	ans, err := f.answer[key], f.errs[key]
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if out != nil && ans != "" {
		return json.Unmarshal([]byte(ans), out)
	}
	return nil
}

func (f *fakeAPI) ConfigCheck(context.Context, int, string) (*api.ConfigAnswer, error) {
	return &api.ConfigAnswer{}, nil
}
func (f *fakeAPI) Stream(ctx context.Context, _ int64, _ func(api.Notification)) error {
	<-ctx.Done()
	return ctx.Err()
}
func (f *fakeAPI) Ack(context.Context, []int64) error { return nil }

func (f *fakeAPI) find(method, path string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method == method && c.path == path {
			out = append(out, c)
		}
	}
	return out
}

type fakeTunnel struct{ applied int }

func (t *fakeTunnel) Apply(string, *config.WG) error { t.applied++; return nil }
func (t *fakeTunnel) Read(string) wg.Status          { return wg.Status{Up: true, Address: "10.8.0.41"} }
func (t *fakeTunnel) Remove(string) error            { return nil }

type nftRec struct {
	mu sync.Mutex
	s  []string
}

func (n *nftRec) Run(_ context.Context, s string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.s = append(n.s, s)
	return nil
}
func (n *nftRec) all() string { n.mu.Lock(); defer n.mu.Unlock(); return strings.Join(n.s, "\n") }

const edPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func setup(t *testing.T, confirm string) (*Agent, *fakeAPI, *nftRec) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	for p, c := range map[string]string{"etc/ssh/ssh_host_ed25519_key.pub": edPub, "proc/9/comm": "wayvnc\n",
		"proc/net/tcp": "h\n 0: 00000000:170C 00000000:0000 0A x\n", "etc/os-release": "ID=raspbian\nVERSION_ID=\"12\"\n"} {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), []byte(c), 0o644)
	}
	st := config.Store{P: config.Paths{Etc: dir, State: dir, Run: dir}}
	cfg := &config.Agent{Server: "https://gate.example.org", Name: "pi-garten", Confirm: confirm, Hub: "10.8.0.1",
		SSH: config.SSHShare{Enabled: true, User: "pi", Tmux: true}, Desktop: config.DesktopShare{Enabled: true}}
	cfg.Defaults()
	if err := st.SaveAgent(cfg); err != nil {
		t.Fatal(err)
	}
	_ = st.SaveWG(&config.WG{Address: "10.8.0.41/32", AllowedIPs: "10.8.0.0/24"})
	_ = st.SaveState(&config.State{PeerID: 4})
	f := &fakeAPI{answer: map[string]string{
		"POST host/register": `{"host":{"deviceId":100007,"platform":"linux","shareMode":"code","allowOpen":true,"state":"ready","ssh":{"offered":true,"user":"pi","publicKey":"` + edPub + ` gc","from":"10.8.0.1"},"desktop":{"offered":true,"protocol":"vnc","port":5900}},"codeRequired":true}`,
		"POST host/code":     `{"code":"482-913-075","expiresAt":"` + time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339Nano) + `"}`,
		"GET host/firewall":  `{"open":[]}`,
		"POST host/state":    `{"shareMode":"code","allowOpen":true,"pending":[]}`,
	}, errs: map[string]error{}}
	n := &nftRec{}
	sys := &detect.System{Root: root, LookPath: func(string) (string, error) { return "/usr/bin/tmux", nil },
		Output: func(context.Context, string, ...string) ([]byte, error) { return []byte("tmux 3.3a"), nil }}
	a, err := New(st, f, &fakeTunnel{}, fw.New(n), sys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return a, f, n
}

func TestRegisterBody(t *testing.T) {
	a, f, n := setup(t, config.ConfirmCode)
	ctx := context.Background()
	if err := a.register(ctx); err != nil {
		t.Fatal(err)
	}
	c := f.find("POST", "host/register")
	if len(c) != 1 {
		t.Fatal("no register")
	}
	b := c[0].body
	ssh := b["ssh"].(map[string]any)
	desk := b["desktop"].(map[string]any)
	if b["platform"] != "linux" || b["name"] != "pi-garten" || ssh["user"] != "pi" || ssh["hostKey"].(map[string]any)["alg"] != "ssh-ed25519" ||
		ssh["tmux"].(map[string]any)["version"] != "3.3a" || desk["kind"] != "wayvnc" || desk["ready"] != true || desk["protocol"] != "vnc" ||
		b["os"].(map[string]any)["id"] != "raspbian" {
		t.Fatalf("%v", b)
	}
	if !strings.Contains(n.all(), "add element inet gatecontrol ssh_from { 10.8.0.1 }") || !strings.Contains(n.all(), "tcp dport { 22, 3389, 5900 } drop") {
		t.Fatal(n.all())
	}
	s := a.Status()
	if s.DeviceID != 100007 || s.Code == nil || s.Code.Code != "482-913-075" || !s.Registered {
		t.Fatalf("%+v", s)
	}
}

func TestRequestAutoAllowWithCode(t *testing.T) {
	a, f, _ := setup(t, config.ConfirmCode)
	ctx := context.Background()
	_ = a.register(ctx)
	sig := `{"type":"remote.request","requestId":"rq_abc","from":{"userId":2,"name":"Tom Berger"},"mode":"control","via":"browser","kind":"desktop","expiresAt":"` + time.Now().Add(30*time.Second).UTC().Format(time.RFC3339) + `"}`
	a.onNotification(ctx, api.Notification{Seq: 3, Kind: "data", Topic: api.SignalTopic, Data: json.RawMessage(sig)})
	c := f.find("POST", "host/requests/rq_abc")
	if len(c) != 1 || c[0].body["decision"] != "allow" || c[0].body["mode"] != "control" {
		t.Fatalf("%+v", c)
	}
	// a replay of the same seq does nothing
	a.onNotification(ctx, api.Notification{Seq: 3, Kind: "data", Topic: api.SignalTopic, Data: json.RawMessage(sig)})
	if len(f.find("POST", "host/requests/rq_abc")) != 1 {
		t.Fatal("replayed")
	}
}

func TestRequestAsk(t *testing.T) {
	a, f, _ := setup(t, config.ConfirmAsk)
	ctx := context.Background()
	_ = a.register(ctx)
	a.onRequest(ctx, Request{RequestID: "rq_1", Mode: "control", Kind: "ssh", ExpiresAt: time.Now().Add(30 * time.Second).Format(time.RFC3339)})
	if len(f.find("POST", "host/requests/rq_1")) != 0 {
		t.Fatal("answered without asking")
	}
	if len(a.Status().Requests) != 1 {
		t.Fatal("not waiting")
	}
	args, _ := json.Marshal(Decision{ID: "rq_1", View: true})
	if _, err := a.handle(ctx, ctlReq("allow", args), true); err != nil {
		t.Fatal(err)
	}
	c := f.find("POST", "host/requests/rq_1")
	if len(c) != 1 || c[0].body["mode"] != "view" {
		t.Fatalf("%+v", c)
	}
	if _, err := a.handle(ctx, ctlReq("deny", args), true); err == nil {
		t.Fatal("second answer accepted")
	}
}

func TestFirewallSignals(t *testing.T) {
	a, f, n := setup(t, config.ConfirmCode)
	ctx := context.Background()
	_ = a.register(ctx)
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	a.onSignal(ctx, Signal{Type: "remote.firewall.open", SessionKey: "fw_aaaaaaaaaaaa", Allow: "10.8.0.1", Port: 5900, Until: until})
	rep := f.find("POST", "host/firewall")
	if len(rep) != 1 || rep[0].body["state"] != "open" || !strings.Contains(n.all(), "allow { 10.8.0.1 . 5900 timeout") {
		t.Fatalf("%+v %s", rep, n.all())
	}
	a.onSignal(ctx, Signal{Type: "remote.firewall.open", SessionKey: "fw_bbbbbbbbbbbb", Allow: "10.8.0.1", Port: 22, Until: until})
	rep = f.find("POST", "host/firewall")
	if rep[1].body["state"] != "failed" || rep[1].body["reason"] != "port_not_shared" {
		t.Fatalf("%+v", rep[1])
	}
	codes := len(f.find("POST", "host/code"))
	a.onSignal(ctx, Signal{Type: "remote.firewall.close", SessionKey: "fw_aaaaaaaaaaaa"})
	rep = f.find("POST", "host/firewall")
	if rep[2].body["state"] != "closed" || len(f.find("POST", "host/code")) != codes+1 {
		t.Fatal("close not reported or no new code")
	}
	if !strings.Contains(n.all(), "delete element inet gatecontrol allow { 10.8.0.1 . 5900 }") {
		t.Fatal(n.all())
	}
}

func TestPluginMissingKeepsRunning(t *testing.T) {
	a, f, _ := setup(t, config.ConfirmCode)
	f.errs["POST host/register"] = &api.Error{Status: 404, Code: "http_404"}
	a.Timing = Timing{Heartbeat: time.Millisecond, ConfigCheck: time.Hour, RequestWait: time.Second, RetryMin: time.Millisecond, RetryMax: time.Millisecond, PluginRetry: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	a.registerLoop(ctx)
	if n := len(f.find("POST", "host/register")); n < 2 {
		t.Fatalf("register tried %d times", n)
	}
	if a.Status().Problem != "http_404" {
		t.Fatal(a.Status().Problem)
	}
}

func TestReloadSharesOpen(t *testing.T) {
	a, f, _ := setup(t, config.ConfirmCode)
	ctx := context.Background()
	_ = a.register(ctx)
	cfg, _ := a.Store.LoadAgent()
	cfg.ShareMode = "open"
	_ = a.Store.SaveAgent(cfg)
	r, err := a.reload(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.SSHPublicKey == "" || r.SSHFrom != "10.8.0.1" || r.ShareMode != "open" || len(f.find("PUT", "host/share")) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestHeartbeatErrorsDoNotPanic(t *testing.T) {
	a, f, _ := setup(t, config.ConfirmCode)
	f.errs["POST host/state"] = errors.New("net down")
	if err := a.heartbeat(context.Background()); err == nil {
		t.Fatal("want error")
	}
}
