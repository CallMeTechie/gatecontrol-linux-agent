// Package fw keeps the firewall of the agent: an nftables table of its own that only
// touches packets coming in on the VPN interface and only the managed ports (SSH and the
// desktop). SSH is open for the hub address while SSH is shared; a desktop port opens per
// session for exactly one address (the hub for a browser session, the helper's app device)
// with a timeout (≤ 8 h). Everything else on the managed ports from the VPN is dropped.
package fw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Table is the name of the agent's nftables table (family inet).
const Table = "gatecontrol"

// MaxRule is the longest a session rule lives.
const MaxRule = 8 * time.Hour

// SessionKeyRE is what the plugin sends as sessionKey (fw_ + base64url).
var SessionKeyRE = regexp.MustCompile(`^fw_[A-Za-z0-9_-]{8,64}$`)

// Runner runs `nft -f -` with a script (tests replace it).
type Runner interface {
	Run(ctx context.Context, script string) error
}

// NftRunner calls the nft binary.
type NftRunner struct{ Path string }

// Run feeds script to nft on stdin.
func (n NftRunner) Run(ctx context.Context, script string) error {
	p := n.Path
	if p == "" {
		p = "nft"
	}
	cmd := exec.CommandContext(ctx, p, "-f", "-") // #nosec G204 -- fixed binary, script on stdin
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Spec is the base of the table.
type Spec struct {
	Interface string
	SSHPort   int        // managed always (dropped from the VPN unless from the hub while shared)
	Desktop   []int      // managed desktop ports (3389, 5900 or the shared one)
	SSHFrom   netip.Addr // the hub; invalid = SSH not shared
	Subnet    netip.Prefix
}

func (s Spec) ports() []int {
	ps := append([]int{s.SSHPort}, s.Desktop...)
	sort.Ints(ps)
	return slices.Compact(ps)
}

// Ruleset renders the whole table (replacing an old one atomically).
func Ruleset(s Spec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", Table, Table)
	fmt.Fprintf(&b, "table inet %s {\n", Table)
	b.WriteString("  set ssh_from { type ipv4_addr; }\n")
	b.WriteString("  set allow { type ipv4_addr . inet_service; flags timeout; }\n")
	b.WriteString("  chain input {\n    type filter hook input priority filter - 5; policy accept;\n")
	fmt.Fprintf(&b, "    iifname != %q accept\n", s.Interface)
	b.WriteString("    ct state established,related accept\n")
	fmt.Fprintf(&b, "    tcp dport %d ip saddr @ssh_from accept\n", s.SSHPort)
	b.WriteString("    ip saddr . tcp dport @allow accept\n")
	ps := s.ports()
	strs := make([]string, len(ps))
	for i, p := range ps {
		strs[i] = fmt.Sprint(p)
	}
	fmt.Fprintf(&b, "    tcp dport { %s } drop\n  }\n}\n", strings.Join(strs, ", "))
	if s.SSHFrom.IsValid() {
		fmt.Fprintf(&b, "add element inet %s ssh_from { %s }\n", Table, s.SSHFrom)
	}
	return b.String()
}

type rule struct {
	ip   netip.Addr
	port int
}

// Firewall holds the rules of the sessions.
type Firewall struct {
	mu    sync.Mutex
	run   Runner
	spec  Spec
	rules map[string]rule // sessionKey → rule
	now   func() time.Time
}

// New makes a firewall with this runner (nil: nft).
func New(r Runner) *Firewall {
	if r == nil {
		r = NftRunner{}
	}
	return &Firewall{run: r, rules: map[string]rule{}, now: time.Now}
}

// Errors of Open.
var (
	ErrInvalid = errors.New("invalid")
	ErrPort    = errors.New("port_not_shared")
)

// Setup (re)creates the table: every session rule is gone afterwards.
func (f *Firewall) Setup(ctx context.Context, s Spec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spec = s
	f.rules = map[string]rule{}
	return f.run.Run(ctx, Ruleset(s))
}

// Open lets allow reach port for the session key until `until` (≤ 8 h).
func (f *Firewall) Open(ctx context.Context, key, allow string, port int, until time.Time) error {
	if !SessionKeyRE.MatchString(key) {
		return ErrInvalid
	}
	ip, err := netip.ParseAddr(allow)
	if err != nil || !ip.Is4() || (f.spec.Subnet.IsValid() && !f.spec.Subnet.Contains(ip)) {
		return ErrInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Contains(f.spec.Desktop, port) {
		return ErrPort
	}
	d := until.Sub(f.now())
	if d <= 0 || d > MaxRule {
		d = MaxRule
	}
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	// "add" keeps an existing element; delete first so the timeout is the new one
	script := ""
	if f.usedBy(rule{ip, port}, "") {
		script = fmt.Sprintf("delete element inet %s allow { %s . %d }\n", Table, ip, port)
	}
	script += fmt.Sprintf("add element inet %s allow { %s . %d timeout %ds }\n", Table, ip, port, secs)
	if err := f.run.Run(ctx, script); err != nil {
		return err
	}
	f.rules[key] = rule{ip, port}
	return nil
}

func (f *Firewall) usedBy(r rule, except string) bool {
	for k, x := range f.rules {
		if k != except && x == r {
			return true
		}
	}
	return false
}

// Close removes the rule of the key (another session with the same address and port keeps it).
func (f *Firewall) Close(ctx context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rules[key]
	if !ok {
		return nil
	}
	delete(f.rules, key)
	if f.usedBy(r, key) {
		return nil
	}
	// the element may have timed out already: a failing delete is not an error then
	_ = f.run.Run(ctx, fmt.Sprintf("delete element inet %s allow { %s . %d }\n", Table, r.ip, r.port))
	return nil
}

// Keys lists the open session keys.
func (f *Firewall) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ks := make([]string, 0, len(f.rules))
	for k := range f.rules {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Teardown removes the table.
func (f *Firewall) Teardown(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = map[string]rule{}
	return f.run.Run(ctx, fmt.Sprintf("table inet %s\ndelete table inet %s\n", Table, Table))
}
