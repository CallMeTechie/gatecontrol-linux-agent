// Package wg turns the WireGuard configuration GateControl hands out into the agent's
// own settings (only the VPN subnet is routed: no default route, no DNS) and applies it —
// over netlink with CAP_NET_ADMIN (netlink.go) or as a wg-quick file (WriteQuick).
package wg

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
)

// Parse reads a wg-quick configuration of GateControl. subnet is the VPN network the
// device routes (from the enroll answer); empty → <Address>/24 and fallback=true.
func Parse(text, subnet, hash string) (w *config.WG, fallback bool, err error) {
	w = &config.WG{Keepalive: 25, Hash: hash}
	section := ""
	var allowed string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch section + "." + k {
		case "interface.privatekey":
			w.PrivateKey = v
		case "interface.address":
			w.Address = strings.TrimSpace(strings.Split(v, ",")[0])
		case "interface.mtu":
			w.MTU, _ = strconv.Atoi(v)
		case "peer.publickey":
			w.PeerKey = v
		case "peer.presharedkey":
			w.PresharedKey = v
		case "peer.endpoint":
			w.Endpoint = v
		case "peer.allowedips":
			allowed = v
		case "peer.persistentkeepalive":
			if n, e := strconv.Atoi(v); e == nil && n >= 0 && n <= 65535 {
				w.Keepalive = n
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, false, err
	}
	_ = allowed // GateControl may hand out 0.0.0.0/0 — the agent never routes more than the VPN
	for _, k := range []string{w.PrivateKey, w.PeerKey} {
		if !validKey(k) {
			return nil, false, errors.New("wg: invalid key in the configuration")
		}
	}
	if w.PresharedKey != "" && !validKey(w.PresharedKey) {
		return nil, false, errors.New("wg: invalid preshared key")
	}
	pfx, err := netip.ParsePrefix(w.Address)
	if err != nil || !pfx.Addr().Is4() {
		return nil, false, errors.New("wg: invalid address")
	}
	w.Address = netip.PrefixFrom(pfx.Addr(), 32).String()
	if _, _, err := net.SplitHostPort(w.Endpoint); err != nil {
		return nil, false, errors.New("wg: invalid endpoint")
	}
	if subnet == "" {
		p, _ := pfx.Addr().Prefix(24)
		subnet, fallback = p.String(), true
	}
	sp, err := netip.ParsePrefix(subnet)
	if err != nil || !sp.Addr().Is4() || sp.Bits() < 8 || !sp.Contains(pfx.Addr()) {
		return nil, false, fmt.Errorf("wg: subnet %q does not contain the address", subnet)
	}
	w.AllowedIPs = sp.Masked().String()
	return w, fallback, nil
}

func validKey(k string) bool {
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32
}

// Quick renders the wg-quick file (0600) for the wg-quick mode: no DNS, the VPN subnet only.
func Quick(w *config.WG) string {
	var b strings.Builder
	b.WriteString("# Written by gatecontrol-agent — changes are overwritten.\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s\n", w.PrivateKey, w.Address)
	if w.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", w.MTU)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", w.PeerKey)
	if w.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", w.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", w.Endpoint, w.AllowedIPs, w.Keepalive)
	return b.String()
}

// Status of the tunnel.
type Status struct {
	Up            bool
	Address       string
	LastHandshake int64 // unix seconds, 0 never
	RxBytes       int64
	TxBytes       int64
}
