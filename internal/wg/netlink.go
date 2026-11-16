//go:build linux

package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/config"
)

// Apply creates or updates the interface over netlink (needs CAP_NET_ADMIN): keys, peer,
// the /32 address, link up and one route for the VPN subnet.
func Apply(iface string, w *config.WG) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = iface
		if w.MTU > 0 {
			attrs.MTU = w.MTU
		}
		if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}); err != nil {
			return fmt.Errorf("wg: creating %s: %w (kernel module wireguard? CAP_NET_ADMIN?)", iface, err)
		}
		if link, err = netlink.LinkByName(iface); err != nil {
			return err
		}
	}
	cfg, err := deviceConfig(w)
	if err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("wg: configuring %s: %w", iface, err)
	}
	addr, err := netlink.ParseAddr(w.Address)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("wg: address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	_, dst, err := net.ParseCIDR(w.AllowedIPs)
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Scope: netlink.SCOPE_LINK}); err != nil {
		return fmt.Errorf("wg: route: %w", err)
	}
	return nil
}

func deviceConfig(w *config.WG) (wgtypes.Config, error) {
	priv, err := wgtypes.ParseKey(w.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, errors.New("wg: private key")
	}
	pub, err := wgtypes.ParseKey(w.PeerKey)
	if err != nil {
		return wgtypes.Config{}, errors.New("wg: peer key")
	}
	ep, err := net.ResolveUDPAddr("udp", w.Endpoint)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("wg: endpoint: %w", err)
	}
	pfx, err := netip.ParsePrefix(w.AllowedIPs)
	if err != nil {
		return wgtypes.Config{}, err
	}
	ka := time.Duration(w.Keepalive) * time.Second
	peer := wgtypes.PeerConfig{PublicKey: pub, Endpoint: ep, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &ka,
		AllowedIPs: []net.IPNet{{IP: pfx.Addr().AsSlice(), Mask: net.CIDRMask(pfx.Bits(), 32)}}}
	if w.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(w.PresharedKey)
		if err != nil {
			return wgtypes.Config{}, errors.New("wg: preshared key")
		}
		peer.PresharedKey = &psk
	}
	return wgtypes.Config{PrivateKey: &priv, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer}}, nil
}

// Remove deletes the interface (gone already: nil).
func Remove(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil
	}
	return netlink.LinkDel(link)
}

// Read returns the state of the tunnel.
func Read(iface string) Status {
	st := Status{}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return st
	}
	st.Up = link.Attrs().Flags&net.FlagUp != 0
	if as, err := netlink.AddrList(link, netlink.FAMILY_V4); err == nil && len(as) > 0 {
		st.Address = as[0].IP.String()
	}
	c, err := wgctrl.New()
	if err != nil {
		return st
	}
	defer func() { _ = c.Close() }()
	d, err := c.Device(iface)
	if err != nil || len(d.Peers) == 0 {
		return st
	}
	p := d.Peers[0]
	if !p.LastHandshakeTime.IsZero() {
		st.LastHandshake = p.LastHandshakeTime.Unix()
	}
	st.RxBytes, st.TxBytes = p.ReceiveBytes, p.TransmitBytes
	return st
}

// Netlink is the tunnel of the service (agent.Tunnel).
type Netlink struct{}

func (Netlink) Apply(iface string, w *config.WG) error { return Apply(iface, w) }
func (Netlink) Read(iface string) Status               { return Read(iface) }
func (Netlink) Remove(iface string) error              { return Remove(iface) }
