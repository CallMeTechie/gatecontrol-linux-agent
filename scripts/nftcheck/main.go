// Command nftcheck prints the agent's nftables ruleset and a session rule, for `nft -c -f -` in CI.
package main

import (
	"fmt"
	"net/netip"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/fw"
)

func main() {
	fmt.Print(fw.Ruleset(fw.Spec{Interface: "wg-gc", SSHPort: 22, Desktop: []int{3389, 5900, 3390}, SSHFrom: netip.MustParseAddr("10.8.0.1")}))
	fmt.Printf("add element inet %s allow { 10.8.0.7 . 3389 timeout 3600s }\n", fw.Table)
}
