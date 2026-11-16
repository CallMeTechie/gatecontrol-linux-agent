// Package version holds the build version of the agent (set with -ldflags at build time).
package version

// Version is overwritten by the build: -X github.com/CallMeTechie/gatecontrol-linux-agent/internal/version.Version=1.0.0
var Version = "0.0.0-dev"

// UserAgent is the User-Agent of every request to GateControl.
func UserAgent() string { return "gatecontrol-agent/" + Version }
