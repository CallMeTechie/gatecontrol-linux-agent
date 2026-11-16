package agent

import (
	"encoding/json"

	"github.com/CallMeTechie/gatecontrol-linux-agent/internal/ctl"
)

func ctlReq(op string, args json.RawMessage) ctl.Request { return ctl.Request{Op: op, Args: args} }
