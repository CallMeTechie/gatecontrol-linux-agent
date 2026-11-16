// Package ctl is the local control channel between the CLI and the service: one JSON
// request and one JSON answer per connection over /run/gatecontrol-agent/agent.sock
// (0660, group gatecontrol). Reading ops (status, code, requests) are open to whoever may
// open the socket; changing ops need root (checked with SO_PEERCRED).
package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// Request from the CLI.
type Request struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response of the service.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Handler answers one request; root tells whether the caller is root.
type Handler func(ctx context.Context, req Request, root bool) (any, error)

// ReadOnly ops anybody with access to the socket may call.
var ReadOnly = map[string]bool{"status": true, "code": true, "requests": true}

// ErrNotRoot is the answer to a changing op from a non-root caller.
var ErrNotRoot = errors.New("not_root")

// Serve accepts connections until ctx ends. The socket file is replaced.
func Serve(ctx context.Context, path string, h Handler) error {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// 0660: the CLI of root and of members of the service group connect
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // a socket; changing ops are guarded by SO_PEERCRED
		_ = l.Close()
		return err
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go serveConn(ctx, c.(*net.UnixConn), h)
	}
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e != nil {
			cerr = e
			return
		}
		uid = int(cred.Uid)
	})
	if err != nil {
		return -1, err
	}
	return uid, cerr
}

func serveConn(ctx context.Context, c *net.UnixConn, h Handler) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	uid, err := peerUID(c)
	if err != nil {
		return
	}
	var req Request
	if err := json.NewDecoder(bufio.NewReader(&limited{c, 64 << 10})).Decode(&req); err != nil {
		return
	}
	root := uid == 0
	var res Response
	if !ReadOnly[req.Op] && !root {
		res = Response{Error: ErrNotRoot.Error()}
	} else if v, err := h(ctx, req, root); err != nil {
		res = Response{Error: err.Error()}
	} else {
		b, _ := json.Marshal(v)
		res = Response{OK: true, Data: b}
	}
	_ = json.NewEncoder(c).Encode(res)
}

type limited struct {
	c *net.UnixConn
	n int
}

func (l *limited) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("request too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.c.Read(p)
	l.n -= n
	return n, err
}

// ErrUnreachable: the service does not answer.
var ErrUnreachable = errors.New("daemon_unreachable")

// Call sends one request and decodes the data into out.
func Call(ctx context.Context, path, op string, args, out any) error {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return ErrUnreachable
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	}
	req := Request{Op: op}
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		req.Args = b
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return ErrUnreachable
	}
	var res Response
	if err := json.NewDecoder(c).Decode(&res); err != nil {
		return ErrUnreachable
	}
	if !res.OK {
		return errors.New(res.Error)
	}
	if out != nil && len(res.Data) > 0 {
		return json.Unmarshal(res.Data, out)
	}
	return nil
}
