package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// SignalTopic is the topic of the plugin's silent signals.
const SignalTopic = "plugin:" + PluginID + ":remote_signal"

// Notification of the push stream (only the fields the agent needs).
type Notification struct {
	Seq   int64           `json:"seq"`
	Topic string          `json:"topic"`
	Kind  string          `json:"kind"`
	Data  json.RawMessage `json:"data"`
}

// Event of the stream.
type Event struct {
	Name string
	ID   string
	Data string
}

// ParseSSE reads events until the reader ends; fn gets each one.
func ParseSSE(r io.Reader, fn func(Event)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var ev Event
	var data []string
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if len(data) > 0 || ev.Name != "" {
				ev.Data = strings.Join(data, "\n")
				if ev.Name == "" {
					ev.Name = "message"
				}
				fn(ev)
			}
			ev, data = Event{}, nil
			continue
		}
		if strings.HasPrefix(line, ":") {
			fn(Event{Name: "comment"})
			continue
		}
		k, v, _ := strings.Cut(line, ":")
		v = strings.TrimPrefix(v, " ")
		switch k {
		case "event":
			ev.Name = v
		case "data":
			data = append(data, v)
		case "id":
			ev.ID = v
		}
	}
	return sc.Err()
}

// Hello of the stream.
type Hello struct {
	KeepaliveS int `json:"keepalive_s"`
}

// Stream opens the push stream once and calls fn for every notification until ctx ends,
// the stream breaks or no byte arrived for 2 × keepalive. lastSeq is sent as Last-Event-ID.
func (c *Client) Stream(ctx context.Context, lastSeq int64, fn func(Notification)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Server+"/api/v1/client/push", nil)
	if err != nil {
		return err
	}
	c.headers(req.Header)
	req.Header.Set("Accept", "text/event-stream")
	if lastSeq > 0 {
		req.Header.Set("Last-Event-ID", strconv.FormatInt(lastSeq, 10))
	}
	res, err := c.StreamHTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		var env struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&env)
		code := env.Error
		if code == "" {
			code = fmt.Sprintf("http_%d", res.StatusCode)
		}
		return &Error{Status: res.StatusCode, Code: code}
	}
	var keep atomic.Int64
	keep.Store(int64(30 * time.Second))
	alive := make(chan struct{}, 1)
	go func() {
		t := time.NewTimer(2 * time.Duration(keep.Load()))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-alive:
				t.Reset(2 * time.Duration(keep.Load()))
			case <-t.C:
				cancel()
				return
			}
		}
	}()
	err = ParseSSE(res.Body, func(ev Event) {
		select {
		case alive <- struct{}{}:
		default:
		}
		switch ev.Name {
		case "hello":
			var h Hello
			if json.Unmarshal([]byte(ev.Data), &h) == nil && h.KeepaliveS >= 1 && h.KeepaliveS <= 600 {
				keep.Store(int64(time.Duration(h.KeepaliveS) * time.Second))
			}
		case "notification":
			var n Notification
			if json.Unmarshal([]byte(ev.Data), &n) != nil {
				return
			}
			if n.Seq == 0 {
				n.Seq, _ = strconv.ParseInt(ev.ID, 10, 64)
			}
			fn(n)
		}
	})
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}
