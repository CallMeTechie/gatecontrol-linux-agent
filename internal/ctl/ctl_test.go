package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCallServe(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "a.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Serve(ctx, sock, func(_ context.Context, r Request, root bool) (any, error) {
			if r.Op == "boom" {
				return nil, errors.New("nft_failed")
			}
			var a map[string]string
			_ = json.Unmarshal(r.Args, &a)
			return map[string]any{"op": r.Op, "x": a["x"], "root": root}, nil
		})
	}()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var out map[string]any
	if err := Call(ctx, sock, "status", map[string]string{"x": "y"}, &out); err != nil {
		t.Fatal(err)
	}
	if out["op"] != "status" || out["x"] != "y" {
		t.Fatalf("%v", out)
	}
	wantRoot := os.Getuid() == 0
	if out["root"] != wantRoot {
		t.Fatalf("root %v", out["root"])
	}
	err := Call(ctx, sock, "share", nil, nil)
	if wantRoot && err != nil || !wantRoot && (err == nil || err.Error() != "not_root") {
		t.Fatalf("share: %v", err)
	}
	if wantRoot {
		if err := Call(ctx, sock, "boom", nil, nil); err == nil || err.Error() != "nft_failed" {
			t.Fatalf("boom: %v", err)
		}
	}
	if err := Call(ctx, filepath.Join(dir, "none"), "status", nil, nil); err != ErrUnreachable {
		t.Fatalf("unreachable: %v", err)
	}
}
