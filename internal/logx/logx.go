// Package logx gives the agent a structured logger (journald reads stderr) that never
// writes a secret: attributes whose key names a token, key, code, password, config or
// fingerprint are replaced by "[redacted]", also inside groups.
package logx

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Redacted is what a secret attribute becomes.
const Redacted = "[redacted]"

var secretWords = []string{"token", "key", "secret", "code", "password", "passphrase", "config", "fingerprint", "private"}

// IsSecretKey reports whether an attribute key names something that must not be logged.
func IsSecretKey(k string) bool {
	k = strings.ToLower(k)
	for _, w := range secretWords {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

type redactor struct{ next slog.Handler }

func (r redactor) Enabled(ctx context.Context, l slog.Level) bool { return r.next.Enabled(ctx, l) }

func (r redactor) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, rec.Message, rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(clean(a))
		return true
	})
	return r.next.Handle(ctx, out)
}

func (r redactor) WithAttrs(as []slog.Attr) slog.Handler {
	c := make([]slog.Attr, len(as))
	for i, a := range as {
		c[i] = clean(a)
	}
	return redactor{r.next.WithAttrs(c)}
}

func (r redactor) WithGroup(name string) slog.Handler { return redactor{r.next.WithGroup(name)} }

func clean(a slog.Attr) slog.Attr {
	if IsSecretKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	if a.Value.Kind() == slog.KindGroup {
		g := a.Value.Group()
		c := make([]any, len(g))
		for i, x := range g {
			c[i] = clean(x)
		}
		return slog.Group(a.Key, c...)
	}
	return a
}

// New returns a redacting text logger on w (journald adds the time itself when quiet is true).
func New(w io.Writer, level slog.Level, quiet bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if quiet {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}
	return slog.New(redactor{slog.NewTextHandler(w, opts)})
}
