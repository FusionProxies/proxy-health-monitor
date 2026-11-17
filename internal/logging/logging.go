// Package logging builds the slog logger. Every record passes through the
// redactor, so a credential cannot reach the log even by accident.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

// New returns a logger writing text or JSON at the given level.
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "", "info":
		lv = slog.LevelInfo
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q (debug, info, warn, error)", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("unknown log format %q (text, json)", format)
	}
	return slog.New(&redacting{h}), nil
}

type redacting struct{ next slog.Handler }

func (r *redacting) Enabled(ctx context.Context, l slog.Level) bool { return r.next.Enabled(ctx, l) }

func (r *redacting) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, redact.String(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(clean(a))
		return true
	})
	return r.next.Handle(ctx, out)
}

func (r *redacting) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		c[i] = clean(a)
	}
	return &redacting{r.next.WithAttrs(c)}
}

func (r *redacting) WithGroup(name string) slog.Handler { return &redacting{r.next.WithGroup(name)} }

func clean(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redact.String(v.String()))
	case slog.KindGroup:
		g := v.Group()
		c := make([]any, len(g))
		for i, x := range g {
			c[i] = clean(x)
		}
		return slog.Group(a.Key, c...)
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, redact.Error(err))
		}
		return slog.String(a.Key, redact.String(fmt.Sprint(v.Any())))
	}
	return a
}
