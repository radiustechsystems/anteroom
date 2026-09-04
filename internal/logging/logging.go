// Package logging builds the process slog.Logger from [log] config and
// attaches request-scoped fields (request_id, trace_id, span_id) from
// context onto every record logged with that context.
//
// Format is a Handler choice. Call sites already emit slog key/value attrs, so
// json, logfmt, and text are encodings of the same records.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/radiustechsystems/anteroom/internal/config"
)

// New builds the process logger. verbose (the -v flag) forces debug regardless
// of cfg.Level, so per-request hit lines stay an explicit opt-in.
func New(w io.Writer, cfg config.Log, verbose bool) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	level := parseLevel(cfg.Level)
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "logfmt" {
		opts.ReplaceAttr = logfmtReplace
	}
	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default: // text, logfmt
		h = slog.NewTextHandler(w, opts)
	}
	lg := slog.New(contextHandler{h})
	if len(cfg.Labels) == 0 {
		return lg
	}
	keys := make([]string, 0, len(cfg.Labels))
	for k := range cfg.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := make([]any, 0, len(keys)*2)
	for _, k := range keys {
		args = append(args, k, cfg.Labels[k])
	}
	return lg.With(args...)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// logfmtReplace makes slog's text handler a collector-friendly logfmt:
// ts=RFC3339Nano (UTC) and lowercase level. Field names otherwise match text.
func logfmtReplace(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		a.Key = "ts"
		if t, ok := a.Value.Any().(time.Time); ok {
			a.Value = slog.StringValue(t.UTC().Format(time.RFC3339Nano))
		}
	case slog.LevelKey:
		a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
	}
	return a
}

// contextHandler copies request-scoped Fields off ctx onto every Record.
// Call sites must use the *Context slog methods or the fields stay off the line.
type contextHandler struct {
	slog.Handler
}

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if f, ok := FromContext(ctx); ok {
		if f.RequestID != "" {
			r.AddAttrs(slog.String("request_id", f.RequestID))
		}
		if f.TraceID != "" {
			r.AddAttrs(slog.String("trace_id", f.TraceID))
		}
		if f.SpanID != "" {
			r.AddAttrs(slog.String("span_id", f.SpanID))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{Handler: h.Handler.WithGroup(name)}
}
