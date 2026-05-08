// Package logging provides a leveled structured logger for the entrypoint process.
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/contract"
)

// Level mirrors slog.Level but uses the string names defined in the project's
// SCRIPT_LOG_LEVEL contract (DEBUG, INFO, WARN, ERROR).
type Level = slog.Level

// Log level aliases mapping SCRIPT_LOG_LEVEL strings to slog levels.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Logger is the project-wide logger. It is initialised once by Init and safe
// for concurrent use. All packages receive it via context or direct reference;
// no package may create its own logger.
type Logger struct {
	handler slog.Handler
	version string
	level   slog.Level
	pid     int
}

// logHandler is a custom slog.Handler that produces the fixed-format output:
//
//	2006-01-02T15:04:05Z [LEVEL] [PID] message (vVERSION)
//
// slog's built-in handlers (Text, JSON) cannot produce this exact line structure,
// so we implement the interface directly rather than wrapping an existing handler.
type logHandler struct {
	version string
	level   slog.Level
	pid     int
}

func (h *logHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *logHandler) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // signature required by slog.Handler interface
	ts := r.Time.UTC().Format("2006-01-02T15:04:05Z")
	levelStr := levelName(r.Level)

	msg := strings.ReplaceAll(r.Message, "\r", "")
	msg = strings.ReplaceAll(msg, "\n", " | ")

	line := fmt.Sprintf("%s [%s] [%d] %s (v%s)\n",
		ts, levelStr, h.pid, msg, h.version)

	_, err := os.Stderr.WriteString(line)
	if err != nil {
		return fmt.Errorf("write log line: %w", err)
	}
	return nil
}

// WithAttrs and WithGroup satisfy the slog.Handler interface.
// Attributes and groups are not used in this logger's output format —
// all contextual information is embedded in the message at call sites.
func (h *logHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *logHandler) WithGroup(_ string) slog.Handler      { return h }

// levelName returns the uppercase level string used in log output.
func levelName(l slog.Level) string {
	switch l {
	case slog.LevelDebug:
		return contract.LogLevelDebug
	case slog.LevelInfo:
		return contract.LogLevelInfo
	case slog.LevelWarn:
		return contract.LogLevelWarn
	case slog.LevelError:
		return contract.LogLevelError
	default:
		return contract.LogLevelInfo
	}
}

// ParseLevel converts the SCRIPT_LOG_LEVEL string value to a slog.Level.
// Returns LevelWarn and an error for unrecognised values — the caller decides
// whether to fatal or fall back to the default.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case contract.LogLevelDebug:
		return LevelDebug, nil
	case contract.LogLevelInfo:
		return LevelInfo, nil
	case contract.LogLevelWarn, "WARNING":
		return LevelWarn, nil
	case contract.LogLevelError:
		return LevelError, nil
	default:
		return LevelWarn, fmt.Errorf("unrecognised %s %q: accepted values are %s, %s, %s, %s",
			contract.EnvScriptLogLevel,
			s,
			contract.LogLevelDebug,
			contract.LogLevelInfo,
			contract.LogLevelWarn,
			contract.LogLevelError,
		)
	}
}

// New creates a Logger at the given level. version is embedded in every log
// line so operators can correlate log output with a specific image build.
func New(level slog.Level, version string) *Logger {
	h := &logHandler{
		level:   level,
		pid:     os.Getpid(),
		version: version,
	}
	return &Logger{
		handler: h,
		level:   level,
		pid:     os.Getpid(),
		version: version,
	}
}

func (l *Logger) log(level slog.Level, msg string) {
	if !l.handler.Enabled(context.Background(), level) {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, 0)
	_ = l.handler.Handle(context.Background(), r) //nolint:errcheck // log writes are fire-and-forget
}

// Debug logs at DEBUG level. Use for verbose diagnostic output that is
// disabled in production (SCRIPT_LOG_LEVEL=WARN or higher).
func (l *Logger) Debug(msg string) { l.log(LevelDebug, msg) }

// Debugf formats and logs at DEBUG level.
func (l *Logger) Debugf(format string, args ...any) {
	l.log(LevelDebug, fmt.Sprintf(format, args...))
}

// Info logs at INFO level.
func (l *Logger) Info(msg string) { l.log(LevelInfo, msg) }

// Infof formats and logs at INFO level.
func (l *Logger) Infof(format string, args ...any) {
	l.log(LevelInfo, fmt.Sprintf(format, args...))
}

// Warn logs at WARN level.
func (l *Logger) Warn(msg string) { l.log(LevelWarn, msg) }

// Warnf formats and logs at WARN level.
func (l *Logger) Warnf(format string, args ...any) {
	l.log(LevelWarn, fmt.Sprintf(format, args...))
}

// Error logs at ERROR level.
func (l *Logger) Error(msg string) { l.log(LevelError, msg) }

// Errorf formats and logs at ERROR level.
func (l *Logger) Errorf(format string, args ...any) {
	l.log(LevelError, fmt.Sprintf(format, args...))
}

// Fatal logs at ERROR level then exits with code 1.
// Use only in main — library packages must return errors instead.
func (l *Logger) Fatal(msg string) {
	l.log(LevelError, msg)
	os.Exit(1)
}

// Fatalf formats, logs at ERROR level, then exits with code 1.
func (l *Logger) Fatalf(format string, args ...any) {
	l.log(LevelError, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// Level returns the minimum level at which this logger emits output.
func (l *Logger) Level() slog.Level { return l.level }

// VersionFromFile reads the single-line version string from /app/version.
// Returns the fallback version string on any read or parse failure — a
// missing version file must not prevent the entrypoint from starting.
func VersionFromFile(path string) string {
	v, ok := readSafeVersion(path)
	if !ok {
		return "unknown"
	}
	return v
}

func readSafeVersion(path string) (string, bool) {
	// #nosec G304 -- The path is a fixed constant (cfg.Paths.VersionFile).
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	v := strings.TrimSpace(string(data))
	if !isSafeVersionString(v) {
		return "", false
	}
	return v, true
}

func isSafeVersionString(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}
