package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/contract"
)

func assertFallbackVersion(t *testing.T, got string) {
	t.Helper()
	if got == "unknown" {
		return
	}
	t.Errorf("got %q, want fallback version", got)
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		input   string
		want    Level
		wantErr bool
	}{
		{contract.LogLevelDebug, LevelDebug, false},
		{"debug", LevelDebug, false},
		{contract.LogLevelInfo, LevelInfo, false},
		{contract.LogLevelWarn, LevelWarn, false},
		{"WARNING", LevelWarn, false},
		{contract.LogLevelError, LevelError, false},
		{"  " + contract.LogLevelWarn + "  ", LevelWarn, false},
		{"", LevelWarn, true},
		{"VERBOSE", LevelWarn, true},
		{"TRACE", LevelWarn, true},
	}

	for _, tc := range cases {
		got, err := ParseLevel(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseLevel(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevel(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseLevel(%q): got %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestVersionFromFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid version", func(t *testing.T) {
		path := filepath.Join(dir, "version")
		if err := os.WriteFile(path, []byte("1.2.3\n"), 0o644); err != nil { // #nosec G306
			t.Fatal(err)
		}
		got := VersionFromFile(path)
		if got != "1.2.3" {
			t.Errorf("got %q, want %q", got, "1.2.3")
		}
	})

	t.Run("missing file uses fallback", func(t *testing.T) {
		assertFallbackVersion(t, VersionFromFile(filepath.Join(dir, "nonexistent")))
	})

	t.Run("empty file uses fallback", func(t *testing.T) {
		path := filepath.Join(dir, "empty")
		if err := os.WriteFile(path, []byte("   \n"), 0o644); err != nil { // #nosec G306
			t.Fatal(err)
		}
		assertFallbackVersion(t, VersionFromFile(path))
	})

	t.Run("oversized version uses fallback", func(t *testing.T) {
		path := filepath.Join(dir, "toolong")
		if err := os.WriteFile(path, []byte(strings.Repeat("a", 33)), 0o644); err != nil { // #nosec G306
			t.Fatal(err)
		}
		assertFallbackVersion(t, VersionFromFile(path))
	})

	t.Run("control characters use fallback", func(t *testing.T) {
		path := filepath.Join(dir, "ctrlchars")
		// Embed a newline inside the version string — potential log injection.
		if err := os.WriteFile(path, []byte("1.0\x00evil"), 0o644); err != nil { // #nosec G306
			t.Fatal(err)
		}
		assertFallbackVersion(t, VersionFromFile(path))
	})
}

func TestLoggerLevelFiltering(t *testing.T) {
	// Verify that a WARN-level logger does not emit DEBUG or INFO records.
	// We redirect stderr to a pipe to capture output without polluting test output.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	logger := New(LevelWarn, "test")
	logger.Debug("this should not appear")
	logger.Info("this should not appear either")
	logger.Warn("this should appear")

	_ = w.Close() //nolint:errcheck // mock close
	os.Stderr = origStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf) //nolint:errcheck // mock read
	output := string(buf[:n])

	if strings.Contains(output, "this should not appear") {
		t.Errorf("DEBUG/INFO message leaked through WARN-level logger: %q", output)
	}
	if !strings.Contains(output, "this should appear") {
		t.Errorf("WARN message missing from output: %q", output)
	}
}

func TestLogOutputFormat(t *testing.T) {
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	logger := New(LevelDebug, "9.9.9")
	logger.Info("hello world")

	_ = w.Close() //nolint:errcheck // mock close
	os.Stderr = origStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf) //nolint:errcheck // mock read
	line := string(buf[:n])

	// Verify all mandatory format components are present.
	if !strings.Contains(line, "[INFO]") {
		t.Errorf("missing level in output: %q", line)
	}
	if !strings.Contains(line, "hello world") {
		t.Errorf("missing message in output: %q", line)
	}
	if !strings.Contains(line, "(v9.9.9)") {
		t.Errorf("missing version in output: %q", line)
	}
	// Timestamp format: 2006-01-02T15:04:05Z
	if !strings.Contains(line, "T") || !strings.Contains(line, "Z") {
		t.Errorf("timestamp format unexpected in output: %q", line)
	}
}
