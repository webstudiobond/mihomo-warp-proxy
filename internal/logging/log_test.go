package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		input   string
		want    Level
		wantErr bool
	}{
		{"DEBUG", LevelDebug, false},
		{"debug", LevelDebug, false},
		{"INFO", LevelInfo, false},
		{"WARN", LevelWarn, false},
		{"WARNING", LevelWarn, false},
		{"ERROR", LevelError, false},
		{"  WARN  ", LevelWarn, false},
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
		if err := os.WriteFile(path, []byte("1.2.3\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := VersionFromFile(path)
		if got != "1.2.3" {
			t.Errorf("got %q, want %q", got, "1.2.3")
		}
	})

	t.Run("missing file returns unknown", func(t *testing.T) {
		got := VersionFromFile(filepath.Join(dir, "nonexistent"))
		if got != "unknown" {
			t.Errorf("got %q, want %q", got, "unknown")
		}
	})

	t.Run("empty file returns unknown", func(t *testing.T) {
		path := filepath.Join(dir, "empty")
		if err := os.WriteFile(path, []byte("   \n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := VersionFromFile(path)
		if got != "unknown" {
			t.Errorf("got %q, want %q", got, "unknown")
		}
	})

	t.Run("oversized version returns unknown", func(t *testing.T) {
		path := filepath.Join(dir, "toolong")
		if err := os.WriteFile(path, []byte(strings.Repeat("a", 33)), 0o644); err != nil {
			t.Fatal(err)
		}
		got := VersionFromFile(path)
		if got != "unknown" {
			t.Errorf("got %q, want %q", got, "unknown")
		}
	})

	t.Run("control characters return unknown", func(t *testing.T) {
		path := filepath.Join(dir, "ctrlchars")
		// Embed a newline inside the version string — potential log injection.
		if err := os.WriteFile(path, []byte("1.0\x00evil"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := VersionFromFile(path)
		if got != "unknown" {
			t.Errorf("got %q, want %q", got, "unknown")
		}
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

	_ = w.Close()
	os.Stderr = origStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf) // #nosec errcheck
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

	_ = w.Close()
	os.Stderr = origStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf) // #nosec errcheck
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
