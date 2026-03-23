package warp

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// --- decodeClientID ---

func TestDecodeClientID(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    [3]byte
		wantErr bool
	}{
		{
			name:  "standard base64 three bytes",
			input: base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}),
			want:  [3]byte{0x01, 0x02, 0x03},
		},
		{
			name:  "url-safe base64 without padding",
			input: base64.RawURLEncoding.EncodeToString([]byte{0xAB, 0xCD, 0xEF}),
			want:  [3]byte{0xAB, 0xCD, 0xEF},
		},
		{
			name:  "zero bytes",
			input: base64.StdEncoding.EncodeToString([]byte{0x00, 0x00, 0x00}),
			want:  [3]byte{0x00, 0x00, 0x00},
		},
		{
			name:    "too few bytes (2)",
			input:   base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}),
			wantErr: true,
		},
		{
			name:    "too many bytes (4)",
			input:   base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04}),
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			input:   "!!!notbase64!!!",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeClientID(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (result: %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// --- parseAccountFile ---

func TestParseAccountFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid file", func(t *testing.T) {
		content := `
account_id = "test-account"
access_token = "my-access-token"
device_id = "abcdef01-1234-5678-abcd-ef0123456789"
license_key = ""
`
		path := filepath.Join(dir, "valid.toml")
		writeFile(t, path, content, 0o600)

		fields, err := parseAccountFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fields.AccessToken != "my-access-token" {
			t.Errorf("AccessToken: got %q", fields.AccessToken)
		}
		if fields.DeviceID != "abcdef01-1234-5678-abcd-ef0123456789" {
			t.Errorf("DeviceID: got %q", fields.DeviceID)
		}
	})

	t.Run("quoted values stripped", func(t *testing.T) {
		content := `access_token = "token-with-quotes"` + "\n" +
			`device_id = "dev-id-123"` + "\n"
		path := filepath.Join(dir, "quoted.toml")
		writeFile(t, path, content, 0o600)

		fields, err := parseAccountFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fields.AccessToken != "token-with-quotes" {
			t.Errorf("quotes not stripped from AccessToken: %q", fields.AccessToken)
		}
	})

	t.Run("missing access_token", func(t *testing.T) {
		content := `device_id = "abc123"` + "\n"
		path := filepath.Join(dir, "no_token.toml")
		writeFile(t, path, content, 0o600)

		_, err := parseAccountFile(path)
		if err == nil {
			t.Error("expected error for missing access_token, got nil")
		}
	})

	t.Run("missing device_id", func(t *testing.T) {
		content := `access_token = "token"` + "\n"
		path := filepath.Join(dir, "no_device.toml")
		writeFile(t, path, content, 0o600)

		_, err := parseAccountFile(path)
		if err == nil {
			t.Error("expected error for missing device_id, got nil")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := parseAccountFile(filepath.Join(dir, "missing.toml"))
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

// --- checkFilePermissions ---

func TestCheckFilePermissions(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		perm    os.FileMode
		wantErr bool
	}{
		{"0o600 accepted", 0o600, false},
		{"0o400 accepted", 0o400, false},
		{"0o644 rejected", 0o644, true},
		{"0o660 rejected", 0o660, true},
		{"0o640 rejected", 0o640, true},
		{"0o777 rejected", 0o777, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".toml")
			writeFile(t, path, "x", tc.perm)

			err := checkFilePermissions(path)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for perm %04o, got nil", tc.perm)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for perm %04o: %v", tc.perm, err)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		err := checkFilePermissions(filepath.Join(dir, "nonexistent.toml"))
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

// --- validDeviceID regex ---

func TestValidDeviceIDRegex(t *testing.T) {
	valid := []string{
		"abcdef01-1234-5678-abcd-ef0123456789",
		"ABCDEF01-1234-5678-ABCD-EF0123456789",
		"abc123",
	}
	invalid := []string{
		"",
		"../etc/passwd",
		"abc/def",
		"abc def",
		"abc\x00def",
		// 65 chars — exceeds limit
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	for _, id := range valid {
		if !validDeviceID.MatchString(id) {
			t.Errorf("validDeviceID rejected valid id %q", id)
		}
	}
	for _, id := range invalid {
		if validDeviceID.MatchString(id) {
			t.Errorf("validDeviceID accepted invalid id %q", id)
		}
	}
}

// writeFile is a test helper that creates a file with given content and permissions.
func writeFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("writeFile %q: %v", path, err)
	}
}
