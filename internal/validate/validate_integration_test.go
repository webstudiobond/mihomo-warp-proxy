//go:build integration

package validate

import (
	"testing"
)

// TestResolveAndValidateIntegration requires a live DNS resolver.
// Run with: go test -tags integration ./internal/validate/...
func TestResolveAndValidateIntegration(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{
			name:    "cloudflare warp endpoint resolves to public IP",
			host:    "engage.cloudflareclient.com",
			wantErr: false,
		},
		{
			name:    "cloudflare public DNS resolves to public IP",
			host:    "one.one.one.one",
			wantErr: false,
		},
		{
			name:    "localhost rejected",
			host:    "localhost",
			wantErr: true,
		},
		{
			name:    "nonexistent domain rejected",
			host:    "this.domain.does.not.exist.invalid",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ResolveAndValidate(tc.host)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for host %q, got nil", tc.host)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for host %q: %v", tc.host, err)
			}
		})
	}
}
