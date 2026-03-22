package main

import (
	"reflect"
	"testing"
)

func TestFilterEnv(t *testing.T) {
	input := []string{
		"PATH=/usr/local/sbin:/usr/local/bin",
		"PROXY_USER=admin",
		"PROXY_PASS=supersecret32chars!!!",
		"GEO_AUTH_USER=alice",
		"GEO_AUTH_PASS=bob",
		"WARP_PLUS_KEY=1234-5678-90ab",
		"TZ=UTC",
		"INVALID_ENV_VAR",
	}
	want := []string{
		"PATH=/usr/local/sbin:/usr/local/bin",
		"PROXY_USER=admin",
		"TZ=UTC",
		"INVALID_ENV_VAR",
	}

	got := filterEnv(input)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEnv() = %v, want %v", got, want)
	}
}
