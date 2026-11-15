package main

import "testing"

func TestCheckRelayURL(t *testing.T) {
	for _, bad := range []string{"http://relay.example.com", "http://10.0.0.5:8787", "http://localhost.evil.com", "ftp://x", "nope"} {
		if checkRelayURL(bad) == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
	for _, bad := range []string{"http://evil.local.example.com", "http://a.b.local:8787"} {
		if checkRelayURL(bad) == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
	for _, ok := range []string{"https://api.wrangle.stackframes.dev", "http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:8787",
		"http://Alexs-MacBook-Pro.local:8787"} {
		if err := checkRelayURL(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}
