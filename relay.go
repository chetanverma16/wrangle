package main

import (
	"fmt"
	"net/url"
	"strings"
)

const defaultRelay = "https://api.wrangle.stackframes.dev"

// checkRelayURL refuses a plain-http relay unless it is this machine (local development).
func checkRelayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("--relay must be an https:// URL, got %q", raw)
	}
	if u.Scheme == "http" {
		h := strings.ToLower(u.Hostname())
		switch {
		case h == "localhost", h == "127.0.0.1", h == "::1":
		case strings.HasSuffix(h, ".local") && h != ".local" && !strings.Contains(strings.TrimSuffix(h, ".local"), "."):
			// A development relay on this Mac, reached by the iPhone over the LAN (docs/dev/device-run.md).
		default:
			return fmt.Errorf("refusing plain http relay %q: use https:// (http is allowed only for localhost, 127.0.0.1, ::1 or <name>.local)", raw)
		}
	}
	return nil
}
