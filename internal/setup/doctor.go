package setup

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

type DoctorDeps struct {
	Home, KeysPath string
	Health         func() error // relay reachable
	HooksPresent   func() bool
	SocketAlive    func() bool // `wrangle serve` answers on its socket
	Now            func() time.Time
}

// Doctor re-runs setup's checks plus relay, daemon, hooks and phone keys. Each failure prints its fix.
func Doctor(e Env, d DoctorDeps) int {
	w := e.Out
	bad := 0
	check := func(pass bool, good, problem, fix string) {
		if pass {
			ok(w, "%s", good)
			return
		}
		bad++
		fail(w, "%s %s", problem, fix)
	}
	tmux, found := FindTmux(e)
	check(found, "tmux  "+tmux, "tmux isn't installed.", "Run: brew install tmux")
	check(RemoteLoginOn(e), "Remote Login is on", "Remote Login is off.", "Turn it on in System Settings → General → Sharing.")
	ts := Tailscale(e)
	check(!ts.SSH, "Tailscale SSH is off (or Tailscale isn't installed)", "Tailscale SSH is on and blocks Remote Login on the Tailscale address.",
		"Turn it off: tailscale set --ssh=false")
	ifaces, _ := e.Interfaces()
	addrs := Addresses(LocalHostName(e), LANIPv4(ifaces), ts.IP, ts.DNSName)
	check(len(addrs) > 0, fmt.Sprintf("%d addresses for your iPhone", len(addrs)), "This Mac has no network address.", "Connect to Wi-Fi.")

	cfg, err := config.Load(d.Home)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fail(w, "Couldn't read ~/.wrangle/config.json (%v). Fix its permissions or restore it, then run `wrangle doctor` again.", err)
		return 1
	}
	// Keys for phones this Mac no longer knows (setup replaced the Mac's identity, or config.json was removed) still
	// open SSH. Checked before anything that needs a pairing.
	if unknown := unknownKeys(d.KeysPath, cfg); len(unknown) > 0 {
		bad++
		noun := "key"
		if len(unknown) > 1 {
			noun = "keys"
		}
		fail(w, "%d SSH %s in ~/.ssh/authorized_keys belongs to an iPhone this Mac no longer knows (%s). Run: wrangle remove-device --unknown",
			len(unknown), noun, strings.Join(unknown, ", "))
	}
	if err != nil || !cfg.Paired() {
		fail(w, "This Mac isn't connected to an iPhone yet. Run `wrangle setup`.")
		return 1
	}
	check(d.Health() == nil, "Wrangle server reachable", "Can't reach the Wrangle server.", "Check your internet connection.")
	check(d.SocketAlive(), "Background service running", "The background service isn't running.",
		"Run: launchctl load -w ~/Library/LaunchAgents/com.stackframe.wrangle.plist (or `wrangle setup` again).")
	st, err := config.ReadStatus(d.Home)
	fresh := err == nil && st.Relay == "up" && d.Now().Sub(time.UnixMilli(st.At)) < 15*time.Second
	check(fresh, "Background service connected to the Wrangle server", "The background service isn't connected to the Wrangle server.",
		"Check your internet connection; the log is ~/.wrangle/serve.log.")
	check(d.HooksPresent(), "Phone approvals for Claude Code are on", "Phone approvals are off.", "Run: wrangle install")
	if len(cfg.Devices) == 0 {
		fail(w, "No iPhone is connected. Run `wrangle setup`.")
		bad++
	}
	for _, dev := range cfg.Devices {
		name := SafeName(dev.Name)
		check(sshkeys.Has(d.KeysPath, dev.DeviceID), fmt.Sprintf("Terminal key for “%s” is in ~/.ssh/authorized_keys", name),
			fmt.Sprintf("The terminal key for “%s” is missing.", name), "Remove this Mac in the Wrangle app, then run `wrangle setup`.")
	}
	if bad > 0 {
		return 1
	}
	return 0
}

// UnknownKeys lists the device ids of Wrangle's authorized_keys lines whose phone isn't in cfg.
func UnknownKeys(keysPath string, cfg config.Config) ([]string, error) {
	ids, err := sshkeys.DeviceIDs(keysPath)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, d := range cfg.Devices {
		known[d.DeviceID] = true
	}
	var unknown []string
	for _, id := range ids {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	return unknown, nil
}

func unknownKeys(keysPath string, cfg config.Config) []string {
	u, _ := UnknownKeys(keysPath, cfg)
	return u
}
