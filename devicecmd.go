package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/relayhttp"
	"github.com/chetanverma16/wrangle/internal/setup"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

type linkRemover interface {
	RemoveLink(ctx context.Context, a relayhttp.Auth, deviceID string) error
}

func runRemoveDevice(args []string) int {
	home := config.Home()
	if len(args) == 1 && args[0] == "--unknown" {
		return removeUnknownDevices(home, sshkeys.DefaultPath(), os.Stdout)
	}
	cfg, _ := config.Load(home) // removeDevice reports a missing or unreadable config itself
	relay := cfg.RelayURL
	if relay == "" {
		relay = defaultRelay
	}
	name := strings.Join(args, " ")
	return removeDevice(context.Background(), home, sshkeys.DefaultPath(), relayhttp.Client{URL: relay}, name, os.Stdout)
}

// removeDevice unlinks one phone (by name or id, case-insensitive; no name = the only phone) and removes its key.
// Exit codes: 0 removed, 1 failed or nothing to remove, 2 the name needs fixing.
func removeDevice(ctx context.Context, home, keysPath string, rel linkRemover, name string, w io.Writer) int {
	cfg, err := config.Load(home)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(w, "✗ Couldn't read ~/.wrangle/config.json (%v). Nothing was removed; fix its permissions or restore it, then try again.\n", err)
		return 1
	case err != nil || len(cfg.Devices) == 0:
		fmt.Fprintln(w, "No iPhone is connected to this Mac. Run `wrangle setup` to connect one.")
		return 1
	}
	var match []config.Device
	for _, d := range cfg.Devices {
		if name == "" && len(cfg.Devices) == 1 || name != "" && (strings.EqualFold(d.Name, name) || d.DeviceID == name) {
			match = append(match, d)
		}
	}
	if len(match) != 1 {
		fmt.Fprintln(w, "Which iPhone? Run `wrangle remove-device <name>` with one of:")
		for _, d := range cfg.Devices {
			fmt.Fprintf(w, "  %s (%s)\n", setup.SafeName(d.Name), setup.SafeName(d.DeviceID))
		}
		return 2
	}
	d := match[0]
	shown := setup.SafeName(d.Name)
	linkGone := false
	if err := rel.RemoveLink(ctx, relayhttp.Auth{HostID: cfg.HostID, HostSecret: cfg.HostSecret}, d.DeviceID); err != nil {
		if !errors.Is(err, relayhttp.ErrUnauthorized) {
			fmt.Fprintf(w, "✗ Couldn't reach the Wrangle server (%s). Nothing was removed; check your internet connection and try again.\n", setup.SafeName(err.Error()))
			return 1
		}
		linkGone = true // the server already forgot this Mac, so only the local key and entry are left to remove
	}
	// Unenroll takes the same lock as the daemon's enrolments and reloads the config right before saving it.
	if err := (liveEnroller{Home: home, KeysPath: keysPath}).Unenroll(d.DeviceID); err != nil {
		fmt.Fprintf(w, "✗ Couldn't update ~/.ssh/authorized_keys or the config (%s). Fix that, then run `wrangle remove-device` again.\n", setup.SafeName(err.Error()))
		return 1
	}
	if linkGone {
		fmt.Fprintln(w, "The Wrangle server no longer lists this Mac, so there was no link to remove there.")
	}
	fmt.Fprintf(w, "✓ Removed “%s”. Its key is gone from ~/.ssh/authorized_keys.\n", shown)
	return 0
}

// removeUnknownDevices is `wrangle remove-device --unknown`: it removes every Wrangle line in authorized_keys whose
// phone isn't in config.json (left behind when setup replaced this Mac's identity). Local only: the relay links of a
// forgotten identity can't be reached any more. A config that can't be read stops it, since every phone would look
// unknown. Exit codes: 0 done (or nothing to do), 1 failed.
func removeUnknownDevices(home, keysPath string, w io.Writer) int {
	unlock, err := config.Lock(home)
	if err != nil {
		fmt.Fprintf(w, "✗ Couldn't lock %s (%s). Nothing was removed.\n", filepath.Join(home, "enroll.lock"), setup.SafeName(err.Error()))
		return 1
	}
	defer unlock()
	cfg, err := config.Load(home)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(w, "✗ Couldn't read ~/.wrangle/config.json (%s). Nothing was removed; fix its permissions or restore it, then try again.\n", setup.SafeName(err.Error()))
		return 1
	}
	unknown, err := setup.UnknownKeys(keysPath, cfg)
	if err != nil {
		fmt.Fprintf(w, "✗ Couldn't read ~/.ssh/authorized_keys (%s). Nothing was removed.\n", setup.SafeName(err.Error()))
		return 1
	}
	if len(unknown) == 0 {
		fmt.Fprintln(w, "No unknown iPhone keys in ~/.ssh/authorized_keys.")
		return 0
	}
	for _, id := range unknown {
		if _, err := sshkeys.Remove(keysPath, id); err != nil {
			fmt.Fprintf(w, "✗ Couldn't update ~/.ssh/authorized_keys (%s). Fix that, then run `wrangle remove-device --unknown` again.\n", setup.SafeName(err.Error()))
			return 1
		}
	}
	noun := "key"
	if len(unknown) > 1 {
		noun = "keys"
	}
	fmt.Fprintf(w, "✓ Removed %d unknown iPhone %s from ~/.ssh/authorized_keys.\n", len(unknown), noun)
	return 0
}
