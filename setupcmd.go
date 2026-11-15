package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/install"
	"github.com/chetanverma16/wrangle/internal/relayhttp"
	"github.com/chetanverma16/wrangle/internal/setup"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

func runSetup(args []string) int {
	home := config.Home()
	saved, _ := config.Load(home)
	relayDefault := defaultRelay
	if saved.RelayURL != "" {
		relayDefault = saved.RelayURL
	}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	relay := fs.String("relay", relayDefault, "relay base URL")
	name := fs.String("name", "", "name shown on your iPhone (default: this Mac's name)")
	yes := fs.Bool("yes", false, "answer every question with its default")
	noService := fs.Bool("no-service", false, "don't install the background service (development)")
	noHooks := fs.Bool("no-hooks", false, "don't ask about or change Claude Code and Codex settings (development)")
	if fs.Parse(args) != nil {
		return 2
	}
	if err := checkRelayURL(*relay); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	e := setup.LiveEnv()
	hostName := *name
	if hostName == "" {
		if out, err := e.Run("scutil", "--get", "ComputerName"); err == nil && strings.TrimSpace(out) != "" {
			hostName = strings.TrimSpace(out)
		} else {
			h, _ := os.Hostname()
			hostName = strings.TrimSuffix(h, ".local")
		}
	}
	if len([]rune(hostName)) > 64 {
		hostName = string([]rune(hostName)[:64])
	}
	exe, _ := os.Executable()
	bin := install.StableBin(exe)
	p := install.DefaultPaths(home)
	// The first Ctrl-C cancels ctx, so setup withdraws its offer and exits 130; stop() then restores the default
	// handler, so a second Ctrl-C kills the process even if a step is stuck.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); stop() }()
	return setup.Run(ctx, e, relayhttp.Client{URL: *relay}, setup.Options{
		RelayURL: *relay, HelperVersion: version, Home: home, HostName: hostName, KeysPath: sshkeys.DefaultPath(),
		Yes: *yes, NoService: *noService, NoHooks: *noHooks, PairPoll: 2 * time.Second, PairTimeout: 10 * time.Minute, KeyWait: 60 * time.Second,
		HooksPresent: func() bool { return install.HooksPresent(p) },
		InstallHooks: func() ([]string, error) {
			hp := p
			hp.ServiceDir = "" // the service is step 4
			var notes []string
			if _, err := exec.LookPath("codex"); err != nil {
				if _, statErr := os.Stat(filepath.Dir(hp.CodexHooks)); statErr != nil {
					hp.CodexHooks = ""
					notes = append(notes, "Codex isn't installed: skipped. Run `wrangle install` after installing it.")
				}
			}
			if _, err := exec.LookPath("claude"); err != nil {
				notes = append(notes, "Claude Code isn't installed yet: its settings are ready for when it is.")
			}
			r, err := install.Install(hp, bin, time.Now())
			if r.CodexTrustNeeded {
				notes = append(notes, "Codex: open Codex once and choose Trust for the Wrangle hooks.")
			}
			return notes, err
		},
		StartService: func() error {
			if _, err := install.WriteService(p, bin); err != nil {
				return err
			}
			startService(p)
			return nil
		},
	})
}
