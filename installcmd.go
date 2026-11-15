package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/install"
)

func runInstall(args []string, uninstall bool) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	claude := fs.String("claude-settings", "", "Claude settings file to change (default ~/.claude/settings.json)")
	noCodex := fs.Bool("no-codex", false, "skip Codex")
	noService := fs.Bool("no-service", false, "don't install the background service")
	if fs.Parse(args) != nil {
		return 2
	}
	p := install.DefaultPaths(config.Home())
	if *claude != "" {
		p.ClaudeSettings = *claude
	}
	if *noCodex {
		p.CodexHooks = ""
	}
	if *noService {
		p.ServiceDir = ""
	}
	exe, _ := os.Executable()
	bin := install.StableBin(exe)
	if uninstall {
		if *noService == false {
			stopService(p)
		}
		if err := install.Uninstall(p, bin, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall failed:", err)
			return 1
		}
		fmt.Println("Wrangle hooks removed. Backups are in", p.Backup)
		return 0
	}
	r, err := install.Install(p, bin, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "install failed, nothing was overwritten:", err)
		return 1
	}
	for _, c := range r.Changed {
		fmt.Println("updated", c)
	}
	if p.ServiceDir != "" {
		startService(p)
	}
	if r.CodexTrustNeeded {
		fmt.Println("Codex: open Codex once and choose Trust for the Wrangle hooks (Hooks need review → Review hooks).")
	}
	return 0
}

func startService(p install.Paths) {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("launchctl", "load", "-w", p.ServiceDir+"/com.stackframe.wrangle.plist").Run()
		return
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	_ = exec.Command("systemctl", "--user", "enable", "--now", "wrangle.service").Run()
}

func stopService(p install.Paths) {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("launchctl", "unload", p.ServiceDir+"/com.stackframe.wrangle.plist").Run()
		return
	}
	_ = exec.Command("systemctl", "--user", "disable", "--now", "wrangle.service").Run()
}
