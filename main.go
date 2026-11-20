package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/hookio"
	"github.com/chetanverma16/wrangle/internal/usage"
)

var version = "0.1.1"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wrangle version | setup | doctor | remove-device [name|--unknown] | install | uninstall | config keep-awake on|off | serve | hook <agent> <event>")
		os.Exit(2)
	}
	switch args[0] {
	case "version":
		fmt.Printf("wrangle %s\n", version)
	case "setup":
		os.Exit(runSetup(args[1:]))
	case "doctor":
		os.Exit(runDoctor())
	case "remove-device":
		os.Exit(runRemoveDevice(args[1:]))
	case "serve":
		os.Exit(runServe())
	case "install":
		os.Exit(runInstall(args[1:], false))
	case "uninstall":
		os.Exit(runInstall(args[1:], true))
	case "statusline":
		fs := flag.NewFlagSet("statusline", flag.ContinueOnError)
		fs.SetOutput(io.Discard) // stdout/stderr noise must never reach Claude's status line
		then := fs.String("then", "", "your previous status line command")
		_ = fs.Parse(args[1:])
		os.Exit(usage.Statusline(os.Stdin, os.Stdout, *then, config.Home(), time.Now()))
	case "hook":
		if len(args) < 3 {
			os.Exit(0) // never break an agent over bad arguments
		}
		home := config.Home()
		cfg, _ := config.Load(home) // missing config → defaults; the socket dial then fails quietly
		claude, codex := cfg.ApprovalTimeoutClaude, cfg.ApprovalTimeoutCodex
		if claude == 0 {
			claude, codex = 120, 30
		}
		os.Exit(hookio.Run(args[1], args[2], os.Stdin, os.Stdout, hookio.Options{
			SocketPath: hookio.SocketPath(home), Deadline: hookio.DeadlineFor(args[1], args[2], claude, codex)}))
	case "config":
		os.Exit(runConfig(args[1:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		os.Exit(2)
	}
}
