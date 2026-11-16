package main

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/hookio"
	"github.com/chetanverma16/wrangle/internal/install"
	"github.com/chetanverma16/wrangle/internal/relayhttp"
	"github.com/chetanverma16/wrangle/internal/setup"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

func runDoctor() int {
	home := config.Home()
	cfg, _ := config.Load(home) // Doctor reports a missing or unreadable config itself
	relay := cfg.RelayURL
	if relay == "" {
		relay = defaultRelay
	}
	p := install.DefaultPaths(home)
	return setup.Doctor(setup.LiveEnv(), setup.DoctorDeps{
		Home: home, KeysPath: sshkeys.DefaultPath(), Now: time.Now,
		Health:       func() error { return relayhttp.Client{URL: relay}.Health(context.Background()) },
		HooksPresent: func() bool { return install.HooksPresent(p) },
		ProjectHooks: func() bool { return install.ProjectHooksPresent(cwd()) },
		AutoAllow:    func() []string { return install.AutoAllowHooks(install.ClaudeSettingsFiles(p, cwd())) },
		SocketAlive: func() bool {
			c, err := net.DialTimeout("unix", hookio.SocketPath(home), time.Second)
			if err != nil {
				return false
			}
			_ = c.Close()
			return true
		},
	})
}

// cwd is the directory doctor runs in: its .claude/ settings are the project's (empty if it can't be read).
func cwd() string {
	d, _ := os.Getwd()
	return d
}
