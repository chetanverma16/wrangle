package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/daemon"
	"github.com/chetanverma16/wrangle/internal/hookio"
	"github.com/chetanverma16/wrangle/internal/keepawake"
	"github.com/chetanverma16/wrangle/internal/proto"
	"github.com/chetanverma16/wrangle/internal/setup"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
	"github.com/chetanverma16/wrangle/internal/usage"
)

func runServe() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveLoop(ctx, config.Home(), 2*time.Second, serveOnce)
}

func configStamp(home string) (time.Time, int64, bool) {
	st, err := os.Stat(filepath.Join(home, "config.json"))
	if err != nil {
		return time.Time{}, 0, false
	}
	return st.ModTime(), st.Size(), true
}

// serveLoop waits for a paired config (launchd starts it before pairing), runs the daemon, and restarts it when
// config.json changes (a new phone, an unlink, keep-awake), so nothing needs launchctl after setup.
func serveLoop(ctx context.Context, home string, every time.Duration, once func(context.Context, config.Config) error) int {
	for {
		var cfg config.Config
		var mod time.Time
		var size int64
		for {
			if ctx.Err() != nil {
				return 0
			}
			if m, s, ok := configStamp(home); ok {
				if c, err := config.Load(home); err == nil && c.Paired() {
					cfg, mod, size = c, m, s
					break
				}
			}
			select {
			case <-ctx.Done():
				return 0
			case <-time.After(every):
			}
		}
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- once(runCtx, cfg) }()
		changed := make(chan struct{})
		go func() {
			for {
				select {
				case <-runCtx.Done():
					return
				case <-time.After(every):
				}
				if m, s, ok := configStamp(home); !ok || !m.Equal(mod) || s != size {
					close(changed)
					return
				}
			}
		}()
		select {
		case <-ctx.Done():
			cancel()
			<-done
			return 0
		case <-changed:
			log.Printf("config changed; restarting")
			cancel()
			<-done
		case err := <-done:
			cancel()
			if err != nil {
				log.Printf("serve stopped: %v; retrying", err)
			}
			select {
			case <-ctx.Done():
				return 0
			case <-time.After(every):
			}
		}
	}
}

func serveOnce(ctx context.Context, cfg config.Config) error {
	home := config.Home()
	sock := hookio.SocketPath(home)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	_ = os.Chmod(sock, 0o600)
	link := daemon.DialLink(ctx, cfg, version, log.Printf)
	d, err := daemon.New(cfg, link)
	if err != nil {
		ln.Close()
		return err
	}
	d.Log = log.Printf
	d.Enroller = liveEnroller{Home: home, KeysPath: sshkeys.DefaultPath(), Env: setup.LiveEnv(), User: currentUser}
	d.Reload = func() (config.Config, error) { return config.Load(home) }
	if runtime.GOOS == "darwin" && !cfg.KeepAwakeOff {
		go keepawake.Run(ctx, keepawake.Caffeinate, 5*time.Second)
	}
	go func() { // status for `wrangle doctor`
		for {
			_ = config.WriteStatus(home, link.Up(), time.Now())
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	go func() {
		codexHome := os.Getenv("CODEX_HOME")
		if codexHome == "" {
			h, _ := os.UserHomeDir()
			codexHome = filepath.Join(h, ".codex")
		}
		for {
			var snaps []usage.Snapshot
			if s, err := usage.ReadClaude(home); err == nil && s != nil {
				snaps = append(snaps, *s)
			}
			if s, err := usage.LatestCodex(codexHome); err == nil && s != nil {
				snaps = append(snaps, *s)
			}
			if len(snaps) > 0 && link.Up() {
				plain, _ := json.Marshal(snaps)
				if envs := d.SealAll(plain, cfg.HostID+"|usage"); len(envs) > 0 {
					_ = link.Send(ctx, usageMsg(envs))
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(60 * time.Second):
			}
		}
	}()
	log.Printf("wrangle %s serving on %s for host %s (%d phones)", version, sock, cfg.HostID, len(cfg.Devices))
	return d.Serve(ctx, ln)
}

func usageMsg(envs []proto.DeviceEnv) proto.UsageMsg { return proto.UsageMsg{T: "usage", Envs: envs} }
