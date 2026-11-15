// Package keepawake keeps the Mac from sleeping while the helper runs, so the phone can reach it.
package keepawake

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Run keeps one child running (start blocks until the child exits) and restarts it after `retry`, until ctx ends.
func Run(ctx context.Context, start func(context.Context) error, retry time.Duration) {
	for ctx.Err() == nil {
		_ = start(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// Caffeinate holds a system-sleep assertion. macOS honours -s only on AC power, which is "while on power";
// the display may still sleep. -w ends caffeinate if this process dies.
func Caffeinate(ctx context.Context) error {
	return exec.CommandContext(ctx, "caffeinate", "-s", "-w", strconv.Itoa(os.Getpid())).Run()
}
