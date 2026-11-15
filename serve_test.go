package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
)

func TestServeLoopWaitsForConfigAndRestartsWhenItChanges(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	runs := make(chan string, 4)
	once := func(ctx context.Context, c config.Config) error { runs <- c.HostID; <-ctx.Done(); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- serveLoop(ctx, home, 10*time.Millisecond, once) }()
	select {
	case id := <-runs:
		t.Fatalf("must wait for a paired config, ran with %q", id)
	case <-time.After(60 * time.Millisecond):
	}
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s"})
	if id := <-runs; id != "host_1" {
		t.Fatalf("got %q", id)
	}
	time.Sleep(20 * time.Millisecond)
	_ = config.Save(home, config.Config{HostID: "host_22", HostSecret: "s"}) // a re-pair or a new phone
	select {
	case id := <-runs:
		if id != "host_22" {
			t.Fatalf("got %q", id)
		}
	case <-time.After(time.Second):
		t.Fatal("a changed config must restart the daemon")
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// `wrangle config keep-awake off` only edits config.json; serve must pick it up without launchctl.
func TestServeLoopPicksUpKeepAwakeChange(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s"})
	runs := make(chan bool, 4)
	once := func(ctx context.Context, c config.Config) error { runs <- c.KeepAwakeOff; <-ctx.Done(); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveLoop(ctx, home, 10*time.Millisecond, once)
	if off := <-runs; off {
		t.Fatal("keep-awake starts on")
	}
	time.Sleep(20 * time.Millisecond)
	c, _ := config.Load(home)
	c.KeepAwakeOff = true
	_ = config.Save(home, c)
	select {
	case off := <-runs:
		if !off {
			t.Fatal("restarted without the new setting")
		}
	case <-time.After(time.Second):
		t.Fatal("keep-awake change not picked up")
	}
}
