package keepawake

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunRestartsTheChildWhenItExits(t *testing.T) {
	var n atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, func(context.Context) error { n.Add(1); return nil }, time.Millisecond)
		close(done)
	}()
	for i := 0; i < 500 && n.Load() < 3; i++ {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if n.Load() < 3 {
		t.Fatalf("want at least 3 starts, got %d", n.Load())
	}
}

func TestRunStopsTheChildOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		Run(ctx, func(c context.Context) error { <-c.Done(); close(stopped); return c.Err() }, time.Second)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run must return promptly after cancel")
	}
	<-stopped
}
