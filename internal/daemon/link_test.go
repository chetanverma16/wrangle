package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/chetanverma16/wrangle/internal/config"
)

func TestNextBackoff(t *testing.T) {
	cases := []struct {
		cur, upFor, want time.Duration
	}{
		{time.Second, time.Second, 2 * time.Second},       // dropped quickly: double
		{2 * time.Second, 0, 4 * time.Second},             // dial failed: double
		{8 * time.Second, 40 * time.Second, time.Second},  // stayed up ≥ 30 s: reset
		{20 * time.Second, time.Second, 30 * time.Second}, // capped
		{30 * time.Second, 0, 30 * time.Second},           // stays at the cap
	}
	for _, c := range cases {
		if got := nextBackoff(c.cur, c.upFor); got != c.want {
			t.Errorf("nextBackoff(%v, %v) = %v, want %v", c.cur, c.upFor, got, c.want)
		}
	}
}

// silentRelay accepts WebSockets and never reads from them, so it never answers a ping (a half-dead connection).
func silentRelay(t *testing.T) string {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		<-release
		_ = c.CloseNow()
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	return srv.URL
}

// shortPings shortens the keepalive for one test. DialLink copies the values, so restoring them is race-free.
func shortPings(t *testing.T) {
	oldI, oldT := pingInterval, pingTimeout
	pingInterval, pingTimeout = 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { pingInterval, pingTimeout = oldI, oldT })
}

func waitUp(t *testing.T, l *WSLink) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !l.Up() {
		if time.Now().After(deadline) {
			t.Fatal("link never came up")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLinkPingTimeoutReportsDown(t *testing.T) {
	shortPings(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := DialLink(ctx, config.Config{RelayURL: silentRelay(t), HostID: "h", HostSecret: "s"}, "0.1.0", func(string, ...any) {})
	waitUp(t, l)
	upAt := time.Now()
	select {
	case m := <-l.Incoming():
		if m.T != "down" {
			t.Fatalf("want down, got %+v", m)
		}
	case <-time.After(time.Second):
		t.Fatal("no down within 1 s although the relay never answers pings")
	}
	if l.Up() {
		t.Fatal("Up() must be false after down")
	}
	if took := time.Since(upAt); took > 500*time.Millisecond {
		t.Fatalf("down took %v, want a few ping intervals", took)
	}
}

func TestPendingApprovalFailsFastWhenPingsGoUnanswered(t *testing.T) {
	shortPings(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg, _ := testConfig(t)
	cfg.RelayURL = silentRelay(t)
	l := DialLink(ctx, cfg, "0.1.0", func(string, ...any) {})
	d, err := New(cfg, l)
	if err != nil {
		t.Fatal(err)
	}
	go d.pump(ctx)
	waitUp(t, l)
	start := time.Now()
	got, _ := ask(t, d, permissionReq("claude")) // claude timeout = 2 s in testConfig
	if got != "" || time.Since(start) > time.Second {
		t.Fatalf("got %q after %v, want no decision well before the 2 s timeout", got, time.Since(start))
	}
}
