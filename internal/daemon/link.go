package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/proto"
)

// WSLink keeps one WebSocket to the relay, reconnecting with backoff. On disconnect it emits {T:"down"}.
type WSLink struct {
	cfg     config.Config
	version string
	in      chan proto.RelayMsg
	mu      sync.Mutex
	conn    *websocket.Conn
	up      atomic.Bool
	Log     func(string, ...any)

	pingEvery, pingWait time.Duration // copied from pingInterval/pingTimeout at dial time
}

func DialLink(ctx context.Context, cfg config.Config, version string, log func(string, ...any)) *WSLink {
	l := &WSLink{cfg: cfg, version: version, in: make(chan proto.RelayMsg, 64), Log: log,
		pingEvery: pingInterval, pingWait: pingTimeout}
	go l.loop(ctx)
	return l
}

func (l *WSLink) Incoming() <-chan proto.RelayMsg { return l.in }
func (l *WSLink) Up() bool                        { return l.up.Load() }

func (l *WSLink) Send(ctx context.Context, v any) error {
	l.mu.Lock()
	c := l.conn
	l.mu.Unlock()
	if c == nil {
		return context.Canceled
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, data)
}

func (l *WSLink) loop(ctx context.Context) {
	backoff := time.Second
	url := strings.Replace(strings.TrimRight(l.cfg.RelayURL, "/"), "http", "ws", 1) + "/v1/hosts/connect"
	for ctx.Err() == nil {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+l.cfg.HostID+"."+l.cfg.HostSecret)
		h.Set("X-Wrangle-Helper", l.version)
		c, res, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: h})
		if err != nil {
			status := 0
			if res != nil {
				status = res.StatusCode
			}
			l.Log("relay connect failed (status %d): %v; retry in %v", status, err, backoff)
			if !wait(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, 0)
			continue
		}
		connected := time.Now()
		c.SetReadLimit(1 << 20)
		l.mu.Lock()
		l.conn = c
		l.mu.Unlock()
		l.up.Store(true)
		l.Log("connected to relay")
		connCtx, stopPings := context.WithCancel(ctx)
		go l.keepalive(connCtx, c)
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				break
			}
			var m proto.RelayMsg
			if json.Unmarshal(data, &m) == nil {
				select {
				case l.in <- m:
				case <-ctx.Done():
				}
			}
		}
		stopPings()
		l.up.Store(false)
		l.mu.Lock()
		l.conn = nil
		l.mu.Unlock()
		_ = c.CloseNow()
		select {
		case l.in <- proto.RelayMsg{T: "down"}:
		case <-ctx.Done():
			return
		}
		// Always wait before redialing after a drop; only a connection that stayed up resets the backoff.
		backoff = nextBackoff(backoff, time.Since(connected))
		l.Log("relay connection lost; retry in %v", backoff)
		if !wait(ctx, backoff) {
			return
		}
	}
}

// Keepalive: while connected, ping the relay every pingInterval; no pong within pingTimeout drops the connection
// (which emits "down" and fails pending approvals). Vars so tests can shorten them.
var (
	pingInterval = 20 * time.Second
	pingTimeout  = 8 * time.Second
)

// keepalive pings the relay until ctx ends. An unanswered ping closes the connection, which ends the read loop.
func (l *WSLink) keepalive(ctx context.Context, c *websocket.Conn) {
	t := time.NewTicker(l.pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, l.pingWait)
		err := c.Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				l.Log("relay did not answer a ping: %v", err)
				_ = c.CloseNow()
			}
			return
		}
	}
}

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
	stableFor  = 30 * time.Second // a connection up this long counts as healthy
)

// nextBackoff returns the wait after a failed dial (upFor = 0) or a dropped connection that was up for upFor:
// it resets to 1 s after a stable connection, otherwise doubles, capped at 30 s.
func nextBackoff(cur, upFor time.Duration) time.Duration {
	if upFor >= stableFor {
		return minBackoff
	}
	return min(max(cur, minBackoff)*2, maxBackoff)
}

// wait sleeps for d, returning false if ctx ends first.
func wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
