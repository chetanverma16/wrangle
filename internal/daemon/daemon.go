// Package daemon is `wrangle serve`: it accepts hook connections on a Unix socket, seals events for the relay,
// waits for decisions, and answers the hooks.
package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/hookio"
	"github.com/chetanverma16/wrangle/internal/proto"
)

type Link interface {
	Send(ctx context.Context, v any) error
	Incoming() <-chan proto.RelayMsg
	Up() bool
}

// Enroller applies SSH enrolment and unlink requests (the live one edits authorized_keys and config.json).
type Enroller interface {
	Enroll(deviceID string, req proto.SSHEnroll) (proto.SSHReply, error)
	Unenroll(deviceID string) error
}

type waiter struct {
	ack      chan bool
	decision chan string
	desk     chan struct{} // answered at the desk (posttool/stop): return no decision; resolved is already sent

	// What the approval was for, to recognise a desk answer: the agent and session, the tool and its canonical input.
	agent, session, tool, input string
	devices                     map[string]bool // the phones this approval was sealed for: only they may decide it
	req                         hookio.Request
	payload                     proto.EventPayload
	resolveOnce                 sync.Once
}

type Daemon struct {
	cfg     config.Config
	kmu     sync.RWMutex
	keys    map[string][]byte // per phone (deviceId → envelope key), under kmu
	order   []string          // config order, so envelopes are deterministic; under kmu
	link    Link
	mu      sync.Mutex
	waiting map[string]*waiter
	// Log reports ignored relay messages. It defaults to a no-op; set it before Serve.
	Log func(format string, args ...any)
	// Enroller handles ssh-enroll and unlink. Nil ignores them; set it before Serve.
	Enroller Enroller
	// Reload reads the current config.json. An ssh-enroll from a phone paired (or re-paired) since this daemon
	// started finds its key there instead of being dropped. Nil disables it; set it before Serve.
	Reload func() (config.Config, error)
}

func New(cfg config.Config, link Link) (*Daemon, error) {
	d := &Daemon{cfg: cfg, keys: map[string][]byte{}, link: link, waiting: map[string]*waiter{}, Log: func(string, ...any) {}}
	for _, dev := range cfg.Devices {
		key, err := deriveKey(dev)
		if err != nil {
			return nil, err
		}
		d.keys[dev.DeviceID] = key
		d.order = append(d.order, dev.DeviceID)
	}
	return d, nil
}

func deriveKey(dev config.Device) ([]byte, error) {
	priv, err := proto.UnB64(dev.HostPrivate)
	if err != nil {
		return nil, err
	}
	app, err := proto.UnB64(dev.AppPublic)
	if err != nil {
		return nil, err
	}
	host, err := proto.UnB64(dev.HostPublic)
	if err != nil {
		return nil, err
	}
	return proto.DeriveKey(priv, app, app, host)
}

func (d *Daemon) key(id string) []byte {
	d.kmu.RLock()
	defer d.kmu.RUnlock()
	return d.keys[id]
}

// freshKey derives a phone's key from the current config.json (nil if it isn't paired with this host).
func (d *Daemon) freshKey(id string) []byte {
	if d.Reload == nil {
		return nil
	}
	cfg, err := d.Reload()
	if err != nil || cfg.HostID != d.cfg.HostID {
		return nil
	}
	for _, dev := range cfg.Devices {
		if dev.DeviceID == id {
			if key, err := deriveKey(dev); err == nil {
				return key
			}
		}
	}
	return nil
}

// setKey adds or replaces a phone's key, so later events are sealed for it too.
func (d *Daemon) setKey(id string, key []byte) {
	d.kmu.Lock()
	defer d.kmu.Unlock()
	if _, ok := d.keys[id]; !ok {
		d.order = append(d.order, id)
	}
	d.keys[id] = key
}

// SealAll seals plain once per phone, each with its own key.
func (d *Daemon) SealAll(plain []byte, aad string) []proto.DeviceEnv {
	d.kmu.RLock()
	defer d.kmu.RUnlock()
	var out []proto.DeviceEnv
	for _, id := range d.order {
		if env, err := proto.Seal(d.keys[id], plain, aad, nil); err == nil {
			out = append(out, proto.DeviceEnv{DeviceID: id, Env: env})
		}
	}
	return out
}

func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	go d.pump(ctx)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(50 * time.Millisecond) // don't spin on a persistent accept error
			continue
		}
		go d.HandleConn(c)
	}
}

// pump routes relay messages to the waiting hook connections. A "down" message (link lost) fails every waiter, and
// so does the daemon stopping (a restart on a config change): the hooks fall back to the agent's prompt at once.
func (d *Daemon) pump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			d.failAll()
			d.mu.Unlock()
			return
		case m := <-d.link.Incoming():
			d.mu.Lock()
			switch m.T {
			case "ack":
				if w := d.waiting[m.ID]; w != nil {
					select {
					case w.ack <- m.Pushed:
					default:
					}
				}
			case "decision":
				w := d.waiting[m.ID]
				dec, ok := d.openDecision(m)
				if !ok || (w != nil && !w.devices[m.DeviceID]) {
					d.Log("ignored a decision for %s from %s that did not verify", m.ID, m.DeviceID)
					break // forged, replayed, malformed or from a phone it wasn't sent to: the approval keeps waiting
				}
				if w != nil {
					select {
					case w.decision <- dec:
					default:
					}
				}
			case "ssh-enroll":
				go d.enroll(m) // writes files and talks to the relay: never under d.mu
			case "unlink":
				go d.unlink(m)
			case "down":
				d.failAll()
			}
			d.mu.Unlock()
		}
	}
}

// failAll ends every waiting approval with no decision. Call with d.mu held.
func (d *Daemon) failAll() {
	for _, w := range d.waiting {
		select {
		case w.decision <- "":
		default:
		}
	}
}

// openDecision verifies a phone-sealed decision (protocol amendment 1 §B) with the key of exactly the phone named.
func (d *Daemon) openDecision(m proto.RelayMsg) (string, bool) {
	key := d.key(m.DeviceID)
	if key == nil || m.Env == nil {
		return "", false
	}
	plain, err := proto.Open(key, *m.Env, proto.DecisionAAD(d.cfg.HostID, m.ID))
	if err != nil {
		return "", false
	}
	var p proto.DecisionPayload
	if json.Unmarshal(plain, &p) != nil || p.ID != m.ID {
		return "", false
	}
	switch p.Decision {
	case "allow", "deny", "always":
		return p.Decision, true
	}
	return "", false
}

func (d *Daemon) HandleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var req hookio.Request
	if json.NewDecoder(r).Decode(&req) != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	decision := d.handle(req, conn)
	if decision == "always" {
		decision = "allow"
	}
	_ = json.NewEncoder(conn).Encode(hookio.Response{Decision: decision})
}

func (d *Daemon) handle(req hookio.Request, conn net.Conn) string {
	if readsPhoneUpload(req) {
		return "allow"
	}
	if req.Agent == "claude" && (req.Event == "posttool" || req.Event == "stop") {
		d.answeredAtDesk(req)
	}
	if req.Event == "posttool" {
		return "" // posttool only withdraws approvals; it sends no event of its own
	}
	kind, payload, ok := BuildEvent(req)
	if !ok || !d.link.Up() {
		return ""
	}
	id := newID()
	plain, _ := json.Marshal(payload)
	envs := d.SealAll(plain, d.cfg.HostID+"|"+id)
	if len(envs) == 0 {
		return "" // no phone is connected to this Mac
	}
	timeout := d.cfg.ApprovalTimeoutClaude
	if req.Agent == "codex" {
		timeout = d.cfg.ApprovalTimeoutCodex
	}
	msg := proto.EventMsg{T: "event", ID: id, Kind: kind, Agent: req.Agent, Thread: thread(payload.Session), Envs: envs}
	if kind != "approval" {
		_ = d.link.Send(context.Background(), msg)
		return ""
	}
	msg.ExpiresIn = timeout
	session, tool, input := toolCall(req.Payload)
	w := &waiter{ack: make(chan bool, 1), decision: make(chan string, 1), desk: make(chan struct{}, 1),
		agent: req.Agent, session: session, tool: tool, input: input, req: req, payload: payload, devices: map[string]bool{}}
	for _, e := range envs {
		w.devices[e.DeviceID] = true
	}
	d.mu.Lock()
	d.waiting[id] = w
	d.mu.Unlock()
	defer func() { d.mu.Lock(); delete(d.waiting, id); d.mu.Unlock() }()
	if d.link.Send(context.Background(), msg) != nil {
		return ""
	}

	closed := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, conn); close(closed) }() // EOF = hook killed (answered at the desk)
	limit := time.After(time.Duration(timeout) * time.Second)

	select {
	case pushed := <-w.ack:
		if !pushed {
			return ""
		}
	case dec := <-w.decision:
		return d.finish(req, payload, dec)
	case <-w.desk:
		return ""
	case <-closed:
		d.resolveOnce(id, w)
		return ""
	case <-limit:
		go d.resolveOnce(id, w) // stop the phone offering a decision nobody waits for
		return ""
	case <-time.After(ackTimeout): // no ack from the relay
		go d.resolveOnce(id, w)
		return ""
	}
	select {
	case dec := <-w.decision:
		return d.finish(req, payload, dec)
	case <-w.desk:
		return ""
	case <-closed:
		d.resolveOnce(id, w)
		return ""
	case <-limit:
		go d.resolveOnce(id, w)
		return ""
	}
}

// answeredAtDesk withdraws approvals the user already answered in the terminal. Claude doesn't kill a pending
// PermissionRequest hook when the terminal prompt is answered, so EOF never comes; instead a PostToolUse for the
// same session, tool and input, or the session's Stop (every approval of that session), means "answered here".
// Each match gets `resolved` (once) and its hook returns no decision at once. Other sessions are never touched.
func (d *Daemon) answeredAtDesk(req hookio.Request) {
	session, tool, input := toolCall(req.Payload)
	if session == "" {
		return
	}
	type match struct {
		id string
		w  *waiter
	}
	var matches []match
	d.mu.Lock()
	for id, w := range d.waiting {
		if w.agent != req.Agent || w.session != session {
			continue
		}
		if req.Event == "posttool" && (w.tool != tool || w.input != input) {
			continue
		}
		delete(d.waiting, id) // a later decision or posttool finds nothing
		select {
		case w.desk <- struct{}{}:
		default:
		}
		matches = append(matches, match{id, w})
	}
	d.mu.Unlock()
	// Sent outside d.mu: a link Send may wait on the relay, and pump needs d.mu to drain incoming messages.
	for _, m := range matches {
		d.resolveOnce(m.id, m.w)
	}
}

// resolveOnce sends `resolved` for an approval at most once, whichever signal (EOF, posttool, stop, timeout, ack
// timeout) came first. A dropped link sends nothing: the relay closes pending approvals when the socket goes.
func (d *Daemon) resolveOnce(id string, w *waiter) {
	w.resolveOnce.Do(func() { d.resolved(id, w.req, w.payload) })
}

// toolCall reads a hook payload's session, tool name and canonical tool input (re-marshalled, so key order and
// whitespace don't matter).
func toolCall(payload json.RawMessage) (session, tool, input string) {
	var in struct {
		SessionID string          `json:"session_id"`
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(payload, &in) != nil {
		return "", "", ""
	}
	var v any
	if len(in.ToolInput) > 0 && json.Unmarshal(in.ToolInput, &v) == nil {
		if b, err := json.Marshal(v); err == nil {
			input = string(b)
		}
	}
	return in.SessionID, in.ToolName, input
}

// finish turns a verified decision into the hook's answer. "always" always answers allow; it also writes a
// project allow rule, but only when that rule can't cover more than the exact command the phone showed.
func (d *Daemon) finish(req hookio.Request, p proto.EventPayload, dec string) string {
	if dec != "always" {
		return dec
	}
	if safeAlwaysRule(req, p) {
		if err := WriteAllowRule(p.Cwd, p.Command); err != nil {
			d.Log("could not write the allow rule in %s: %v", p.Cwd, err)
		}
	}
	return "allow"
}

// safeAlwaysRule reports whether Bash(<command>) may be written for this approval. Claude Code reads `*` as a
// wildcard, a trailing `:*` as a prefix match, and parentheses delimit the rule, so any of those (or a newline)
// would let the rule allow more than what was approved. The cwd must be a real project directory.
func safeAlwaysRule(req hookio.Request, p proto.EventPayload) bool {
	if req.Agent != "claude" || toolName(req) != "Bash" || p.Command == "" {
		return false
	}
	if utf8.RuneCountInString(p.Command) > maxCommand || strings.ContainsAny(p.Command, "*()\n\r") {
		return false
	}
	cwd := filepath.Clean(p.Cwd)
	if !filepath.IsAbs(p.Cwd) || cwd == "/" {
		return false
	}
	if home, err := os.UserHomeDir(); err != nil || home == "" || filepath.Clean(home) == cwd {
		return false
	}
	return true
}

func toolName(req hookio.Request) string {
	var in struct {
		ToolName string `json:"tool_name"`
	}
	_ = json.Unmarshal(req.Payload, &in)
	return in.ToolName
}

func (d *Daemon) resolved(id string, req hookio.Request, p proto.EventPayload) {
	p.Title = p.Project + ": answered on the computer"
	p.Body = ""
	plain, _ := json.Marshal(p)
	envs := d.SealAll(plain, d.cfg.HostID+"|"+id)
	if len(envs) == 0 {
		return
	}
	_ = d.link.Send(context.Background(), proto.EventMsg{T: "event", ID: id, Kind: "resolved", Agent: req.Agent, Thread: thread(p.Session), Envs: envs})
}

// BuildEvent turns a hook request into an event kind and payload. ok=false means "don't send anything".
func BuildEvent(req hookio.Request) (string, proto.EventPayload, bool) {
	var in struct {
		SessionID        string          `json:"session_id"`
		Cwd              string          `json:"cwd"`
		ToolName         string          `json:"tool_name"`
		ToolInput        json.RawMessage `json:"tool_input"`
		NotificationType string          `json:"notification_type"`
		LastMessage      string          `json:"last_assistant_message"`
	}
	if json.Unmarshal(req.Payload, &in) != nil {
		return "", proto.EventPayload{}, false
	}
	agentName := map[string]string{"claude": "Claude", "codex": "Codex"}[req.Agent]
	p := proto.EventPayload{Agent: req.Agent, Cwd: in.Cwd, Project: filepath.Base(in.Cwd), Pane: req.Pane, Session: in.SessionID}
	if p.Project == "." || p.Project == "/" || p.Project == "" {
		p.Project = "your agent"
	}
	switch req.Event {
	case "permission":
		var input struct {
			Command  any `json:"command"`
			FilePath any `json:"file_path"`
		}
		_ = json.Unmarshal(in.ToolInput, &input)
		command, isCommand := input.Command.(string)
		p.Title = p.Project + " needs you"
		// The phone must see in full what it approves: a command or tool input over maxCommand runes is not sent
		// for remote approval (the hook gets no decision and the agent shows its own prompt).
		// Codex's shell escalations carry tool_input.command; their tool_name isn't guaranteed to be "Bash".
		if in.ToolName == "Bash" || (req.Agent == "codex" && isCommand && command != "") {
			if utf8.RuneCountInString(command) > maxCommand {
				return "", p, false
			}
			p.Command = command
			what := "use " + in.ToolName
			if command != "" {
				what = "run " + command
			}
			p.Body = truncate(agentName+" wants to "+what, maxBody)
			return "approval", p, true
		}
		p.Detail = canonicalJSON(in.ToolInput)
		if utf8.RuneCountInString(p.Detail) > maxCommand {
			return "", p, false
		}
		body := agentName + " wants to use " + in.ToolName
		if path, ok := input.FilePath.(string); ok && path != "" {
			body += ": " + path
		}
		p.Body = truncate(body, maxBody)
		return "approval", p, true
	case "stop":
		p.Title = p.Project + " is done"
		p.Body = truncate(firstLine(in.LastMessage), maxBody)
		if p.Body == "" {
			p.Body = agentName + " finished its turn."
		}
		return "done", p, true
	case "notification":
		if in.NotificationType != "idle_prompt" {
			return "", p, false
		}
		p.Title = p.Project + " is waiting for you"
		p.Body = agentName + " is waiting for your next message."
		return "waiting", p, true
	}
	return "", p, false
}

// maxCommand is the longest command (in runes) that can be sent for approval; maxBody caps display text.
// ackTimeout is how long an approval waits for the relay's ack (a var so tests can shorten it).
var ackTimeout = 10 * time.Second

const (
	maxCommand = 500
	maxBody    = 300
)

// canonicalJSON re-encodes raw JSON compactly with sorted object keys and without HTML escaping, for display.
func canonicalJSON(raw json.RawMessage) string {
	// UseNumber keeps numbers exactly as sent, so the phone shows what will run.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if len(raw) == 0 || dec.Decode(&v) != nil || dec.More() {
		return ""
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func firstLine(s string) string { return strings.TrimSpace(strings.SplitN(s, "\n", 2)[0]) }

func thread(session string) string {
	h := sha256.Sum256([]byte(session))
	return hex.EncodeToString(h[:8])
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

func (d *Daemon) enroll(m proto.RelayMsg) {
	if m.Env == nil || d.Enroller == nil {
		return
	}
	aad := proto.SSHAAD(d.cfg.HostID, m.DeviceID)
	key := d.key(m.DeviceID)
	err := errors.New("no key")
	var plain []byte
	if key != nil {
		plain, err = proto.Open(key, *m.Env, aad)
	}
	if err != nil { // a phone paired or re-paired since this daemon started: its key is in config.json by now
		if fresh := d.freshKey(m.DeviceID); fresh != nil && !bytes.Equal(fresh, key) {
			if plain, err = proto.Open(fresh, *m.Env, aad); err == nil {
				key = fresh
				d.setKey(m.DeviceID, fresh)
			}
		}
	}
	if err != nil {
		d.Log("ignored an ssh-enroll for %s that did not verify", m.DeviceID)
		return
	}
	var req proto.SSHEnroll
	if json.Unmarshal(plain, &req) != nil {
		return
	}
	reply, err := d.Enroller.Enroll(m.DeviceID, req)
	if err != nil {
		d.Log("ssh enrolment for %s failed: %v", m.DeviceID, err)
		return
	}
	out, _ := json.Marshal(reply)
	env, err := proto.Seal(key, out, proto.SSHReplyAAD(d.cfg.HostID, m.DeviceID), nil)
	if err != nil {
		return
	}
	_ = d.link.Send(context.Background(), proto.SSHEnrolledMsg{T: "ssh-enrolled", DeviceID: m.DeviceID, Env: env})
}

// unlink removes the phone's key and config entry, then tells the relay so it stops replaying the request.
func (d *Daemon) unlink(m proto.RelayMsg) {
	if d.Enroller != nil {
		if err := d.Enroller.Unenroll(m.DeviceID); err != nil {
			d.Log("unlink of %s failed: %v", m.DeviceID, err)
			return
		}
	}
	_ = d.link.Send(context.Background(), proto.UnlinkedMsg{T: "unlinked", DeviceID: m.DeviceID})
}
