package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/hookio"
	"github.com/chetanverma16/wrangle/internal/proto"
)

type fakeLink struct {
	mu    sync.Mutex
	sent  []proto.EventMsg
	in    chan proto.RelayMsg
	up    bool
	ack   func(proto.EventMsg) *proto.RelayMsg // reply to an event, nil = no ack
	other []any                                // everything else sent to the relay
}

func (f *fakeLink) Send(_ context.Context, v any) error {
	if m, ok := v.(proto.EventMsg); ok {
		f.mu.Lock()
		f.sent = append(f.sent, m)
		f.mu.Unlock()
		if f.ack != nil {
			if r := f.ack(m); r != nil {
				f.in <- *r
			}
		}
	} else {
		f.mu.Lock()
		f.other = append(f.other, v)
		f.mu.Unlock()
	}
	return nil
}

func (f *fakeLink) waitOther(t *testing.T) any {
	t.Helper()
	for i := 0; i < 400; i++ {
		f.mu.Lock()
		if len(f.other) > 0 {
			v := f.other[0]
			f.mu.Unlock()
			return v
		}
		f.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no message sent to the relay")
	return nil
}
func (f *fakeLink) Incoming() <-chan proto.RelayMsg { return f.in }
func (f *fakeLink) Up() bool                        { return f.up }
func (f *fakeLink) events() []proto.EventMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]proto.EventMsg(nil), f.sent...)
}

func device(t *testing.T, id string) (config.Device, []byte) {
	t.Helper()
	app, _ := proto.GenerateKeyPair()
	host, _ := proto.GenerateKeyPair()
	key, err := proto.DeriveKey(app.Private, host.Public, app.Public, host.Public)
	if err != nil {
		t.Fatal(err)
	}
	return config.Device{DeviceID: id, Name: "iPhone", AppPublic: proto.B64(app.Public), HostPrivate: proto.B64(host.Private),
		HostPublic: proto.B64(host.Public)}, key
}

func testConfig(t *testing.T) (config.Config, []byte) {
	dev, key := device(t, "dev_1")
	return config.Config{HostID: "host_1", ApprovalTimeoutClaude: 2, ApprovalTimeoutCodex: 1, Devices: []config.Device{dev}}, key
}

func start(t *testing.T, link *fakeLink) (*Daemon, config.Config, []byte) {
	cfg, key := testConfig(t)
	d, err := New(cfg, link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go d.pump(ctx)
	return d, cfg, key
}

// ask simulates `wrangle hook`: send a request and wait for one response line (or keep the conn open).
func ask(t *testing.T, d *Daemon, req hookio.Request) (string, net.Conn) {
	a, b := net.Pipe()
	go d.HandleConn(b)
	_ = json.NewEncoder(a).Encode(req)
	var res hookio.Response
	_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewDecoder(bufio.NewReader(a)).Decode(&res); err != nil {
		return "ERR " + err.Error(), a
	}
	return res.Decision, a
}

// sealed builds the relay → host decision message exactly as the phone would.
func sealed(t *testing.T, key []byte, hostID, id, decision string) proto.RelayMsg {
	t.Helper()
	plain, _ := json.Marshal(proto.DecisionPayload{ID: id, Decision: decision})
	env, err := proto.Seal(key, plain, proto.DecisionAAD(hostID, id), nil)
	if err != nil {
		t.Fatal(err)
	}
	return proto.RelayMsg{T: "decision", ID: id, DeviceID: "dev_1", Env: &env}
}

func permissionReq(agent string) hookio.Request {
	p := `{"session_id":"sess-1","tool_name":"Bash","tool_input":{"command":"git push origin main"},"cwd":"/Users/dev/code/api-server"}`
	return hookio.Request{Agent: agent, Event: "permission", Pane: "%2", Payload: json.RawMessage(p)}
}

func TestApprovalAllowFromPhone(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, key := start(t, link)
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() {
			time.Sleep(50 * time.Millisecond)
			link.in <- sealed(t, key, cfg.HostID, m.ID, "allow")
		}()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	got, _ := ask(t, d, permissionReq("claude"))
	if got != "allow" {
		t.Fatalf("want allow, got %q", got)
	}
	ev := link.events()[0]
	if ev.Kind != "approval" || ev.Agent != "claude" || ev.ExpiresIn != cfg.ApprovalTimeoutClaude || len(ev.Thread) != 16 {
		t.Fatalf("event %+v", ev)
	}
	plain, err := proto.Open(key, ev.Envs[0].Env, cfg.HostID+"|"+ev.ID)
	if err != nil {
		t.Fatal(err)
	}
	var p proto.EventPayload
	_ = json.Unmarshal(plain, &p)
	if p.Title != "api-server needs you" || p.Command != "git push origin main" || p.Pane != "%2" || p.Project != "api-server" {
		t.Fatalf("payload %+v", p)
	}
}

func TestForgedDecisionIsIgnored(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, _ := start(t, link)
	wrongKey := make([]byte, 32) // the relay doesn't have the pairing key
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() {
			link.in <- sealed(t, wrongKey, cfg.HostID, m.ID, "allow")
			link.in <- proto.RelayMsg{T: "decision", ID: m.ID} // no envelope at all
		}()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	start := time.Now()
	got, _ := ask(t, d, permissionReq("codex")) // codex timeout = 1 s
	if got != "" || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("a forged decision must not be accepted: got %q after %v", got, time.Since(start))
	}
}

func TestDecisionForAnotherEventIsIgnored(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, key := start(t, link)
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() {
			msg := sealed(t, key, cfg.HostID, "evt_other", "allow") // a real decision for a different approval…
			msg.ID = m.ID                                           // …replayed under this approval's id
			link.in <- msg
		}()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	if got, _ := ask(t, d, permissionReq("codex")); got != "" {
		t.Fatalf("replayed decision must be ignored, got %q", got)
	}
}

func TestNotPushedReturnsAtOnce(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: false} }
	d, _, _ := start(t, link)
	start := time.Now()
	got, _ := ask(t, d, permissionReq("claude"))
	if got != "" || time.Since(start) > time.Second {
		t.Fatalf("got %q after %v", got, time.Since(start))
	}
}

func TestLinkDownReturnsAtOnce(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: false}
	d, _, _ := start(t, link)
	if got, _ := ask(t, d, permissionReq("claude")); got != "" {
		t.Fatalf("got %q", got)
	}
	if len(link.events()) != 0 {
		t.Fatal("nothing should be sent while the link is down")
	}
}

func TestPendingApprovalFailsFastWhenLinkDrops(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true} }
	d, _, _ := start(t, link)
	go func() {
		time.Sleep(200 * time.Millisecond)
		link.in <- proto.RelayMsg{T: "down"}
	}()
	start := time.Now()
	got, _ := ask(t, d, permissionReq("claude"))
	if got != "" || time.Since(start) > time.Second {
		t.Fatalf("got %q after %v", got, time.Since(start))
	}
}

func TestApprovalTimesOutPerAgent(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true} }
	d, _, _ := start(t, link)
	start := time.Now()
	got, _ := ask(t, d, permissionReq("codex")) // codex timeout = 1 s in testConfig
	took := time.Since(start)
	if got != "" || took < 900*time.Millisecond || took > 2*time.Second {
		t.Fatalf("got %q after %v", got, took)
	}
}

func TestAnsweredAtDeskSendsResolved(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true} }
	d, _, _ := start(t, link)
	a, b := net.Pipe()
	go d.HandleConn(b)
	_ = json.NewEncoder(a).Encode(permissionReq("claude"))
	time.Sleep(100 * time.Millisecond)
	a.Close() // the agent killed the hook: the user answered in the terminal
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ev := link.events()
		if len(ev) == 2 && ev[1].Kind == "resolved" && ev[1].ID == ev[0].ID {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want approval then resolved with the same id, got %+v", link.events())
}

func TestAlwaysWritesRuleAndAllows(t *testing.T) {
	dir := t.TempDir()
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, key := start(t, link)
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() { link.in <- sealed(t, key, cfg.HostID, m.ID, "always") }()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	req := permissionReq("claude")
	req.Payload = json.RawMessage(strings.Replace(string(req.Payload), "/Users/dev/code/api-server", dir, 1))
	if got, _ := ask(t, d, req); got != "allow" {
		t.Fatalf("always must answer allow, got %q", got)
	}
	rules, _ := readAllow(dir)
	if len(rules) != 1 || rules[0] != "Bash(git push origin main)" {
		t.Fatalf("rules %v", rules)
	}
}

func TestStopSendsDoneAndAnswersEmpty(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true} }
	d, _, _ := start(t, link)
	got, _ := ask(t, d, hookio.Request{Agent: "claude", Event: "stop", Payload: json.RawMessage(`{"session_id":"s","cwd":"/x/docs","last_assistant_message":"Updated README"}`)})
	if got != "" {
		t.Fatalf("got %q", got)
	}
	if ev := link.events(); len(ev) != 1 || ev[0].Kind != "done" {
		t.Fatalf("%+v", ev)
	}
}

func TestPermissionPromptNotificationIsIgnored(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, _, _ := start(t, link)
	_, _ = ask(t, d, hookio.Request{Agent: "claude", Event: "notification", Payload: json.RawMessage(`{"notification_type":"permission_prompt","cwd":"/x"}`)})
	if len(link.events()) != 0 {
		t.Fatal("permission_prompt duplicates the approval event and must be ignored")
	}
}

func TestOverlongCommandIsNotSentForApproval(t *testing.T) {
	long := strings.Repeat("x", 5000)
	req := hookio.Request{Agent: "claude", Event: "permission", Payload: json.RawMessage(`{"session_id":"s","tool_name":"Bash","tool_input":{"command":"` + long + `"},"cwd":"/x/p"}`)}
	if kind, _, ok := BuildEvent(req); ok {
		t.Fatalf("a command the phone can't show in full must not be sent for approval, got %q", kind)
	}
	ok500 := strings.Repeat("y", 500)
	req.Payload = json.RawMessage(`{"session_id":"s","tool_name":"Bash","tool_input":{"command":"` + ok500 + `"},"cwd":"/x/p"}`)
	kind, p, ok := BuildEvent(req)
	if !ok || kind != "approval" || p.Command != ok500 || len([]rune(p.Body)) > 300 {
		t.Fatalf("%v %v cmd=%d body=%d", ok, kind, len(p.Command), len([]rune(p.Body)))
	}
}

func TestOverlongCommandReturnsAtOnceAndSendsNothing(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true} }
	d, _, _ := start(t, link)
	long := strings.Repeat("x", 501)
	req := hookio.Request{Agent: "claude", Event: "permission", Payload: json.RawMessage(`{"session_id":"s","tool_name":"Bash","tool_input":{"command":"` + long + `"},"cwd":"/x/p"}`)}
	begin := time.Now()
	if got, _ := ask(t, d, req); got != "" || time.Since(begin) > time.Second {
		t.Fatalf("got %q after %v", got, time.Since(begin))
	}
	if len(link.events()) != 0 {
		t.Fatalf("nothing should be sent: %+v", link.events())
	}
}

func TestDoneBodyIsTruncatedBeforeSeal(t *testing.T) {
	req := hookio.Request{Agent: "claude", Event: "stop", Payload: json.RawMessage(`{"session_id":"s","cwd":"/x/p","last_assistant_message":"` + strings.Repeat("z", 5000) + `"}`)}
	kind, p, ok := BuildEvent(req)
	if !ok || kind != "done" || len([]rune(p.Body)) > 300 {
		t.Fatalf("%v %v body=%d", ok, kind, len([]rune(p.Body)))
	}
}

// alwaysCase runs finish with an "always" decision and reports the answer and whether a rule file appeared.
func alwaysCase(t *testing.T, agent, tool, command, cwd string) (string, bool) {
	t.Helper()
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, _, _ := start(t, link)
	in, _ := json.Marshal(map[string]any{"session_id": "s", "tool_name": tool, "tool_input": map[string]string{"command": command}, "cwd": cwd})
	req := hookio.Request{Agent: agent, Event: "permission", Payload: in}
	_, p, ok := BuildEvent(req)
	if !ok {
		t.Fatalf("BuildEvent refused %q", command)
	}
	got := d.finish(req, p, "always")
	_, err := readAllow(cwd)
	return got, err == nil
}

func TestAlwaysOnlyWritesSafeRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // os.UserHomeDir reads $HOME; never touch the real one
	t.Chdir(t.TempDir())   // a relative cwd must never land inside the repo, even on regression
	cases := []struct {
		name, agent, tool, command string
		cwd                        func() string
		wantRule                   bool
	}{
		{"plain", "claude", "Bash", "git push origin main", func() string { return t.TempDir() }, true},
		{"star", "claude", "Bash", "rm -rf *", func() string { return t.TempDir() }, false},
		{"prefix", "claude", "Bash", "foo:*", func() string { return t.TempDir() }, false},
		{"paren", "claude", "Bash", "echo a) && rm x", func() string { return t.TempDir() }, false},
		{"open paren", "claude", "Bash", "echo (a", func() string { return t.TempDir() }, false},
		{"newline", "claude", "Bash", "ls\nrm x", func() string { return t.TempDir() }, false},
		{"relative cwd", "claude", "Bash", "git status", func() string { return "relative/dir" }, false},
		{"root cwd", "claude", "Bash", "git status", func() string { return "/" }, false},
		{"home cwd", "claude", "Bash", "git status", func() string { return home }, false},
		{"not bash", "claude", "Edit", "git status", func() string { return t.TempDir() }, false},
		{"codex", "codex", "Bash", "git status", func() string { return t.TempDir() }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cwd := c.cwd()
			got, wrote := alwaysCase(t, c.agent, c.tool, c.command, cwd)
			if got != "allow" || wrote != c.wantRule {
				t.Fatalf("got %q, rule written %v (want %v)", got, wrote, c.wantRule)
			}
		})
	}
}

// waitResolved waits until the fake relay has seen an approval and then a resolved with the same id.
func waitResolved(t *testing.T, link *fakeLink) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ev := link.events()
		if len(ev) == 2 && ev[0].Kind == "approval" && ev[1].Kind == "resolved" && ev[1].ID == ev[0].ID {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want approval then resolved with the same id, got %+v", link.events())
}

func TestTimeoutSendsResolved(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true} }
	d, _, _ := start(t, link)
	if got, _ := ask(t, d, permissionReq("codex")); got != "" { // codex timeout = 1 s
		t.Fatalf("got %q", got)
	}
	waitResolved(t, link)
}

func TestAckTimeoutSendsResolved(t *testing.T) {
	old := ackTimeout
	ackTimeout = 100 * time.Millisecond
	defer func() { ackTimeout = old }()
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true} // never acks
	d, _, _ := start(t, link)
	begin := time.Now()
	if got, _ := ask(t, d, permissionReq("claude")); got != "" || time.Since(begin) > time.Second {
		t.Fatalf("got %q after %v", got, time.Since(begin))
	}
	waitResolved(t, link)
}

func TestLinkDownDoesNotSendResolved(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg { return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true} }
	d, _, _ := start(t, link)
	go func() { time.Sleep(100 * time.Millisecond); link.in <- proto.RelayMsg{T: "down"} }()
	if got, _ := ask(t, d, permissionReq("claude")); got != "" {
		t.Fatalf("got %q", got)
	}
	time.Sleep(100 * time.Millisecond)
	if ev := link.events(); len(ev) != 1 {
		t.Fatalf("the relay closes approvals itself when the link drops; want only the approval, got %+v", ev)
	}
}

func TestNonBashApprovalCarriesDetail(t *testing.T) {
	req := hookio.Request{Agent: "claude", Event: "permission", Payload: json.RawMessage(
		`{"session_id":"s","tool_name":"Write","tool_input":{"file_path":"/x/p/a<b>.txt","content":"hi"},"cwd":"/x/p"}`)}
	kind, p, ok := BuildEvent(req)
	if !ok || kind != "approval" {
		t.Fatalf("%v %v", ok, kind)
	}
	if p.Command != "" {
		t.Fatalf("non-Bash must not fill command: %q", p.Command)
	}
	if p.Detail != `{"content":"hi","file_path":"/x/p/a<b>.txt"}` {
		t.Fatalf("detail %q", p.Detail)
	}
	if p.Body != "Claude wants to use Write: /x/p/a<b>.txt" {
		t.Fatalf("body %q", p.Body)
	}
}

func TestNonBashWithoutFilePathNamesTheTool(t *testing.T) {
	req := hookio.Request{Agent: "claude", Event: "permission", Payload: json.RawMessage(
		`{"session_id":"s","tool_name":"mcp__db__query","tool_input":{"sql":"select 1"},"cwd":"/x/p"}`)}
	_, p, ok := BuildEvent(req)
	if !ok || p.Body != "Claude wants to use mcp__db__query" || p.Detail != `{"sql":"select 1"}` {
		t.Fatalf("%v %+v", ok, p)
	}
}

func TestNonBashWithLargeInputIsNotSentForApproval(t *testing.T) {
	mk := func(n int) hookio.Request { // detail = {"sql":"<n runes>"} = n+10 runes
		return hookio.Request{Agent: "claude", Event: "permission", Payload: json.RawMessage(
			`{"session_id":"s","tool_name":"mcp__db__query","tool_input":{"sql":"` + strings.Repeat("é", n) + `"},"cwd":"/x/p"}`)}
	}
	if kind, _, ok := BuildEvent(mk(491)); ok {
		t.Fatalf("input the phone can't show in full (501 runes) must not be sent for approval, got %q", kind)
	}
	if _, p, ok := BuildEvent(mk(490)); !ok || len([]rune(p.Detail)) != 500 {
		t.Fatalf("500 runes is still approvable: %v %d", ok, len([]rune(p.Detail)))
	}
}

func TestBashApprovalHasNoDetail(t *testing.T) {
	_, p, ok := BuildEvent(permissionReq("claude"))
	if !ok || p.Command != "git push origin main" || p.Detail != "" || p.Body != "Claude wants to run git push origin main" {
		t.Fatalf("%v %+v", ok, p)
	}
}

// Codex's PermissionRequest sends tool_input{command,description}; its tool_name for shell escalations isn't
// documented as "Bash", so a Codex request with a command stays a command approval whatever the tool is called.
func TestCodexCommandApprovalKeepsCommandWhateverTheToolName(t *testing.T) {
	req := hookio.Request{Agent: "codex", Event: "permission", Payload: json.RawMessage(
		`{"session_id":"s","tool_name":"shell","tool_input":{"command":"touch ~/x","description":"make x"},"cwd":"/x/p"}`)}
	_, p, ok := BuildEvent(req)
	if !ok || p.Command != "touch ~/x" || p.Detail != "" || p.Body != "Codex wants to run touch ~/x" {
		t.Fatalf("%v %+v", ok, p)
	}
}

func TestCanonicalJSONKeepsLargeIntegersExact(t *testing.T) {
	got := canonicalJSON(json.RawMessage(`{"b":12345678901234567890,"a":1.50}`))
	want := `{"a":1.50,"b":12345678901234567890}`
	if got != want {
		t.Fatalf("canonicalJSON = %s, want %s", got, want)
	}
}

type fakeEnroller struct {
	mu         sync.Mutex
	enrolled   []proto.SSHEnroll
	unenrolled []string
	reply      proto.SSHReply
}

func (f *fakeEnroller) Enroll(id string, r proto.SSHEnroll) (proto.SSHReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolled = append(f.enrolled, r)
	return f.reply, nil
}

func (f *fakeEnroller) Unenroll(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unenrolled = append(f.unenrolled, id)
	return nil
}

func TestEventsAreSealedForEveryPhone(t *testing.T) {
	d1, k1 := device(t, "dev_1")
	d2, k2 := device(t, "dev_2")
	cfg := config.Config{HostID: "host_1", ApprovalTimeoutClaude: 2, ApprovalTimeoutCodex: 1, Devices: []config.Device{d1, d2}}
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, err := New(cfg, link)
	if err != nil {
		t.Fatal(err)
	}
	stop := hookio.Request{Agent: "claude", Event: "stop", Payload: json.RawMessage(`{"session_id":"s","cwd":"/x/app","last_assistant_message":"done"}`)}
	_, _ = ask(t, d, stop)
	ev := link.events()[0]
	if len(ev.Envs) != 2 {
		t.Fatalf("want one envelope per phone, got %d", len(ev.Envs))
	}
	for i, key := range [][]byte{k1, k2} {
		if _, err := proto.Open(key, ev.Envs[i].Env, "host_1|"+ev.ID); err != nil || ev.Envs[i].DeviceID != cfg.Devices[i].DeviceID {
			t.Fatalf("phone %d can't open its envelope: %v", i, err)
		}
	}
}

func TestNoPhoneMeansNoEvent(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, _ := New(config.Config{HostID: "host_1", ApprovalTimeoutClaude: 2, ApprovalTimeoutCodex: 1}, link)
	if got, _ := ask(t, d, permissionReq("claude")); got != "" || len(link.events()) != 0 {
		t.Fatalf("got %q, %d events", got, len(link.events()))
	}
}

func TestDecisionForAnUnknownPhoneIsIgnored(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, key := start(t, link)
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() {
			msg := sealed(t, key, cfg.HostID, m.ID, "allow")
			msg.DeviceID = "dev_9"
			link.in <- msg
		}()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	if got, _ := ask(t, d, permissionReq("codex")); got != "" {
		t.Fatalf("a decision under another phone's id must not count, got %q", got)
	}
}

// twoPhones starts a daemon linked to dev_1 and dev_2 and returns both phones' keys.
func twoPhones(t *testing.T, link *fakeLink) (*Daemon, config.Config, []byte, []byte) {
	t.Helper()
	d1, k1 := device(t, "dev_1")
	d2, k2 := device(t, "dev_2")
	cfg := config.Config{HostID: "host_1", ApprovalTimeoutClaude: 2, ApprovalTimeoutCodex: 1, Devices: []config.Device{d1, d2}}
	d, err := New(cfg, link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go d.pump(ctx)
	return d, cfg, k1, k2
}

func TestEitherLinkedPhoneCanDecideWithItsOwnKey(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, _, k2 := twoPhones(t, link)
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() {
			msg := sealed(t, k2, cfg.HostID, m.ID, "deny")
			msg.DeviceID = "dev_2"
			link.in <- msg
		}()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	if got, _ := ask(t, d, permissionReq("codex")); got != "deny" {
		t.Fatalf("the second phone's own decision must count, got %q", got)
	}
}

func TestDecisionSealedWithAnotherPhonesKeyIsIgnored(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, _, k2 := twoPhones(t, link)
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() {
			msg := sealed(t, k2, cfg.HostID, m.ID, "allow") // dev_2's key, but claims to be dev_1
			msg.DeviceID = "dev_1"
			link.in <- msg
		}()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	if got, _ := ask(t, d, permissionReq("codex")); got != "" {
		t.Fatalf("a decision must open only with the named phone's key, got %q", got)
	}
}

func TestDecisionFromAPhoneTheEventWasNotSealedForIsIgnored(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, _ := start(t, link)
	_, kLate := device(t, "dev_late")
	d.keys["dev_late"] = kLate // a key the daemon holds, but the event below is sealed for dev_1 only
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() {
			msg := sealed(t, kLate, cfg.HostID, m.ID, "allow")
			msg.DeviceID = "dev_late"
			link.in <- msg
		}()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	got, _ := ask(t, d, permissionReq("codex"))
	if got != "" {
		t.Fatalf("a decision from a phone the approval wasn't sealed for must not count, got %q", got)
	}
	if ev := link.events()[0]; len(ev.Envs) != 1 || ev.Envs[0].DeviceID != "dev_1" {
		t.Fatalf("%+v", ev.Envs)
	}
}

// Re-running setup on a paired Mac adds a phone: the hostId and the first phone's keys stay, and each phone gets an
// envelope it can open with its own key.
func TestAddingAPhoneKeepsHostAndFirstPhonesKeys(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	d1, k1 := device(t, "dev_1")
	if err := config.Save(home, config.Config{HostID: "host_1", HostSecret: "s", Devices: []config.Device{d1}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(home)
	d2, k2 := device(t, "dev_2")
	cfg.UpsertDevice(d2)
	if err := config.Save(home, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(home)
	if cfg.HostID != "host_1" || len(cfg.Devices) != 2 || cfg.Devices[0] != d1 || cfg.Devices[1] != d2 {
		t.Fatalf("%+v", cfg)
	}
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, err := New(cfg, link)
	if err != nil {
		t.Fatal(err)
	}
	stop := hookio.Request{Agent: "claude", Event: "stop", Payload: json.RawMessage(`{"session_id":"s","cwd":"/x/app"}`)}
	_, _ = ask(t, d, stop)
	ev := link.events()[0]
	for i, key := range [][]byte{k1, k2} {
		if len(ev.Envs) != 2 {
			t.Fatalf("%d envelopes", len(ev.Envs))
		}
		if _, err := proto.Open(key, ev.Envs[i].Env, "host_1|"+ev.ID); err != nil {
			t.Fatalf("phone %d: %v", i, err)
		}
	}
	if _, err := proto.Open(k1, ev.Envs[1].Env, "host_1|"+ev.ID); err == nil {
		t.Fatal("the first phone must not open the second phone's envelope")
	}
}

func TestSSHEnrollRepliesSealedForThatPhone(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, key := start(t, link)
	fe := &fakeEnroller{reply: proto.SSHReply{User: "alex", Port: 22, TmuxPath: "/opt/homebrew/bin/tmux",
		Addresses: []proto.Address{{Kind: "lan", Host: "Mac.local"}}, HostKeys: []string{"ssh-ed25519 AAAA"}}}
	d.Enroller = fe
	plain, _ := json.Marshal(proto.SSHEnroll{SSHPublicKey: "ssh-ed25519 AAAA wrangle@iPhone", DeviceName: "iPhone"})
	env, _ := proto.Seal(key, plain, proto.SSHAAD(cfg.HostID, "dev_1"), nil)
	link.in <- proto.RelayMsg{T: "ssh-enroll", DeviceID: "dev_1", Env: &env}
	m, ok := link.waitOther(t).(proto.SSHEnrolledMsg)
	if !ok || m.T != "ssh-enrolled" || m.DeviceID != "dev_1" {
		t.Fatalf("%#v", m)
	}
	out, err := proto.Open(key, m.Env, proto.SSHReplyAAD(cfg.HostID, "dev_1"))
	if err != nil {
		t.Fatal(err)
	}
	var reply proto.SSHReply
	_ = json.Unmarshal(out, &reply)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if reply.User != "alex" || reply.TmuxPath != "/opt/homebrew/bin/tmux" || len(fe.enrolled) != 1 || fe.enrolled[0].DeviceName != "iPhone" {
		t.Fatalf("%+v %+v", reply, fe.enrolled)
	}
}

func TestSSHEnrollSealedForAnotherPhoneIsIgnored(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, key := start(t, link)
	fe := &fakeEnroller{}
	d.Enroller = fe
	env, _ := proto.Seal(key, []byte(`{"sshPublicKey":"x","deviceName":"y"}`), proto.SSHAAD(cfg.HostID, "dev_2"), nil)
	link.in <- proto.RelayMsg{T: "ssh-enroll", DeviceID: "dev_1", Env: &env}
	time.Sleep(100 * time.Millisecond)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if len(fe.enrolled) != 0 {
		t.Fatal("a request whose AAD names another phone must be ignored")
	}
}

func TestUnlinkUnenrollsAndAcknowledges(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, _, _ := start(t, link)
	fe := &fakeEnroller{}
	d.Enroller = fe
	link.in <- proto.RelayMsg{T: "unlink", DeviceID: "dev_1"}
	if m := link.waitOther(t); m != (proto.UnlinkedMsg{T: "unlinked", DeviceID: "dev_1"}) {
		t.Fatalf("%#v", m)
	}
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if len(fe.unenrolled) != 1 || fe.unenrolled[0] != "dev_1" {
		t.Fatalf("%v", fe.unenrolled)
	}
}

// enrollFrom sends an ssh-enroll sealed with key under deviceID.
func enrollFrom(t *testing.T, link *fakeLink, key []byte, hostID, deviceID string) {
	t.Helper()
	plain, _ := json.Marshal(proto.SSHEnroll{SSHPublicKey: "ssh-ed25519 AAAA wrangle@iPhone", DeviceName: "iPhone"})
	env, err := proto.Seal(key, plain, proto.SSHAAD(hostID, deviceID), nil)
	if err != nil {
		t.Fatal(err)
	}
	link.in <- proto.RelayMsg{T: "ssh-enroll", DeviceID: deviceID, Env: &env}
}

// A phone paired (or re-paired) while the daemon runs enrols at once: the daemon reloads the config for its key.
func TestSSHEnrollReloadsConfigForANewOrRepairedPhone(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	d, cfg, _ := start(t, link)
	fe := &fakeEnroller{reply: proto.SSHReply{User: "alex"}}
	d.Enroller = fe
	d2, k2 := device(t, "dev_2")
	d1new, k1new := device(t, "dev_1") // dev_1 re-paired: a fresh host key
	var mu sync.Mutex
	current := cfg
	current.Devices = append([]config.Device(nil), cfg.Devices...)
	current.UpsertDevice(d2)
	d.Reload = func() (config.Config, error) { mu.Lock(); defer mu.Unlock(); return current, nil }

	enrollFrom(t, link, k2, cfg.HostID, "dev_2")
	m, ok := link.waitOther(t).(proto.SSHEnrolledMsg)
	if !ok || m.DeviceID != "dev_2" {
		t.Fatalf("%#v", m)
	}
	if _, err := proto.Open(k2, m.Env, proto.SSHReplyAAD(cfg.HostID, "dev_2")); err != nil {
		t.Fatalf("reply must be sealed with dev_2's key: %v", err)
	}

	mu.Lock()
	current.UpsertDevice(d1new)
	mu.Unlock()
	link.mu.Lock()
	link.other = nil
	link.mu.Unlock()
	enrollFrom(t, link, k1new, cfg.HostID, "dev_1")
	m, ok = link.waitOther(t).(proto.SSHEnrolledMsg)
	if !ok || m.DeviceID != "dev_1" {
		t.Fatalf("%#v", m)
	}
	if _, err := proto.Open(k1new, m.Env, proto.SSHReplyAAD(cfg.HostID, "dev_1")); err != nil {
		t.Fatalf("reply must be sealed with dev_1's new key: %v", err)
	}

	// New events reach the new phone with its key, and the re-paired one with its new key.
	stop := hookio.Request{Agent: "claude", Event: "stop", Payload: json.RawMessage(`{"session_id":"s","cwd":"/x/app"}`)}
	_, _ = ask(t, d, stop)
	ev := link.events()[0]
	opened := map[string]bool{}
	for _, e := range ev.Envs {
		k := map[string][]byte{"dev_1": k1new, "dev_2": k2}[e.DeviceID]
		if _, err := proto.Open(k, e.Env, cfg.HostID+"|"+ev.ID); err == nil {
			opened[e.DeviceID] = true
		}
	}
	if !opened["dev_1"] || !opened["dev_2"] {
		t.Fatalf("envelopes %+v", ev.Envs)
	}

	link.mu.Lock()
	link.other = nil
	link.mu.Unlock()
	_, k9 := device(t, "dev_9")
	enrollFrom(t, link, k9, cfg.HostID, "dev_9") // in no config
	time.Sleep(100 * time.Millisecond)
	link.mu.Lock()
	defer link.mu.Unlock()
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if len(link.other) != 0 || len(fe.enrolled) != 2 {
		t.Fatalf("an unknown phone must be ignored: %v %d", link.other, len(fe.enrolled))
	}
}

// A restart (config change) stops the daemon: waiting approvals fail at once, as on a dropped link.
func TestStoppingTheDaemonFailsPendingApprovalsAtOnce(t *testing.T) {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	cfg, _ := testConfig(t)
	cfg.ApprovalTimeoutClaude = 30
	d, err := New(cfg, link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.pump(ctx)
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		go func() { time.Sleep(100 * time.Millisecond); cancel() }()
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	began := time.Now()
	got, _ := ask(t, d, permissionReq("claude"))
	if got != "" || time.Since(began) > 2*time.Second {
		t.Fatalf("got %q after %v", got, time.Since(began))
	}
}
