package hookio

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeDaemon answers every request with decision (or never answers if decision == "hang").
func fakeDaemon(t *testing.T, decision string) (string, chan Request) {
	t.Helper()
	// Short path: t.TempDir() + test name can exceed the 104-byte unix socket limit on macOS.
	dir, err := os.MkdirTemp("/tmp", "wh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "w.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan Request, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var r Request
				if json.NewDecoder(bufio.NewReader(c)).Decode(&r) == nil {
					got <- r
				}
				if decision == "hang" {
					time.Sleep(10 * time.Second)
					return
				}
				_ = json.NewEncoder(c).Encode(Response{Decision: decision})
			}(c)
		}
	}()
	return sock, got
}

func run(stdin io.Reader, agent, event, sock string, d time.Duration) (int, string, time.Duration) {
	var out bytes.Buffer
	start := time.Now()
	code := Run(agent, event, stdin, &out, Options{SocketPath: sock, Deadline: d})
	return code, out.String(), time.Since(start)
}

const permission = `{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"git push"},"cwd":"/tmp/p"}`

func TestAllowPrintsClaudeShapedDecision(t *testing.T) {
	sock, got := fakeDaemon(t, "allow")
	t.Setenv("TMUX_PANE", "%7")
	code, out, _ := run(strings.NewReader(permission), "claude", "permission", sock, 2*time.Second)
	if code != 0 || out != `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}` {
		t.Fatalf("%d %q", code, out)
	}
	r := <-got
	if r.Agent != "claude" || r.Event != "permission" || r.Pane != "%7" || !strings.Contains(string(r.Payload), "git push") {
		t.Fatalf("request %+v", r)
	}
}

func TestDenyIncludesReason(t *testing.T) {
	sock, _ := fakeDaemon(t, "deny")
	_, out, _ := run(strings.NewReader(permission), "codex", "permission", sock, 2*time.Second)
	if out != `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied from Wrangle"}}}` {
		t.Fatalf("%q", out)
	}
}

func TestNoDecisionPrintsNothing(t *testing.T) {
	sock, _ := fakeDaemon(t, "")
	if _, out, _ := run(strings.NewReader(permission), "claude", "permission", sock, 2*time.Second); out != "" {
		t.Fatalf("%q", out)
	}
}

func TestStopNeverPrintsEvenIfDaemonSaysAllow(t *testing.T) {
	sock, got := fakeDaemon(t, "allow")
	if _, out, _ := run(strings.NewReader(`{"session_id":"s1"}`), "codex", "stop", sock, 2*time.Second); out != "" {
		t.Fatalf("codex stop must print nothing, got %q", out)
	}
	if r := <-got; r.Event != "stop" {
		t.Fatalf("%+v", r)
	}
}

func TestMissingDaemonIsSilent(t *testing.T) {
	code, out, _ := run(strings.NewReader(permission), "claude", "permission", filepath.Join(t.TempDir(), "none.sock"), time.Second)
	if code != 0 || out != "" {
		t.Fatalf("%d %q", code, out)
	}
}

func TestDaemonThatNeverAnswersRespectsDeadline(t *testing.T) {
	sock, _ := fakeDaemon(t, "hang")
	code, out, took := run(strings.NewReader(permission), "claude", "permission", sock, 300*time.Millisecond)
	if code != 0 || out != "" || took > 2*time.Second {
		t.Fatalf("%d %q %v", code, out, took)
	}
}

func TestHookUnclosedStdinRespectsDeadline(t *testing.T) {
	sock, _ := fakeDaemon(t, "allow")
	r, w := io.Pipe()
	defer w.Close() // the writer stays open: the agent never closes stdin
	code, out, took := run(r, "claude", "permission", sock, 300*time.Millisecond)
	if code != 0 || out != "" || took > 2*time.Second {
		t.Fatalf("%d %q %v", code, out, took)
	}
}

func TestHookOver8MBIsSilent(t *testing.T) {
	sock, got := fakeDaemon(t, "allow")
	big := `{"tool_input":{"command":"` + strings.Repeat("a", 9<<20) + `"}}`
	code, out, _ := run(strings.NewReader(big), "claude", "permission", sock, 5*time.Second)
	if code != 0 || out != "" {
		t.Fatalf("%d %q", code, out)
	}
	select {
	case r := <-got:
		t.Fatalf("over-limit input must not reach the daemon: %d bytes", len(r.Payload))
	default:
	}
}

func TestGarbageAndUnknownAreSilent(t *testing.T) {
	sock, _ := fakeDaemon(t, "allow")
	for _, c := range []struct{ agent, event, in string }{
		{"claude", "permission", "not json {"}, {"claude", "permission", "[]"}, {"claude", "permission", "null"},
		{"gemini", "permission", permission}, {"claude", "brand-new", permission}, {"claude", "permission", ""},
	} {
		if code, out, _ := run(strings.NewReader(c.in), c.agent, c.event, sock, time.Second); code != 0 || out != "" {
			t.Fatalf("%+v → %d %q", c, code, out)
		}
	}
}

func TestDeadlineFor(t *testing.T) {
	if DeadlineFor("claude", "permission", 120, 30) != 125*time.Second || DeadlineFor("codex", "permission", 120, 30) != 35*time.Second {
		t.Fatal("permission deadlines")
	}
	if DeadlineFor("claude", "stop", 120, 30) != 3*time.Second {
		t.Fatal("other events")
	}
}

func TestClaudePostToolIsForwardedAndNeverPrints(t *testing.T) {
	sock, got := fakeDaemon(t, "allow")
	in := `{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}`
	if _, out, _ := run(strings.NewReader(in), "claude", "posttool", sock, 2*time.Second); out != "" {
		t.Fatalf("posttool must print nothing, got %q", out)
	}
	select {
	case r := <-got:
		if r.Agent != "claude" || r.Event != "posttool" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("posttool was not forwarded to the daemon")
	}
	if DeadlineFor("claude", "posttool", 120, 30) != 3*time.Second {
		t.Fatal("posttool deadline must be 3 s")
	}
}
