// Package hookio is the `wrangle hook <agent> <event>` side: read the agent's JSON, ask the daemon, print a
// decision. Safety rule: any problem → print nothing and return 0, within one deadline.
package hookio

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

const maxInput = 8 << 20

var knownAgents = map[string]bool{"claude": true, "codex": true}

// posttool is Claude-only (PostToolUse): it tells the daemon a tool ran, so an approval answered at the desk is withdrawn.
var knownEvents = map[string]bool{"permission": true, "stop": true, "notification": true, "posttool": true}

type Request struct {
	Agent   string          `json:"agent"`
	Event   string          `json:"event"`
	Pane    string          `json:"pane,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

type Response struct {
	Decision string `json:"decision"`
}

type Options struct {
	SocketPath string
	Deadline   time.Duration
}

func SocketPath(home string) string { return filepath.Join(home, "wrangle.sock") }

func DeadlineFor(agent, event string, claudeTimeout, codexTimeout int) time.Duration {
	if event != "permission" {
		return 3 * time.Second
	}
	if agent == "codex" {
		return time.Duration(codexTimeout+5) * time.Second
	}
	return time.Duration(claudeTimeout+5) * time.Second
}

func Output(decision string) string {
	switch decision {
	case "allow":
		return `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`
	case "deny":
		return `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied from Wrangle"}}}`
	}
	return ""
}

func Run(agent, event string, stdin io.Reader, stdout io.Writer, opt Options) int {
	if !knownAgents[agent] || !knownEvents[event] {
		return 0
	}
	deadline := time.Now().Add(opt.Deadline)
	decision := make(chan string, 1)
	go func() { decision <- ask(agent, event, stdin, opt.SocketPath, deadline) }()
	select {
	case d := <-decision:
		if event == "permission" {
			if out := Output(d); out != "" {
				_, _ = io.WriteString(stdout, out)
			}
		}
	case <-time.After(time.Until(deadline)):
	}
	return 0
}

func ask(agent, event string, stdin io.Reader, socket string, deadline time.Time) string {
	data, err := io.ReadAll(io.LimitReader(stdin, maxInput+1))
	if err != nil || len(data) == 0 || len(data) > maxInput {
		return ""
	}
	var obj map[string]any
	if json.Unmarshal(data, &obj) != nil || obj == nil {
		return ""
	}
	conn, err := net.DialTimeout("unix", socket, time.Until(deadline))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	var buf bytes.Buffer
	if json.NewEncoder(&buf).Encode(Request{Agent: agent, Event: event, Pane: os.Getenv("TMUX_PANE"), Payload: data}) != nil {
		return ""
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return ""
	}
	var res Response
	if json.NewDecoder(bufio.NewReader(conn)).Decode(&res) != nil {
		return ""
	}
	return res.Decision
}
