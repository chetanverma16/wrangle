package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/chetanverma16/wrangle/internal/hookio"
	"github.com/chetanverma16/wrangle/internal/proto"
)

// deskLink acks every approval as pushed and never decides, so approvals stay pending until something resolves them.
func deskLink() *fakeLink {
	link := &fakeLink{in: make(chan proto.RelayMsg, 8), up: true}
	link.ack = func(m proto.EventMsg) *proto.RelayMsg {
		if m.Kind != "approval" {
			return nil
		}
		return &proto.RelayMsg{T: "ack", ID: m.ID, Pushed: true}
	}
	return link
}

func claudeReq(event, payload string) hookio.Request {
	return hookio.Request{Agent: "claude", Event: event, Pane: "%2", Payload: json.RawMessage(payload)}
}

// pending starts an approval and waits until its event has gone out. It returns the approval's id and a channel
// that receives the hook's decision.
func pending(t *testing.T, d *Daemon, link *fakeLink, payload string) (string, chan string) {
	t.Helper()
	before := len(link.events())
	out := make(chan string, 1)
	go func() { got, _ := ask(t, d, claudeReq("permission", payload)); out <- got }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ev := link.events(); len(ev) > before && ev[len(ev)-1].Kind == "approval" {
			id := ev[len(ev)-1].ID
			// wait until the waiter is registered and acked
			time.Sleep(50 * time.Millisecond)
			return id, out
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("approval was never sent")
	return "", nil
}

func kinds(evs []proto.EventMsg) (out []string) {
	for _, e := range evs {
		out = append(out, e.Kind+":"+e.ID)
	}
	return out
}

func resolvedIDs(link *fakeLink) map[string]int {
	got := map[string]int{}
	for _, e := range link.events() {
		if e.Kind == "resolved" {
			got[e.ID]++
		}
	}
	return got
}

func stillPending(t *testing.T, out chan string, link *fakeLink, id string) {
	t.Helper()
	select {
	case got := <-out:
		t.Fatalf("approval %s must still be pending, the hook returned %q", id, got)
	case <-time.After(300 * time.Millisecond):
	}
	if resolvedIDs(link)[id] != 0 {
		t.Fatalf("approval %s must not be resolved: %v", id, kinds(link.events()))
	}
}

const (
	bashLs   = `{"session_id":"sess-1","cwd":"/Users/dev/code/api","tool_name":"Bash","tool_input":{"command":"ls -la","description":"List"}}`
	bashLsPT = `{"session_id":"sess-1","cwd":"/Users/dev/code/api","tool_name":"Bash","tool_input":{"description":"List","command":"ls -la"},"tool_response":{"stdout":"x"}}`
)

func TestPostToolResolvesMatchingApproval(t *testing.T) {
	link := deskLink()
	d, _, _ := start(t, link)
	id, out := pending(t, d, link, bashLs)
	n := len(link.events())
	got, _ := ask(t, d, claudeReq("posttool", bashLsPT)) // same input, different key order
	if got != "" {
		t.Fatalf("posttool must get an empty response, got %q", got)
	}
	select {
	case dec := <-out:
		if dec != "" {
			t.Fatalf("a desk answer must give the hook no decision, got %q", dec)
		}
	case <-time.After(time.Second):
		t.Fatal("the approval hook did not return within 1 s of the posttool")
	}
	evs := link.events()[n:]
	if len(evs) != 1 || evs[0].Kind != "resolved" || evs[0].ID != id {
		t.Fatalf("want exactly one resolved for %s, got %v", id, kinds(evs))
	}
	time.Sleep(100 * time.Millisecond)
	if c := resolvedIDs(link)[id]; c != 1 {
		t.Fatalf("resolved must be sent once, got %d", c)
	}
}

func TestPostToolWithDifferentInputLeavesApprovalPending(t *testing.T) {
	link := deskLink()
	d, _, _ := start(t, link)
	id, out := pending(t, d, link, bashLs)
	other := `{"session_id":"sess-1","tool_name":"Bash","tool_input":{"command":"ls -l","description":"List"}}`
	if got, _ := ask(t, d, claudeReq("posttool", other)); got != "" {
		t.Fatalf("%q", got)
	}
	stillPending(t, out, link, id)
}

func TestPostToolFromAnotherSessionLeavesApprovalPending(t *testing.T) {
	link := deskLink()
	d, _, _ := start(t, link)
	id, out := pending(t, d, link, bashLs)
	other := `{"session_id":"sess-2","tool_name":"Bash","tool_input":{"command":"ls -la","description":"List"}}`
	if got, _ := ask(t, d, claudeReq("posttool", other)); got != "" {
		t.Fatalf("%q", got)
	}
	stillPending(t, out, link, id)
}

func TestStopResolvesAllApprovalsOfItsSession(t *testing.T) {
	link := deskLink()
	d, _, _ := start(t, link)
	id1, out1 := pending(t, d, link, bashLs)
	id2, out2 := pending(t, d, link, `{"session_id":"sess-1","tool_name":"Write","tool_input":{"file_path":"/x"}}`)
	id3, out3 := pending(t, d, link, `{"session_id":"sess-2","tool_name":"Bash","tool_input":{"command":"ls -la"}}`)
	n := len(link.events())
	if got, _ := ask(t, d, claudeReq("stop", `{"session_id":"sess-1","cwd":"/Users/dev/code/api","last_assistant_message":"All set."}`)); got != "" {
		t.Fatalf("%q", got)
	}
	for _, out := range []chan string{out1, out2} {
		select {
		case dec := <-out:
			if dec != "" {
				t.Fatalf("got %q", dec)
			}
		case <-time.After(time.Second):
			t.Fatal("approval of the stopped session did not return")
		}
	}
	evs := link.events()[n:]
	if len(evs) != 3 || evs[2].Kind != "done" {
		t.Fatalf("want two resolved then done, got %v", kinds(evs))
	}
	r := resolvedIDs(link)
	if r[id1] != 1 || r[id2] != 1 {
		t.Fatalf("resolved %v (want %s and %s)", r, id1, id2)
	}
	stillPending(t, out3, link, id3)
}

func TestPostToolWithNothingPendingSendsNothing(t *testing.T) {
	link := deskLink()
	d, _, _ := start(t, link)
	if got, _ := ask(t, d, claudeReq("posttool", bashLsPT)); got != "" {
		t.Fatalf("%q", got)
	}
	time.Sleep(100 * time.Millisecond)
	if evs := link.events(); len(evs) != 0 {
		t.Fatalf("posttool must send no event: %v", kinds(evs))
	}
}

func TestStopWithNothingPendingSendsOnlyDone(t *testing.T) {
	link := deskLink()
	d, _, _ := start(t, link)
	_, _ = ask(t, d, claudeReq("stop", `{"session_id":"sess-1","cwd":"/x/api"}`))
	if evs := link.events(); len(evs) != 1 || evs[0].Kind != "done" {
		t.Fatalf("%v", kinds(evs))
	}
}
