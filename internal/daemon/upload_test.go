package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/chetanverma16/wrangle/internal/hookio"
	"github.com/chetanverma16/wrangle/internal/proto"
)

func readReq(agent, path string) hookio.Request {
	in, _ := json.Marshal(map[string]any{"session_id": "s1", "tool_name": "Read", "tool_input": map[string]string{"file_path": path}, "cwd": "/tmp/p"})
	return hookio.Request{Agent: agent, Event: "permission", Pane: "%2", Payload: in}
}

// The phone uploads a picture to ~/.wrangle/uploads and puts its path in the message, so Claude asks to Read it.
// The phone already chose that file: it is allowed at once, without a second question, even with no phone online.
// Anything else (another folder, a link, a different name, another tool or agent) still goes to the phone.
func TestReadingAPhoneUploadIsAllowedAtOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	uploads := filepath.Join(home, ".wrangle", "uploads")
	if err := os.MkdirAll(uploads, 0o700); err != nil {
		t.Fatal(err)
	}
	const name = "6F9619FF-8B86-D011-B42D-00C04FC964FF.png"
	upload := filepath.Join(uploads, name)
	_ = os.WriteFile(upload, []byte("png"), 0o600)
	secret := filepath.Join(home, "secret.txt")
	_ = os.WriteFile(secret, []byte("x"), 0o600)
	link := filepath.Join(uploads, "7A9619FF-8B86-D011-B42D-00C04FC964FF.png")
	_ = os.Symlink(secret, link)
	other := filepath.Join(uploads, "notes.png")
	_ = os.WriteFile(other, []byte("png"), 0o600)

	d, _, _ := start(t, &fakeLink{in: make(chan proto.RelayMsg, 8), up: false})
	if got, _ := ask(t, d, readReq("claude", upload)); got != "allow" {
		t.Fatalf("upload: got %q", got)
	}
	for _, path := range []string{
		link, other, secret,
		filepath.Join(uploads, "..", "..", "secret.txt"),
		uploads + "/../uploads/" + name,                                    // not the clean path Wrangle wrote
		filepath.Join(uploads, "0F9619FF-8B86-D011-B42D-00C04FC964FF.png"), // no such file
	} {
		if got, _ := ask(t, d, readReq("claude", path)); got != "" {
			t.Errorf("%s: got %q, want the usual question", path, got)
		}
	}
	if got, _ := ask(t, d, readReq("codex", upload)); got != "" {
		t.Errorf("codex: got %q", got)
	}
	edit := readReq("claude", upload)
	edit.Payload = json.RawMessage(`{"tool_name":"Edit","tool_input":{"file_path":"` + upload + `"}}`)
	if got, _ := ask(t, d, edit); got != "" {
		t.Errorf("edit: got %q", got)
	}
}
