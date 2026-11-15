package proto

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite protocol/vectors.json")

type qrVector struct {
	T             string `json:"t"`
	K             string `json:"k"`
	OfferID       string `json:"offerId"`
	Relay         string `json:"relay"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	MAC           string `json:"mac"`
	TokenHash     string `json:"tokenHash"`
	HostKeyCommit string `json:"hostKeyCommit"`
}

type sshVector struct {
	DeviceID       string   `json:"deviceId"`
	Plaintext      string   `json:"plaintext"`
	AAD            string   `json:"aad"`
	Nonce          string   `json:"nonce"`
	Envelope       Envelope `json:"envelope"`
	ReplyPlaintext string   `json:"replyPlaintext"`
	ReplyAAD       string   `json:"replyAad"`
	ReplyNonce     string   `json:"replyNonce"`
	ReplyEnvelope  Envelope `json:"replyEnvelope"`
}

type vectors struct {
	AppPrivate  string   `json:"appPrivate"`
	HostPrivate string   `json:"hostPrivate"`
	AppPublic   string   `json:"appPublic"`
	HostPublic  string   `json:"hostPublic"`
	Key         string   `json:"key"`
	Nonce       string   `json:"nonce"`
	AAD         string   `json:"aad"`
	Plaintext   string   `json:"plaintext"`
	Envelope    Envelope `json:"envelope"`
	SAS         []string `json:"sas"`
	Commit      string   `json:"commit"`
	// DecisionEnvelope seals {"id":"evt_1","decision":"allow"} with AAD host_1|evt_1|decision, nonce "wrangle-n-02".
	DecisionEnvelope Envelope  `json:"decisionEnvelope"`
	QR               qrVector  `json:"qr"`
	SSH              sshVector `json:"ssh"`
}

const decisionPlain = `{"id":"evt_1","decision":"allow"}`

// protocolFile finds a file in protocol/ at the repository root: three levels up in the app's repository, two in
// the helper's public one.
func protocolFile(name string) string {
	for _, dir := range []string{"../../../protocol/", "../../protocol/"} {
		if _, err := os.Stat(dir + name); err == nil {
			return dir + name
		}
	}
	return "../../../protocol/" + name
}

func vectorsPath() string { return protocolFile("vectors.json") }

func fixed(start byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func build(t *testing.T) vectors {
	t.Helper()
	app, err := KeyPairFromPrivate(fixed(0x01))
	if err != nil {
		t.Fatal(err)
	}
	host, err := KeyPairFromPrivate(fixed(0x41))
	if err != nil {
		t.Fatal(err)
	}
	keyApp, _ := DeriveKey(app.Private, host.Public, app.Public, host.Public)
	keyHost, _ := DeriveKey(host.Private, app.Public, app.Public, host.Public)
	if !bytes.Equal(keyApp, keyHost) {
		t.Fatal("both sides must derive the same key")
	}
	nonce := []byte("wrangle-n-01")
	plain := `{"title":"api-server needs you","body":"Claude wants to run git push","agent":"claude"}`
	env, err := Seal(keyApp, []byte(plain), "host_1|evt_1", nonce)
	if err != nil {
		t.Fatal(err)
	}
	denv, err := Seal(keyApp, []byte(decisionPlain), DecisionAAD("host_1", "evt_1"), []byte("wrangle-n-02"))
	if err != nil {
		t.Fatal(err)
	}
	q := QR{Relay: "https://api.wrangle.stackframes.dev", OfferID: "off_vector", Name: "Alex's Mac",
		T: fixed(0x10)[:16], K: fixed(0x20)[:16], HostPublic: host.Public}
	sshPlain := `{"sshPublicKey":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY= wrangle@iPhone","deviceName":"iPhone"}`
	senv, err := Seal(keyApp, []byte(sshPlain), SSHAAD("host_1", "dev_1"), []byte("wrangle-n-03"))
	if err != nil {
		t.Fatal(err)
	}
	replyPlain := `{"user":"alex","port":22,"addresses":[{"kind":"lan","host":"Alexs-MacBook-Pro.local"},{"kind":"tailscale","host":"100.101.102.103"}],"hostKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"],"tmuxPath":"/opt/homebrew/bin/tmux"}`
	renv, err := Seal(keyHost, []byte(replyPlain), SSHReplyAAD("host_1", "dev_1"), []byte("wrangle-n-04"))
	if err != nil {
		t.Fatal(err)
	}
	return vectors{
		AppPrivate: B64(app.Private), HostPrivate: B64(host.Private), AppPublic: B64(app.Public), HostPublic: B64(host.Public),
		Key: B64(keyApp), Nonce: B64(nonce), AAD: "host_1|evt_1", Plaintext: plain, Envelope: env,
		SAS: SAS(app.Public, host.Public), Commit: Commit(app.Public), DecisionEnvelope: denv,
		QR: qrVector{T: B64(q.T), K: B64(q.K), OfferID: q.OfferID, Relay: q.Relay, Name: q.Name, URL: q.URL(),
			MAC: B64(QRMAC(q.K, app.Public, host.Public)), TokenHash: TokenHash(q.T), HostKeyCommit: HostKeyCommit(host.Public)},
		SSH: sshVector{DeviceID: "dev_1", Plaintext: sshPlain, AAD: SSHAAD("host_1", "dev_1"), Nonce: B64([]byte("wrangle-n-03")),
			Envelope: senv, ReplyPlaintext: replyPlain, ReplyAAD: SSHReplyAAD("host_1", "dev_1"),
			ReplyNonce: B64([]byte("wrangle-n-04")), ReplyEnvelope: renv},
	}
}

func TestVectorsMatchFile(t *testing.T) {
	got := build(t)
	if *update {
		data, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(filepath.Clean(vectorsPath()), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Fatalf("missing vectors (run go test ./internal/proto -update): %v", err)
	}
	var want vectors
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if !bytes.Equal(g, w) {
		t.Fatalf("vectors drifted:\n got %s\nwant %s", g, w)
	}
}

func TestOpenRoundTripAndTamper(t *testing.T) {
	key := fixed(0x10)
	env, err := Seal(key, []byte("hello"), "h|e", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Open(key, env, "h|e")
	if err != nil || string(out) != "hello" {
		t.Fatalf("round trip: %q %v", out, err)
	}
	if _, err := Open(key, env, "h|other"); err == nil {
		t.Fatal("wrong AAD must fail")
	}
	env.V = 2
	if _, err := Open(key, env, "h|e"); err == nil {
		t.Fatal("unknown version must fail")
	}
}

func TestSASIsFourKnownWordsAndOrderSensitive(t *testing.T) {
	a, b := fixed(0x01), fixed(0x41)
	s := SAS(a, b)
	if len(s) != 4 {
		t.Fatalf("want 4 words, got %v", s)
	}
	if len(Words) != 64 {
		t.Fatalf("want 64 words, got %d", len(Words))
	}
	if equal(SAS(a, b), SAS(b, a)) {
		t.Fatal("SAS must depend on which key is the app's")
	}
}

func equal(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func TestOpenRejectsShortNonceWithoutPanic(t *testing.T) {
	key := fixed(0x10)
	env, _ := Seal(key, []byte("x"), "h|e", nil)
	env.N = B64([]byte{1, 2, 3, 4})
	if _, err := Open(key, env, "h|e"); err == nil {
		t.Fatal("short nonce must error")
	}
}

func TestOpenRejectsTruncatedCiphertext(t *testing.T) {
	key := fixed(0x10)
	env, _ := Seal(key, []byte("x"), "h|e", nil)
	env.C = B64([]byte{1, 2, 3})
	if _, err := Open(key, env, "h|e"); err == nil {
		t.Fatal("truncated ciphertext must error")
	}
}

func TestCommitVerify(t *testing.T) {
	a, b := fixed(0x01), fixed(0x41)
	c := Commit(a)
	if !VerifyCommit(a, c) {
		t.Fatal("right key must verify")
	}
	if VerifyCommit(b, c) {
		t.Fatal("other key must not verify")
	}
	if VerifyCommit(a, "!!not-base64!!") || VerifyCommit(a, "") {
		t.Fatal("malformed commit must not verify")
	}
}

func TestDecisionVectorRoundTrip(t *testing.T) {
	data, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	key, _ := UnB64(v.Key)
	out, err := Open(key, v.DecisionEnvelope, DecisionAAD("host_1", "evt_1"))
	if err != nil || string(out) != decisionPlain {
		t.Fatalf("decision open: %q %v", out, err)
	}
}

func TestEmbeddedWordsMatchProtocolFile(t *testing.T) {
	data, err := os.ReadFile(protocolFile("sas-words.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !equal(strings.Fields(string(data)), Words) {
		t.Fatal("embedded words differ from protocol/sas-words.txt (run go generate)")
	}
}
