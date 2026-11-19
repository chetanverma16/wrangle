package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/proto"
	"github.com/chetanverma16/wrangle/internal/relayhttp"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

type fakeRelay struct {
	mu         sync.Mutex
	calls      []string
	offerAuth  *relayhttp.Auth
	offer      relayhttp.OfferResult
	keys       []error // errors returned by PairKey before the key (ErrWaiting…)
	key        relayhttp.KeyResult
	confirmErr error
	hostKey    string
	offerErr   error
	onKey      func(n int) // called on the n-th PairKey (1-based)
	onHostKey  func()
	onConfirm  func()
	nKeys      int
}

func (f *fakeRelay) log(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }
func (f *fakeRelay) Offer(_ context.Context, a *relayhttp.Auth, _ relayhttp.OfferRequest) (relayhttp.OfferResult, error) {
	f.log("offer")
	f.offerAuth = a
	return f.offer, f.offerErr
}
func (f *fakeRelay) PairKey(context.Context, relayhttp.Auth) (relayhttp.KeyResult, error) {
	f.log("key")
	f.nKeys++
	if f.onKey != nil {
		f.onKey(f.nKeys)
	}
	if len(f.keys) > 0 {
		e := f.keys[0]
		f.keys = f.keys[1:]
		return relayhttp.KeyResult{}, e
	}
	return f.key, nil
}
func (f *fakeRelay) HostKey(_ context.Context, _ relayhttp.Auth, k string) error {
	f.log("host-key")
	f.hostKey = k
	if f.onHostKey != nil {
		f.onHostKey()
	}
	return nil
}
func (f *fakeRelay) Confirm(context.Context, relayhttp.Auth) error {
	f.log("confirm")
	if f.onConfirm != nil {
		f.onConfirm()
	}
	return f.confirmErr
}
func (f *fakeRelay) Reject(context.Context, relayhttp.Auth) error { f.log("reject"); return nil }

var (
	tBytes = bytes.Repeat([]byte{0x10}, 16)
	kBytes = bytes.Repeat([]byte{0x20}, 16)
)

type harness struct {
	f      *fake
	relay  *fakeRelay
	opts   Options
	out    *bytes.Buffer
	app    proto.KeyPair
	host   proto.KeyPair
	hooked bool
}

// newHarness: a Mac where every check passes, an iPhone app key, and a relay that answers in the QR path.
func newHarness(t *testing.T, input string) *harness {
	t.Helper()
	dir := t.TempDir()
	app, _ := proto.GenerateKeyPair()
	host, _ := proto.GenerateKeyPair()
	h := &harness{app: app, host: host, out: &bytes.Buffer{}}
	h.f = &fake{paths: map[string]string{"tmux": "/opt/homebrew/bin/tmux"}, banners: []string{"SSH-2.0-OpenSSH_9.8"},
		runs: map[string]string{"scutil --get LocalHostName": "Alexs-MacBook-Pro\n"}}
	h.relay = &fakeRelay{offer: relayhttp.OfferResult{OfferID: "off_1", Code: "7KQ4MZ", HostID: "host_1", HostSecret: "sec", ExpiresAt: 1},
		keys: []error{relayhttp.ErrWaiting}, key: relayhttp.KeyResult{AppPublicKey: proto.B64(app.Public), DeviceID: "dev_1",
			DeviceName: "Alex's iPhone", Path: "qr", MAC: proto.B64(proto.QRMAC(kBytes, app.Public, host.Public))}}
	h.opts = Options{RelayURL: "https://relay.test", HelperVersion: "0.2.0", Home: filepath.Join(dir, "w"), HostName: "Alex's MacBook Pro",
		KeysPath: filepath.Join(dir, "authorized_keys"), NoService: true, PairPoll: time.Millisecond, PairTimeout: time.Second,
		KeyWait: 0, Rand: bytes.NewReader(append(append([]byte{}, tBytes...), kBytes...)),
		GenerateKey:  func() (proto.KeyPair, error) { return host, nil },
		InstallHooks: func() ([]string, error) { h.hooked = true; return []string{"updated ~/.claude/settings.json"}, nil },
		HooksPresent: func() bool { return h.hooked }, Now: func() time.Time { return time.UnixMilli(1000) }}
	e := h.f.env()
	e.In = strings.NewReader(input)
	e.Out = h.out
	h.opts.env = e
	return h
}

func (h *harness) run() int { return Run(context.Background(), h.opts.env, h.relay, h.opts) }

func (h *harness) devices() []string {
	c, _ := config.Load(h.opts.Home)
	var ids []string
	for _, d := range c.Devices {
		ids = append(ids, d.DeviceID)
	}
	return ids
}

func TestSetupQRPathConnectsAndSavesThePhone(t *testing.T) {
	h := newHarness(t, "y\ny\n") // hooks? yes; connect? yes
	_ = sshkeys.Add(h.opts.KeysPath, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "dev_1", "x")
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if got := strings.Join(h.relay.calls, ","); got != "offer,key,key,host-key,confirm" {
		t.Fatalf("calls %s", got)
	}
	if h.relay.offerAuth != nil || h.relay.hostKey != proto.B64(h.host.Public) {
		t.Fatalf("new Mac offers without auth; host key %q", h.relay.hostKey)
	}
	out := h.out.String()
	for _, want := range []string{"✓ tmux", "/opt/homebrew/bin/tmux", "✓ Remote Login", "7KQ-4MZ", "Expires in 10 minutes",
		"Connect “Alex's iPhone”? [Y/n]", "✓ Connected to “Alex's iPhone”", "wrangle config keep-awake off", "Alexs-MacBook-Pro.local"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	c, err := config.Load(h.opts.Home)
	if err != nil || c.HostID != "host_1" || c.HostSecret != "sec" || c.TmuxPath != "/opt/homebrew/bin/tmux" || len(c.Devices) != 1 ||
		c.Devices[0].DeviceID != "dev_1" || c.Devices[0].HostPrivate != proto.B64(h.host.Private) || c.RelayURL != "https://relay.test" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestSetupBadMACRejectsAndSavesNoPhone(t *testing.T) {
	h := newHarness(t, "y\n")
	h.relay.key.MAC = proto.B64(proto.QRMAC(bytes.Repeat([]byte{9}, 16), h.app.Public, h.host.Public))
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(strings.Join(h.relay.calls, ","), "reject") || strings.Contains(strings.Join(h.relay.calls, ","), "confirm") {
		t.Fatalf("calls %v", h.relay.calls)
	}
	if !strings.Contains(h.out.String(), "Someone may be intercepting") {
		t.Fatal(h.out.String())
	}
	if c, _ := config.Load(h.opts.Home); len(c.Devices) != 0 {
		t.Fatalf("%+v", c.Devices)
	}
}

func TestSetupAnsweringNoRejects(t *testing.T) {
	h := newHarness(t, "y\nn\n")
	if code := h.run(); code != 1 || h.relay.calls[len(h.relay.calls)-1] != "reject" {
		t.Fatalf("exit %d calls %v", code, h.relay.calls)
	}
	if d := h.devices(); len(d) != 0 {
		t.Fatalf("a refused phone must not be saved: %v", d)
	}
}

func TestSetupCodePathShowsWordsAndDefaultsToNo(t *testing.T) {
	h := newHarness(t, "y\n\n") // Enter at the word check = No
	h.relay.key.Path, h.relay.key.MAC = "code", ""
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	words := strings.Join(proto.SAS(h.app.Public, h.host.Public), " · ")
	if !strings.Contains(h.out.String(), words) || !strings.Contains(h.out.String(), "[y/N]") {
		t.Fatalf("words %q missing:\n%s", words, h.out)
	}
	if got := strings.Join(h.relay.calls, ","); got != "offer,key,key,host-key,reject" {
		t.Fatalf("host key goes first so the phone can show the words; got %s", got)
	}
}

func TestSetupCodePathYesConfirmsAndPhoneDeclineIsReported(t *testing.T) {
	h := newHarness(t, "y\ny\n")
	h.relay.key.Path, h.relay.key.MAC = "code", ""
	h.relay.confirmErr = relayhttp.ErrDeclined
	if code := h.run(); code != 1 || !strings.Contains(h.out.String(), "Your iPhone didn't accept the words") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if c, _ := config.Load(h.opts.Home); len(c.Devices) != 0 {
		t.Fatalf("a declined phone must not stay in the config: %+v", c.Devices)
	}
}

func TestSetupOnPairedMacAddsSecondDevice(t *testing.T) {
	h := newHarness(t, "y\n")
	h.hooked = true // hooks already on: no question
	_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://relay.test", HostID: "host_1", HostSecret: "sec",
		Devices: []config.Device{{DeviceID: "dev_0", Name: "Old iPhone"}}})
	h.relay.offer.HostSecret = "" // a reused host gets no new secret
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if h.relay.offerAuth == nil || *h.relay.offerAuth != (relayhttp.Auth{HostID: "host_1", HostSecret: "sec"}) {
		t.Fatalf("offer auth %+v", h.relay.offerAuth)
	}
	c, _ := config.Load(h.opts.Home)
	if c.HostSecret != "sec" || len(c.Devices) != 2 || c.Devices[0].DeviceID != "dev_0" || c.Devices[1].DeviceID != "dev_1" {
		t.Fatalf("%+v", c)
	}
	if strings.Contains(h.out.String(), "Turn on phone approvals") || strings.Contains(h.out.String(), "Codex are on") {
		t.Fatal("hooks already on must be skipped, without claiming Codex")
	}
}

func TestSetupMissingTmuxWithoutHomebrewStops(t *testing.T) {
	h := newHarness(t, "")
	delete(h.f.paths, "tmux")
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.out.String(), "brew install tmux") || len(h.relay.calls) != 0 {
		t.Fatalf("%v\n%s", h.relay.calls, h.out)
	}
}

func TestSetupInstallsTmuxWithHomebrew(t *testing.T) {
	h := newHarness(t, "y\ny\ny\n") // install tmux? yes; hooks? yes; connect? yes
	delete(h.f.paths, "tmux")
	h.f.paths["/opt/homebrew/bin/brew"] = "/opt/homebrew/bin/brew"
	var ran string
	h.opts.env.Run = func(name string, args ...string) (string, error) {
		k := strings.Join(append([]string{name}, args...), " ")
		if k == "/opt/homebrew/bin/brew install tmux" {
			ran = k
			h.f.paths["tmux"] = "/opt/homebrew/bin/tmux"
			return "", nil
		}
		if out, ok := h.f.runs[k]; ok {
			return out, nil
		}
		return "", errors.New("exit 1")
	}
	if code := h.run(); code != 0 || ran == "" {
		t.Fatalf("exit %d ran %q\n%s", code, ran, h.out)
	}
}

func TestSetupWaitsForRemoteLogin(t *testing.T) {
	h := newHarness(t, "y\ny\n")
	h.f.banners = []string{"", "", "", "SSH-2.0-OpenSSH_9.8"}
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if len(h.f.opened) != 1 || h.f.opened[0] != RemoteLoginURL || !strings.Contains(h.out.String(), "System Settings → General → Sharing") {
		t.Fatalf("%v\n%s", h.f.opened, h.out)
	}
}

func TestSetupExpiredCode(t *testing.T) {
	h := newHarness(t, "y\n")
	h.relay.keys = []error{relayhttp.ErrExpired}
	if code := h.run(); code != 1 || !strings.Contains(h.out.String(), "This code expired. Run `wrangle setup` again.") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
}

func TestSetupNeverPrintsTheQRSecrets(t *testing.T) {
	h := newHarness(t, "y\ny\n")
	h.relay.offer.HostSecret = "hs_TOPSECRET"
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	out := h.out.String()
	for _, secret := range []string{"wrangle://", proto.B64(tBytes), proto.B64(kBytes), "hs_TOPSECRET", proto.B64(h.host.Private)} {
		if strings.Contains(out, secret) {
			t.Fatalf("output shows %q:\n%s", secret, out)
		}
	}
}

func TestSetupCleansThePhoneName(t *testing.T) {
	h := newHarness(t, "y\ny\n")
	h.relay.key.DeviceName = "Evil\x1b[2J\nPhone\u202e\u2028\u2029" + strings.Repeat("x", 100)
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	out := h.out.String()
	if strings.Contains(out, "\x1b[2J") || strings.Contains(out, "\u202e") || strings.Contains(out, "\u2028") || strings.Contains(out, "\u2029") || strings.Contains(out, "Evil\n") {
		t.Fatalf("control characters reached the terminal:\n%q", out)
	}
	c, _ := config.Load(h.opts.Home)
	if len(c.Devices) != 1 || !strings.HasPrefix(c.Devices[0].Name, "Evil[2JPhone") || len([]rune(c.Devices[0].Name)) != 64 {
		t.Fatalf("saved name %q", c.Devices[0].Name)
	}

	h = newHarness(t, "y\ny\n")
	h.relay.key.DeviceName = "\x00\x07"
	if code := h.run(); code != 0 || !strings.Contains(h.out.String(), "Connect “your iPhone”? [Y/n]") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
}

func TestSetupStartsTheServiceAndWaitsForIt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		startErr error
		status   bool // a fresh status.json from the restarted daemon
		want     string
		sleeps   int // waiting sleeps after saving the phone
	}{
		{"running", nil, true, "✓ Background service running (starts with your Mac)", 0},
		{"no heartbeat", nil, false, "✓ Background service running (starts with your Mac)", serviceWaitPolls},
		{"failed", errors.New("launchctl said no"), false, "✗ Couldn't start the background service: launchctl said no. Run `wrangle doctor`.", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "y\ny\n")
			started := 0
			h.opts.NoService = false
			h.opts.StartService = func() error { started++; return tc.startErr }
			if tc.status {
				// The restarted daemon writes its first "up" heartbeat after the config poll grace.
				_ = config.WriteStatus(h.opts.Home, true, time.UnixMilli(1000).Add(serviceRestartGrace+time.Second))
			}
			if code := h.run(); code != 0 {
				t.Fatalf("exit %d\n%s", code, h.out)
			}
			if started != 1 || !strings.Contains(h.out.String(), tc.want) {
				t.Fatalf("started %d, want %q:\n%s", started, tc.want, h.out)
			}
			if got := strings.Join(h.relay.calls, ","); got != "offer,key,key,host-key,confirm" {
				t.Fatalf("calls %s", got)
			}
			if len(h.f.sleeps) != tc.sleeps {
				t.Fatalf("slept %d times, want %d", len(h.f.sleeps), tc.sleeps)
			}
		})
	}
}

func TestSetupIgnoresAStaleHeartbeat(t *testing.T) {
	h := newHarness(t, "y\ny\n")
	h.opts.NoService = false
	h.opts.StartService = func() error { return nil }
	// Written by the old daemon before it noticed the new config: not proof the new one is up.
	_ = config.WriteStatus(h.opts.Home, true, time.UnixMilli(1000).Add(time.Second))
	if code := h.run(); code != 0 || len(h.f.sleeps) != serviceWaitPolls {
		t.Fatalf("exit %d sleeps %d", code, len(h.f.sleeps))
	}
}

// cancelReader cancels the run the moment setup reads an answer, as Ctrl-C at a prompt does, then hands over "y".
type cancelReader struct{ cancel func() }

func (c cancelReader) Read(p []byte) (int, error) { c.cancel(); return copy(p, "y\n"), nil }

func TestSetupCtrlCAtHooksPromptWritesNothing(t *testing.T) {
	h := newHarness(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.opts.env.In = cancelReader{cancel}
	if code := Run(ctx, h.opts.env, h.relay, h.opts); code != 130 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if h.hooked || len(h.relay.calls) != 0 || !strings.Contains(h.out.String(), "Setup stopped. Run `wrangle setup` again.") {
		t.Fatalf("hooked %v calls %v\n%s", h.hooked, h.relay.calls, h.out)
	}
}

func TestSetupCtrlCWhileWaitingForPhoneRejectsTheOffer(t *testing.T) {
	h := newHarness(t, "y\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.relay.keys = []error{relayhttp.ErrWaiting, relayhttp.ErrWaiting, relayhttp.ErrWaiting}
	h.relay.onKey = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	if code := Run(ctx, h.opts.env, h.relay, h.opts); code != 130 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	out := h.out.String()
	if !strings.Contains(out, "Setup stopped. Run `wrangle setup` again.") || strings.Contains(out, "No iPhone connected in time") {
		t.Fatal(out)
	}
	if h.relay.calls[len(h.relay.calls)-1] != "reject" {
		t.Fatalf("the open offer must be rejected: %v", h.relay.calls)
	}
}

func TestSetupNoInputIsNotYes(t *testing.T) {
	h := newHarness(t, "") // stdin closed: EOF at the first question
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if h.hooked || len(h.relay.calls) != 0 || !strings.Contains(h.out.String(), "No answer. Run `wrangle setup` in a terminal.") {
		t.Fatalf("hooked %v calls %v\n%s", h.hooked, h.relay.calls, h.out)
	}
}

func TestSetupNoInputAtConnectRejects(t *testing.T) {
	h := newHarness(t, "y\n") // hooks yes, then EOF at "Connect …?"
	if code := h.run(); code != 1 || h.relay.calls[len(h.relay.calls)-1] != "reject" || len(h.devices()) != 0 {
		t.Fatalf("exit %d calls %v\n%s", code, h.relay.calls, h.out)
	}
}

func TestSetupUnreadableConfigStops(t *testing.T) {
	h := newHarness(t, "y\ny\n")
	path := filepath.Join(h.opts.Home, "config.json")
	_ = os.MkdirAll(h.opts.Home, 0o700)
	_ = os.WriteFile(path, []byte(`{"host_id":"host_1",`), 0o600)
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if !strings.Contains(h.out.String(), "Couldn't read "+path+". Fix or remove it, then run `wrangle setup` again.") ||
		h.hooked || len(h.relay.calls) != 0 {
		t.Fatalf("hooked %v calls %v\n%s", h.hooked, h.relay.calls, h.out)
	}
	if data, _ := os.ReadFile(path); string(data) != `{"host_id":"host_1",` {
		t.Fatalf("config was replaced: %s", data)
	}
}

func TestSetupKeepsConfigChangesMadeWhilePairing(t *testing.T) {
	h := newHarness(t, "y\n")
	h.hooked = true
	_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://relay.test", HostID: "host_1", HostSecret: "sec",
		Devices: []config.Device{{DeviceID: "dev_0"}, {DeviceID: "dev_9"}}})
	h.relay.offer.HostSecret = ""
	h.relay.onHostKey = func() { // `wrangle config keep-awake off` and an unlink of dev_9 while setup waits
		c, _ := config.Load(h.opts.Home)
		c.KeepAwakeOff = true
		c.RemoveDevice("dev_9")
		_ = config.Save(h.opts.Home, c)
	}
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	c, _ := config.Load(h.opts.Home)
	if !c.KeepAwakeOff || strings.Join(h.devices(), ",") != "dev_0,dev_1" {
		t.Fatalf("keep-awake %v devices %v", c.KeepAwakeOff, h.devices())
	}
}

func TestSetupNewHostIdentity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		confirmErr error
		wantHost   string
		wantDevs   string
	}{
		{"confirmed: old phones dropped", nil, "host_1", "dev_1"},
		{"declined: old phones kept", relayhttp.ErrDeclined, "host_old", "dev_0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "y\n")
			h.hooked = true
			// Saved for another relay, so the offer goes out without auth and the relay hands back a new host.
			_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://old.test", HostID: "host_old", HostSecret: "old",
				Devices: []config.Device{{DeviceID: "dev_0"}}})
			h.relay.confirmErr = tc.confirmErr
			code := h.run()
			c, _ := config.Load(h.opts.Home)
			if (code == 0) != (tc.confirmErr == nil) || c.HostID != tc.wantHost || strings.Join(h.devices(), ",") != tc.wantDevs {
				t.Fatalf("exit %d host %q devices %v\n%s", code, c.HostID, h.devices(), h.out)
			}
		})
	}
}

// An offer sent without auth (config saved for another relay) that comes back with no host secret must not fall
// back to the stored secret: that secret belongs to the other relay and would be sent to this one.
func TestSetupUnauthenticatedOfferWithoutSecretNeverSendsTheStoredSecret(t *testing.T) {
	h := newHarness(t, "y\n")
	h.hooked = true
	_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://old.test", HostID: "host_old", HostSecret: "old"})
	h.relay.offer.HostSecret = ""
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if got := strings.Join(h.relay.calls, ","); got != "offer" {
		t.Fatalf("calls %s", got)
	}
	if c, _ := config.Load(h.opts.Home); c.HostID != "host_old" || c.HostSecret != "old" {
		t.Fatalf("config changed: %+v", c)
	}
}

func TestSetupQRWithoutMACFallsBackToTheWords(t *testing.T) {
	h := newHarness(t, "y\n\n") // hooks yes; Enter at the word check
	h.relay.key.MAC = ""
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	words := strings.Join(proto.SAS(h.app.Public, h.host.Public), " · ")
	if !strings.Contains(h.out.String(), words) || !strings.Contains(h.out.String(), "[y/N]") {
		t.Fatalf("words %q missing:\n%s", words, h.out)
	}
	if got := strings.Join(h.relay.calls, ","); got != "offer,key,key,host-key,reject" || len(h.devices()) != 0 {
		t.Fatalf("calls %s devices %v", got, h.devices())
	}
}

func TestSetupExpiredHostLinkOnReoffer(t *testing.T) {
	h := newHarness(t, "y\n")
	h.hooked = true
	_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://relay.test", HostID: "host_1", HostSecret: "sec"})
	h.relay.offerErr = relayhttp.ErrUnauthorized
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	want := "This Mac's link to Wrangle is no longer valid. Remove " + filepath.Join(h.opts.Home, "config.json") + ", then run `wrangle setup` again."
	if !strings.Contains(h.out.String(), want) {
		t.Fatal(h.out.String())
	}
}

func TestSetupErrorsAreOneSentenceAndANextStep(t *testing.T) {
	// brew fails: no raw brew output, one line.
	h := newHarness(t, "y\n")
	delete(h.f.paths, "tmux")
	h.f.paths["/opt/homebrew/bin/brew"] = "/opt/homebrew/bin/brew"
	h.opts.env.Run = func(name string, args ...string) (string, error) {
		return "==> Downloading\\nlots\\nof\\noutput\\nError: no bottle", errors.New("exit 1")
	}
	if code := h.run(); code != 1 || !strings.Contains(h.out.String(), "✗ Couldn't install tmux with Homebrew. Run `brew install tmux` to see why, then run `wrangle setup` again.\n") ||
		strings.Contains(h.out.String(), "Downloading") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}

	// No randomness: a sentence, not a silent exit.
	h = newHarness(t, "y\n")
	h.opts.Rand = bytes.NewReader(nil)
	if code := h.run(); code != 1 || !strings.Contains(h.out.String(), "✗ Couldn't create a pairing code. Run `wrangle setup` again.") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}

	// Installing hooks fails: no "nothing was changed" claim.
	h = newHarness(t, "y\ny\n")
	h.opts.InstallHooks = func() ([]string, error) { return nil, errors.New("disk full") }
	if code := h.run(); code != 0 || !strings.Contains(h.out.String(), "✗ Couldn't turn on phone approvals (disk full). Run `wrangle install` to try again.") ||
		strings.Contains(h.out.String(), "nothing was changed") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}

	// Saying no: what happened and what to do.
	h = newHarness(t, "y\nn\n")
	if code := h.run(); code != 1 || !strings.Contains(h.out.String(), "Not connected. Run `wrangle setup` again to connect a phone.") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
}

func TestSetupWithoutAnInstallerSkipsApprovals(t *testing.T) {
	h := newHarness(t, "y\n") // only the connect question
	h.opts.InstallHooks = nil
	if code := h.run(); code != 0 || strings.Contains(h.out.String(), "Turn on phone approvals") {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
}

const userKey = "ssh-rsa AAAAB3mine laptop"
const phoneKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func wrangleIDs(t *testing.T, keys string) []string {
	t.Helper()
	ids, err := sshkeys.DeviceIDs(keys)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// I1: a paired Mac re-run against another relay gets a new host identity; the old phones can't reach it any more,
// so their SSH keys go too, not just their config entries.
func TestSetupAgainstANewRelayRemovesTheOldPhonesKeys(t *testing.T) {
	h := newHarness(t, "y\n")
	h.hooked = true
	_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://old-relay.test", HostID: "host_0", HostSecret: "old",
		Devices: []config.Device{{DeviceID: "dev_0", Name: "Old iPhone"}, {DeviceID: "dev_9", Name: "Old iPad"}}})
	if err := os.WriteFile(h.opts.KeysPath, []byte(userKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = sshkeys.Add(h.opts.KeysPath, phoneKeyLine, "dev_0", "Old iPhone")
	_ = sshkeys.Add(h.opts.KeysPath, phoneKeyLine, "dev_9", "Old iPad")
	h.relay.onConfirm = func() { _ = sshkeys.Add(h.opts.KeysPath, phoneKeyLine, "dev_1", "Alex's iPhone") } // the new phone enrols
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if h.relay.offerAuth != nil {
		t.Fatal("another relay must get an unauthenticated offer")
	}
	if ids := wrangleIDs(t, h.opts.KeysPath); strings.Join(ids, ",") != "dev_1" {
		t.Fatalf("old wrangle: lines left: %v", ids)
	}
	if b, _ := os.ReadFile(h.opts.KeysPath); !strings.HasPrefix(string(b), userKey+"\n") {
		t.Fatalf("the user's own key must stay:\n%s", b)
	}
	if got := h.devices(); strings.Join(got, ",") != "dev_1" {
		t.Fatalf("devices %v", got)
	}
}

// I1: a confirm that fails after the phone already enrolled (its answer lost) takes the phone's key back out.
func TestSetupUndoAfterAFailedConfirmRemovesTheNewPhonesKey(t *testing.T) {
	h := newHarness(t, "y\n")
	h.hooked = true
	_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://relay.test", HostID: "host_1", HostSecret: "sec",
		Devices: []config.Device{{DeviceID: "dev_0", Name: "Old iPhone"}}})
	h.relay.offer.HostSecret = ""
	_ = sshkeys.Add(h.opts.KeysPath, phoneKeyLine, "dev_0", "Old iPhone")
	h.relay.onConfirm = func() { _ = sshkeys.Add(h.opts.KeysPath, phoneKeyLine, "dev_1", "Alex's iPhone") }
	h.relay.confirmErr = errors.New("timeout")
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if ids := wrangleIDs(t, h.opts.KeysPath); strings.Join(ids, ",") != "dev_0" {
		t.Fatalf("wrangle: lines %v", ids)
	}
	if got := h.devices(); strings.Join(got, ",") != "dev_0" {
		t.Fatalf("devices %v", got)
	}
}

// I4: --no-hooks never asks about approvals and never touches the agents' settings.
func TestSetupNoHooksSkipsTheApprovalsStepEntirely(t *testing.T) {
	h := newHarness(t, "y\n")
	h.opts.NoHooks = true
	asked := false
	h.opts.HooksPresent = func() bool { asked = true; return false }
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if h.hooked || asked || strings.Contains(h.out.String(), "Turn on phone approvals") {
		t.Fatalf("hooks touched (installed %v, checked %v)\n%s", h.hooked, asked, h.out)
	}
	if !strings.Contains(h.out.String(), "– Phone approvals skipped (--no-hooks).") {
		t.Fatal(h.out.String())
	}
}

// Re-connecting a phone this Mac already has: a failed confirm keeps the earlier pairing (its entry and its working
// SSH key), since the phone never enrolled a new key.
func TestSetupUndoOfAFailedRepairKeepsTheEarlierPairing(t *testing.T) {
	h := newHarness(t, "y\n")
	h.hooked = true
	old := config.Device{DeviceID: "dev_1", Name: "Alex's iPhone", AppPublic: "old-app", HostPrivate: "old-priv", HostPublic: "old-pub"}
	_ = config.Save(h.opts.Home, config.Config{RelayURL: "https://relay.test", HostID: "host_1", HostSecret: "sec", Devices: []config.Device{old}})
	h.relay.offer.HostSecret = ""
	_ = sshkeys.Add(h.opts.KeysPath, phoneKeyLine, "dev_1", "Alex's iPhone")
	h.relay.confirmErr = errors.New("timeout")
	if code := h.run(); code != 1 {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	c, _ := config.Load(h.opts.Home)
	if len(c.Devices) != 1 || c.Devices[0] != old {
		t.Fatalf("earlier pairing not restored: %+v", c.Devices)
	}
	if !sshkeys.Has(h.opts.KeysPath, "dev_1") {
		t.Fatal("the earlier pairing's SSH key was removed")
	}
}
