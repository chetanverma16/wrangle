package setup

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/proto"
	"github.com/chetanverma16/wrangle/internal/qrterm"
	"github.com/chetanverma16/wrangle/internal/relayhttp"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

// Relay is the part of relayhttp.Client that setup uses.
type Relay interface {
	Offer(ctx context.Context, auth *relayhttp.Auth, req relayhttp.OfferRequest) (relayhttp.OfferResult, error)
	PairKey(ctx context.Context, a relayhttp.Auth) (relayhttp.KeyResult, error)
	HostKey(ctx context.Context, a relayhttp.Auth, hostPublicKey string) error
	Confirm(ctx context.Context, a relayhttp.Auth) error
	Reject(ctx context.Context, a relayhttp.Auth) error
}

var _ Relay = relayhttp.Client{}

type Options struct {
	RelayURL, HelperVersion, Home, HostName, KeysPath string
	Yes                                               bool // answer every question with its default
	NoService                                         bool // development: you run `wrangle serve` yourself
	NoHooks                                           bool // never ask about or touch the agents' hook settings
	PairPoll, PairTimeout                             time.Duration
	KeyWait                                           time.Duration // how long to wait for the phone's SSH key
	Rand                                              io.Reader
	GenerateKey                                       func() (proto.KeyPair, error)
	InstallHooks                                      func() ([]string, error)
	HooksPresent                                      func() bool
	StartService                                      func() error
	Now                                               func() time.Time

	env Env // tests only: lets the harness keep its Env next to the options
}

const (
	brewHint   = `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" && brew install tmux`
	rerun      = "Run `wrangle setup` again."
	rerunLower = "run `wrangle setup` again."

	// serveLoop notices a changed config.json within 2 s; a heartbeat written later than this after saving comes
	// from the restarted daemon, not the old one.
	serviceRestartGrace = 3 * time.Second
	// serviceWaitPolls × 1 s is how long setup waits for that heartbeat before confirming anyway.
	serviceWaitPolls = 15
	maxNameRunes     = 64
)

var (
	errStopped  = errors.New("stopped")   // Ctrl-C
	errNoAnswer = errors.New("no answer") // stdin closed: nothing typed is never consent
)

type prompter struct {
	in  *bufio.Reader
	out io.Writer
	yes bool
}

// ask prints q and reads one answer. Only --yes takes the default without input; an empty line (Enter) takes it
// too. A closed stdin is errNoAnswer, and Ctrl-C (ctx cancelled) is errStopped, even if a line arrives with it.
func (p prompter) ask(ctx context.Context, q string, def bool) (bool, error) {
	fmt.Fprint(p.out, q+" ")
	if p.yes {
		if def {
			fmt.Fprintln(p.out, "y")
		} else {
			fmt.Fprintln(p.out, "n")
		}
		return def, nil
	}
	type answer struct {
		line string
		err  error
	}
	ch := make(chan answer, 1)
	go func() { l, err := p.in.ReadString('\n'); ch <- answer{l, err} }()
	var a answer
	select {
	case <-ctx.Done():
	case a = <-ch:
	}
	if ctx.Err() != nil {
		fmt.Fprintln(p.out)
		return false, errStopped
	}
	line := strings.ToLower(strings.TrimSpace(a.line))
	if a.err != nil && line == "" {
		fmt.Fprintln(p.out)
		return false, errNoAnswer
	}
	switch line {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func ok(w io.Writer, format string, a ...any)   { fmt.Fprintf(w, "✓ "+format+"\n", a...) }
func fail(w io.Writer, format string, a ...any) { fmt.Fprintf(w, "✗ "+format+"\n", a...) }

// stopped ends setup after Ctrl-C (exit 130) or a closed stdin (exit 1). withdraw, if set, rejects the open offer.
func stopped(w io.Writer, err error, withdraw func()) int {
	if withdraw != nil {
		withdraw()
	}
	if errors.Is(err, errNoAnswer) {
		fail(w, "No answer. Run `wrangle setup` in a terminal.")
		return 1
	}
	fmt.Fprintln(w, "Setup stopped. "+rerun)
	return 130
}

// cleanName makes a phone-supplied name safe to print: no control, format or line/paragraph separator characters
// (escape codes, bidi overrides), at most 64 characters.
func cleanName(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == unicode.ReplacementChar {
			continue
		}
		if n == maxNameRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	if strings.TrimSpace(b.String()) == "" {
		return "your iPhone"
	}
	return b.String()
}

// loadConfig reads config.json. A missing file is a fresh Mac; anything else unreadable stops setup, so a broken
// file is never replaced (it holds this Mac's identity and its phones).
func loadConfig(w io.Writer, home string) (config.Config, bool) {
	c, err := config.Load(home)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fail(w, "Couldn't read %s. Fix or remove it, then %s", filepath.Join(home, "config.json"), rerunLower)
		return c, false
	}
	return c, true
}

// Run is `wrangle setup`: the checklist (one line per step), then the pairing offer as a QR code.
func Run(ctx context.Context, e Env, r Relay, o Options) int {
	p := prompter{in: bufio.NewReader(e.In), out: e.Out, yes: o.Yes}
	w := e.Out
	cfg, readable := loadConfig(w, o.Home)
	if !readable {
		return 1
	}

	// 1. tmux
	tmux, found := FindTmux(e)
	if !found {
		brew, hasBrew := FindBrew(e)
		if !hasBrew {
			fail(w, "tmux is missing. Install Homebrew and tmux with:\n    %s\n  then %s", brewHint, rerunLower)
			return 1
		}
		yes, err := p.ask(ctx, "Install tmux with Homebrew? [Y/n]", true)
		if err != nil {
			return stopped(w, err, nil)
		}
		if !yes {
			fail(w, "tmux is needed for the terminal. Install it with `brew install tmux`, then %s", rerunLower)
			return 1
		}
		if _, err := e.Run(brew, "install", "tmux"); err != nil {
			if ctx.Err() != nil {
				return stopped(w, errStopped, nil)
			}
			fail(w, "Couldn't install tmux with Homebrew. Run `brew install tmux` to see why, then %s", rerunLower)
			return 1
		}
		if tmux, found = FindTmux(e); !found {
			fail(w, "tmux still isn't on this Mac. Run `brew install tmux`, then %s", rerunLower)
			return 1
		}
	}
	ok(w, "tmux  %s", tmux)

	// 2. Remote Login
	if !RemoteLoginOn(e) {
		fmt.Fprintln(w, "  Turn on Remote Login (System Settings → General → Sharing). Opening it for you…")
		_ = e.OpenURL(RemoteLoginURL)
		if !WaitRemoteLoginCtx(ctx, e, PollEvery, PollLimit) {
			if ctx.Err() != nil {
				return stopped(w, errStopped, nil)
			}
			fail(w, "Remote Login is still off. Turn it on, then %s", rerunLower)
			return 1
		}
	}
	ok(w, "Remote Login is on")

	// 3. Agent alerts
	switch {
	case o.NoHooks:
		fmt.Fprintln(w, "– Phone approvals skipped (--no-hooks).")
	case o.HooksPresent != nil && o.HooksPresent():
		ok(w, "Phone approvals are already on")
	case o.InstallHooks == nil:
		fmt.Fprintln(w, "– Phone approvals skipped. Turn them on later with `wrangle install`.")
	default:
		yes, err := p.ask(ctx, "Turn on phone approvals for Claude Code and Codex? [Y/n]", true)
		if err != nil {
			return stopped(w, err, nil)
		}
		if !yes {
			fmt.Fprintln(w, "– Phone approvals skipped. Turn them on later with `wrangle install`.")
			break
		}
		if notes, err := o.InstallHooks(); err != nil {
			fail(w, "Couldn't turn on phone approvals (%v). Run `wrangle install` to try again.", err)
		} else {
			ok(w, "Phone approvals on (backups in ~/.wrangle/backup)")
			for _, n := range notes {
				fmt.Fprintln(w, "  "+n)
			}
		}
	}

	// 4. Background service
	if ctx.Err() != nil {
		return stopped(w, errStopped, nil)
	}
	serviceUp := false
	if o.NoService || o.StartService == nil {
		fmt.Fprintln(w, "– Background service skipped: run `wrangle serve` yourself.")
	} else if err := o.StartService(); err != nil {
		fail(w, "Couldn't start the background service: %v. Run `wrangle doctor`.", err)
	} else {
		ok(w, "Background service running (starts with your Mac)")
		serviceUp = true
	}

	// 5. Stay awake
	if cfg.KeepAwakeOff {
		fmt.Fprintln(w, "– Stay awake is off. Turn it on with: wrangle config keep-awake on")
	} else {
		ok(w, "Stay awake while on power (turn off: wrangle config keep-awake off)")
	}

	// 6. Addresses
	ifaces, _ := e.Interfaces()
	ts := Tailscale(e)
	addrs := Addresses(LocalHostName(e), LANIPv4(ifaces), ts.IP, ts.DNSName)
	for _, a := range addrs {
		ok(w, "Address (%s)  %s", a.Kind, a.Host)
	}
	if ts.SSH {
		fmt.Fprintln(w, "  Tailscale SSH is on and blocks Remote Login on the Tailscale address. Turn it off with: tailscale set --ssh=false")
	}

	// 7. QR code
	if ctx.Err() != nil {
		return stopped(w, errStopped, nil)
	}
	return pair(ctx, e, r, o, p, cfg, tmux, serviceUp)
}

func pair(ctx context.Context, e Env, r Relay, o Options, p prompter, cfg config.Config, tmux string, serviceUp bool) int {
	w := e.Out
	cfgPath := filepath.Join(o.Home, "config.json")
	rnd := o.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	t, k := make([]byte, 16), make([]byte, 16)
	if _, err := io.ReadFull(rnd, t); err != nil {
		fail(w, "Couldn't create a pairing code. %s", rerun)
		return 1
	}
	if _, err := io.ReadFull(rnd, k); err != nil {
		fail(w, "Couldn't create a pairing code. %s", rerun)
		return 1
	}
	gen := o.GenerateKey
	if gen == nil {
		gen = proto.GenerateKeyPair
	}
	kp, err := gen() // a fresh host key for every phone
	if err != nil {
		fail(w, "Couldn't create keys (%v). %s", err, rerun)
		return 1
	}
	var auth *relayhttp.Auth
	if cfg.Paired() && cfg.RelayURL == o.RelayURL {
		auth = &relayhttp.Auth{HostID: cfg.HostID, HostSecret: cfg.HostSecret}
	}
	res, err := r.Offer(ctx, auth, relayhttp.OfferRequest{HostName: o.HostName, HelperVersion: o.HelperVersion,
		HostKeyCommit: proto.HostKeyCommit(kp.Public), TokenHash: proto.TokenHash(t)})
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return stopped(w, errStopped, nil)
	case errors.Is(err, relayhttp.ErrTooMany):
		fail(w, "Too many tries from this network. Wait 10 minutes, then %s", rerunLower)
		return 1
	case errors.Is(err, relayhttp.ErrUnauthorized):
		fail(w, "This Mac's link to Wrangle is no longer valid. Remove %s, then %s", cfgPath, rerunLower)
		return 1
	default:
		fail(w, "Couldn't reach the Wrangle server (%v). Check your internet connection, then %s", err, rerunLower)
		return 1
	}
	a := relayhttp.Auth{HostID: res.HostID, HostSecret: res.HostSecret}
	if a.HostSecret == "" {
		// The stored secret may only be reused for the host it belongs to, on the relay it came from (the offer was
		// sent with that auth). Otherwise it would go to a different relay.
		if auth == nil || res.HostID != cfg.HostID {
			fail(w, "The Wrangle server didn't send this Mac's link. %s", rerun)
			return 1
		}
		a.HostSecret = cfg.HostSecret
	}
	withdraw := func() { // best effort, also after Ctrl-C has cancelled ctx
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.Reject(rctx, a)
	}
	qr := proto.QR{Relay: o.RelayURL, OfferID: res.OfferID, Name: o.HostName, T: t, K: k, HostPublic: kp.Public}
	art, err := qrterm.Render(qr.URL()) // the QR is the only place t and k ever appear
	if err != nil {
		withdraw()
		fail(w, "Couldn't draw the QR code. %s", rerun)
		return 1
	}
	fmt.Fprintln(w, "\nScan this with the Wrangle app on your iPhone (Connect your Mac → Scan QR code):")
	fmt.Fprint(w, art)
	fmt.Fprintf(w, "Can't scan? Enter this code in the app: %s\nExpires in 10 minutes\n\n", proto.FormatCode(res.Code))

	kr, code := waitForPhone(ctx, e, r, o, a, withdraw)
	if code >= 0 {
		return code
	}
	appPub, err := proto.UnB64(kr.AppPublicKey)
	if err != nil || len(appPub) != 32 {
		withdraw()
		fail(w, "The iPhone sent a bad key. %s", rerun)
		return 1
	}
	name := cleanName(kr.DeviceName)
	dev := config.Device{DeviceID: kr.DeviceID, Name: name, AppPublic: proto.B64(appPub), HostPrivate: proto.B64(kp.Private),
		HostPublic: proto.B64(kp.Public), PairedAt: now(o).UnixMilli()}
	notConnected := func() int {
		withdraw()
		fmt.Fprintln(w, "Not connected. Run `wrangle setup` again to connect a phone.")
		return 1
	}
	sendHostKey := func() int {
		if err := r.HostKey(ctx, a, proto.B64(kp.Public)); err != nil {
			if ctx.Err() != nil {
				return stopped(w, errStopped, withdraw)
			}
			withdraw()
			fail(w, "Pairing failed (%v). %s", err, rerun)
			return 1
		}
		return -1
	}

	if kr.Path == "qr" && kr.MAC != "" {
		if !proto.VerifyQRMAC(k, appPub, kp.Public, kr.MAC) {
			withdraw()
			fail(w, "Someone may be intercepting: the iPhone's key didn't match the QR code. %s", rerun)
			return 1
		}
		yes, err := p.ask(ctx, fmt.Sprintf("Connect “%s”? [Y/n]", name), true)
		if err != nil {
			return stopped(w, err, withdraw)
		}
		if !yes {
			return notConnected()
		}
		if code := sendHostKey(); code >= 0 {
			return code
		}
	} else {
		// Typed code, or a QR answer without its MAC: the 4-word check. Default No, because a relay that strips
		// the MAC can only be caught here.
		if code := sendHostKey(); code >= 0 {
			return code
		}
		fmt.Fprintf(w, "Check your iPhone shows these 4 words:  %s\n", strings.Join(proto.SAS(appPub, kp.Public), " · "))
		yes, err := p.ask(ctx, fmt.Sprintf("Only answer y if your iPhone shows these same 4 words. Connect “%s”? [y/N]", name), false)
		if err != nil {
			return stopped(w, err, withdraw)
		}
		if !yes {
			return notConnected()
		}
	}

	// Save before confirming, so `wrangle serve` (which follows config.json) already has this phone's key when
	// the phone sends its SSH key right after linking. Re-read first: keep-awake or an unlink may have changed it
	// while the phone was scanning.
	if ctx.Err() != nil {
		return stopped(w, errStopped, withdraw)
	}
	unlock, err := config.Lock(o.Home) // `wrangle serve` may be editing config.json or authorized_keys
	if err != nil {
		withdraw()
		fail(w, "Couldn't lock %s (%v). %s", filepath.Join(o.Home, "enroll.lock"), err, rerun)
		return 1
	}
	prev, readable := loadConfig(w, o.Home)
	if !readable {
		unlock()
		withdraw()
		return 1
	}
	cur := prev
	cur.Devices = append([]config.Device(nil), prev.Devices...)
	cur.RelayURL, cur.HostID, cur.HostSecret, cur.HostName, cur.TmuxPath = o.RelayURL, a.HostID, a.HostSecret, o.HostName, tmux
	cur.UpsertDevice(dev)
	saved := now(o)
	err = config.Save(o.Home, cur)
	unlock() // never held across the service wait or the confirm: serve's enrolment needs it
	if err != nil {
		withdraw()
		fail(w, "Couldn't save %s (%v). %s", cfgPath, err, rerun)
		return 1
	}
	// undo takes this phone back out (its config entry and, if it already enrolled, its SSH key), and the old host
	// identity back in, without losing the old phones. A phone this Mac already had gets its earlier entry back and
	// keeps its key: it never enrolled a new one, so that key is the earlier pairing's working key.
	newHost := a.HostID != prev.HostID
	var earlier *config.Device
	for _, d := range prev.Devices {
		if d.DeviceID == dev.DeviceID {
			d := d
			earlier = &d
		}
	}
	undo := func() {
		_ = editLocked(o.Home, func(c *config.Config) {
			if earlier != nil {
				c.UpsertDevice(*earlier)
			} else {
				c.RemoveDevice(dev.DeviceID)
				_, _ = sshkeys.Remove(o.KeysPath, dev.DeviceID)
			}
			if newHost {
				c.RelayURL, c.HostID, c.HostSecret, c.HostName = prev.RelayURL, prev.HostID, prev.HostSecret, prev.HostName
			}
		})
	}
	if serviceUp && !waitForService(ctx, e, o.Home, saved) && ctx.Err() != nil {
		undo()
		return stopped(w, errStopped, withdraw)
	}
	if err := r.Confirm(ctx, a); err != nil {
		undo()
		switch {
		case ctx.Err() != nil:
			return stopped(w, errStopped, withdraw)
		case errors.Is(err, relayhttp.ErrDeclined):
			fail(w, "Your iPhone didn't accept the words. Nothing was connected. %s", rerun)
		default:
			fail(w, "Pairing failed (%v). %s", err, rerun)
		}
		return 1
	}
	if newHost { // linked to a new host identity: the old one's phones can't reach this Mac any more, so their keys go too
		_ = editLocked(o.Home, func(c *config.Config) {
			for _, d := range c.Devices {
				if d.DeviceID != dev.DeviceID {
					_, _ = sshkeys.Remove(o.KeysPath, d.DeviceID)
				}
			}
			c.Devices = []config.Device{dev}
		})
	}

	deadline := now(o).Add(o.KeyWait)
	for !sshkeys.Has(o.KeysPath, dev.DeviceID) && now(o).Before(deadline) && ctx.Err() == nil {
		e.Sleep(time.Second)
	}
	if sshkeys.Has(o.KeysPath, dev.DeviceID) {
		ok(w, "Connected to “%s”", name)
	} else {
		ok(w, "Alerts connected to “%s”", name)
		fmt.Fprintln(w, "  The terminal key hasn't arrived yet. Open Wrangle on your iPhone, or run `wrangle doctor`.")
	}
	return 0
}

// editLocked loads config.json, applies edit and saves it, holding the enrolment lock throughout (edit may also change
// authorized_keys). A config that can't be read is left alone.
func editLocked(home string, edit func(*config.Config)) error {
	unlock, err := config.Lock(home)
	if err != nil {
		return err
	}
	defer unlock()
	c, err := config.Load(home)
	if err != nil {
		return err
	}
	edit(&c)
	return config.Save(home, c)
}

// waitForService waits until the background service, restarted by the new config.json, is back on the relay, so
// the phone's SSH key request right after /confirm finds it. It gives up after serviceWaitPolls seconds (the app
// retries enrolment when the relay times out), or on Ctrl-C.
func waitForService(ctx context.Context, e Env, home string, saved time.Time) bool {
	fresh := saved.Add(serviceRestartGrace).UnixMilli()
	for i := 0; ; i++ {
		if s, err := config.ReadStatus(home); err == nil && s.Relay == "up" && s.At >= fresh {
			return true
		}
		if i == serviceWaitPolls || ctx.Err() != nil {
			return false
		}
		e.Sleep(time.Second)
	}
}

// waitForPhone polls until a phone accepts. code < 0 means a key arrived; otherwise it is the exit code.
func waitForPhone(ctx context.Context, e Env, r Relay, o Options, a relayhttp.Auth, withdraw func()) (relayhttp.KeyResult, int) {
	w := e.Out
	start := now(o)
	for {
		kr, err := r.PairKey(ctx, a)
		switch {
		case err == nil:
			return kr, -1
		case ctx.Err() != nil:
			return kr, stopped(w, errStopped, withdraw)
		case errors.Is(err, relayhttp.ErrExpired):
			fail(w, "This code expired. %s", rerun)
			return kr, 1
		case errors.Is(err, relayhttp.ErrRejected), errors.Is(err, relayhttp.ErrDeclined):
			fail(w, "Pairing was cancelled. %s", rerun)
			return kr, 1
		}
		if now(o).Sub(start) > o.PairTimeout {
			withdraw()
			fail(w, "No iPhone connected in time. %s", rerun)
			return kr, 1
		}
		select {
		case <-ctx.Done():
			return kr, stopped(w, errStopped, withdraw)
		case <-time.After(o.PairPoll):
		}
	}
}

func now(o Options) time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// SafeName is cleanName for other commands (`wrangle doctor`, `wrangle remove-device`).
func SafeName(s string) string { return cleanName(s) }
