package setup

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chetanverma16/wrangle/internal/proto"
)

type fake struct {
	paths   map[string]string // LookPath name → result (missing = not found)
	runs    map[string]string // "name arg1 arg2" → output (missing = error)
	banners []string          // successive DialBanner results; "" = connection refused
	dials   int
	sleeps  []time.Duration
	files   map[string]string
	opened  []string
}

func (f *fake) env() Env {
	return Env{
		LookPath: func(n string) (string, error) {
			if p, ok := f.paths[n]; ok {
				return p, nil
			}
			return "", errors.New("not found")
		},
		Run: func(name string, args ...string) (string, error) {
			k := strings.Join(append([]string{name}, args...), " ")
			if out, ok := f.runs[k]; ok {
				return out, nil
			}
			return "", errors.New("exit 1")
		},
		DialBanner: func(string, time.Duration) (string, error) {
			i := f.dials
			f.dials++
			if i >= len(f.banners) {
				i = len(f.banners) - 1
			}
			if i < 0 || f.banners[i] == "" {
				return "", errors.New("connection refused")
			}
			return f.banners[i], nil
		},
		OpenURL:    func(u string) error { f.opened = append(f.opened, u); return nil },
		Sleep:      func(d time.Duration) { f.sleeps = append(f.sleeps, d) },
		Interfaces: func() ([]Iface, error) { return nil, nil },
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := f.files[p]; ok {
				return []byte(s), nil
			}
			return nil, errors.New("missing")
		},
		Glob: func(string) ([]string, error) {
			var out []string
			for p := range f.files {
				if strings.HasPrefix(p, "/etc/ssh/ssh_host_") && strings.HasSuffix(p, "_key.pub") {
					out = append(out, p)
				}
			}
			return out, nil
		},
		In:  strings.NewReader(""),
		Out: io.Discard,
	}
}

func TestFindTmuxUsesPathThenHomebrewLocations(t *testing.T) {
	f := &fake{paths: map[string]string{"tmux": "/usr/local/bin/tmux"}}
	if p, ok := FindTmux(f.env()); !ok || p != "/usr/local/bin/tmux" {
		t.Fatalf("%q %v", p, ok)
	}
	// launchd's PATH has no Homebrew: the absolute fallbacks still find it.
	f = &fake{paths: map[string]string{"/opt/homebrew/bin/tmux": "/opt/homebrew/bin/tmux"}}
	if p, ok := FindTmux(f.env()); !ok || p != "/opt/homebrew/bin/tmux" {
		t.Fatalf("%q %v", p, ok)
	}
	if _, ok := FindTmux((&fake{}).env()); ok {
		t.Fatal("no tmux anywhere must be reported")
	}
}

func TestFindBrew(t *testing.T) {
	f := &fake{paths: map[string]string{"/opt/homebrew/bin/brew": "/opt/homebrew/bin/brew"}}
	if p, ok := FindBrew(f.env()); !ok || p != "/opt/homebrew/bin/brew" {
		t.Fatalf("%q %v", p, ok)
	}
	if _, ok := FindBrew((&fake{}).env()); ok {
		t.Fatal("want no brew")
	}
}

func TestRemoteLoginNeedsAnSSHBanner(t *testing.T) {
	for banner, want := range map[string]bool{"SSH-2.0-OpenSSH_9.8\r\n": true, "HTTP/1.1 400": false, "": false} {
		f := &fake{banners: []string{banner}}
		if got := RemoteLoginOn(f.env()); got != want {
			t.Fatalf("banner %q: got %v", banner, got)
		}
	}
}

func TestWaitRemoteLoginPollsEvery2sUpTo5Minutes(t *testing.T) {
	f := &fake{banners: []string{"", "", "", "SSH-2.0-OpenSSH_9.8"}}
	if !WaitRemoteLogin(f.env(), PollEvery, PollLimit) {
		t.Fatal("want on after 3 polls")
	}
	if len(f.sleeps) != 3 || f.sleeps[0] != 2*time.Second {
		t.Fatalf("sleeps %v", f.sleeps)
	}
	f = &fake{banners: []string{""}}
	if WaitRemoteLogin(f.env(), PollEvery, PollLimit) {
		t.Fatal("never on must time out")
	}
	if len(f.sleeps) != 150 {
		t.Fatalf("want 150 sleeps (5 min / 2 s), got %d", len(f.sleeps))
	}
}

func TestLANIPv4SkipsLoopbackTailscaleLinkLocalAndNonEthernet(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo0", Up: true, Loopback: true, IPv4: []string{"127.0.0.1"}},
		{Name: "utun4", Up: true, IPv4: []string{"100.101.102.103"}},
		{Name: "en0", Up: false, IPv4: []string{"192.168.1.9"}},
		{Name: "en1", Up: true, IPv4: []string{"169.254.3.4", "100.64.0.9", "192.168.1.20"}},
	}
	if got := LANIPv4(ifaces); got != "192.168.1.20" {
		t.Fatalf("got %q", got)
	}
	if got := LANIPv4(nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestAddressesOrderLanNameLanIPThenTailscale(t *testing.T) {
	got := Addresses("Alexs-MacBook-Pro", "192.168.1.20", "100.101.102.103", "alexs-mbp.tail1234.ts.net")
	want := []proto.Address{
		{Kind: "lan", Host: "Alexs-MacBook-Pro.local"}, {Kind: "lan", Host: "192.168.1.20"},
		{Kind: "tailscale", Host: "100.101.102.103"}, {Kind: "tailscale", Host: "alexs-mbp.tail1234.ts.net"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := Addresses("", "", "", ""); len(got) != 0 {
		t.Fatalf("empty inputs give no addresses, got %+v", got)
	}
}

func TestTailscaleReadsIPDNSNameAndSSHSetting(t *testing.T) {
	cli := "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
	f := &fake{paths: map[string]string{cli: cli}, runs: map[string]string{
		cli + " ip -4":         "100.101.102.103\n",
		cli + " status --json": `{"Self":{"DNSName":"alexs-mbp.tail1234.ts.net."}}`,
		cli + " debug prefs":   `{"RunSSH":true}`,
	}}
	got := Tailscale(f.env())
	if got != (TailscaleInfo{IP: "100.101.102.103", DNSName: "alexs-mbp.tail1234.ts.net", SSH: true}) {
		t.Fatalf("got %+v", got)
	}
	if got := Tailscale((&fake{}).env()); got != (TailscaleInfo{}) {
		t.Fatalf("missing CLI must be fine, got %+v", got)
	}
}

func TestLocalHostNameAndHostKeys(t *testing.T) {
	f := &fake{runs: map[string]string{"scutil --get LocalHostName": "Alexs-MacBook-Pro\n"}, files: map[string]string{
		"/etc/ssh/ssh_host_rsa_key.pub":     "ssh-rsa AAAAB3rsa root@mac\n",
		"/etc/ssh/ssh_host_ed25519_key.pub": "ssh-ed25519 AAAAC3ed root@mac\n",
		"/etc/ssh/ssh_host_ecdsa_key.pub":   "ecdsa-sha2-nistp256 AAAAE2ec root@mac\n",
	}}
	if got := LocalHostName(f.env()); got != "Alexs-MacBook-Pro" {
		t.Fatalf("got %q", got)
	}
	want := []string{"ecdsa-sha2-nistp256 AAAAE2ec", "ssh-ed25519 AAAAC3ed", "ssh-rsa AAAAB3rsa"}
	if got := HostKeys(f.env()); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}
