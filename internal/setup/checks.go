// Package setup is `wrangle setup` and `wrangle doctor`: macOS checks, the pairing offer and the QR.
package setup

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chetanverma16/wrangle/internal/proto"
)

// Env is everything setup and doctor touch on this Mac. LiveEnv is the real one; tests pass fakes.
type Env struct {
	LookPath   func(file string) (string, error)
	Run        func(name string, args ...string) (string, error) // combined output
	DialBanner func(addr string, timeout time.Duration) (string, error)
	OpenURL    func(url string) error
	Sleep      func(time.Duration)
	Interfaces func() ([]Iface, error)
	ReadFile   func(path string) ([]byte, error)
	Glob       func(pattern string) ([]string, error)
	In         io.Reader
	Out        io.Writer
}

type Iface struct {
	Name         string
	Up, Loopback bool
	IPv4         []string
}

const (
	RemoteLoginURL = "x-apple.systempreferences:com.apple.Sharing-Settings.extension"
	PollEvery      = 2 * time.Second
	PollLimit      = 5 * time.Minute
	tailscaleApp   = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
)

// launchd's PATH has no Homebrew, so absolute locations are tried after PATH.
var tmuxFallbacks = []string{"/opt/homebrew/bin/tmux", "/usr/local/bin/tmux"}
var brewFallbacks = []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"}

func find(e Env, name string, fallbacks []string) (string, bool) {
	if p, err := e.LookPath(name); err == nil && filepath.IsAbs(p) {
		return p, true
	}
	for _, p := range fallbacks {
		if _, err := e.LookPath(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// FindTmux returns tmux's absolute path; every tmux call and the phone use this path, never the login PATH.
func FindTmux(e Env) (string, bool) { return find(e, "tmux", tmuxFallbacks) }
func FindBrew(e Env) (string, bool) { return find(e, "brew", brewFallbacks) }

// RemoteLoginOn checks Remote Login without sudo: something on 127.0.0.1:22 answers with an SSH banner.
func RemoteLoginOn(e Env) bool {
	b, err := e.DialBanner("127.0.0.1:22", time.Second)
	return err == nil && strings.HasPrefix(b, "SSH-")
}

// WaitRemoteLogin polls every `every` until Remote Login is on or `limit` has passed.
func WaitRemoteLogin(e Env, every, limit time.Duration) bool {
	return WaitRemoteLoginCtx(context.Background(), e, every, limit)
}

// WaitRemoteLoginCtx is WaitRemoteLogin that also gives up when ctx is cancelled (Ctrl-C).
func WaitRemoteLoginCtx(ctx context.Context, e Env, every, limit time.Duration) bool {
	for waited := time.Duration(0); ; waited += every {
		if RemoteLoginOn(e) {
			return true
		}
		if waited >= limit || ctx.Err() != nil {
			return false
		}
		e.Sleep(every)
	}
}

// LANIPv4 is the first private IPv4 on an up en* interface (not Tailscale's 100.64/10, not link-local).
func LANIPv4(ifaces []Iface) string {
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	_, linkLocal, _ := net.ParseCIDR("169.254.0.0/16")
	for _, i := range ifaces {
		if !i.Up || i.Loopback || !strings.HasPrefix(i.Name, "en") {
			continue
		}
		for _, a := range i.IPv4 {
			ip := net.ParseIP(a).To4()
			if ip == nil || cgnat.Contains(ip) || linkLocal.Contains(ip) {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

func LocalHostName(e Env) string {
	out, err := e.Run("scutil", "--get", "LocalHostName")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

type TailscaleInfo struct {
	IP, DNSName string
	SSH         bool // Tailscale SSH is on: it intercepts port 22 on the tailnet address
}

// Tailscale reads the Tailscale CLI if present. A missing CLI, or one that isn't logged in, gives the zero value.
func Tailscale(e Env) TailscaleInfo {
	cli, ok := find(e, "tailscale", []string{tailscaleApp})
	if !ok {
		return TailscaleInfo{}
	}
	var t TailscaleInfo
	if out, err := e.Run(cli, "ip", "-4"); err == nil {
		if ip := net.ParseIP(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])); ip != nil && ip.To4() != nil {
			t.IP = ip.String()
		}
	}
	if t.IP == "" {
		return TailscaleInfo{}
	}
	if out, err := e.Run(cli, "status", "--json"); err == nil {
		var s struct{ Self struct{ DNSName string } }
		if json.Unmarshal([]byte(out), &s) == nil {
			t.DNSName = strings.TrimSuffix(s.Self.DNSName, ".")
		}
	}
	if out, err := e.Run(cli, "debug", "prefs"); err == nil {
		var p struct{ RunSSH bool }
		if json.Unmarshal([]byte(out), &p) == nil {
			t.SSH = p.RunSSH
		}
	}
	return t
}

// Addresses lists the ways to reach this Mac in the order the phone tries them: LAN name, LAN IP, Tailscale.
func Addresses(localHostName, lanIP, tsIP, tsDNS string) []proto.Address {
	var out []proto.Address
	add := func(kind, host string) {
		if host != "" {
			out = append(out, proto.Address{Kind: kind, Host: host})
		}
	}
	if localHostName != "" {
		add("lan", localHostName+".local")
	}
	add("lan", lanIP)
	add("tailscale", tsIP)
	add("tailscale", tsDNS)
	return out
}

// HostKeys returns "<type> <base64>" for each /etc/ssh/ssh_host_*_key.pub (world-readable), sorted.
func HostKeys(e Env) []string {
	paths, _ := e.Glob("/etc/ssh/ssh_host_*_key.pub")
	sort.Strings(paths)
	var keys []string
	for _, p := range paths {
		data, err := e.ReadFile(p)
		if err != nil {
			continue
		}
		f := strings.Fields(string(data))
		if len(f) >= 2 && (strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-")) {
			keys = append(keys, f[0]+" "+f[1])
		}
	}
	sort.Strings(keys)
	return keys
}
