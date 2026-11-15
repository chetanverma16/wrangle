package main

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/proto"
	"github.com/chetanverma16/wrangle/internal/setup"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

func quietEnv() setup.Env {
	return setup.Env{
		LookPath: func(string) (string, error) { return "", errors.New("no") },
		Run: func(name string, args ...string) (string, error) {
			if name == "scutil" {
				return "Mac\n", nil
			}
			return "", errors.New("no")
		},
		DialBanner: func(string, time.Duration) (string, error) { return "", errors.New("no") },
		OpenURL:    func(string) error { return nil },
		Sleep:      func(time.Duration) {},
		Interfaces: func() ([]setup.Iface, error) {
			return []setup.Iface{{Name: "en0", Up: true, IPv4: []string{"192.168.1.20"}}}, nil
		},
		ReadFile: func(p string) ([]byte, error) { return []byte("ssh-ed25519 AAAAC3host root@mac\n"), nil },
		Glob:     func(string) ([]string, error) { return []string{"/etc/ssh/ssh_host_ed25519_key.pub"}, nil },
		In:       strings.NewReader(""), Out: io.Discard,
	}
}

const phoneKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY= wrangle@iPhone"

func TestLiveEnrollerAddsTheKeyAndDescribesThisMac(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "w")
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s", TmuxPath: "/opt/homebrew/bin/tmux",
		Devices: []config.Device{{DeviceID: "dev_1", Name: "iPhone"}}})
	e := liveEnroller{Home: home, KeysPath: filepath.Join(dir, ".ssh", "authorized_keys"), Env: quietEnv(), User: func() string { return "alex" }}
	reply, err := e.Enroll("dev_1", proto.SSHEnroll{SSHPublicKey: phoneKey, DeviceName: "iPhone"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.User != "alex" || reply.Port != 22 || reply.TmuxPath != "/opt/homebrew/bin/tmux" ||
		len(reply.Addresses) != 2 || reply.Addresses[0].Host != "Mac.local" || reply.HostKeys[0] != "ssh-ed25519 AAAAC3host" {
		t.Fatalf("%+v", reply)
	}
	if !sshkeys.Has(e.KeysPath, "dev_1") {
		t.Fatal("key not written")
	}
	if _, err := e.Enroll("dev_9", proto.SSHEnroll{SSHPublicKey: phoneKey}); err == nil {
		t.Fatal("a phone that isn't paired with this Mac must be refused")
	}
}

func TestLiveEnrollerUnenrollRemovesKeyAndDevice(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "w")
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s", Devices: []config.Device{{DeviceID: "dev_1"}, {DeviceID: "dev_2"}}})
	e := liveEnroller{Home: home, KeysPath: filepath.Join(dir, "authorized_keys"), Env: quietEnv(), User: func() string { return "c" }}
	_ = sshkeys.Add(e.KeysPath, phoneKey, "dev_1", "iPhone")
	if err := e.Unenroll("dev_1"); err != nil {
		t.Fatal(err)
	}
	c, _ := config.Load(home)
	if sshkeys.Has(e.KeysPath, "dev_1") || len(c.Devices) != 1 || c.Devices[0].DeviceID != "dev_2" {
		t.Fatalf("%+v", c.Devices)
	}
	if err := e.Unenroll("dev_1"); err != nil {
		t.Fatalf("unlinking twice must be fine: %v", err)
	}
}

func TestLiveEnrollerSerialisesWrites(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "w")
	var devs []config.Device
	for i := 0; i < 10; i++ {
		devs = append(devs, config.Device{DeviceID: "dev_" + string(rune('a'+i))})
	}
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s", Devices: devs})
	e := liveEnroller{Home: home, KeysPath: filepath.Join(dir, "authorized_keys"), Env: quietEnv(), User: func() string { return "c" }}
	done := make(chan error, 20)
	for _, dv := range devs {
		go func(id string) {
			_, err := e.Enroll(id, proto.SSHEnroll{SSHPublicKey: phoneKey, DeviceName: "p"})
			done <- err
		}(dv.DeviceID)
		go func(id string) { done <- e.Unenroll(id + "_gone") }(dv.DeviceID)
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for _, dv := range devs {
		if !sshkeys.Has(e.KeysPath, dv.DeviceID) {
			t.Fatalf("lost the key of %s: concurrent writes clobbered authorized_keys", dv.DeviceID)
		}
	}
}
