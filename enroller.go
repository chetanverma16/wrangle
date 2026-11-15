package main

import (
	"errors"
	"os/user"
	"sync"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/proto"
	"github.com/chetanverma16/wrangle/internal/setup"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

// liveEnroller writes the phone's key to authorized_keys and answers with how to reach this Mac.
type liveEnroller struct {
	Home, KeysPath string
	Env            setup.Env
	User           func() string
}

// enrollMu serialises this process's authorized_keys and config.json edits (enrolments and unlinks run on their own
// goroutines); config.Lock does the same across processes (`wrangle setup`, `wrangle remove-device`).
var enrollMu sync.Mutex

// locked runs fn holding both locks.
func locked(home string, fn func() error) error {
	enrollMu.Lock()
	defer enrollMu.Unlock()
	unlock, err := config.Lock(home)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func (e liveEnroller) Enroll(deviceID string, req proto.SSHEnroll) (proto.SSHReply, error) {
	var cfg config.Config
	err := locked(e.Home, func() error {
		var err error
		if cfg, err = config.Load(e.Home); err != nil {
			return err
		}
		known := false
		for _, d := range cfg.Devices {
			known = known || d.DeviceID == deviceID
		}
		if !known {
			return errors.New("this phone is not paired with this Mac")
		}
		return sshkeys.Add(e.KeysPath, req.SSHPublicKey, deviceID, req.DeviceName)
	})
	if err != nil {
		return proto.SSHReply{}, err
	}
	ifaces, _ := e.Env.Interfaces()
	ts := setup.Tailscale(e.Env)
	return proto.SSHReply{
		User: e.User(), Port: 22,
		Addresses: setup.Addresses(setup.LocalHostName(e.Env), setup.LANIPv4(ifaces), ts.IP, ts.DNSName),
		HostKeys:  setup.HostKeys(e.Env), TmuxPath: cfg.TmuxPath,
	}, nil
}

func (e liveEnroller) Unenroll(deviceID string) error {
	return locked(e.Home, func() error {
		if _, err := sshkeys.Remove(e.KeysPath, deviceID); err != nil {
			return err
		}
		cfg, err := config.Load(e.Home)
		if err != nil {
			return err
		}
		if cfg.RemoveDevice(deviceID) {
			return config.Save(e.Home, cfg)
		}
		return nil
	})
}
