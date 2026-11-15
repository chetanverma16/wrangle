package config

import (
	"os"
	"path/filepath"
	"syscall"
)

// Lock takes the enrolment lock, <home>/enroll.lock (home honours WRANGLE_HOME via Home()). Every read-modify-write
// of ~/.ssh/authorized_keys and config.json holds it, so `wrangle serve`, `wrangle setup`, `wrangle remove-device`
// and `wrangle config` (separate processes) never lose each other's edits. It blocks until the lock is free.
// flock isn't reentrant across opens: take it once per edit, at one layer, and never across a network call.
func Lock(home string) (unlock func(), err error) {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(home, "enroll.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
