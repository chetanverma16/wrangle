package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The child half of TestLockExcludesAnotherProcess: holds the lock, says so, then lets go after a pause.
func TestLockChildProcess(t *testing.T) {
	home := os.Getenv("WRANGLE_LOCK_CHILD_HOME")
	if home == "" {
		t.Skip("only runs as the child process")
	}
	unlock, err := Lock(home)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(home, "child-locked"), nil, 0o600)
	time.Sleep(400 * time.Millisecond)
	_ = os.WriteFile(filepath.Join(home, "child-released"), nil, 0o600)
	unlock()
}

func TestLockExcludesAnotherProcess(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockChildProcess$")
	cmd.Env = append(os.Environ(), "WRANGLE_LOCK_CHILD_HOME="+home)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }()
	for i := 0; ; i++ {
		if _, err := os.Stat(filepath.Join(home, "child-locked")); err == nil {
			break
		}
		if i == 500 {
			t.Fatal("the child never took the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	unlock, err := Lock(home)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := os.Stat(filepath.Join(home, "child-released")); err != nil {
		t.Fatal("got the lock while another process held it")
	}
	st, err := os.Stat(filepath.Join(home, "enroll.lock"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v %v", st, err)
	}
}

func TestLockExcludesAnotherLockerInTheSameProcess(t *testing.T) {
	home := filepath.Join(t.TempDir(), "new-home") // created on demand
	unlock, err := Lock(home)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		u, err := Lock(home)
		if err == nil {
			u()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a second locker got in")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the second locker never got the lock")
	}
}
