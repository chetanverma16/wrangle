package setup

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func LiveEnv() Env {
	return Env{
		LookPath: exec.LookPath,
		Run: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).CombinedOutput()
			return string(out), err
		},
		DialBanner: func(addr string, timeout time.Duration) (string, error) {
			c, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return "", err
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(timeout))
			buf := make([]byte, 64)
			n, err := c.Read(buf)
			if n == 0 {
				return "", err
			}
			return string(buf[:n]), nil
		},
		OpenURL:    func(u string) error { return exec.Command("open", u).Run() },
		Sleep:      time.Sleep,
		Interfaces: liveInterfaces,
		ReadFile:   os.ReadFile,
		Glob:       filepath.Glob,
		In:         os.Stdin,
		Out:        os.Stdout,
	}
}

func liveInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, i := range ifs {
		x := Iface{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				x.IPv4 = append(x.IPv4, n.IP.String())
			}
		}
		out = append(out, x)
	}
	return out, nil
}
