package main

import (
	"fmt"
	"os"

	"github.com/chetanverma16/wrangle/internal/config"
)

// runConfig handles `wrangle config keep-awake on|off`. It works before pairing too (the file is created).
func runConfig(args []string) int {
	if len(args) != 2 || args[0] != "keep-awake" || (args[1] != "on" && args[1] != "off") {
		fmt.Fprintln(os.Stderr, "usage: wrangle config keep-awake on|off")
		return 2
	}
	home := config.Home()
	unlock, err := config.Lock(home) // setup and serve edit the same file
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not lock config:", err)
		return 1
	}
	defer unlock()
	c, err := config.Load(home)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "could not read config:", err)
		return 1
	}
	c.KeepAwakeOff = args[1] == "off"
	if err := config.Save(home, c); err != nil {
		fmt.Fprintln(os.Stderr, "could not save config:", err)
		return 1
	}
	fmt.Printf("Keep awake is %s. The helper picks this up within a few seconds.\n", args[1])
	return 0
}
