package proto

import (
	"crypto/sha256"
	_ "embed"
	"strings"
)

//go:embed sas-words.txt
var wordsFile string

// Words is protocol/sas-words.txt (copied next to this file by `go generate`).
var Words = strings.Fields(wordsFile)

//go:generate cp ../../../protocol/sas-words.txt sas-words.txt

// SAS returns the 4-word short authentication string for an (app, host) public-key pair.
func SAS(appPublic, hostPublic []byte) []string {
	h := sha256.New()
	h.Write([]byte("wrangle/v1/sas"))
	h.Write(appPublic)
	h.Write(hostPublic)
	d := h.Sum(nil)
	bits := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
	out := make([]string, 4)
	for i := 0; i < 4; i++ {
		out[i] = Words[(bits>>(18-6*uint(i)))&0x3F]
	}
	return out
}
