package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// QRMaxLen is the longest QR payload accepted; the real one is about 220 characters.
const QRMaxLen = 512

var offerIDRE = regexp.MustCompile(`^off_[A-Za-z0-9_-]{1,40}$`)

// TokenHash is what the relay stores for the claim token t: B64(SHA-256(t)).
func TokenHash(t []byte) string { s := sha256.Sum256(t); return B64(s[:]) }

// HostKeyCommit is B64(SHA-256("wrangle/v1/commit" ‖ hostPublic)), sent in the offer before the key itself.
func HostKeyCommit(hostPublic []byte) string { return Commit(hostPublic) }

// QRMAC proves the app key came from a phone that saw the QR: HMAC-SHA256(k, "wrangle/v1/qr" ‖ appPub ‖ hostPub).
func QRMAC(k, appPublic, hostPublic []byte) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte("wrangle/v1/qr"))
	m.Write(appPublic)
	m.Write(hostPublic)
	return m.Sum(nil)
}

// VerifyQRMAC compares in constant time. A malformed mac returns false.
func VerifyQRMAC(k, appPublic, hostPublic []byte, mac string) bool {
	got, err := UnB64(mac)
	if err != nil {
		return false
	}
	return hmac.Equal(got, QRMAC(k, appPublic, hostPublic))
}

// QR is the pairing offer shown on the Mac. T and K never reach the relay in clear (the relay sees only TokenHash(T)).
type QR struct {
	Relay, OfferID, Name string
	T, K, HostPublic     []byte
}

func (q QR) URL() string {
	return "wrangle://pair?v=1&r=" + B64([]byte(q.Relay)) + "&o=" + q.OfferID + "&t=" + B64(q.T) + "&k=" + B64(q.K) +
		"&h=" + B64(q.HostPublic) + "&n=" + B64([]byte(q.Name))
}

var errBadQR = errors.New("not a Wrangle pairing code")

func ParseQR(s string) (QR, error) {
	if len(s) > QRMaxLen || !strings.HasPrefix(s, "wrangle://pair?") {
		return QR{}, errBadQR
	}
	v, err := url.ParseQuery(strings.TrimPrefix(s, "wrangle://pair?"))
	if err != nil || v.Get("v") != "1" || !offerIDRE.MatchString(v.Get("o")) {
		return QR{}, errBadQR
	}
	dec := func(key string, n int) ([]byte, bool) {
		b, err := UnB64(v.Get(key))
		return b, err == nil && (n == 0 || len(b) == n) && len(b) > 0
	}
	relay, ok1 := dec("r", 0)
	t, ok2 := dec("t", 16)
	k, ok3 := dec("k", 16)
	h, ok4 := dec("h", 32)
	name, ok5 := dec("n", 0)
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || len(name) > 64 {
		return QR{}, errBadQR
	}
	return QR{Relay: string(relay), OfferID: v.Get("o"), Name: string(name), T: t, K: k, HostPublic: h}, nil
}

// FormatCode shows a 6-character code as "7KQ-4MZ".
func FormatCode(code string) string {
	if len(code) != 6 {
		return code
	}
	return code[:3] + "-" + code[3:]
}
