package proto

import (
	"strings"
	"testing"
)

func qrFixture() QR {
	return QR{Relay: "https://api.wrangle.stackframes.dev", OfferID: "off_vector", Name: "Alex's Mac",
		T: fixed(0x10)[:16], K: fixed(0x20)[:16], HostPublic: fixed(0x41)}
}

func TestQRURLRoundTripsAndFitsTheLimit(t *testing.T) {
	q := qrFixture()
	u := q.URL()
	if !strings.HasPrefix(u, "wrangle://pair?v=1&r=") || len(u) > QRMaxLen || len(u) > 240 {
		t.Fatalf("url %q (%d chars)", u, len(u))
	}
	got, err := ParseQR(u)
	if err != nil {
		t.Fatal(err)
	}
	if got.Relay != q.Relay || got.OfferID != q.OfferID || got.Name != q.Name || string(got.T) != string(q.T) ||
		string(got.K) != string(q.K) || string(got.HostPublic) != string(q.HostPublic) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseQRRefusesBadInput(t *testing.T) {
	good := qrFixture().URL()
	for name, s := range map[string]string{
		"scheme":    strings.Replace(good, "wrangle://", "https://", 1),
		"version":   strings.Replace(good, "v=1", "v=2", 1),
		"no token":  strings.Replace(good, "&t=", "&x=", 1),
		"short k":   strings.Replace(good, "&k="+B64(qrFixture().K), "&k=AAAA", 1),
		"bad offer": strings.Replace(good, "o=off_vector", "o=../x", 1),
		"oversized": good + "&pad=" + strings.Repeat("a", QRMaxLen),
	} {
		if _, err := ParseQR(s); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

func TestQRMACBindsBothKeys(t *testing.T) {
	k, app, host := fixed(0x20)[:16], fixed(0x01), fixed(0x41)
	mac := B64(QRMAC(k, app, host))
	if !VerifyQRMAC(k, app, host, mac) {
		t.Fatal("valid mac rejected")
	}
	if VerifyQRMAC(k, fixed(0x02), host, mac) || VerifyQRMAC(k, app, fixed(0x42), mac) || VerifyQRMAC(fixed(0x21)[:16], app, host, mac) {
		t.Fatal("mac must bind k, app key and host key")
	}
	if VerifyQRMAC(k, app, host, "not base64!") {
		t.Fatal("malformed mac must fail")
	}
}

func TestTokenHashAndCode(t *testing.T) {
	if len(TokenHash(fixed(0x10)[:16])) != 43 {
		t.Fatal("token hash is 32 bytes base64url")
	}
	if HostKeyCommit(fixed(0x41)) != Commit(fixed(0x41)) {
		t.Fatal("host commit uses the commit prefix")
	}
	if FormatCode("7KQ4MZ") != "7KQ-4MZ" || FormatCode("abc") != "abc" {
		t.Fatal(FormatCode("7KQ4MZ"))
	}
}
