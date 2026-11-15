// Package proto implements the Wrangle wire protocol v1 (see protocol/README.md).
package proto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type KeyPair struct{ Private, Public []byte }

type Envelope struct {
	V int    `json:"v"`
	N string `json:"n"`
	C string `json:"c"`
}

func B64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func UnB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func GenerateKeyPair() (KeyPair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{k.Bytes(), k.PublicKey().Bytes()}, nil
}

func KeyPairFromPrivate(priv []byte) (KeyPair, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{k.Bytes(), k.PublicKey().Bytes()}, nil
}

// DeriveKey returns the 32-byte envelope key. Both sides pass the same (appPublic, hostPublic) order.
func DeriveKey(myPrivate, peerPublic, appPublic, hostPublic []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(myPrivate)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	info := append(append([]byte("envelope"), appPublic...), hostPublic...)
	return hkdf.Key(sha256.New, shared, []byte("wrangle/v1"), string(info), 32)
}

func Seal(key, plaintext []byte, aad string, nonce []byte) (Envelope, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return Envelope{}, err
	}
	if nonce == nil {
		nonce = make([]byte, chacha20poly1305.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return Envelope{}, err
		}
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return Envelope{}, errors.New("nonce must be 12 bytes")
	}
	return Envelope{V: 1, N: B64(nonce), C: B64(aead.Seal(nil, nonce, plaintext, []byte(aad)))}, nil
}

func Open(key []byte, env Envelope, aad string) ([]byte, error) {
	if env.V != 1 {
		return nil, errors.New("unsupported envelope version")
	}
	nonce, err := UnB64(env.N)
	if err != nil {
		return nil, err
	}
	ct, err := UnB64(env.C)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, errors.New("nonce must be 12 bytes")
	}
	if len(ct) < chacha20poly1305.Overhead {
		return nil, errors.New("ciphertext too short")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, []byte(aad))
}

// Commit is B64(SHA-256("wrangle/v1/commit" ‖ appPublic)), sent before the host's key is known.
func Commit(appPublic []byte) string {
	h := sha256.New()
	h.Write([]byte("wrangle/v1/commit"))
	h.Write(appPublic)
	return B64(h.Sum(nil))
}

// VerifyCommit checks a commitment in constant time. A malformed commit returns false.
func VerifyCommit(appPublic []byte, commit string) bool {
	got, err := UnB64(commit)
	if err != nil {
		return false
	}
	want, _ := UnB64(Commit(appPublic))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// DecisionAAD is the AAD for a sealed approval decision.
func DecisionAAD(hostID, eventID string) string { return hostID + "|" + eventID + "|decision" }
