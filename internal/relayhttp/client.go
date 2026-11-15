// Package relayhttp talks to the relay's HTTP API from the host (pairing v2, protocol/README.md).
package relayhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrTooMany  = errors.New("too many tries from this network; wait 10 minutes")
	ErrWaiting  = errors.New("waiting for the iPhone")
	ErrExpired  = errors.New("this code has expired")
	ErrRejected = errors.New("pairing was cancelled on this Mac")
	ErrDeclined = errors.New("your iPhone didn't accept")
	ErrConflict = errors.New("the relay refused this step")
	ErrNotFound = errors.New("not found")
	// ErrUnauthorized: the relay no longer accepts this Mac's host id and secret.
	ErrUnauthorized = errors.New("this Mac's link to Wrangle is no longer valid")
)

type Auth struct{ HostID, HostSecret string }

func (a Auth) header() string { return "Bearer " + a.HostID + "." + a.HostSecret }

type Client struct {
	URL  string
	HTTP *http.Client // nil = http.DefaultClient
}

type OfferRequest struct {
	HostName      string `json:"hostName"`
	HelperVersion string `json:"helperVersion"`
	HostKeyCommit string `json:"hostKeyCommit"`
	TokenHash     string `json:"tokenHash"`
}

type OfferResult struct {
	OfferID    string `json:"offerId"`
	Code       string `json:"code"`
	HostID     string `json:"hostId"`
	HostSecret string `json:"hostSecret"` // empty when the offer reused this Mac's host
	ExpiresAt  int64  `json:"expiresAt"`
}

type KeyResult struct {
	AppPublicKey string `json:"appPublicKey"`
	DeviceID     string `json:"deviceId"`
	DeviceName   string `json:"deviceName"`
	Path         string `json:"path"` // "qr" or "code"
	MAC          string `json:"mac"`  // QR path only
}

func (c Client) do(ctx context.Context, method, path string, auth *Auth, body any) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		r.Header.Set("content-type", "application/json")
	}
	if auth != nil {
		r.Header.Set("Authorization", auth.header())
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	return res.StatusCode, data, nil
}

func statusErr(s int) error {
	switch s {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	case http.StatusGone:
		return ErrExpired
	case http.StatusTooManyRequests:
		return ErrTooMany
	}
	return fmt.Errorf("relay returned %d", s)
}

func (c Client) Offer(ctx context.Context, auth *Auth, req OfferRequest) (OfferResult, error) {
	var out OfferResult
	s, data, err := c.do(ctx, http.MethodPost, "/v1/pair/offer", auth, req)
	if err != nil {
		return out, err
	}
	if s != http.StatusCreated {
		return out, statusErr(s)
	}
	return out, json.Unmarshal(data, &out)
}

func (c Client) PairKey(ctx context.Context, a Auth) (KeyResult, error) {
	var out KeyResult
	s, data, err := c.do(ctx, http.MethodGet, "/v1/pair/key", &a, nil)
	if err != nil {
		return out, err
	}
	switch s {
	case http.StatusOK:
		return out, json.Unmarshal(data, &out)
	case http.StatusAccepted:
		return out, ErrWaiting
	case http.StatusConflict:
		var st struct{ Status string }
		_ = json.Unmarshal(data, &st)
		if st.Status == "declined" {
			return out, ErrDeclined
		}
		return out, ErrRejected
	}
	return out, statusErr(s)
}

func (c Client) HostKey(ctx context.Context, a Auth, hostPublicKey string) error {
	s, data, err := c.do(ctx, http.MethodPost, "/v1/pair/host-key", &a, map[string]string{"hostPublicKey": hostPublicKey})
	switch {
	case err != nil:
		return err
	case s == http.StatusNoContent:
		return nil
	case s == http.StatusBadRequest:
		return errors.New("the relay refused this computer's key")
	case s == http.StatusConflict && strings.Contains(string(data), `"expired"`):
		return ErrExpired // the offer ran out before this Mac keyed it
	}
	return statusErr(s)
}

func (c Client) Confirm(ctx context.Context, a Auth) error {
	s, data, err := c.do(ctx, http.MethodPost, "/v1/pair/confirm", &a, map[string]string{})
	if err != nil {
		return err
	}
	if s == http.StatusNoContent {
		return nil
	}
	if s == http.StatusConflict && strings.Contains(string(data), `"declined"`) {
		return ErrDeclined
	}
	return statusErr(s)
}

func (c Client) Reject(ctx context.Context, a Auth) error {
	s, _, err := c.do(ctx, http.MethodPost, "/v1/pair/reject", &a, map[string]string{})
	if err != nil {
		return err
	}
	if s != http.StatusNoContent {
		return statusErr(s)
	}
	return nil
}

// RemoveLink unlinks a phone from this Mac. A link that is already gone counts as removed.
func (c Client) RemoveLink(ctx context.Context, a Auth, deviceID string) error {
	s, _, err := c.do(ctx, http.MethodDelete, "/v1/pair/link/"+url.PathEscape(deviceID), &a, nil)
	if err != nil {
		return err
	}
	if s != http.StatusNoContent && s != http.StatusNotFound {
		return statusErr(s)
	}
	return nil
}

func (c Client) Health(ctx context.Context) error {
	s, _, err := c.do(ctx, http.MethodGet, "/v1/health", nil, nil)
	if err != nil {
		return err
	}
	if s != http.StatusOK {
		return statusErr(s)
	}
	return nil
}
