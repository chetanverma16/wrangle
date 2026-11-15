package relayhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type seen struct {
	method, path, auth string
	body               map[string]any
}

func server(t *testing.T, status int, reply string, got *seen) Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return Client{URL: srv.URL}
}

var a = Auth{HostID: "host_1", HostSecret: "sec"}

func TestOfferSendsBodyAndOptionalAuth(t *testing.T) {
	var got seen
	c := server(t, 201, `{"offerId":"off_1","code":"7KQ4MZ","hostId":"host_1","hostSecret":"s","expiresAt":5}`, &got)
	req := OfferRequest{HostName: "mac", HelperVersion: "0.2.0", HostKeyCommit: "C", TokenHash: "T"}
	res, err := c.Offer(context.Background(), nil, req)
	if err != nil || res != (OfferResult{OfferID: "off_1", Code: "7KQ4MZ", HostID: "host_1", HostSecret: "s", ExpiresAt: 5}) {
		t.Fatalf("%+v %v", res, err)
	}
	if got.method != "POST" || got.path != "/v1/pair/offer" || got.auth != "" || got.body["tokenHash"] != "T" || got.body["hostKeyCommit"] != "C" {
		t.Fatalf("%+v", got)
	}
	if _, err := c.Offer(context.Background(), &a, req); err != nil || got.auth != "Bearer host_1.sec" {
		t.Fatalf("auth %q %v", got.auth, err)
	}
}

func TestOfferMapsTooMany(t *testing.T) {
	var got seen
	if _, err := server(t, 429, ``, &got).Offer(context.Background(), nil, OfferRequest{}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("got %v", err)
	}
}

func TestPairKeyStates(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{202, `{"status":"waiting"}`, ErrWaiting}, {410, `{"status":"expired"}`, ErrExpired},
		{409, `{"status":"declined"}`, ErrDeclined}, {409, `{"status":"rejected"}`, ErrRejected},
	}
	for _, tc := range cases {
		var got seen
		if _, err := server(t, tc.status, tc.body, &got).PairKey(context.Background(), a); !errors.Is(err, tc.want) {
			t.Fatalf("%d %s: got %v", tc.status, tc.body, err)
		}
	}
	var got seen
	k, err := server(t, 200, `{"appPublicKey":"APP","deviceId":"dev_1","deviceName":"iPhone","path":"qr","mac":"M"}`, &got).PairKey(context.Background(), a)
	if err != nil || k != (KeyResult{AppPublicKey: "APP", DeviceID: "dev_1", DeviceName: "iPhone", Path: "qr", MAC: "M"}) || got.auth != "Bearer host_1.sec" {
		t.Fatalf("%+v %v %q", k, err, got.auth)
	}
}

func TestHostKeyConfirmRejectRemoveLink(t *testing.T) {
	var got seen
	if err := server(t, 204, ``, &got).HostKey(context.Background(), a, "PUB"); err != nil || got.path != "/v1/pair/host-key" || got.body["hostPublicKey"] != "PUB" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := server(t, 409, ``, &got).HostKey(context.Background(), a, "PUB"); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v", err)
	}
	if err := server(t, 204, ``, &got).Confirm(context.Background(), a); err != nil || got.path != "/v1/pair/confirm" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := server(t, 409, `{"error":"declined"}`, &got).Confirm(context.Background(), a); !errors.Is(err, ErrDeclined) {
		t.Fatalf("got %v", err)
	}
	if err := server(t, 204, ``, &got).Reject(context.Background(), a); err != nil || got.path != "/v1/pair/reject" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := server(t, 404, ``, &got).RemoveLink(context.Background(), a, "dev_1"); err != nil || got.method != "DELETE" || got.path != "/v1/pair/link/dev_1" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := server(t, 200, `{"ok":true}`, &got).Health(context.Background()); err != nil || got.path != "/v1/health" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestHostKeyExpiredAndRelayStatuses(t *testing.T) {
	var got seen
	if err := server(t, 409, `{"error":"expired"}`, &got).HostKey(context.Background(), a, "PUB"); !errors.Is(err, ErrExpired) {
		t.Fatalf("host-key expired: got %v", err)
	}
	if err := server(t, 400, `{"error":"commit_mismatch"}`, &got).HostKey(context.Background(), a, "PUB"); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("host-key 400: got %v", err)
	}
	if _, err := server(t, 404, `{"error":"not_found"}`, &got).PairKey(context.Background(), a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key 404: got %v", err)
	}
	if err := server(t, 409, `{"error":"conflict"}`, &got).Confirm(context.Background(), a); !errors.Is(err, ErrConflict) {
		t.Fatalf("confirm conflict: got %v", err)
	}
}

func TestOfferMapsUnauthorized(t *testing.T) {
	var got seen
	if _, err := server(t, 401, `{"error":"unauthorized"}`, &got).Offer(context.Background(), &a, OfferRequest{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("got %v", err)
	}
}
