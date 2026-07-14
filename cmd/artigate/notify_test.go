package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestValidateWebhookURL(t *testing.T) {
	cases := []struct {
		raw string
		ok  bool
	}{
		{"", true},
		{"https://hooks.example.com/notify", true},
		{"http://127.0.0.1:9000/x", true},
		{"ftp://example.com", false},
		{"not a url", false},
		{"https://", false},
	}
	for _, c := range cases {
		err := validateWebhookURL(c.raw)
		if (err == nil) != c.ok {
			t.Errorf("validateWebhookURL(%q) err=%v, want ok=%v", c.raw, err, c.ok)
		}
	}
}

func TestNilNotifierIsNoOp(_ *testing.T) {
	var n *webhookNotifier
	// Must not panic and must do nothing.
	n.notify("schedule_failed", map[string]any{"stream": "go"})
}

func TestBuildPayload(t *testing.T) {
	n := &webhookNotifier{side: "high"}
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	b := n.buildPayload("gap_detected", map[string]any{
		"stream": "python", "blocking_sequence": 42,
		// A reserved key from the caller must not override the envelope.
		"side": "attacker",
	}, at)

	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if doc["event"] != "gap_detected" {
		t.Errorf("event = %v", doc["event"])
	}
	if doc["side"] != "high" {
		t.Errorf("reserved side was overridden: %v", doc["side"])
	}
	if doc["time"] != "2026-07-14T12:00:00Z" {
		t.Errorf("time = %v", doc["time"])
	}
	if doc["stream"] != "python" {
		t.Errorf("stream = %v", doc["stream"])
	}
	if doc["blocking_sequence"].(float64) != 42 {
		t.Errorf("blocking_sequence = %v", doc["blocking_sequence"])
	}
}

func TestBuildPayloadFieldCap(t *testing.T) {
	n := &webhookNotifier{side: "low"}
	fields := map[string]any{}
	for i := 0; i < maxWebhookFields*2; i++ {
		fields[strconv.Itoa(i)] = i
	}
	b := n.buildPayload("schedule_failed", fields, time.Unix(0, 0).UTC())
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	// 3 reserved keys + at most maxWebhookFields caller keys.
	if len(doc) > 3+maxWebhookFields {
		t.Errorf("payload carried %d keys, want <= %d", len(doc), 3+maxWebhookFields)
	}
}

func TestNotifyDelivers(t *testing.T) {
	got := make(chan map[string]any, 1)
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		got <- doc
	}))
	defer srv.Close()

	n := &webhookNotifier{url: srv.URL, token: "secret", side: "high", client: srv.Client()}
	n.notify("bundle_rejected", map[string]any{"stream": "npm", "bundle": "npm-bundle-000003"})

	select {
	case doc := <-got:
		if doc["event"] != "bundle_rejected" || doc["stream"] != "npm" {
			t.Errorf("receiver got unexpected doc: %+v", doc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook was not delivered within 5s")
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("Authorization header = %q, want bearer token", gotAuth)
	}
}

func TestNotifyReceiverErrorDoesNotPanic(_ *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	n := &webhookNotifier{url: srv.URL, side: "low", client: srv.Client()}
	// deliver runs inline here so a panic would surface in the test.
	n.deliver("schedule_failed", []byte(`{"event":"schedule_failed"}`))
}
