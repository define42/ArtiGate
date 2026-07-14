package main

// Failure webhooks. When ARTIGATE_WEBHOOK_URL is set, ArtiGate POSTs a small
// JSON document to it whenever an operationally significant failure happens: a
// scheduled collect fails on the low side, or the high side rejects a bundle or
// detects a sequencing gap. This is the notification half of the observability
// story (the /metrics endpoint is the polling half): a stalled stream or a
// failing nightly schedule reaches an on-call channel instead of waiting for a
// human to notice a dashboard.
//
// Delivery is best-effort and fire-and-forget: the notifier never blocks the
// import or export path, a slow or unreachable receiver only costs one bounded
// background POST, and a panic in the delivery goroutine is recovered rather
// than allowed to crash the process (the same discipline the watch scheduler
// and diode workers follow).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

// webhookTimeout bounds one delivery attempt end to end (connect + send +
// response). A diode receiver behind a slow link must never pin a goroutine.
const webhookTimeout = 10 * time.Second

// maxWebhookFields caps how many caller-supplied fields a single event carries,
// a defensive bound so a buggy call site can never build an unbounded payload.
const maxWebhookFields = 32

// webhookNotifier posts failure events to a configured HTTP(S) endpoint. A nil
// *webhookNotifier is the "not configured" state and every method is a no-op on
// it, so call sites need no `if n != nil` guard.
type webhookNotifier struct {
	url    string
	token  string
	side   string // "low" or "high", included in every event
	client *http.Client
}

// validateWebhookURL mirrors validateDiodeURL: an empty value disables the
// feature, anything else must be a well-formed http/https URL.
func validateWebhookURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid ARTIGATE_WEBHOOK_URL %q (need an http/https URL)", raw)
	}
	return nil
}

// mustWebhookNotifier builds the notifier for one side from the environment,
// failing fast (like the diode and TLS configuration) on a malformed URL. It
// returns nil when ARTIGATE_WEBHOOK_URL is unset, which disables notifications.
func mustWebhookNotifier(side string) *webhookNotifier {
	raw := strings.TrimSpace(os.Getenv("ARTIGATE_WEBHOOK_URL"))
	must(validateWebhookURL(raw))
	if raw == "" {
		return nil
	}
	return &webhookNotifier{
		url:    raw,
		token:  strings.TrimSpace(os.Getenv("ARTIGATE_WEBHOOK_TOKEN")),
		side:   side,
		client: &http.Client{Timeout: webhookTimeout},
	}
}

// notify delivers one event asynchronously. It returns immediately; the actual
// POST runs on a background goroutine so the caller (an import or a scheduler
// tick) is never blocked by the receiver. On a nil notifier it does nothing.
func (n *webhookNotifier) notify(event string, fields map[string]any) {
	if n == nil {
		return
	}
	payload := n.buildPayload(event, fields, time.Now().UTC())
	go n.deliver(event, payload)
}

// buildPayload renders the event document: the event name, the side, an RFC3339
// timestamp, and the caller's fields (bounded, and never allowed to shadow the
// reserved keys).
func (n *webhookNotifier) buildPayload(event string, fields map[string]any, now time.Time) []byte {
	doc := map[string]any{
		"event": event,
		"side":  n.side,
		"time":  now.Format(time.RFC3339),
	}
	reserved := map[string]bool{"event": true, "side": true, "time": true}
	added := 0
	for k, v := range fields {
		if reserved[k] || added >= maxWebhookFields {
			continue
		}
		doc[k] = v
		added++
	}
	b, err := json.Marshal(doc)
	if err != nil {
		// A field the caller passed was not JSON-serializable; fall back to the
		// reserved envelope so the event is still delivered.
		b, _ = json.Marshal(map[string]any{"event": event, "side": n.side, "time": now.Format(time.RFC3339)})
	}
	return b
}

// deliver performs one bounded POST, recovering any panic so a delivery failure
// can never take down the goroutine's owner. Failures are logged, not retried:
// the /metrics counters remain the durable record of what happened.
func (n *webhookNotifier) deliver(event string, payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("webhook %s: delivery panicked: %v\n%s", event, r, debug.Stack())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("webhook %s: build request: %v", event, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ArtiGate")
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("webhook %s: post to receiver failed: %v", event, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= http.StatusBadRequest {
		log.Printf("webhook %s: receiver returned %s", event, resp.Status)
	}
}
