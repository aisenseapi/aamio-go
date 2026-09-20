package aamio

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Asking the service for a small answer.
//
// The service has taken X-Limit and X-Max-Bytes since 0.7.2, and no file in this
// package sent either. A thread may hold two hundred messages of 65536 bytes, so
// one read can be about a megabyte. Measured on the live service on 20 September
// 2026: the same thread, 20 529 bytes without the headers and 360 with them.
//
// Whole messages only. A signed message cut in half does not verify, so a budget
// under the first message comes back as too_large naming it, never as a piece of
// it. Nothing here does the cutting: the service does, and this asks and passes
// on what came back.
//
// Read keeps the signature it always had and asks for nothing, so a caller that
// never heard of this sends the bytes it always sent. ReadLimited is the one
// that asks.

const limitW = "llllllllllllllllllll"

// seenHeaders answers one read and reports the headers it was asked with.
func seenHeaders(t *testing.T, body map[string]any) (*Client, *http.Header) {
	t.Helper()
	var seen http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	return &Client{Host: server.URL, HTTP: server.Client()}, &seen
}

func emptyRead() map[string]any {
	return map[string]any{"w": limitW, "exists": true, "count": 0, "allow": []string{}, "messages": []any{}, "next": 0, "waited": 0}
}

func TestReadWithoutLimitsSendsNone(t *testing.T) {
	client, seen := seenHeaders(t, emptyRead())
	client.Read(limitW, "read-key", 0, 0)

	if got := seen.Get("X-Limit"); got != "" {
		t.Fatalf("a read that asked for nothing sent X-Limit %q, so an older service sees a call it never saw before", got)
	}
	if got := seen.Get("X-Max-Bytes"); got != "" {
		t.Fatalf("a read that asked for nothing sent X-Max-Bytes %q", got)
	}
	if got := seen.Get("X-Read"); got != "read-key" {
		t.Fatalf("the read key went missing: %q", got)
	}
}

func TestReadLimitedSendsBothHeaders(t *testing.T) {
	client, seen := seenHeaders(t, emptyRead())
	client.ReadLimited(limitW, "read-key", 0, 0, 5, 4096)

	if got := seen.Get("X-Limit"); got != "5" {
		t.Fatalf("the count did not reach the wire: %q", got)
	}
	if got := seen.Get("X-Max-Bytes"); got != "4096" {
		t.Fatalf("the budget did not reach the wire: %q", got)
	}
}

func TestEachLimitCanBeSetOnItsOwn(t *testing.T) {
	client, seen := seenHeaders(t, emptyRead())
	client.ReadLimited(limitW, "read-key", 0, 0, 3, 0)
	if got, none := seen.Get("X-Limit"), seen.Get("X-Max-Bytes"); got != "3" || none != "" {
		t.Fatalf("a count on its own sent limit %q and bytes %q", got, none)
	}

	client, seen = seenHeaders(t, emptyRead())
	client.ReadLimited(limitW, "read-key", 0, 0, 0, 2048)
	if none, got := seen.Get("X-Limit"), seen.Get("X-Max-Bytes"); none != "" || got != "2048" {
		t.Fatalf("a budget on its own sent limit %q and bytes %q", none, got)
	}
}

func TestWhatWasLeftBehindComesBack(t *testing.T) {
	body := emptyRead()
	body["more"] = true
	body["next"] = 12
	client, _ := seenHeaders(t, body)
	answer, _, next := client.ReadLimited(limitW, "read-key", 0, 0, 2, 0)

	if more, _ := answer.Body["more"].(bool); !more {
		t.Fatal("more was dropped, so a caller cannot tell a short answer from an empty thread")
	}
	if next != 12 {
		t.Fatalf("next must be the last message handed over, or the next read steps over one: %d", next)
	}
}

func TestATooLargeMessageIsNamedNotCut(t *testing.T) {
	body := emptyRead()
	body["too_large"] = map[string]any{"seq": 7, "bytes": 70000, "fix": "Raise X-Max-Bytes above 70000 or read this one on its own."}
	client, _ := seenHeaders(t, body)
	answer, _, _ := client.ReadLimited(limitW, "read-key", 0, 0, 0, 1024)

	named, ok := answer.Body["too_large"].(map[string]any)
	if !ok {
		t.Fatalf("a budget too small for the first message came back with nothing to act on: %v", answer.Body)
	}
	if named["fix"] == nil {
		t.Fatal("too_large without a fix leaves the caller to guess at a number")
	}
}

func TestLimitsRideAlongWithWaitAndCursor(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("X-Limit") != "4" {
			t.Errorf("the limit was dropped when a cursor and a wait were set: %q", r.Header.Get("X-Limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(emptyRead())
	}))
	defer server.Close()

	client := &Client{Host: server.URL, HTTP: server.Client()}
	client.ReadLimited(limitW, "read-key", 9, 3, 4, 0)

	if want := "/" + limitW + "/after/9/wait/3"; path != want {
		t.Fatalf("path %q, want %q", path, want)
	}
}

func TestReadThreadLimitedStillKeepsTheAllowlist(t *testing.T) {
	keys := readerKeys(t, 1)
	stranger := readerKeys(t, 9)
	body := emptyRead()
	body["messages"] = []any{stored(limitW, 1, "from a partner", keys), stored(limitW, 2, "from a stranger", stranger)}
	body["count"] = 2
	body["next"] = 2

	client, seen := seenHeaders(t, body)
	_, handed, kept, _ := client.ReadThreadLimited(Thread{W: limitW, ID: "read-key", Allow: []string{keys.Public}}, 0, 0, 2, 4096)

	if seen.Get("X-Limit") != "2" || seen.Get("X-Max-Bytes") != "4096" {
		t.Fatalf("the limits did not reach the wire through ReadThread: %q %q", seen.Get("X-Limit"), seen.Get("X-Max-Bytes"))
	}
	if len(handed) != 1 || handed[0].Seq != 1 {
		t.Fatalf("a smaller answer must not become a looser one: handed %d", len(handed))
	}
	if len(kept) != 1 {
		t.Fatalf("what the list kept out is still said out loud: %d", len(kept))
	}
}
