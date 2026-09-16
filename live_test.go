//go:build live

package aamio

// One thread end to end against a running aamio, then a gate with work,
// presence, and the board's read side. Nothing secret is left behind: every
// thread is closed and would expire in two minutes anyway. The board is only
// read. Run with:
//
//	go test -tags live -run TestLive -v .
//
// AAMIO_HOST overrides https://aamio.at.

import (
	"os"
	"testing"
	"time"
)

func TestLive(t *testing.T) {
	host := os.Getenv("AAMIO_HOST")
	me, _ := Generate()
	partner, _ := Generate()
	client := New(host, me)
	other := New(host, partner)

	thread, err := client.Open(120, []string{me.Public, partner.Public}, nil)
	if err != nil || thread.Status != 201 {
		t.Fatalf("open: %v %s", err, thread.Answer)
	}
	defer client.Close(thread.W, thread.ID)

	sent, _ := client.Send(thread.W, []byte("hello from go"), SendOptions{})
	if sent.Status != 201 || sent.Body["verified"] != true {
		t.Fatalf("signed text write: %s", sent.Answer)
	}
	sealed, _ := other.Send(thread.W, []byte(`{"tender":"ARC-4471"}`), SendOptions{SealTo: me.Public, JSON: true})
	if sealed.Status != 201 || sealed.Body["sealed"] != true || sealed.Body["verified"] != true {
		t.Fatalf("sealed write: %s", sealed.Answer)
	}
	stranger, _ := Generate()
	if s, _ := New(host, stranger).Send(thread.W, []byte("x"), SendOptions{}); s.Status != 403 || s.Body["fix"] == nil {
		t.Fatalf("a key outside the allowlist is refused with a fix: %s", s.Answer)
	}

	a, messages, next := client.Read(thread.W, thread.ID, 0, 0)
	if a.Status != 200 || len(messages) != 2 || next != 2 {
		t.Fatalf("read: %s", a)
	}
	if messages[0].Format != "text" || messages[0].Body != "hello from go" || !messages[0].Verified {
		t.Fatalf("text message: %+v", messages[0])
	}
	if messages[1].Format != "sealed" || messages[1].JSON["tender"] != "ARC-4471" || messages[1].From != partner.Public {
		t.Fatalf("sealed message opens: %+v", messages[1])
	}
	started := time.Now()
	if a, m, _ := client.Read(thread.W, thread.ID, 2, 3); a.Status != 200 || len(m) != 0 || time.Since(started) < 2500*time.Millisecond {
		t.Fatalf("long poll on nothing waits: %s after %s", a, time.Since(started))
	}
	ra, receipt, check := client.GetReceipt(thread.W, thread.ID)
	if ra.Status != 200 || receipt == nil || !check.RootAddsUp || !check.CommitmentMatches || receipt.Count != 2 {
		t.Fatalf("receipt: %s %+v", ra, check)
	}
	if c := client.Close(thread.W, thread.ID); c.Status != 200 {
		t.Fatalf("close: %s", c)
	}

	// gate
	gated, _ := client.Open(120, []string{"*"}, map[string]any{"advise": map[string]any{"pow": map[string]any{"bits": 8}}})
	if gated.Status != 201 {
		t.Fatalf("gated open: %s", gated.Answer)
	}
	defer client.Close(gated.W, gated.ID)
	gate := client.Gate(gated.W, true)
	if h, _ := GateHash(gate); h != mustHash(`{"advise":{"pow":{"bits":8,"covers":1}}}`) {
		t.Fatalf("gate read back, canonical: %v", gate)
	}
	worked, _ := client.Send(gated.W, []byte("with work"), SendOptions{})
	met, _ := worked.Body["met"].(map[string]any)
	if worked.Status != 201 || worked.Work == "" || met["pow"] == nil || met["pow"].(interface{ String() string }).String() != "8" {
		t.Fatalf("advised work done: %s work=%s", worked.Answer, worked.Work)
	}
	required, _ := client.Open(120, []string{"*"}, map[string]any{"require": map[string]any{"pow": map[string]any{"bits": 10}}})
	defer client.Close(required.W, required.ID)
	if r, _ := client.Send(required.W, []byte("required"), SendOptions{}); r.Status != 201 {
		t.Fatalf("required work done before the first attempt: %s", r.Answer)
	}

	// presence
	inbox, _ := client.Open(120, nil, nil)
	defer client.Close(inbox.W, inbox.ID)
	if p, _ := client.PresencePublish(inbox.W, []string{"go.test"}, 30); p.Status != 200 {
		t.Fatalf("presence publish: %s", p)
	}
	if g := client.PresenceGet(me.Public); g.Status != 200 {
		t.Fatalf("presence get: %s", g)
	}
	if l, _ := client.PresenceLookup([]string{me.HashPrefix}, 0); l.Status != 200 || l.Body["count"].(interface{ String() string }).String() != "1" {
		t.Fatalf("presence lookup: %s", l)
	}
	if d, _ := client.PresenceDelete(); d.Status != 200 {
		t.Fatalf("presence delete: %s", d)
	}

	// board, read side
	board := NewBoard(client, "")
	if board.AdvisedBits() == 0 {
		t.Fatal("the board descriptor says what work it advises")
	}
	if fa, _, _ := board.Find(FindOptions{}); fa.Status != 200 {
		t.Fatalf("find: %s", fa)
	}
	if ta := board.Tags(); ta.Status != 200 {
		t.Fatalf("tags: %s", ta)
	}
	reply, _ := board.ReplyInbox(120)
	defer client.Close(reply.W, reply.ID)
	if reply.Status != 201 {
		t.Fatalf("reply inbox: %s", reply.Answer)
	}
}

func mustHash(text string) string {
	g, _ := ParseGate([]byte(text))
	h, _ := GateHash(g)
	return h
}
