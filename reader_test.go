package aamio

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A reader checks for itself, and keeps the allowlist it opened a thread with.
//
// From a security review on 18 September 2026. verified in an answer was the
// service's word, and Read took it: the trust model says an operator cannot
// forge a signature, which is only true for a reader that checks one. And the
// service holds an allowlist in memory, so a write to an address after its
// store was emptied opens a thread with no list at all.

const readerW = "iiiiiiiiiiiiiiiiiiii"

func readerKeys(t *testing.T, b byte) *Keys {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// stored is one message as GET /{w} returns it, really signed. keys nil is an unsigned one.
func stored(w string, seq int, body string, keys *Keys) map[string]any {
	m := map[string]any{"seq": json.Number(itoa(seq)), "at": json.Number(itoa(seq)), "type": "text", "body": body, "sha256": Sha256Hex([]byte(body)), "from": nil, "sig": nil, "verified": false}
	if keys != nil {
		m["from"] = keys.Public
		m["sig"] = keys.Sign(ThreadSigningInput(w, []byte(body)))
		m["verified"] = true
	}
	return m
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// reading is a client whose service answers every read with these messages.
func reading(t *testing.T, messages []map[string]any) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"w": readerW, "exists": true, "messages": messages, "next": len(messages), "waited": 0})
	}))
	t.Cleanup(server.Close)
	return New(server.URL, nil)
}

func TestTheContractVectorVerifiesAndStopsWhenAnythingMoves(t *testing.T) {
	v := load(t)
	if !Verify(v.A.Public, v.Signature, ThreadSigningInput(v.W, []byte(v.Body))) {
		t.Fatal("the contract vector does not verify")
	}
	if Verify(v.A.Public, v.Signature, ThreadSigningInput("aaaaaaaaaaaaaaaaaaaa", []byte(v.Body))) {
		t.Fatal("it verified at another address")
	}
	if Verify(v.A.Public, v.Signature, ThreadSigningInput(v.W, []byte(v.Body+" "))) {
		t.Fatal("it verified over another body")
	}
	if Verify(readerKeys(t, 1).Public, v.Signature, ThreadSigningInput(v.W, []byte(v.Body))) {
		t.Fatal("it verified under another key")
	}
}

func TestWhatTheServiceCallsVerifiedHasToCheckOut(t *testing.T) {
	alice := readerKeys(t, 1)
	if verified, whyNot, digest := CheckMessage(readerW, stored(readerW, 1, "hello", alice)); !verified || whyNot != "" || len(digest) != 64 {
		t.Fatalf("a signed message did not verify: %v %q", verified, whyNot)
	}
	if verified, whyNot, _ := CheckMessage(readerW, stored(readerW, 1, "hello", nil)); verified || whyNot != "" {
		t.Fatalf("an unsigned message is unverified without a complaint, got %v %q", verified, whyNot)
	}
	moved := stored("oooooooooooooooooooo", 1, "hello", alice)
	bare := stored(readerW, 1, "hello", nil)
	bare["verified"] = true
	wrongHash := stored(readerW, 1, "hello", alice)
	wrongHash["sha256"] = strings.Repeat("0", 64)
	for name, c := range map[string]struct {
		raw  map[string]any
		want string
	}{"signed for another address": {moved, "though the service said it did"}, "verified with nothing to check": {bare, "gave no key or signature"}, "another hash": {wrongHash, "does not hash"}} {
		verified, whyNot, _ := CheckMessage(readerW, c.raw)
		if verified || !strings.Contains(whyNot, c.want) {
			t.Fatalf("%s: got %v %q", name, verified, whyNot)
		}
	}
}

func TestReadGoesByItsOwnResult(t *testing.T) {
	alice, mallory := readerKeys(t, 1), readerKeys(t, 9)
	forged := stored(readerW, 2, "pay the invoice", mallory)
	forged["from"] = alice.Public
	_, messages, _ := reading(t, []map[string]any{stored(readerW, 1, "hello", alice), forged}).Read(readerW, "read-key", 0, 0)
	if len(messages) != 2 || !messages[0].Verified || messages[0].From != alice.Public || messages[0].UnverifiedBecause != "" {
		t.Fatalf("the signed message: %+v", messages)
	}
	if messages[1].Verified || messages[1].From != "" || !strings.Contains(messages[1].UnverifiedBecause, "though the service said it did") {
		t.Fatalf("the forged message kept something of its claim: %+v", messages[1])
	}
}

func TestASealedMessageUnderAForgedSenderIsNotOpened(t *testing.T) {
	alice, bob, mallory := readerKeys(t, 1), readerKeys(t, 2), readerKeys(t, 9)
	envelope, err := mallory.Seal(bob.Public, []byte("for bob"))
	if err != nil {
		t.Fatal(err)
	}
	forged := stored(readerW, 1, envelope, mallory)
	forged["from"] = alice.Public
	forged["sealed"] = true
	client := reading(t, []map[string]any{forged})
	client.Keys = bob
	_, messages, _ := client.Read(readerW, "read-key", 0, 0)
	if len(messages) != 1 || messages[0].Opened != "" || messages[0].Format != "sealed-unchecked" {
		t.Fatalf("it was opened against the key it claimed: %+v", messages)
	}
}

func TestAThreadKeepsTheAllowlistItWasOpenedWith(t *testing.T) {
	alice, mallory := readerKeys(t, 1), readerKeys(t, 9)
	forged := stored(readerW, 4, "let me in", mallory)
	forged["from"] = alice.Public
	messages := []map[string]any{stored(readerW, 1, "from alice", alice), stored(readerW, 2, "from a stranger", mallory), stored(readerW, 3, "unsigned", nil), forged}

	_, handed, kept, next := reading(t, messages).ReadThread(Thread{ID: "read-key", W: readerW, Allow: []string{alice.Public}}, 0, 0)
	if len(handed) != 1 || handed[0].Seq != 1 || len(kept) != 3 || kept[0].Seq != 2 || !strings.Contains(kept[0].Why, "named keys") || next != 4 {
		t.Fatalf("named keys: handed %+v kept %+v next %d", handed, kept, next)
	}

	_, handed, kept, _ = reading(t, messages).ReadThread(Thread{ID: "read-key", W: readerW, Allow: []string{"*"}}, 0, 0)
	if len(handed) != 2 || len(kept) != 2 || kept[0].Seq != 3 || !strings.Contains(kept[0].Why, "signed messages only") {
		t.Fatalf("any signed key: handed %+v kept %+v", handed, kept)
	}

	_, handed, kept, _ = reading(t, messages).ReadThread(Thread{ID: "read-key", W: readerW}, 0, 0)
	if len(handed) != 4 || kept != nil {
		t.Fatalf("no list: handed %d kept %+v", len(handed), kept)
	}
}
