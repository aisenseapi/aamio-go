package aamio

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestOpenRetainsNormalizedPolicyAndBoardUsesIt(t *testing.T) {
	alice := readerKeys(t, 1)
	forged := stored(readerW, 2, "forged", readerKeys(t, 9))
	forged["from"] = alice.Public
	var sent []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			sent = append(sent, r.Header.Get("X-Allow"))
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"allow": []string{"*"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{stored(readerW, 1, "unsigned", nil), forged}, "next": 2})
	}))
	defer server.Close()
	client := New(server.URL, alice)
	thread, err := client.Open(600, []string{" " + alice.Public + ", ", "", alice.Public}, nil)
	if err != nil || !reflect.DeepEqual(thread.Allow, []string{alice.Public}) || sent[0] != alice.Public {
		t.Fatalf("normalization: %+v %v %v", thread, err, sent)
	}
	thread.W = readerW
	board := NewBoard(client, server.URL)
	_, replies, kept, next := board.RepliesThread(thread, 0, 0)
	if len(replies) != 0 || len(kept) != 2 || kept[1].UnverifiedBecause == "" || next != 2 {
		t.Fatalf("policy bypass or reason lost: %v %v %v", replies, kept, next)
	}
	_, plain, _ := board.Replies(readerW, thread.ID, 0, 0)
	if len(plain) != 2 {
		t.Fatal("compatibility overload must remain listless")
	}
	inbox, err := board.ReplyInbox(600)
	if err != nil || !reflect.DeepEqual(inbox.Allow, []string{"*"}) {
		t.Fatal("reply inbox lost signed-only policy")
	}
	board.descriptor = map[string]any{}
	posted, err := board.Post("need", "test", "local only", nil, PostOptions{})
	if err != nil || !reflect.DeepEqual(posted.Inbox.Allow, []string{"*"}) {
		t.Fatal("posted inbox lost signed-only policy")
	}
}

func TestNormalizationOnManuallyHeldThread(t *testing.T) {
	alice := readerKeys(t, 1)
	c := reading(t, []map[string]any{stored(readerW, 1, "signed", alice)})
	_, got, kept, _ := c.ReadThread(Thread{W: readerW, ID: "key", Allow: []string{" " + alice.Public}}, 0, 0)
	if len(got) != 1 || len(kept) != 0 {
		t.Fatal("manual allowlist was not normalized")
	}
	if len(normalizeAllow([]string{" "})) != 0 || !reflect.DeepEqual(normalizeAllow([]string{"a", " * "}), []string{"*"}) {
		t.Fatal("empty or wildcard normalization")
	}
}

func TestInvalidCursorPreservesAfterAndFloatMetadataWorks(t *testing.T) {
	for _, next := range []json.Number{"5.0", "1e1", "9223372036854775808"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"next": next})
		}))
		_, _, got := New(server.URL, nil).Read(readerW, "key", 5, 0)
		server.Close()
		if got != 5 {
			t.Fatalf("invalid cursor %s reset to %d", next, got)
		}
	}
	raw := stored(readerW, 7, "signed", readerKeys(t, 1))
	bytes, _ := json.Marshal(raw)
	_ = json.Unmarshal(bytes, &raw)
	m := New("", nil).DecodeAt(readerW, raw)
	if !m.Verified || m.Seq != 7 || m.At != 7 {
		t.Fatal("json.Unmarshal metadata lost")
	}
	raw["seq"] = 1.5
	m = New("", nil).DecodeAt(readerW, raw)
	if m.Verified || m.From != "" || m.UnverifiedBecause == "" {
		t.Fatal("invalid metadata acquired authority")
	}
}

func TestMalformedMessageDoesNotEndBatch(t *testing.T) {
	messages := []map[string]any{stored(readerW, 1, strings.Repeat("[", 60000), readerKeys(t, 1)), nil, stored(readerW, 3, "next", readerKeys(t, 1))}
	_, got, next := reading(t, messages).Read(readerW, "key", 0, 0)
	if len(got) != 3 || got[1].Verified || got[1].From != "" || got[1].UnverifiedBecause == "" || !got[2].Verified || next != 3 {
		t.Fatal("malformed message stopped or gained authority")
	}
}

func TestLegacyTrailingBitsAndExactIdentity(t *testing.T) {
	bytes, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(bytes, &data); err != nil {
		t.Fatal(err)
	}
	stray := data["strayBits"].(map[string]any)
	a := data["a"].(map[string]any)["public"].(string)
	input := data["signInput"].(string)
	sig := data["signature"].(string)
	if !Verify(a, stray["signature"].(string), input) || !Verify(stray["key"].(string), sig, input) {
		t.Fatal("legacy bytes failed verification")
	}
	raw := stored(data["w"].(string), 1, data["body"].(string), nil)
	raw["from"] = stray["key"]
	raw["sig"] = sig
	_, got, kept, _ := reading(t, []map[string]any{raw}).ReadThread(Thread{W: data["w"].(string), ID: "key", Allow: []string{a}}, 0, 0)
	if len(got) != 0 || len(kept) != 1 {
		t.Fatal("identity strings were normalized")
	}
}

func TestReceiptCannotMatchAPrefixOfLocalHashes(t *testing.T) {
	r := &Receipt{Messages: []ReceiptMessage{}, Root: Root(nil)}
	got := VerifyReceipt(r, []string{"a"}).LocalRootMatches
	if got == nil || *got {
		t.Fatal("shorter receipt is not a match")
	}
}
