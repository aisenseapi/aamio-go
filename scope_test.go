package aamio

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Scopes: the shared vector, a post that carries the address inside what is
// signed, and a find that sends the key in the body and believes only an
// answer that names the scope. The board is a test server that answers as told.

func TestScopeVector(t *testing.T) {
	v := load(t)
	if got, err := ScopeAddress(v.Scope.Key); err != nil || got != v.Scope.Address {
		t.Fatalf("scope(%s) = %s, want %s", v.Scope.Key, got, v.Scope.Address)
	}
	if w, _ := W(v.Scope.Key); w != v.Scope.ThreadW || w == v.Scope.Address {
		t.Fatal("the thread address of the same string is another address")
	}
	key, err := NewScopeKey()
	if err != nil || len(key) != 26 || !IsScopeKey(key) {
		t.Fatal("a new scope key has the form")
	}
	address, _ := ScopeAddress(key)
	if !IsW(address) || IsScopeKey(address) {
		t.Fatal("an address is never a key")
	}
	if _, err := ScopeAddress(v.Scope.Address); err == nil {
		t.Fatal("an address is refused where the key goes")
	}
}

type recorded struct {
	method, path string
	headers      http.Header
	body         []byte
}

func board(t *testing.T, answer func(r recorded) (int, string)) (*Board, *[]recorded) {
	t.Helper()
	var seen []recorded
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recorded{r.Method, r.URL.Path, r.Header, body}
		seen = append(seen, rec)
		status, text := answer(rec)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(text))
	}))
	t.Cleanup(server.Close)
	keys, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := New(server.URL, keys)
	return NewBoard(client, server.URL), &seen
}

func TestPostInAScope(t *testing.T) {
	v := load(t)
	b, seen := board(t, func(r recorded) (int, string) {
		switch {
		case r.method == "PUT":
			return 201, `{"w":"x","expire_at":4102444800,"allow":["*"]}`
		case strings.HasSuffix(r.path, "aamio-board.json"):
			return 200, `{"work":{"advise_bits":0}}`
		default:
			return 201, `{"id":"pppppppppppppppppppp"}`
		}
	})
	posted, err := b.Post("need", "Chapter 3 draft ready", "At commit 4f2a9c1.", []string{"chapter-03"}, PostOptions{TTL: 900, Scope: v.Scope.Address})
	if err != nil || posted.Status != 201 {
		t.Fatalf("post: %v %d", err, posted.Status)
	}
	sent := (*seen)[len(*seen)-1]
	var fields map[string]any
	if err := json.Unmarshal(sent.body, &fields); err != nil || fields["scope"] != v.Scope.Address {
		t.Fatalf("the post carries the address: %s", sent.body)
	}
	if strings.Contains(string(sent.body), v.Scope.Key) {
		t.Fatal("and never the key")
	}
	if !Verify(b.Client.Keys.Public, sent.headers.Get("X-Sig"), BoardSigningInput(b.Client.Keys.Public, sent.body)) {
		t.Fatal("inside what is signed")
	}
	if _, err := b.Post("need", "t", "x", nil, PostOptions{Scope: v.Scope.Key}); err == nil {
		t.Fatal("a key where the address goes is refused")
	}
}

func TestFindInAScope(t *testing.T) {
	v := load(t)
	answer := `{"count":1,"live":1,"next":3,"posts":[{"id":"pppppppppppppppppppp"}],"scope":"` + v.Scope.Address + `"}`
	status := 200
	b, seen := board(t, func(r recorded) (int, string) { return status, answer })

	a, posts, next, err := b.FindInScope(v.Scope.Key, FindOptions{Tags: []string{"chapter-03"}})
	if err != nil || a.Status != 200 || len(posts) != 1 || next != 3 {
		t.Fatalf("find in scope: %v %d %d", err, len(posts), next)
	}
	var sent map[string]any
	_ = json.Unmarshal((*seen)[0].body, &sent)
	if sent["scope_key"] != v.Scope.Key || strings.Contains((*seen)[0].path, v.Scope.Key) {
		t.Fatal("the key goes in the body and never in the path")
	}

	answer = `{"count":0,"live":0,"next":0,"posts":[]}`
	if _, _, _, err := b.FindInScope(v.Scope.Key, FindOptions{}); err == nil || !strings.Contains(err.Error(), "did not say it read that scope") {
		t.Fatal("an answer that does not name the scope is not believed")
	}

	status, answer = 400, `{"error":"Unknown field scope_key","fix":"Drop that field"}`
	if a, _, _, err := b.FindInScope(v.Scope.Key, FindOptions{}); err != nil || a.Status != 400 {
		t.Fatal("a board older than scopes refuses, and the refusal comes back")
	}

	if _, _, _, err := b.FindInScope(v.Scope.Address, FindOptions{}); err == nil {
		t.Fatal("the address is refused where the key goes")
	}

	status, answer = 200, `{"count":0,"live":0,"next":0,"posts":[]}`
	b.Find(FindOptions{})
	var public map[string]any
	_ = json.Unmarshal((*seen)[len(*seen)-1].body, &public)
	if _, has := public["scope_key"]; has {
		t.Fatal("Find reads the public board")
	}
}
