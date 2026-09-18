package aamio

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A gate kept for an address, and a new inbox at the same address. Found by an
// outside review on 18 September 2026: the time a kept gate said counted down
// to nothing and stayed there, and a send to the new inbox was refused on the
// old one's terms without the service being asked.

type lives struct {
	gates     []string
	lefts     []string
	post      int
	gateReads int32
	posts     int32
}

func (l *lives) serve(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/gate") {
			i := int(atomic.AddInt32(&l.gateReads, 1)) - 1
			if i >= len(l.gates) {
				i = len(l.gates) - 1
			}
			w.Header().Set("X-Seconds-Left", l.lefts[i])
			w.WriteHeader(200)
			_, _ = w.Write([]byte(l.gates[i]))
			return
		}
		atomic.AddInt32(&l.posts, 1)
		w.WriteHeader(l.post)
		_, _ = w.Write([]byte(`{"seq":1,"error":"x","fix":"y"}`))
	}))
	t.Cleanup(server.Close)
	keys, _ := Generate()
	return New(server.URL, keys)
}

func TestANewInboxAtAnOldAddressIsAskedAboutBeforeANo(t *testing.T) {
	l := &lives{gates: []string{`{"require":{"pow":{"bits":17,"covers":1}}}`, `{}`}, lefts: []string{"0", "600"}, post: 201}
	c := l.serve(t)
	c.Gate("qqqqqqqqqqqqqqqqqqqq", false)
	sent, err := c.Send("qqqqqqqqqqqqqqqqqqqq", []byte("hello"), SendOptions{})
	if err != nil || sent.Stopped || sent.Status != 201 {
		t.Fatalf("the send to the new inbox goes through: %+v %v", sent, err)
	}
	if l.gateReads != 2 || l.posts != 1 {
		t.Fatalf("one more read of the gate, and only one: %d reads, %d posts", l.gateReads, l.posts)
	}
}

func TestARealNoIsStillANoAfterOneMoreRead(t *testing.T) {
	closed := `{"require":{"pow":{"bits":30,"covers":1}}}`
	l := &lives{gates: []string{closed, closed}, lefts: []string{"0", "0"}, post: 201}
	c := l.serve(t)
	c.Gate("qqqqqqqqqqqqqqqqqqqq", false)
	sent, err := c.Send("qqqqqqqqqqqqqqqqqqqq", []byte("hello"), SendOptions{})
	if err != nil || !sent.Stopped || l.posts != 0 || l.gateReads != 2 {
		t.Fatalf("a real no stays a no: %+v %v, %d reads, %d posts", sent, err, l.gateReads, l.posts)
	}
}

func TestAnInboxThatAnswers410TakesItsGateWithIt(t *testing.T) {
	l := &lives{gates: []string{`{}`}, lefts: []string{"600"}, post: 410}
	c := l.serve(t)
	sent, _ := c.Send("qqqqqqqqqqqqqqqqqqqq", []byte("hello"), SendOptions{})
	if _, ok := c.SecondsLeft("qqqqqqqqqqqqqqqqqqqq"); ok || sent.Status != 410 {
		t.Fatal("a 410 takes the gate and its time with it")
	}
}
