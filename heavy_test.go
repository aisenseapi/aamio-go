package aamio

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Work up to 32 bits, for an inbox that means to meet only writers with
// compute. 32 bits takes this client hours and an inbox lives an hour at most,
// so the time left is read from X-Seconds-Left on the gate, work that would
// not be done by then is not started, and work that runs over is stopped.

func TestHeavyWorkThatCannotFitIsNotStarted(t *testing.T) {
	if RequireMaxBits != 32 || AdviseMaxBits != 18 {
		t.Fatal("the ceilings are the service's, 32 required and 18 advised")
	}
	g, _ := ParseGate([]byte(`{"require":{"pow":{"bits":32,"covers":1}}}`))
	// A minute: no loop like this one does 32 bits in that, on any machine.
	p := PlanWithin(g, 60)
	if !strings.Contains(p.Stop, "not started") || !strings.Contains(p.Stop, "nothing was sent") {
		t.Fatalf("32 bits with a minute left is not started: %q", p.Stop)
	}
	g, _ = ParseGate([]byte(`{"require":{"pow":{"bits":20,"covers":1}}}`))
	if p := PlanWithin(g, 3600); p.Stop != "" || p.Bits != 20 || p.ExpectedSeconds <= 0 {
		t.Fatalf("work that fits goes ahead with how long it takes: %+v", p)
	}
	if p := PlanFor(g); p.Stop != "" || p.Bits != 20 {
		t.Fatal("and without a time left the plan is what it was")
	}
}

func TestHeavyWorkStopsAtItsDeadline(t *testing.T) {
	start := time.Now()
	nonce, done, err := SolveUntil("wwwwwwwwwwwwwwwwwwww", strings.Repeat("k", 43), []byte("body"), 30, time.Now().Add(300*time.Millisecond))
	if err != nil || done || nonce != "" || time.Since(start) > 5*time.Second {
		t.Fatalf("work past its deadline is stopped: %q %v %v", nonce, done, err)
	}
	if e21, e20 := ExpectedSeconds(21), ExpectedSeconds(20); e21 < 1.99*e20 || e21 > 2.01*e20 {
		t.Fatal("the estimate doubles with each bit")
	}
	if DescribeSeconds(600) != "10 minutes" {
		t.Fatal("a time reads as a time")
	}
}

func TestTheSecondsLeftComeFromTheGateAndStopTheSend(t *testing.T) {
	var posts int
	b, _ := board(t, func(r recorded) (int, string) {
		if strings.HasSuffix(r.path, "/gate") {
			return 200, `{"require":{"pow":{"bits":26,"covers":1}}}`
		}
		posts++
		return 201, `{"seq":1}`
	})
	// The fake above cannot set headers, so this one answers the gate itself.
	c := b.Client
	c.HTTP = &http.Client{Transport: gateHeader{next: c.HTTP.Transport, left: "5"}}
	sent, err := c.Send("qqqqqqqqqqqqqqqqqqqq", []byte("hello"), SendOptions{})
	if err != nil || !sent.Stopped || !strings.Contains(sent.Error(), "not started") || posts != 0 {
		t.Fatalf("a send whose work cannot fit sends nothing and says why: %+v %v, %d posts", sent, err, posts)
	}
	if left, ok := c.SecondsLeft("qqqqqqqqqqqqqqqqqqqq"); !ok || left > 5 || left < 4 {
		t.Fatalf("the client counts down what the gate said: %v %v", left, ok)
	}
}

// gateHeader adds X-Seconds-Left to every answer, as the service does on a gate.
type gateHeader struct {
	next http.RoundTripper
	left string
}

func (g gateHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	next := g.next
	if next == nil {
		next = http.DefaultTransport
	}
	resp, err := next.RoundTrip(r)
	if err == nil {
		resp.Header.Set("X-Seconds-Left", g.left)
	}
	return resp, err
}
