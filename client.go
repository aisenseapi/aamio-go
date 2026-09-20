package aamio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// errWorkRanOut is the work stopped at the inbox's deadline, turned into a
// Stopped send before it leaves this file.
var errWorkRanOut = errors.New("the work ran past the time the inbox takes writes")

const (
	// DefaultTTL is the thread lifetime the service uses when none is given.
	DefaultTTL = 600
	userAgent  = "aamio-go/0.2.6"
	maxBody    = 65536
)

// Answer is what the service said: the HTTP status, the decoded body when it
// was JSON (a map for objects), the raw text otherwise. Status 0 is no answer
// at all: the request may have landed, which is unknown, never refused.
type Answer struct {
	Status int
	Body   map[string]any
	Text   string
	Header http.Header
}

// Error is the refusal contract: every 4xx and 5xx carries error and fix.
func (a Answer) Error() string {
	if a.Body == nil {
		return a.Text
	}
	msg, _ := a.Body["error"].(string)
	fix, _ := a.Body["fix"].(string)
	return strings.TrimSpace(msg + ". " + fix)
}

// Unknown says whether the outcome is unknown rather than a refusal.
func (a Answer) Unknown() bool { return a.Status == 0 }

// Client talks to one aamio host, optionally with keys.
type Client struct {
	Host string
	Keys *Keys
	HTTP *http.Client

	mu    sync.Mutex
	gates map[string]map[string]any
	// X-Seconds-Left per address, and when it was read.
	gateLeft map[string]gateClock
}

type gateClock struct {
	left float64
	at   time.Time
}

// New makes a client for a host; keys may be nil for reads and unsigned writes.
func New(host string, keys *Keys) *Client {
	if host == "" {
		host = DefaultHost
	}
	return &Client{Host: strings.TrimRight(host, "/"), Keys: keys, HTTP: &http.Client{Timeout: 70 * time.Second}, gates: map[string]map[string]any{}}
}

// Call does one HTTP request and decodes the answer.
func (c *Client) Call(method, url string, body []byte, headers map[string]string) Answer {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return Answer{Status: 0, Text: err.Error(), Body: map[string]any{"error": "no request: " + err.Error(), "fix": "This is a client-side error; nothing was sent."}}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Answer{Status: 0, Text: err.Error(), Body: map[string]any{"error": "no answer: " + err.Error(), "fix": "The request may have landed. Keep the bytes, mark the send unknown, and retry only when somebody has decided it is safe to."}}
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)
	a := Answer{Status: resp.StatusCode, Text: string(text), Header: resp.Header}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err == nil {
		a.Body = m
	}
	return a
}

// ------------------------------------------------------------------ threads --

// Thread is an opened thread: keep ID, share W. Allow is the allowlist it was
// opened with, kept here because the service holds it in memory only: see
// ReadThread.
type Thread struct {
	ID    string
	W     string
	Allow []string
	Answer
}

// Open opens a thread with a lifetime. allow lists signer keys, or ["*"] for
// any key as long as the message is signed; gate sets conditions, or nil.
func (c *Client) Open(ttl int, allow []string, gate map[string]any) (Thread, error) {
	allow = normalizeAllow(allow)
	id, err := NewID()
	if err != nil {
		return Thread{}, err
	}
	w, _ := W(id)
	headers := map[string]string{"X-Read": id, "X-TTL": strconv.Itoa(ttl), "Content-Type": "application/json"}
	if allow != nil {
		headers["X-Allow"] = strings.Join(allow, ",")
	}
	var body []byte
	if gate != nil {
		body, err = JSON(map[string]any{"gate": gate})
		if err != nil {
			return Thread{}, err
		}
	}
	a := c.Call("PUT", c.Host+"/"+w, body, headers)
	return Thread{ID: id, W: w, Allow: append([]string(nil), allow...), Answer: a}, nil
}

func normalizeAllow(allow []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, entry := range allow {
		for _, part := range strings.Split(entry, ",") {
			key := strings.TrimSpace(part)
			if key != "" && !seen[key] {
				out = append(out, key)
				seen[key] = true
			}
		}
	}
	if seen["*"] {
		return []string{"*"}
	}
	return out
}

// integer accepts JSON decoder numbers and exact integer values from json.Unmarshal.
func integer(value any) (int64, bool) {
	switch n := value.(type) {
	case json.Number:
		v, err := n.Int64()
		return v, err == nil
	case float64:
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n >= -9223372036854775808.0 && n < 9223372036854775808.0 && math.Trunc(n) == n {
			return int64(n), true
		}
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

// Gate reads the conditions an inbox was opened with, once per address unless
// fresh; an empty map means none, nil means the thread is gone.
func (c *Client) Gate(w string, fresh bool) map[string]any {
	c.mu.Lock()
	if g, ok := c.gates[w]; ok && !fresh {
		c.mu.Unlock()
		return g
	}
	c.mu.Unlock()
	a := c.Call("GET", c.Host+"/"+w+"/gate", nil, nil)
	var gate map[string]any
	if a.Status == 200 {
		gate, _ = ParseGate([]byte(a.Text))
		if gate == nil {
			gate = map[string]any{}
		}
	}
	c.mu.Lock()
	c.gates[w] = gate
	// The time left rides in a header, since the body is the exact bytes the
	// gate hash is taken over.
	if left, err := strconv.Atoi(a.Header.Get("X-Seconds-Left")); err == nil && a.Status == 200 {
		c.setLeft(w, float64(left))
	}
	c.mu.Unlock()
	return gate
}

// setLeft records how long w takes writes. The caller holds mu.
func (c *Client) setLeft(w string, left float64) {
	if c.gateLeft == nil {
		c.gateLeft = map[string]gateClock{}
	}
	c.gateLeft[w] = gateClock{left: left, at: time.Now()}
}

// SecondsLeft is how long w still takes writes, counted down from what its
// gate said; ok is false when the gate did not say.
func (c *Client) SecondsLeft(w string) (float64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	said, ok := c.gateLeft[w]
	if !ok {
		return 0, false
	}
	return math.Max(0, said.left-time.Since(said.at).Seconds()), true
}

// ForgetGate drops the gate kept for w and the time it said: they belong to
// an inbox that may not be there now.
func (c *Client) ForgetGate(w string) {
	c.mu.Lock()
	delete(c.gates, w)
	delete(c.gateLeft, w)
	c.mu.Unlock()
}

// PlanTo is the plan for w's gate, read again once before a no that rests on a
// gate read earlier. A gate never changes while its thread lives, which is why
// it is kept, but an address can have more than one life: the time a kept gate
// said counted down to nothing and stayed there, and a new inbox at the same
// address was refused on the old one's terms without the service being asked.
func (c *Client) PlanTo(w string) Plan {
	c.mu.Lock()
	_, cached := c.gates[w]
	c.mu.Unlock()
	plan := PlanWithin(c.Gate(w, false), c.leftOrUnknown(w))
	if plan.Stop != "" && cached {
		c.ForgetGate(w)
		plan = PlanWithin(c.Gate(w, false), c.leftOrUnknown(w))
	}
	return plan
}

func (c *Client) leftOrUnknown(w string) float64 {
	if left, ok := c.SecondsLeft(w); ok {
		return left
	}
	return -1
}

// Sent is the outcome of a write: the answer, the exact bytes, the nonce when work was done, and notes.
type Sent struct {
	Answer
	Bytes []byte
	Work  string
	Notes []string
	// Stopped is true when this client refused to send at all, because the
	// inbox asks for something it cannot do. Nothing left the machine, so
	// nothing can have landed. Status 0 alone means the opposite: no answer
	// came back and the request may be through.
	Stopped bool
}

// SendOptions shape a write.
type SendOptions struct {
	// Sign with this client's keys (default true when keys are present).
	Unsigned bool
	// SealTo is a recipient key; the body is sealed to it and the content type becomes JSON.
	SealTo string
	// JSON marks the body as application/json.
	JSON bool
}

// Send writes bytes to an address. It reads the gate once, does the work it
// asks for within the ceilings, answers a 428 once, and stops with a reason
// rather than send what the gate would refuse.
func (c *Client) Send(w string, body []byte, opts SendOptions) (Sent, error) {
	if !IsW(w) {
		return Sent{}, errors.New("not a write address")
	}
	contentType := "text/plain; charset=utf-8"
	if opts.JSON {
		contentType = "application/json"
	}
	if opts.SealTo != "" {
		if c.Keys == nil {
			return Sent{}, errors.New("sealing needs keys")
		}
		sealed, err := c.Keys.Seal(opts.SealTo, body)
		if err != nil {
			return Sent{}, err
		}
		body = []byte(sealed)
		contentType = "application/json"
	}
	if len(body) > maxBody {
		return Sent{}, errors.New("a message is at most 65536 bytes; send a URL and a hash instead")
	}
	signing := !opts.Unsigned && c.Keys != nil
	key := ""
	if signing {
		key = c.Keys.Public
	}
	plan := c.PlanTo(w)
	if plan.Stop != "" {
		return Sent{Stopped: true, Answer: Answer{Status: 0, Body: map[string]any{"error": plan.Stop, "fix": "Open an address whose conditions this client can meet, or update the client."}}, Notes: plan.Notes}, nil
	}
	attempt := func(bits int) (Answer, string, error) {
		headers := map[string]string{"Content-Type": contentType}
		if signing {
			headers["X-Key"] = key
			headers["X-Sig"] = c.Keys.Sign(ThreadSigningInput(w, body))
		}
		work := ""
		if bits > 0 {
			// The work stops when the inbox would close, less a few seconds
			// for the post itself: past that a nonce buys nothing but a 410.
			var deadline time.Time
			if left, ok := c.SecondsLeft(w); ok {
				deadline = time.Now().Add(time.Duration(math.Max(0, left-5) * float64(time.Second)))
			}
			nonce, done, err := SolveUntil(w, key, body, bits, deadline)
			if err != nil {
				return Answer{}, "", err
			}
			if !done {
				return Answer{}, "", errWorkRanOut
			}
			work = nonce
			headers["X-Work"] = work
		}
		return c.Call("POST", c.Host+"/"+w, body, headers), work, nil
	}
	ranOut := func(bits int) Sent {
		return Sent{Stopped: true, Answer: Answer{Status: 0, Body: map[string]any{"error": fmt.Sprintf("the proof of work of %d bits was not done before the inbox stops taking writes, so the work was stopped and nothing was sent", bits), "fix": "The estimate before it started said it would fit, and this time it took longer, which happens: the work is a lottery. Ask the owner for a longer inbox, or send from a machine with more compute."}}, Notes: plan.Notes}
	}
	a, work, err := attempt(plan.Bits)
	if errors.Is(err, errWorkRanOut) {
		return ranOut(plan.Bits), nil
	}
	if err != nil {
		return Sent{}, err
	}
	if a.Status == 428 && a.Body != nil {
		if gate, ok := a.Body["gate"].(map[string]any); ok {
			c.mu.Lock()
			c.gates[w] = gate
			if left, ok := a.Body["seconds_left"].(json.Number); ok {
				if n, err := left.Int64(); err == nil {
					c.setLeft(w, float64(n))
				}
			}
			c.mu.Unlock()
			again := PlanWithin(gate, c.leftOrUnknown(w))
			if again.Stop != "" {
				return Sent{Stopped: true, Answer: Answer{Status: 0, Body: map[string]any{"error": again.Stop, "fix": "Open an address whose conditions this client can meet, or update the client."}}, Notes: append(plan.Notes, again.Notes...)}, nil
			}
			if again.Bits > 0 {
				a, work, err = attempt(again.Bits)
				if errors.Is(err, errWorkRanOut) {
					return ranOut(again.Bits), nil
				}
				if err != nil {
					return Sent{}, err
				}
				plan.Notes = append(plan.Notes, again.Notes...)
			}
		}
	}
	// An inbox that is not there, or has expired, takes its gate with it: the
	// next send here reads the gate of whatever is there then.
	if a.Status == 404 || a.Status == 410 {
		c.ForgetGate(w)
	}
	return Sent{Answer: a, Bytes: body, Work: work, Notes: plan.Notes}, nil
}

// Message is one message as read, with the service's own fields around the
// body and, when this client could open it, the plaintext.
type Message struct {
	Seq      int64
	At       int64
	From     string
	Verified bool
	Sealed   bool
	Body     string
	Opened   string
	Format   string // text | sealed | unreadable | sealed-to-someone-else
	Err      string
	JSON     map[string]any
	// UnverifiedBecause is set by Read when something that should have held did
	// not: the service called the message verified, or gave its hash, and it
	// does not check out here. Verified is then false and From is empty.
	UnverifiedBecause string
}

// KeptOut is a message the thread's own allowlist kept out of what ReadThread handed over.
type KeptOut struct {
	Seq               int64
	Why               string
	UnverifiedBecause string
}

// Read reads with the read key from after, waiting up to wait seconds (25 at most).
//
// Every message is checked here before it is handed over: the body is hashed
// and compared with the sha256 beside it, and the signature is verified over
// this address. Verified and From on what comes back are this client's result,
// not the service's word, and a message the service called verified that does
// not check out says why in UnverifiedBecause.
func (c *Client) Read(w, id string, after, wait int) (Answer, []Message, int64) {
	return c.ReadLimited(w, id, after, wait, 0, 0)
}

// ReadLimited is Read, asking the service for a small answer.
//
// limit is at most this many messages; maxBytes at most this many bytes of them.
// Zero for either means do not ask, and asking for neither is exactly Read. A
// thread may hold two hundred messages of 65536 bytes, so one read can be about a
// megabyte, and without these the whole of it crosses the network before anything
// here looks at it.
//
// Whole messages only: a signed message cut in half does not verify. When something
// was left behind the answer carries more, and next is the last message handed
// over, so passing it back as after skips nothing. When one message alone is over
// budget the answer carries too_large naming it and its size.
//
// A service that does not offer read-limits ignores both headers and answers as it
// always did, so these are safe to send without asking what it supports.
func (c *Client) ReadLimited(w, id string, after, wait, limit, maxBytes int) (Answer, []Message, int64) {
	path := "/" + w
	if after > 0 || wait > 0 {
		path += "/after/" + strconv.Itoa(after)
	}
	if wait > 0 {
		if wait > 25 {
			wait = 25
		}
		path += "/wait/" + strconv.Itoa(wait)
	}
	headers := map[string]string{"X-Read": id}
	if limit > 0 {
		headers["X-Limit"] = strconv.Itoa(limit)
	}
	if maxBytes > 0 {
		headers["X-Max-Bytes"] = strconv.Itoa(maxBytes)
	}
	a := c.Call("GET", c.Host+path, nil, headers)
	var messages []Message
	// The cursor the caller already has, so a refusal or a dead connection
	// leaves it where it was. Zero sent the documented loop back to the first
	// message and delivered the whole thread a second time.
	next := int64(after)
	if a.Status == 200 && a.Body != nil {
		if n, ok := integer(a.Body["next"]); ok {
			next = n
		}
		if list, ok := a.Body["messages"].([]any); ok {
			for _, item := range list {
				m, _ := item.(map[string]any)
				messages = append(messages, c.DecodeAt(w, m))
			}
		}
	}
	return a, messages, next
}

// ReadThread is Read for a thread this client opened, with the allowlist it
// was opened with applied to what is read. The service enforces the list while
// it holds the thread, and it holds it in memory: a write to the address after
// its store was emptied opens a thread with no list. With named keys, only
// messages verified here from one of them are handed over; with "*", only
// messages verified here from any key. The rest is listed as kept out, never
// dropped in silence. The cursor covers both.
func (c *Client) ReadThread(t Thread, after, wait int) (Answer, []Message, []KeptOut, int64) {
	return c.ReadThreadLimited(t, after, wait, 0, 0)
}

// ReadThreadLimited is ReadThread with the limits of ReadLimited. A smaller answer
// is not a looser one: the allowlist is checked here exactly as before, and what it
// keeps out is still listed rather than dropped in silence.
func (c *Client) ReadThreadLimited(t Thread, after, wait, limit, maxBytes int) (Answer, []Message, []KeptOut, int64) {
	t.Allow = normalizeAllow(t.Allow)
	a, messages, next := c.ReadLimited(t.W, t.ID, after, wait, limit, maxBytes)
	if len(t.Allow) == 0 {
		return a, messages, nil, next
	}
	anySigned := false
	for _, key := range t.Allow {
		if key == "*" {
			anySigned = true
		}
	}
	var handed []Message
	var kept []KeptOut
	for _, m := range messages {
		allowed := m.Verified && anySigned
		if m.Verified && !anySigned {
			for _, key := range t.Allow {
				if key == m.From {
					allowed = true
				}
			}
		}
		if allowed {
			handed = append(handed, m)
			continue
		}
		why := "this thread was opened for named keys, and this one was not signed by one of them, as checked here"
		if anySigned {
			why = "this thread was opened for signed messages only, and this one did not verify here"
		}
		kept = append(kept, KeptOut{Seq: m.Seq, Why: why, UnverifiedBecause: m.UnverifiedBecause})
	}
	return a, handed, kept, next
}

// CheckMessage checks one message as the service returned it: the body is
// hashed and compared with the sha256 beside it, and the signature verified
// over the address being read. verified in an answer is the service's word, and
// the trust model says an operator cannot forge a signature, which only holds
// for a reader that checks. whyNot is empty for a message that verified and for
// an ordinary unsigned one, and a sentence when something that should have held
// did not.
func CheckMessage(w string, raw map[string]any) (verified bool, whyNot string, digest string) {
	body, ok := raw["body"].(string)
	if !ok {
		return false, "the message has no body to check", ""
	}
	digest = Sha256Hex([]byte(body))
	if given, _ := raw["sha256"].(string); given != digest {
		return false, "the body does not hash to the sha256 the service gave with it, so these are not the bytes that were stored", digest
	}
	from, _ := raw["from"].(string)
	signature, _ := raw["sig"].(string)
	claimed, _ := raw["verified"].(bool)
	if from == "" || signature == "" {
		if claimed {
			return false, "the service calls it verified and gave no key or signature to check", digest
		}
		return false, "", digest
	}
	if Verify(from, signature, ThreadSigningInput(w, []byte(body))) {
		return true, "", digest
	}
	whyNot = "the signature does not check out for this key, this address and these bytes"
	if claimed {
		whyNot += ", though the service said it did"
	}
	return false, whyNot, digest
}

// DecodeAt is Decode for a message read at w: the hash and the signature are
// checked first, and everything Decode does goes by that result. A message that
// does not verify here has no From, so a sealed body under a forged sender is
// not opened against the key it claimed.
func (c *Client) DecodeAt(w string, raw map[string]any) (m Message) {
	failed := func(reason string) Message {
		seq, _ := integer(raw["seq"])
		at, _ := integer(raw["at"])
		body, _ := raw["body"].(string)
		return Message{Seq: seq, At: at, Body: body, Format: "unreadable", Err: reason, UnverifiedBecause: reason}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			m = failed(fmt.Sprintf("the message could not be checked here: %T", recovered))
		}
	}()
	if _, ok := integer(raw["seq"]); !ok {
		return failed("the message has invalid sequence metadata")
	}
	if _, ok := integer(raw["at"]); !ok {
		return failed("the message has invalid time metadata")
	}
	verified, whyNot, digest := CheckMessage(w, raw)
	checked := make(map[string]any, len(raw))
	for key, value := range raw {
		checked[key] = value
	}
	checked["verified"] = verified
	if !verified {
		checked["from"] = nil
	}
	if digest != "" {
		checked["sha256"] = digest
	}
	m = c.Decode(checked)
	m.UnverifiedBecause = whyNot
	return m
}

// Decode turns one raw message into a Message, opening it when it is sealed
// to us. verified, sealed and from are never taken from the payload. Decode
// takes the service's fields as they are; Read goes through DecodeAt, which
// checks them first.
// Deprecated: Decode trusts supplied fields. Use DecodeAt or Read for remote input.
func (c *Client) Decode(raw map[string]any) Message {
	m := Message{Format: "text"}
	m.Seq, _ = integer(raw["seq"])
	m.At, _ = integer(raw["at"])
	m.From, _ = raw["from"].(string)
	m.Verified, _ = raw["verified"].(bool)
	m.Sealed, _ = raw["sealed"].(bool)
	m.Body, _ = raw["body"].(string)
	text := m.Body
	if m.Sealed {
		// The envelope names who it is sealed to, so read that rather than
		// guess. This said "sealed to someone else" whenever the client had no
		// keys or the message carried no sender, with no error beside the
		// claim, and envelopes sealed to the reader were dropped on that word.
		to := EnvelopeTo([]byte(m.Body))
		mine := ""
		if c.Keys != nil {
			mine = c.Keys.HashPrefix
		}
		switch {
		case to != "" && mine != "" && to != mine:
			m.Format = "sealed-to-someone-else"
			m.Err = "this envelope is sealed to " + to + ", not to " + mine
		case c.Keys == nil || m.From == "":
			m.Format = "sealed-unchecked"
		default:
			plain, err := c.Keys.Open(m.From, []byte(m.Body))
			if err != nil {
				m.Format = "unreadable"
				m.Err = err.Error()
			} else {
				m.Format = "sealed"
				m.Opened = string(plain)
				text = m.Opened
			}
		}
		if m.Format != "sealed" {
			// Nothing was opened, so there is no payload here. JSON used to
			// hold the envelope itself, and "if JSON != nil" then read as
			// "this message was decoded".
			return m
		}
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var j map[string]any
	if err := dec.Decode(&j); err == nil {
		m.JSON = j
	}
	return m
}

// GetReceipt takes the receipt and checks it.
func (c *Client) GetReceipt(w, id string) (Answer, *Receipt, Check) {
	a := c.Call("GET", c.Host+"/"+w+"/receipt", nil, map[string]string{"X-Read": id})
	if a.Status != 200 {
		return a, nil, Check{}
	}
	var r Receipt
	if err := json.Unmarshal([]byte(a.Text), &r); err != nil {
		return a, nil, Check{}
	}
	return a, &r, VerifyReceipt(&r, nil)
}

// Close closes a thread early.
func (c *Client) Close(w, id string) Answer {
	return c.Call("DELETE", c.Host+"/"+w, nil, map[string]string{"X-Read": id})
}

// ----------------------------------------------------------------- presence --

// PresencePublish says where this key can be reached, for up to 120 seconds.
func (c *Client) PresencePublish(w string, tags []string, ttl int) (Answer, error) {
	if c.Keys == nil {
		return Answer{}, errNoKeys
	}
	if tags == nil {
		tags = []string{}
	}
	body, err := JSON(map[string]any{"w": w, "tags": tags, "ttl": ttl})
	if err != nil {
		return Answer{}, err
	}
	headers := map[string]string{"Content-Type": "application/json", "X-Key": c.Keys.Public, "X-Sig": c.Keys.Sign(PresenceSigningInput(c.Keys.Public, body))}
	return c.Call("PUT", c.Host+"/p/"+c.Keys.Public, body, headers), nil
}

// PresenceGet reads one key's record.
func (c *Client) PresenceGet(key string) Answer {
	return c.Call("GET", c.Host+"/p/"+key, nil, nil)
}

// PresenceLookup finds live records by hash prefix; with wait it watches.
func (c *Client) PresenceLookup(prefixes []string, wait int) (Answer, error) {
	route := "/p/lookup"
	req := map[string]any{"prefixes": prefixes}
	if wait > 0 {
		route = "/p/watch"
		if wait > 25 {
			wait = 25
		}
		req["wait"] = wait
	}
	body, err := JSON(req)
	if err != nil {
		return Answer{}, err
	}
	return c.Call("POST", c.Host+route, body, map[string]string{"Content-Type": "application/json"}), nil
}

// PresenceDelete withdraws this key's record.
func (c *Client) PresenceDelete() (Answer, error) {
	if c.Keys == nil {
		return Answer{}, errNoKeys
	}
	body, _ := JSON(map[string]any{"at": time.Now().Unix()})
	headers := map[string]string{"Content-Type": "application/json", "X-Key": c.Keys.Public, "X-Sig": c.Keys.Sign(PresenceDeleteSigningInput(c.Keys.Public, body))}
	return c.Call("DELETE", c.Host+"/p/"+c.Keys.Public, body, headers), nil
}

func (a Answer) String() string {
	return fmt.Sprintf("%d %s", a.Status, a.Text)
}
