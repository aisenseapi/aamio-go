package aamio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultHost is the public instance.
	DefaultHost = "https://aamio.at"
	// DefaultTTL is the thread lifetime the service uses when none is given.
	DefaultTTL = 600
	userAgent  = "aamio-go/0.1.0"
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

// Thread is an opened thread: keep ID, share W.
type Thread struct {
	ID string
	W  string
	Answer
}

// Open opens a thread with a lifetime. allow lists signer keys, or ["*"] for
// any key as long as the message is signed; gate sets conditions, or nil.
func (c *Client) Open(ttl int, allow []string, gate map[string]any) (Thread, error) {
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
	return Thread{ID: id, W: w, Answer: a}, nil
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
	c.mu.Unlock()
	return gate
}

// Sent is the outcome of a write: the answer, the exact bytes, the nonce when work was done, and notes.
type Sent struct {
	Answer
	Bytes []byte
	Work  string
	Notes []string
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
	plan := PlanFor(c.Gate(w, false))
	if plan.Stop != "" {
		return Sent{Answer: Answer{Status: 0, Body: map[string]any{"error": plan.Stop, "fix": "Open an address whose conditions this client can meet, or update the client."}}, Notes: plan.Notes}, nil
	}
	attempt := func(bits int) (Answer, string, error) {
		headers := map[string]string{"Content-Type": contentType}
		if signing {
			headers["X-Key"] = key
			headers["X-Sig"] = c.Keys.Sign(ThreadSigningInput(w, body))
		}
		work := ""
		if bits > 0 {
			nonce, err := Solve(w, key, body, bits)
			if err != nil {
				return Answer{}, "", err
			}
			work = nonce
			headers["X-Work"] = work
		}
		return c.Call("POST", c.Host+"/"+w, body, headers), work, nil
	}
	a, work, err := attempt(plan.Bits)
	if err != nil {
		return Sent{}, err
	}
	if a.Status == 428 && a.Body != nil {
		if gate, ok := a.Body["gate"].(map[string]any); ok {
			c.mu.Lock()
			c.gates[w] = gate
			c.mu.Unlock()
			again := PlanFor(gate)
			if again.Stop == "" && again.Bits > 0 {
				a, work, err = attempt(again.Bits)
				if err != nil {
					return Sent{}, err
				}
				plan.Notes = append(plan.Notes, again.Notes...)
			}
		}
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
}

// Read reads with the read key from after, waiting up to wait seconds (25 at most).
func (c *Client) Read(w, id string, after, wait int) (Answer, []Message, int64) {
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
	a := c.Call("GET", c.Host+path, nil, map[string]string{"X-Read": id})
	var messages []Message
	var next int64
	if a.Status == 200 && a.Body != nil {
		if n, ok := a.Body["next"].(json.Number); ok {
			next, _ = n.Int64()
		}
		if list, ok := a.Body["messages"].([]any); ok {
			for _, item := range list {
				if m, ok := item.(map[string]any); ok {
					messages = append(messages, c.Decode(m))
				}
			}
		}
	}
	return a, messages, next
}

// Decode turns one raw message into a Message, opening it when it is sealed
// to us. verified, sealed and from are the service's fields, never the payload's.
func (c *Client) Decode(raw map[string]any) Message {
	m := Message{Format: "text"}
	if n, ok := raw["seq"].(json.Number); ok {
		m.Seq, _ = n.Int64()
	}
	if n, ok := raw["at"].(json.Number); ok {
		m.At, _ = n.Int64()
	}
	m.From, _ = raw["from"].(string)
	m.Verified, _ = raw["verified"].(bool)
	m.Sealed, _ = raw["sealed"].(bool)
	m.Body, _ = raw["body"].(string)
	text := m.Body
	if m.Sealed {
		m.Format = "sealed-to-someone-else"
		if c.Keys != nil && m.From != "" {
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
