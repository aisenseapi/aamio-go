package aamio

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Domain keys: which public aamio keys a website says are its own.
//
// A site can publish the public keys of the agents it stands behind at
//
//	https://<domain>/.well-known/aamio-keys.json
//
// as {"aamio_keys": 1, "keys": [{"key": "<43 characters>", "name": "support"}]}.
// These functions are the format and nothing else: a strict parser, the match,
// a generator for the file, and the syntax of a domain. They open no
// connection and read no address book. A library has neither the user's list
// of websites nor a hardened read, so fetching a list is for the caller, who
// also says which key is compared: the result says subject_source
// supplied_key, and aamio-python and aamio-php have the whole check.
//
// Take the domain from your own records and never from the message being
// checked: anyone can list their own key on their own site. A listed key says
// that this exact site listed this key when it was read. It is not an identity,
// an authority to act or proof that a message is true.
//
// encoding/json keeps the last of two members of the same name without a word,
// so it cannot hold the format's rule about duplicates, and the reader here is
// its own. testdata/domain_keys_vectors.json holds what every client answers.

// DomainKeysVersion and the limits of the format.
const (
	DomainKeysVersion  = 1
	DomainKeysPath     = "/.well-known/aamio-keys.json"
	DomainKeysMaxBytes = 16384
	DomainKeysMaxKeys  = 64
	domainMaxDepth     = 16
	domainMaxInteger   = 1<<53 - 1
)

var (
	domainKeyPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	domainNamePattern    = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	domainLabelPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	domainNumericPattern = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]+)$`)
)

// DomainKey is one entry on a list. Name is empty when it has none, and it
// labels and authorises nothing.
type DomainKey struct {
	Key  string
	Name string
}

// DomainMatch is what a list says about one key. Status is listed, not_listed
// or invalid, and not_listed is no evidence of fraud: a key rotated out, the
// wrong name or the wrong domain look the same. DocumentSHA256 is of the exact
// bytes compared, for comparison and fault finding; the domain did not sign it.
type DomainMatch struct {
	Status         string
	Reason         string
	Detail         string
	MatchedName    string
	DocumentSHA256 string
	SubjectSource  string
}

// InvalidDomainKeys is a list that is not version 1. Reason says why, without
// echoing the content.
type InvalidDomainKeys struct{ Reason string }

func (e *InvalidDomainKeys) Error() string { return "invalid domain key list: " + e.Reason }

// ErrInvalidDomain is a value that is not a plain host name.
var ErrInvalidDomain = errors.New("invalid_domain")

func invalidList(reason string) error { return &InvalidDomainKeys{Reason: reason} }

// CanonicalKey says whether value is a public key as aamio writes it: 32 bytes,
// 43 characters, one spelling only.
func CanonicalKey(value string) bool {
	if !domainKeyPattern.MatchString(value) {
		return false
	}
	// Strict refuses a last character carrying bits past the 32 bytes: it
	// decodes to the same bytes as another string, and only one is the key.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

// ValidDomainKeyName says whether a list can carry this name: 1 to 64
// characters of a-z, 0-9, dot, underscore and dash.
func ValidDomainKeyName(value string) bool { return domainNamePattern.MatchString(value) }

// NormaliseDomain gives the exact host a list is read from, in lowercase.
// Plain ASCII names of two labels or more. No port, path, IP literal, trailing
// dot, underscore or space is trimmed into shape. Internationalised names, xn--
// labels, wait until every client converts them the same way. www.example.org
// and example.org are different places, and no parent domain lends its list to
// a child.
func NormaliseDomain(value string) (string, error) {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return "", ErrInvalidDomain
		}
	}
	domain := strings.ToLower(value)
	labels := strings.Split(domain, ".")
	if len(domain) < 1 || len(domain) > 253 || len(labels) < 2 {
		return "", ErrInvalidDomain
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) || strings.HasPrefix(label, "xn--") {
			return "", ErrInvalidDomain
		}
	}
	// A last label of digits or hex is an old spelling of an IPv4 address.
	if domainNumericPattern.MatchString(labels[len(labels)-1]) {
		return "", ErrInvalidDomain
	}
	return domain, nil
}

// DomainKeysURL says where the list of this exact domain is, over HTTPS on the
// default port.
func DomainKeysURL(domain string) (string, error) {
	host, err := NormaliseDomain(domain)
	if err != nil {
		return "", err
	}
	return "https://" + host + DomainKeysPath, nil
}

// ParseDomainKeys gives the entries of a version 1 list, or *InvalidDomainKeys.
// A duplicate key, a duplicate member name in any object or one bad entry makes
// the whole document invalid: a list is never valid with the bad part left out.
func ParseDomainKeys(raw []byte) ([]DomainKey, error) {
	if len(raw) > DomainKeysMaxBytes {
		return nil, invalidList("body_limit")
	}
	if !utf8.Valid(raw) {
		return nil, invalidList("not_utf8")
	}
	if bytes.HasPrefix(raw, []byte("\xEF\xBB\xBF")) {
		return nil, invalidList("byte_order_mark")
	}
	reader := domainReader{text: raw}
	value, err := reader.value(1)
	if err != nil {
		return nil, err
	}
	reader.skip()
	if reader.at != len(raw) {
		return nil, invalidList("invalid_json")
	}
	document, ok := value.(map[string]any)
	if !ok {
		return nil, invalidList("object_required")
	}
	// int64 and nothing looser: 1.0, 1e0 and true are not the integer 1.
	if version, ok := document["aamio_keys"].(int64); !ok || version != DomainKeysVersion {
		return nil, invalidList("unsupported_version")
	}
	rows, ok := document["keys"].([]any)
	if !ok || len(rows) > DomainKeysMaxKeys {
		return nil, invalidList("invalid_keys")
	}
	seen := make(map[string]bool, len(rows))
	entries := make([]DomainKey, 0, len(rows))
	for _, row := range rows {
		object, ok := row.(map[string]any)
		if !ok {
			return nil, invalidList("invalid_key")
		}
		key, ok := object["key"].(string)
		if !ok || !CanonicalKey(key) {
			return nil, invalidList("invalid_key")
		}
		if seen[key] {
			return nil, invalidList("duplicate_key")
		}
		seen[key] = true
		entry := DomainKey{Key: key}
		// A name of null is a bad name and not a missing one.
		if name, present := object["name"]; present {
			text, ok := name.(string)
			if !ok || !ValidDomainKeyName(text) {
				return nil, invalidList("invalid_name")
			}
			entry.Name = text
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// MatchDomainKey says whether this exact document lists key, and under name
// when one is given; an empty name asks for any. The key is the caller's to
// choose and to answer for, which the result says as subject_source.
func MatchDomainKey(raw []byte, key, name string) DomainMatch {
	const source = "supplied_key"
	if !CanonicalKey(key) {
		return DomainMatch{Status: "invalid", Reason: "invalid_subject_key", SubjectSource: source}
	}
	if name != "" && !ValidDomainKeyName(name) {
		return DomainMatch{Status: "invalid", Reason: "invalid_requested_name", SubjectSource: source}
	}
	entries, err := ParseDomainKeys(raw)
	if err != nil {
		detail := err.Error()
		var invalid *InvalidDomainKeys
		if errors.As(err, &invalid) {
			detail = invalid.Reason
		}
		return DomainMatch{Status: "invalid", Reason: "invalid_document", Detail: detail, SubjectSource: source}
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	for _, entry := range entries {
		if entry.Key == key && (name == "" || entry.Name == name) {
			return DomainMatch{Status: "listed", Reason: "key_listed", MatchedName: entry.Name, DocumentSHA256: digest, SubjectSource: source}
		}
	}
	return DomainMatch{Status: "not_listed", Reason: "key_or_name_not_listed", DocumentSHA256: digest, SubjectSource: source}
}

// MakeDomainKeys writes the file for a site to publish. The bytes are fixed, so
// every generator gives the same file for the same list: two spaces of
// indentation, aamio_keys before keys, key before name, ASCII only, and a line
// break at the end. An empty list is allowed, since that is how a site says it
// lists no key, so callers ask for it on purpose. A list this would refuse to
// read is refused here as well.
func MakeDomainKeys(entries []DomainKey) ([]byte, error) {
	var rows []string
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !CanonicalKey(entry.Key) {
			return nil, invalidList("invalid_key")
		}
		if seen[entry.Key] {
			return nil, invalidList("duplicate_key")
		}
		seen[entry.Key] = true
		row := "    {\n      \"key\": \"" + entry.Key + "\""
		if entry.Name != "" {
			if !ValidDomainKeyName(entry.Name) {
				return nil, invalidList("invalid_name")
			}
			row += ",\n      \"name\": \"" + entry.Name + "\""
		}
		rows = append(rows, row+"\n    }")
	}
	if len(rows) > DomainKeysMaxKeys {
		return nil, invalidList("invalid_keys")
	}
	list := "[]"
	if len(rows) > 0 {
		list = "[\n" + strings.Join(rows, ",\n") + "\n  ]"
	}
	raw := []byte("{\n  \"aamio_keys\": " + strconv.Itoa(DomainKeysVersion) + ",\n  \"keys\": " + list + "\n}\n")
	if _, err := ParseDomainKeys(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// domainReader is JSON with the format's limits. An object comes back as a
// map[string]any, a list as []any, an integer as int64 and any other number as
// float64. Strings are bytes in Go, so two surrogate escapes in a row are one
// character, the same bytes as the character written out, and one on its own
// stays what it is, so two different ones are never taken for one name.
type domainReader struct {
	text []byte
	at   int
}

func (r *domainReader) peek() byte {
	if r.at < len(r.text) {
		return r.text[r.at]
	}
	return 0
}

func (r *domainReader) skip() {
	for r.at < len(r.text) {
		switch r.text[r.at] {
		case ' ', '\t', '\r', '\n':
			r.at++
		default:
			return
		}
	}
}

func (r *domainReader) value(level int) (any, error) {
	r.skip()
	if r.at >= len(r.text) {
		return nil, invalidList("invalid_json")
	}
	switch r.text[r.at] {
	case '{':
		return r.members(level)
	case '[':
		return r.rows(level)
	case '"':
		return r.str()
	}
	rest := r.text[r.at:]
	for word, meaning := range map[string]any{"true": true, "false": false, "null": nil} {
		if bytes.HasPrefix(rest, []byte(word)) {
			r.at += len(word)
			return meaning, nil
		}
	}
	return r.number()
}

func (r *domainReader) members(level int) (any, error) {
	if level > domainMaxDepth {
		return nil, invalidList("depth_limit")
	}
	r.at++
	found := map[string]any{}
	r.skip()
	if r.peek() == '}' && r.at < len(r.text) {
		r.at++
		return found, nil
	}
	for {
		r.skip()
		if r.at >= len(r.text) || r.text[r.at] != '"' {
			return nil, invalidList("invalid_json")
		}
		name, err := r.str()
		if err != nil {
			return nil, err
		}
		if _, twice := found[name]; twice {
			return nil, invalidList("duplicate_member")
		}
		r.skip()
		if r.at >= len(r.text) || r.text[r.at] != ':' {
			return nil, invalidList("invalid_json")
		}
		r.at++
		value, err := r.value(level + 1)
		if err != nil {
			return nil, err
		}
		found[name] = value
		r.skip()
		if r.at >= len(r.text) {
			return nil, invalidList("invalid_json")
		}
		next := r.text[r.at]
		r.at++
		if next == '}' {
			return found, nil
		}
		if next != ',' {
			return nil, invalidList("invalid_json")
		}
	}
}

func (r *domainReader) rows(level int) (any, error) {
	if level > domainMaxDepth {
		return nil, invalidList("depth_limit")
	}
	r.at++
	found := []any{}
	r.skip()
	if r.peek() == ']' && r.at < len(r.text) {
		r.at++
		return found, nil
	}
	for {
		value, err := r.value(level + 1)
		if err != nil {
			return nil, err
		}
		found = append(found, value)
		r.skip()
		if r.at >= len(r.text) {
			return nil, invalidList("invalid_json")
		}
		next := r.text[r.at]
		r.at++
		if next == ']' {
			return found, nil
		}
		if next != ',' {
			return nil, invalidList("invalid_json")
		}
	}
}

func (r *domainReader) str() (string, error) {
	r.at++
	var out []byte
	for {
		if r.at >= len(r.text) {
			return "", invalidList("invalid_json")
		}
		c := r.text[r.at]
		switch {
		case c == '"':
			r.at++
			return string(out), nil
		case c < 0x20:
			return "", invalidList("invalid_json")
		case c != '\\':
			out = append(out, c)
			r.at++
			continue
		}
		if r.at+1 >= len(r.text) {
			return "", invalidList("invalid_json")
		}
		escape := r.text[r.at+1]
		r.at += 2
		switch escape {
		case '"', '\\', '/':
			out = append(out, escape)
		case 'b':
			out = append(out, 0x08)
		case 'f':
			out = append(out, 0x0c)
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			unit, err := r.unit()
			if err != nil {
				return "", err
			}
			if unit >= 0xD800 && unit <= 0xDBFF && r.at+1 < len(r.text) && r.text[r.at] == '\\' && r.text[r.at+1] == 'u' {
				mark := r.at
				r.at += 2
				low, err := r.unit()
				if err != nil {
					return "", err
				}
				if low >= 0xDC00 && low <= 0xDFFF {
					unit = 0x10000 + (unit-0xD800)<<10 + (low - 0xDC00)
				} else {
					r.at = mark
				}
			}
			out = appendCodePoint(out, unit)
		default:
			return "", invalidList("invalid_json")
		}
	}
}

// unit reads the four hexadecimal digits of a \u escape.
func (r *domainReader) unit() (int, error) {
	if r.at+4 > len(r.text) {
		return 0, invalidList("invalid_json")
	}
	value := 0
	for _, c := range r.text[r.at : r.at+4] {
		switch {
		case c >= '0' && c <= '9':
			value = value<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			value = value<<4 | int(c-'a'+10)
		case c >= 'A' && c <= 'F':
			value = value<<4 | int(c-'A'+10)
		default:
			return 0, invalidList("invalid_json")
		}
	}
	r.at += 4
	return value, nil
}

// appendCodePoint writes UTF-8, a lone surrogate in the same three-byte form,
// where utf8.AppendRune would make every one the same replacement character.
func appendCodePoint(out []byte, point int) []byte {
	switch {
	case point < 0x80:
		return append(out, byte(point))
	case point < 0x800:
		return append(out, byte(0xC0|point>>6), byte(0x80|point&0x3F))
	case point < 0x10000:
		return append(out, byte(0xE0|point>>12), byte(0x80|(point>>6)&0x3F), byte(0x80|point&0x3F))
	}
	return append(out, byte(0xF0|point>>18), byte(0x80|(point>>12)&0x3F), byte(0x80|(point>>6)&0x3F), byte(0x80|point&0x3F))
}

func (r *domainReader) digits() int {
	from := r.at
	for r.at < len(r.text) && r.text[r.at] >= '0' && r.text[r.at] <= '9' {
		r.at++
	}
	return r.at - from
}

func (r *domainReader) number() (any, error) {
	start := r.at
	if r.peek() == '-' {
		r.at++
	}
	if r.peek() == '0' && r.at < len(r.text) {
		r.at++
	} else if r.digits() == 0 {
		return nil, invalidList("invalid_json")
	}
	float := false
	// A point or an exponent with no digit is not part of the number, and what
	// follows the number then fails as what it is.
	if r.peek() == '.' && r.at+1 < len(r.text) && r.text[r.at+1] >= '0' && r.text[r.at+1] <= '9' {
		r.at++
		r.digits()
		float = true
	}
	if c := r.peek(); c == 'e' || c == 'E' {
		mark := r.at
		r.at++
		if c := r.peek(); c == '+' || c == '-' {
			r.at++
		}
		if r.digits() == 0 {
			r.at = mark
		} else {
			float = true
		}
	}
	token := string(r.text[start:r.at])
	if float {
		value, _ := strconv.ParseFloat(token, 64)
		if math.IsInf(value, 0) || math.IsNaN(value) {
			return nil, invalidList("non_finite_number")
		}
		return value, nil
	}
	value, err := strconv.ParseInt(token, 10, 64)
	if err != nil || value > domainMaxInteger || value < -domainMaxInteger {
		return nil, invalidList("integer_range")
	}
	return value, nil
}
