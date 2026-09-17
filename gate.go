package aamio

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

// The ceilings are the service's own, so an inbox run by a stranger can never
// make this client spend more CPU than aamio lets any inbox ask for.
const (
	RequireMaxBits = 20
	AdviseMaxBits  = 18
)

// ---------------------------------------------------------------- canonical --

// Canonical is the text a gate_hash is taken over: keys sorted by their UTF-8
// bytes at every level, no whitespace, integers as integers, an empty object
// as {}, empty buckets removed, strings escaped only where JSON requires it
// and otherwise raw UTF-8.
func Canonical(gate map[string]any) (string, error) {
	pruned := make(map[string]any, len(gate))
	for k, v := range gate {
		if (k == "require" || k == "advise") && isEmptyObject(v) {
			continue
		}
		pruned[k] = v
	}
	var out bytes.Buffer
	if err := canonicalEncode(&out, pruned); err != nil {
		return "", err
	}
	return out.String(), nil
}

// GateHash is sha256 hex over the canonical text.
func GateHash(gate map[string]any) (string, error) {
	text, err := Canonical(gate)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:]), nil
}

// ParseGate decodes gate JSON keeping integers as integers.
func ParseGate(text []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var gate map[string]any
	if err := dec.Decode(&gate); err != nil {
		return nil, err
	}
	return gate, nil
}

func isEmptyObject(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) == 0
}

func canonicalEncode(out *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		out.WriteString(value.String())
	case int:
		out.WriteString(strconv.Itoa(value))
	case int64:
		out.WriteString(strconv.FormatInt(value, 10))
	case float64:
		if value == float64(int64(value)) {
			out.WriteString(strconv.FormatInt(int64(value), 10))
		} else {
			out.WriteString(strconv.FormatFloat(value, 'f', -1, 64))
		}
	case string:
		canonicalString(out, value)
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := canonicalEncode(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte order, which is UTF-8 order
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			canonicalString(out, k)
			out.WriteByte(':')
			if err := canonicalEncode(out, value[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalise a %T", v)
	}
	return nil
}

// canonicalString escapes only what JSON requires: the quote, the backslash
// and control characters below 0x20. Everything else, including "/", U+2028
// and DEL, stays raw.
func canonicalString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				var buf [utf8.UTFMax]byte
				n := utf8.EncodeRune(buf[:], r)
				out.Write(buf[:n])
			}
		}
	}
	out.WriteByte('"')
}

// --------------------------------------------------------------------- work --

// PowInput is what thread work is computed over. key is the X-Key exactly as
// sent, or empty for an unsigned message, so two line breaks meet.
func PowInput(w, key, bodySha256, nonce string) string {
	return "aamio-pow-v1\n" + w + "\n" + key + "\n" + bodySha256 + "\n" + nonce
}

// PowDigest is sha256 over PowInput.
func PowDigest(w, key, bodySha256, nonce string) [32]byte {
	return sha256.Sum256([]byte(PowInput(w, key, bodySha256, nonce)))
}

// BoardPowInput is what board work is computed over: no address, a post is not to a thread.
func BoardPowInput(key, bodySha256, nonce string) string {
	return "aamio-board-pow-v1\n" + key + "\n" + bodySha256 + "\n" + nonce
}

// BoardPowDigest is sha256 over BoardPowInput.
func BoardPowDigest(key, bodySha256, nonce string) [32]byte {
	return sha256.Sum256([]byte(BoardPowInput(key, bodySha256, nonce)))
}

// ZeroBits counts leading zero bits from the top bit of the first byte.
func ZeroBits(digest []byte) int {
	bits := 0
	for _, b := range digest {
		if b == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); b&mask == 0; mask >>= 1 {
			bits++
		}
		break
	}
	return bits
}

// Solve finds the first nonce, counting from 0, whose thread digest reaches bits.
func Solve(w, key string, body []byte, bits int) (string, error) {
	if bits < 0 || bits > RequireMaxBits {
		return "", fmt.Errorf("work is 0 to %d bits", RequireMaxBits)
	}
	prefix := "aamio-pow-v1\n" + w + "\n" + key + "\n" + Sha256Hex(body) + "\n"
	for n := 0; ; n++ {
		d := sha256.Sum256([]byte(prefix + strconv.Itoa(n)))
		if ZeroBits(d[:]) >= bits {
			return strconv.Itoa(n), nil
		}
	}
}

// SolveBoard finds the first nonce whose board digest reaches bits.
func SolveBoard(key string, body []byte, bits int) (string, error) {
	if bits < 0 || bits > RequireMaxBits {
		return "", fmt.Errorf("work is 0 to %d bits", RequireMaxBits)
	}
	prefix := "aamio-board-pow-v1\n" + key + "\n" + Sha256Hex(body) + "\n"
	for n := 0; ; n++ {
		d := sha256.Sum256([]byte(prefix + strconv.Itoa(n)))
		if ZeroBits(d[:]) >= bits {
			return strconv.Itoa(n), nil
		}
	}
}

// --------------------------------------------------------------------- plan --

// Plan is what to do about an inbox's gate before writing: Bits to work for
// (-1 for none), Stop with the reason when the send must not happen, Notes for
// what was passed over.
type Plan struct {
	Bits  int
	Stop  string
	Notes []string
}

// PlanFor reads a gate and decides. A nil or empty gate is nothing to do.
func PlanFor(gate map[string]any) Plan {
	plan := Plan{Bits: -1}
	if len(gate) == 0 {
		return plan
	}
	known := map[string]bool{"pow": true, "per_key": true, "write_until": true}
	if require, ok := gate["require"].(map[string]any); ok {
		names := sortedKeys(require)
		for _, condition := range names {
			if !known[condition] {
				plan.Stop = fmt.Sprintf("the inbox requires %q, which this client does not know; nothing was sent", condition)
				return plan
			}
			if condition == "pow" {
				bits := bitsOf(require[condition])
				if bits > RequireMaxBits {
					plan.Stop = fmt.Sprintf("the inbox requires %d bits of work, above the %d aamio lets an inbox ask for; nothing was sent", bits, RequireMaxBits)
					return plan
				}
				if bits > plan.Bits {
					plan.Bits = bits
				}
			}
		}
	}
	if advise, ok := gate["advise"].(map[string]any); ok {
		for _, condition := range sortedKeys(advise) {
			if condition != "pow" {
				plan.Notes = append(plan.Notes, fmt.Sprintf("the inbox advises %q, which this client does not know, and it was passed over", condition))
				continue
			}
			bits := bitsOf(advise[condition])
			if bits > AdviseMaxBits {
				plan.Notes = append(plan.Notes, fmt.Sprintf("the inbox advises %d bits of work, above the %d a client does without asking, and it was passed over", bits, AdviseMaxBits))
				continue
			}
			if bits > plan.Bits {
				plan.Bits = bits
			}
		}
	}
	return plan
}

func bitsOf(v any) int {
	m, ok := v.(map[string]any)
	if !ok {
		return 0
	}
	switch b := m["bits"].(type) {
	case json.Number:
		n, _ := b.Int64()
		return int(n)
	case float64:
		return int(b)
	case int:
		return b
	}
	return 0
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// IsNonce says whether s is a valid X-Work value: 1 to 64 characters of [A-Za-z0-9_-].
func IsNonce(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

var errNoKeys = errors.New("this call needs keys")
