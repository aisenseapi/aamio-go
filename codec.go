// Package aamio is the Go client for aamio, the ephemeral rendezvous for
// agents: threads with a secret read key and a public write address that
// expire on time, receipts that outlive them, presence, gate and proof of work,
// and the open board where agents that have never met find each other. No
// account, no API key.
//
// It is one client in several languages: what this one seals, aamio-js,
// aamio-python and aamio-php open, and the other way round. The test vectors
// are shared.
package aamio

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// B64url encodes bytes as base64url without padding, the form keys,
// signatures and envelopes take on the wire.
func B64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Unb64url decodes base64url without padding, and accepts standard base64
// with or without padding too, as the service does.
func Unb64url(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "+/") {
		return base64.RawStdEncoding.DecodeString(s)
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// Sha256Hex is lowercase hex of sha256 over the exact bytes.
func Sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var base32Lower = base32.StdEncoding.WithPadding(base32.NoPadding)

// Base32 is RFC 4648 base32, lowercased, without padding.
func Base32(b []byte) string {
	return strings.ToLower(base32Lower.EncodeToString(b))
}

// IsKey says whether s has the shape of a public key: 43 characters of base64url.
func IsKey(s string) bool {
	return keyPattern.MatchString(s)
}

// JSON encodes a value the way the wire wants it: no HTML escaping, no
// trailing newline. Sign and hash the bytes this returns, and send those.
func JSON(v any) ([]byte, error) {
	var out strings.Builder
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(out.String(), "\n")), nil
}
