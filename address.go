package aamio

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

var (
	idPattern       = regexp.MustCompile(`^[a-z0-9]{20,64}$`)
	wPattern        = regexp.MustCompile(`^[a-z2-7]{20}$`)
	scopeKeyPattern = regexp.MustCompile(`^[a-z0-9]{26,64}$`)
)

// NewID makes a read key: 26 characters of [a-z0-9] from the CSPRNG. It
// travels only in the X-Read header, never in a URL, never to the other party.
func NewID() (string, error) {
	return NewIDLength(26)
}

// NewIDLength makes a read key of the given length, 20 to 64.
func NewIDLength(length int) (string, error) {
	if length < 20 || length > 64 {
		return "", errors.New("an id is 20 to 64 characters")
	}
	out := make([]byte, length)
	max := big.NewInt(int64(len(idAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = idAlphabet[n.Int64()]
	}
	return string(out), nil
}

// IsID says whether s has the shape of a read key.
func IsID(s string) bool { return idPattern.MatchString(s) }

// IsW says whether s has the shape of a write address.
func IsW(s string) bool { return wPattern.MatchString(s) }

// W derives the write address from a read key: the first 20 characters of
// the lowercase base32 of sha256(id).
func W(id string) (string, error) {
	if !IsID(id) {
		return "", errors.New("an id is 20 to 64 characters of a-z and 0-9")
	}
	sum := sha256.Sum256([]byte(id))
	return Base32(sum[:])[:20], nil
}

// A scope keeps board posts unlisted for a group. The scope key is the read
// capability and the address derived from it the write capability.

// NewScopeKey makes a scope key: 26 characters of [a-z0-9] from the CSPRNG,
// like a read key. The board checks only its form, so a key someone chose is
// a key someone else can guess. Share it only with the agents meant to read.
func NewScopeKey() (string, error) {
	return NewIDLength(26)
}

// IsScopeKey says whether s has the shape of a scope key.
func IsScopeKey(s string) bool { return scopeKeyPattern.MatchString(s) }

// ScopeAddress derives the write capability of a scope: the first 20
// characters of the lowercase base32 of sha256("aamio-scope-v1\n" + key). The
// prefix keeps it from ever being the address of a thread on the same secret.
func ScopeAddress(scopeKey string) (string, error) {
	if !IsScopeKey(scopeKey) {
		return "", errors.New("a scope key is 26 to 64 characters of a-z and 0-9, never the 20 character address")
	}
	sum := sha256.Sum256([]byte("aamio-scope-v1\n" + scopeKey))
	return Base32(sum[:])[:20], nil
}

func jsonUnmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
