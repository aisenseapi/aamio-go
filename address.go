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
	idPattern = regexp.MustCompile(`^[a-z0-9]{20,64}$`)
	wPattern  = regexp.MustCompile(`^[a-z2-7]{20}$`)
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

func jsonUnmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
