package aamio

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

// Envelope is the name a sealed body carries in its e2ee field.
const Envelope = "nacl.box.v1"

// Keys is one Ed25519 identity: it signs what leaves, seals to partners and
// opens what arrives. The X25519 pair used for sealing is derived from the
// Ed25519 pair the way libsodium does it, so a box sealed here opens in the
// other clients, and theirs open here.
type Keys struct {
	seed       []byte
	private    ed25519.PrivateKey
	curveSecret [32]byte
	// Public is the key as it travels: base64url, 43 characters.
	Public string
	// Hash is sha256 hex over the raw 32 bytes; HashPrefix its first 8.
	Hash       string
	HashPrefix string
}

// Generate makes a fresh identity from the system's CSPRNG.
func Generate() (*Keys, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return FromSeed(seed)
}

// FromSeed rebuilds an identity from its 32 seed bytes.
func FromSeed(seed []byte) (*Keys, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("a seed is 32 bytes")
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(public)
	k := &Keys{seed: append([]byte(nil), seed...), private: private, Public: B64url(public), Hash: hex.EncodeToString(sum[:])}
	k.HashPrefix = k.Hash[:8]
	// libsodium: crypto_sign_ed25519_sk_to_curve25519 is sha512(seed)[:32], clamped.
	h := sha512.Sum512(seed)
	copy(k.curveSecret[:], h[:32])
	k.curveSecret[0] &= 248
	k.curveSecret[31] &= 127
	k.curveSecret[31] |= 64
	return k, nil
}

// FromSeedHex is FromSeed over a hex string.
func FromSeedHex(s string) (*Keys, error) {
	seed, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return FromSeed(seed)
}

// Seed returns the 32 bytes to keep under a file with mode 600, and nowhere else.
func (k *Keys) Seed() []byte { return append([]byte(nil), k.seed...) }

// ----------------------------------------------------------------- signing --

// Sign returns a detached signature over the exact string, base64url.
func (k *Keys) Sign(input string) string {
	return B64url(ed25519.Sign(k.private, []byte(input)))
}

// Verify checks a signature by the holder of key over the exact string.
func Verify(key, signature, input string) bool {
	if !IsKey(key) {
		return false
	}
	pub, err := Unb64url(key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := Unb64url(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(input), sig)
}

// ThreadSigningInput is what a thread write is signed over.
func ThreadSigningInput(w string, body []byte) string {
	return "aamio-v1\n" + w + "\n" + Sha256Hex(body)
}

// PresenceSigningInput is what a presence publish is signed over.
func PresenceSigningInput(key string, body []byte) string {
	return "aamio-presence-v1\n" + key + "\n" + Sha256Hex(body)
}

// PresenceDeleteSigningInput is what a presence delete is signed over.
func PresenceDeleteSigningInput(key string, body []byte) string {
	return "aamio-presence-delete-v1\n" + key + "\n" + Sha256Hex(body)
}

// BoardSigningInput is what a board post is signed over.
func BoardSigningInput(key string, body []byte) string {
	return "aamio-board-v1\n" + key + "\n" + Sha256Hex(body)
}

// BoardDeleteSigningInput is what a board withdrawal is signed over.
func BoardDeleteSigningInput(id string, body []byte) string {
	return "aamio-board-delete-v1\n" + id + "\n" + Sha256Hex(body)
}

// ----------------------------------------------------------------- sealing --

// CurvePublic derives the X25519 public key from an Ed25519 public key, the
// way libsodium's crypto_sign_ed25519_pk_to_curve25519 does.
func CurvePublic(key string) ([32]byte, error) {
	var out [32]byte
	if !IsKey(key) {
		return out, errors.New("not a base64url Ed25519 public key of 32 bytes")
	}
	raw, err := Unb64url(key)
	if err != nil {
		return out, err
	}
	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return out, fmt.Errorf("not a point on the curve: %w", err)
	}
	copy(out[:], point.BytesMontgomery())
	return out, nil
}

// HashPrefixOf is the first 8 hex characters of sha256 over a key's raw bytes.
func HashPrefixOf(key string) (string, error) {
	raw, err := Unb64url(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:8], nil
}

type envelope struct {
	E2EE  string `json:"e2ee"`
	To    string `json:"to"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// Seal returns the envelope, as JSON text, sealed to the recipient's key. The
// recipient opens it with our public key.
func (k *Keys) Seal(recipientKey string, plaintext []byte) (string, error) {
	peer, err := CurvePublic(recipientKey)
	if err != nil {
		return "", err
	}
	to, _ := HashPrefixOf(recipientKey)
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	ct := box.Seal(nil, plaintext, &nonce, &peer, &k.curveSecret)
	out, err := JSON(envelope{E2EE: Envelope, To: to, Nonce: B64url(nonce[:]), CT: B64url(ct)})
	return string(out), err
}

// IsEnvelope says whether a body claims to be a sealed envelope.
func IsEnvelope(body []byte) bool {
	var e envelope
	if err := jsonUnmarshal(body, &e); err != nil {
		return false
	}
	return e.E2EE == Envelope && e.Nonce != "" && e.CT != ""
}

// Open opens an envelope sealed to us by the holder of senderKey.
func (k *Keys) Open(senderKey string, envelopeText []byte) ([]byte, error) {
	var e envelope
	if err := jsonUnmarshal(envelopeText, &e); err != nil || e.E2EE != Envelope {
		return nil, errors.New("not an envelope")
	}
	if e.To != k.HashPrefix {
		return nil, fmt.Errorf("this envelope is sealed to %s, not to %s", e.To, k.HashPrefix)
	}
	peer, err := CurvePublic(senderKey)
	if err != nil {
		return nil, err
	}
	nonceBytes, err := Unb64url(e.Nonce)
	if err != nil || len(nonceBytes) != 24 {
		return nil, errors.New("the nonce is not 24 bytes")
	}
	ct, err := Unb64url(e.CT)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	copy(nonce[:], nonceBytes)
	plain, ok := box.Open(nil, ct, &nonce, &peer, &k.curveSecret)
	if !ok {
		return nil, errors.New("the envelope does not open with this key pair")
	}
	return plain, nil
}
