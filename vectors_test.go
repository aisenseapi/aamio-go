package aamio

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The vectors every client shares, reproduced here with nothing in between.
// testdata/vectors.json is the file aamio-js keeps; the gate vectors are the
// ones the service, aamio-python and aamio-php check.

type vectors struct {
	Sha256Abc string `json:"sha256_abc"`
	ID        string `json:"id"`
	W         string `json:"w"`
	A         struct {
		Seed, Public, CurvePublic, Hash string
	} `json:"a"`
	B struct {
		Seed, Public, CurvePublic string
	} `json:"b"`
	Body             string  `json:"body"`
	SignInput        string  `json:"signInput"`
	Signature        string  `json:"signature"`
	Plaintext        string  `json:"plaintext"`
	EnvelopeFromAToB string  `json:"envelopeFromAToB"`
	Receipt          Receipt `json:"receipt"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEncodings(t *testing.T) {
	v := load(t)
	if Sha256Hex([]byte("abc")) != v.Sha256Abc {
		t.Fatal("sha256 of abc")
	}
	if B64url([]byte{0xfb, 0xff}) != "-_8" {
		t.Fatal("base64url")
	}
	if b, err := Unb64url("+/8="); err != nil || string(b) != "\xfb\xff" {
		t.Fatal("standard base64 with padding is accepted too")
	}
	if !IsKey(v.A.Public) || IsKey("short") {
		t.Fatal("key shape")
	}
}

func TestAddresses(t *testing.T) {
	v := load(t)
	if w, _ := W(v.ID); w != v.W {
		t.Fatalf("w(%s) = %s, want %s", v.ID, w, v.W)
	}
	if w, _ := W("aamio0000000000000000000ok"); w != "5d6gubrpdewztqru2nmi" {
		t.Fatal("w(aamio…ok)")
	}
	id, err := NewID()
	if err != nil || len(id) != 26 || !IsID(id) {
		t.Fatal("a fresh id is 26 characters of the alphabet")
	}
	if w, _ := W(id); !IsW(w) {
		t.Fatal("w shape")
	}
	if _, err := W("short"); err == nil {
		t.Fatal("a short id is refused before it is hashed")
	}
}

func TestKeys(t *testing.T) {
	v := load(t)
	a, err := FromSeedHex(v.A.Seed)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := FromSeedHex(v.B.Seed)
	if a.Public != v.A.Public || b.Public != v.B.Public {
		t.Fatal("public keys from seeds")
	}
	if a.Hash != v.A.Hash || a.HashPrefix != v.A.Hash[:8] {
		t.Fatal("hash of A")
	}
	if ca, _ := CurvePublic(a.Public); hex.EncodeToString(ca[:]) != v.A.CurvePublic {
		t.Fatal("X25519 public of A")
	}
	if cb, _ := CurvePublic(b.Public); hex.EncodeToString(cb[:]) != v.B.CurvePublic {
		t.Fatal("X25519 public of B")
	}
	if ThreadSigningInput(v.W, []byte(v.Body)) != v.SignInput {
		t.Fatal("thread signing input")
	}
	if a.Sign(v.SignInput) != v.Signature {
		t.Fatal("signature of A over it, byte for byte")
	}
	if !Verify(a.Public, v.Signature, v.SignInput) || Verify(b.Public, v.Signature, v.SignInput) || Verify(a.Public, v.Signature, v.SignInput+"x") {
		t.Fatal("verify")
	}
	again, _ := FromSeed(a.Seed())
	if again.Public != a.Public {
		t.Fatal("a key rebuilt from its seed is the same key")
	}
}

func TestSealing(t *testing.T) {
	v := load(t)
	a, _ := FromSeedHex(v.A.Seed)
	b, _ := FromSeedHex(v.B.Seed)
	opened, err := b.Open(a.Public, []byte(v.EnvelopeFromAToB))
	if err != nil || string(opened) != v.Plaintext {
		t.Fatalf("B opens the envelope A sealed, made by PyNaCl: %v %q", err, opened)
	}
	env, err := a.Seal(b.Public, []byte("fra go til hvem som helst"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(env, `{"e2ee":"nacl.box.v1","to":"`+b.HashPrefix+`","nonce":"`) || !IsEnvelope([]byte(env)) {
		t.Fatalf("envelope shape: %s", env)
	}
	if plain, err := b.Open(a.Public, []byte(env)); err != nil || string(plain) != "fra go til hvem som helst" {
		t.Fatal("B opens what A sealed here")
	}
	if _, err := a.Open(b.Public, []byte(env)); err == nil || !strings.Contains(err.Error(), "sealed to") {
		t.Fatal("A cannot open an envelope sealed to B, and is told whom it was sealed to")
	}
	stranger, _ := Generate()
	if _, err := b.Open(stranger.Public, []byte(env)); err == nil {
		t.Fatal("does not open with the wrong sender key")
	}
	other, _ := a.Seal(b.Public, []byte("x"))
	if other == env {
		t.Fatal("a fresh nonce every time")
	}
}

func TestReceipt(t *testing.T) {
	v := load(t)
	if Root(v.Receipt.Messages) != v.Receipt.Root {
		t.Fatal("the root recomputed from the lines is the published root")
	}
	c := VerifyReceipt(&v.Receipt, nil)
	if !c.RootAddsUp || !c.CommitmentMatches || c.LocalRootMatches != nil {
		t.Fatal("root_adds_up and commitment_matches on a real receipt, local unknown")
	}
	reversed := []ReceiptMessage{v.Receipt.Messages[1], v.Receipt.Messages[0]}
	if Root(reversed) != v.Receipt.Root {
		t.Fatal("the order the lines arrive in does not matter, seq does")
	}
	broken := v.Receipt
	broken.Messages = append([]ReceiptMessage(nil), v.Receipt.Messages...)
	broken.Messages[0].Sha256 = strings.Repeat("0", 64)
	if VerifyReceipt(&broken, nil).RootAddsUp {
		t.Fatal("one changed hash breaks the root")
	}
	hashes := []string{v.Receipt.Messages[0].Sha256, v.Receipt.Messages[1].Sha256}
	if c := VerifyReceipt(&v.Receipt, hashes); c.LocalRootMatches == nil || !*c.LocalRootMatches {
		t.Fatal("local hashes that match say so")
	}
	if c := VerifyReceipt(&v.Receipt, hashes[:1]); c.LocalRootMatches != nil {
		t.Fatal("fewer local hashes than the receipt counts is nil, not a failure")
	}
}

const (
	gateW      = "b4netymg7r5nnt2yiscp"
	gateKey    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	gateBody   = `{"post":"abc","reply_to":"xyz","text":"hei"}`
	gateSha256 = "36751f20147f74e3dfbaf829fb8f04ea9ed596268bd685a69fdfa5992fddd6b8"
)

func TestGateVectors(t *testing.T) {
	if Sha256Hex([]byte(gateBody)) != gateSha256 {
		t.Fatal("the vector body hashes to the published sha256")
	}
	signed := PowDigest(gateW, gateKey, gateSha256, "7036")
	if hex.EncodeToString(signed[:]) != "00003a2ac769f2265d621969d9ff1feaaa2b9dcc6f006b6adae1d22c2db8a842" || ZeroBits(signed[:]) != 18 {
		t.Fatal("signed: nonce 7036")
	}
	unsigned := PowDigest(gateW, "", gateSha256, "91617")
	if hex.EncodeToString(unsigned[:]) != "000018b5cc286cf27d2c97296aff9e2e60db0c165e7cf3af7a44857423c08612" || ZeroBits(unsigned[:]) != 19 {
		t.Fatal("unsigned: nonce 91617")
	}
	if !strings.Contains(PowInput(gateW, "", gateSha256, "1"), "\n\n") {
		t.Fatal("an unsigned message puts an empty key in the input")
	}
	for _, d := range [][32]byte{
		PowDigest(gateW, strings.Repeat("B", 43), gateSha256, "7036"),
		PowDigest(gateW, "", gateSha256, "7036"),
		PowDigest("aaaaaaaaaaaaaaaaaaaa", gateKey, gateSha256, "7036"),
		PowDigest(gateW, gateKey, strings.Repeat("0", 64), "7036"),
	} {
		if ZeroBits(d[:]) >= 16 {
			t.Fatal("work is bound to what it was done for")
		}
	}
	if ZeroBits(make([]byte, 32)) != 256 || ZeroBits(append([]byte{0x00, 0x0f}, make([]byte, 30)...)) != 12 || ZeroBits([]byte{0x80}) != 0 || ZeroBits([]byte{0x01}) != 7 {
		t.Fatal("zero bits from the top bit of the first byte")
	}
	nonce, err := Solve(gateW, gateKey, []byte(gateBody), 8)
	if err != nil || !IsNonce(nonce) {
		t.Fatal(err)
	}
	if d := PowDigest(gateW, gateKey, gateSha256, nonce); ZeroBits(d[:]) < 8 {
		t.Fatal("solve reaches the bits")
	}
	bn, _ := SolveBoard(gateKey, []byte(gateBody), 6)
	if d := BoardPowDigest(gateKey, gateSha256, bn); ZeroBits(d[:]) < 6 {
		t.Fatal("board work solves the same way")
	}
}

func TestCanonical(t *testing.T) {
	g, _ := ParseGate([]byte(`{"advise":{"pow":{"covers":1,"bits":16}},"require":{}}`))
	if c, _ := Canonical(g); c != `{"advise":{"pow":{"bits":16,"covers":1}}}` {
		t.Fatalf("keys sorted, empty bucket removed: %s", c)
	}
	if h, _ := GateHash(g); h != "de2a8fd4c8d7cbf9f6839c810632caf2c4b40fd8ba99ad19678f6c5b063d4d64" {
		t.Fatal("published gate_hash")
	}
	e, _ := ParseGate([]byte(`{"require":{},"advise":{}}`))
	if c, _ := Canonical(e); c != "{}" {
		t.Fatal("an empty gate is {}")
	}
	if h, _ := GateHash(e); h != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Fatal("hash of {}")
	}
	points := []rune{0x61, 0x22, 0x62, 0x5C, 0x63, 0x2F, 0x64, 0x01, 0x65, 0x1F, 0x66, 0x0A, 0x67, 0xE6, 0x68, 0x2028, 0x69, 0x1F600, 0x6A, 0x7F}
	c, _ := Canonical(map[string]any{"s": string(points)})
	if hex.EncodeToString([]byte(c)) != "7b2273223a22615c22625c5c632f645c7530303031655c7530303166665c6e67c3a668e280a869f09f98806a7f227d" {
		t.Fatalf("string escaping: %x", c)
	}
	if Sha256Hex([]byte(c)) != "b089754be373b84fb2b5fd2d6db856363986712915c98a5f7a412ff38b313b63" {
		t.Fatal("and hashes to the published value")
	}
}

func TestPlan(t *testing.T) {
	if p := PlanFor(nil); p.Bits != -1 || p.Stop != "" {
		t.Fatal("no gate: nothing to do")
	}
	g, _ := ParseGate([]byte(`{"advise":{"pow":{"bits":16,"covers":1}}}`))
	if p := PlanFor(g); p.Bits != 16 || p.Stop != "" {
		t.Fatal("advised 16 bits are done without asking")
	}
	g, _ = ParseGate([]byte(`{"advise":{"pow":{"bits":19}}}`))
	if p := PlanFor(g); p.Bits != -1 || len(p.Notes) != 1 {
		t.Fatal("advised 19 bits are passed over with a note")
	}
	g, _ = ParseGate([]byte(`{"require":{"pow":{"bits":20,"covers":1},"per_key":3,"write_until":1800000000}}`))
	if p := PlanFor(g); p.Bits != 20 || p.Stop != "" {
		t.Fatal("required 20 bits are done; per_key and write_until are known")
	}
	g, _ = ParseGate([]byte(`{"require":{"pow":{"bits":21}}}`))
	if p := PlanFor(g); !strings.Contains(p.Stop, "21") {
		t.Fatal("required 21 bits stop the send")
	}
	g, _ = ParseGate([]byte(`{"require":{"captcha":true}}`))
	if p := PlanFor(g); !strings.Contains(p.Stop, "captcha") {
		t.Fatal("an unknown requirement stops the send and names it")
	}
	g, _ = ParseGate([]byte(`{"advise":{"captcha":true,"pow":{"bits":8}}}`))
	if p := PlanFor(g); p.Stop != "" || p.Bits != 8 || len(p.Notes) != 1 {
		t.Fatal("an unknown advice is passed over, the known one is done")
	}
}
