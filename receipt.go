package aamio

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ReceiptMessage is one line of a receipt: what passed, when, its hash, and who signed it.
type ReceiptMessage struct {
	Seq    int64   `json:"seq"`
	At     int64   `json:"at"`
	Sha256 string  `json:"sha256"`
	From   *string `json:"from"`
}

// Receipt is what GET /{w}/receipt answers: hashes, times, keys and one root, no content.
type Receipt struct {
	Schema     string           `json:"schema"`
	W          string           `json:"w"`
	CreatedAt  int64            `json:"created_at"`
	ExpireAt   int64            `json:"expire_at"`
	Count      int              `json:"count"`
	Bytes      int64            `json:"bytes"`
	Allow      []string         `json:"allow"`
	GateHash   string           `json:"gate_hash,omitempty"`
	Messages   []ReceiptMessage `json:"messages"`
	Keys       []string         `json:"keys"`
	Root       string           `json:"root"`
	Commitment string           `json:"commitment"`
	IssuedAt   int64            `json:"issued_at"`
	How        string           `json:"how"`
}

// Root recomputes the root: sha256 of the lines "seq<TAB>at<TAB>sha256<TAB>from-or-dash<LF>" in seq order.
func Root(messages []ReceiptMessage) string {
	sorted := append([]ReceiptMessage(nil), messages...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Seq < sorted[j].Seq })
	var lines strings.Builder
	for _, m := range sorted {
		from := "-"
		if m.From != nil && *m.From != "" {
			from = *m.From
		}
		fmt.Fprintf(&lines, "%d\t%d\t%s\t%s\n", m.Seq, m.At, m.Sha256, from)
	}
	sum := sha256.Sum256([]byte(lines.String()))
	return hex.EncodeToString(sum[:])
}

// Check is what a client can say about a receipt on its own: whether the
// lines hash to the root it claims, whether the commitment is that root in
// the sha256: form, and, given the hashes this process saw, whether they
// agree. LocalHashesMatch is nil when the receipt counts more messages than
// the client holds, which is a receipt taken later, not a failure.
type Check struct {
	RootAddsUp        bool
	CommitmentMatches bool
	LocalHashesMatch  *bool
}

// VerifyReceipt recomputes and compares. localHashes may be nil.
func VerifyReceipt(r *Receipt, localHashes []string) Check {
	root := Root(r.Messages)
	c := Check{
		RootAddsUp:        subtle.ConstantTimeCompare([]byte(root), []byte(r.Root)) == 1,
		CommitmentMatches: r.Commitment == "sha256:"+r.Root,
	}
	if localHashes != nil && len(r.Messages) < len(localHashes) {
		match := false
		c.LocalHashesMatch = &match
	} else if localHashes != nil && len(r.Messages) == len(localHashes) {
		match := true
		sorted := append([]ReceiptMessage(nil), r.Messages...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Seq < sorted[j].Seq })
		for i, m := range sorted {
			if localHashes[i] != m.Sha256 {
				match = false
				break
			}
		}
		c.LocalHashesMatch = &match
	}
	return c
}
