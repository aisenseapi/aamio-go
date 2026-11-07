package aamio

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The vectors every client that takes the format up shares, the same file
// aamio-python keeps.

type domainVectors struct {
	Documents []struct {
		Case  string  `json:"case"`
		Text  *string `json:"text"`
		B64   string  `json:"b64"`
		Valid bool    `json:"valid"`
		Keys  int     `json:"keys"`
	} `json:"documents"`
	Matches []struct {
		Case           string  `json:"case"`
		Text           string  `json:"text"`
		Key            string  `json:"key"`
		Name           string  `json:"name"`
		Status         string  `json:"status"`
		Reason         string  `json:"reason"`
		MatchedName    *string `json:"matched_name"`
		DocumentSHA256 string  `json:"document_sha256"`
	} `json:"matches"`
	Domains struct {
		Valid   [][2]string `json:"valid"`
		Invalid []string    `json:"invalid"`
	} `json:"domains"`
	Generated []struct {
		Case    string `json:"case"`
		Entries []struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"entries"`
		Text string `json:"text"`
	} `json:"generated"`
	Refused []struct {
		Case    string `json:"case"`
		Entries []struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"entries"`
	} `json:"refused"`
}

func loadDomainVectors(t *testing.T) domainVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/domain_keys_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors domainVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestDomainKeyVectorsAreTheSharedOnes(t *testing.T) {
	there, err := os.ReadFile("../aamio-python/tests/domain_keys_vectors.json")
	if err != nil {
		t.Skip("no aamio-python checkout beside this one")
	}
	here, err := os.ReadFile("testdata/domain_keys_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	// Compared without what a checkout does to line breaks.
	if strings.ReplaceAll(string(there), "\r\n", "\n") != strings.ReplaceAll(string(here), "\r\n", "\n") {
		t.Fatal("testdata/domain_keys_vectors.json differs from the one aamio-python keeps")
	}
}

func TestDomainKeyDocuments(t *testing.T) {
	for _, row := range loadDomainVectors(t).Documents {
		raw := []byte{}
		if row.Text != nil {
			raw = []byte(*row.Text)
		} else {
			decoded, err := base64.StdEncoding.DecodeString(row.B64)
			if err != nil {
				t.Fatal(row.Case, err)
			}
			raw = decoded
		}
		entries, err := ParseDomainKeys(raw)
		if row.Valid && (err != nil || len(entries) != row.Keys) {
			t.Errorf("%s: %v, %d keys", row.Case, err, len(entries))
		}
		if !row.Valid {
			var invalid *InvalidDomainKeys
			if !errors.As(err, &invalid) {
				t.Errorf("%s: read as valid, %v", row.Case, err)
			}
		}
	}
}

func TestDomainKeyMatches(t *testing.T) {
	for _, row := range loadDomainVectors(t).Matches {
		found := MatchDomainKey([]byte(row.Text), row.Key, row.Name)
		if found.Status != row.Status || (row.Reason != "" && found.Reason != row.Reason) {
			t.Errorf("%s: %+v", row.Case, found)
		}
		if row.MatchedName != nil && found.MatchedName != *row.MatchedName {
			t.Errorf("%s: matched %q", row.Case, found.MatchedName)
		}
		if found.DocumentSHA256 != row.DocumentSHA256 {
			t.Errorf("%s: hash %q", row.Case, found.DocumentSHA256)
		}
		if found.SubjectSource != "supplied_key" {
			t.Errorf("%s: the key was the caller's, and the result has to say so", row.Case)
		}
	}
}

func TestDomainKeyDomains(t *testing.T) {
	vectors := loadDomainVectors(t)
	for _, pair := range vectors.Domains.Valid {
		if got, err := NormaliseDomain(pair[0]); err != nil || got != pair[1] {
			t.Errorf("%q: %q, %v", pair[0], got, err)
		}
	}
	for _, domain := range vectors.Domains.Invalid {
		if got, err := NormaliseDomain(domain); !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("%q: %q", domain, got)
		}
	}
	if url, err := DomainKeysURL("Example.ORG"); err != nil || url != "https://example.org/.well-known/aamio-keys.json" {
		t.Errorf("%q, %v", url, err)
	}
	if _, err := DomainKeysURL("https://example.org"); err == nil {
		t.Error("the address is built from a host alone")
	}
}

func TestDomainKeysGenerated(t *testing.T) {
	vectors := loadDomainVectors(t)
	for _, row := range vectors.Generated {
		entries := []DomainKey{}
		for _, entry := range row.Entries {
			entries = append(entries, DomainKey{Key: entry.Key, Name: entry.Name})
		}
		raw, err := MakeDomainKeys(entries)
		if err != nil || string(raw) != row.Text {
			t.Errorf("%s: %q, %v", row.Case, raw, err)
		}
	}
	for _, row := range vectors.Refused {
		entries := []DomainKey{}
		for _, entry := range row.Entries {
			entries = append(entries, DomainKey{Key: entry.Key, Name: entry.Name})
		}
		if raw, err := MakeDomainKeys(entries); err == nil {
			t.Errorf("%s: wrote %q", row.Case, raw)
		}
	}
}

func TestAnInvalidDocumentSaysWhyWithoutItsContent(t *testing.T) {
	found := MatchDomainKey([]byte(`{"aamio_keys":2,"keys":[],"x":"secret text"}`), "29VTeOqp8srcy1SyPZ3NtHy9XBnLf4h7D2LDrCzo7S4", "")
	if found.Status != "invalid" || found.Reason != "invalid_document" || found.Detail != "unsupported_version" {
		t.Errorf("%+v", found)
	}
}
