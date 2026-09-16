// interop is the Go side of tests/interop.py: it reads one JSON object on
// stdin, opens what Python sealed, verifies what Python signed, seals and
// signs for Python, and prints one JSON object. Nothing touches the network.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	aamio "github.com/aisenseapi/aamio-go"
)

func main() {
	var in struct {
		GoSeed         string `json:"go_seed"`
		PyPublic       string `json:"py_public"`
		SigningInput   string `json:"signing_input"`
		PySignature    string `json:"py_signature"`
		PlaintextForPy string `json:"plaintext_for_py"`
		EnvelopeFromPy string `json:"envelope_from_py"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	keys, err := aamio.FromSeedHex(in.GoSeed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	opened, err := keys.Open(in.PyPublic, []byte(in.EnvelopeFromPy))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sealed, err := keys.Seal(in.PyPublic, []byte(in.PlaintextForPy))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := map[string]any{
		"go_public":             keys.Public,
		"opened":                string(opened),
		"py_signature_verifies": aamio.Verify(in.PyPublic, in.PySignature, in.SigningInput),
		"envelope_from_go":      sealed,
		"go_signature":          keys.Sign(in.SigningInput),
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
