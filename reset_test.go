package aamio

import "testing"

// The service has answered reset since 0.6.0, and this client never named it.
//
// reset means the cursor belongs to an earlier thread at the address: the one
// being read expired and was swept, and a write opened a new one there. Following
// next alone comes out right, and says nothing -- so a stranger's new thread at
// the same address arrives as if the conversation had continued.
func TestAnswerSaysWhenTheCursorBelongsToAnEarlierThread(t *testing.T) {
	answer := Answer{Status: 200, Body: map[string]any{
		"exists": true,
		"next":   float64(2),
		"reset": map[string]any{
			"after":  float64(91),
			"newest": float64(2),
			"what":   "after 91 is past the newest number this thread holds, 2",
		},
	}}

	got, ok := answer.Reset()

	if !ok {
		t.Fatal("an answer that read from the start said nothing about it")
	}

	if got.After != 91 || got.Newest != 2 {
		t.Fatalf("the numbers did not come through: %+v", got)
	}

	if got.What == "" {
		t.Fatal("and it said nothing in words, which is what a caller shows a person")
	}
}

func TestAnAnswerWithoutAResetSaysSo(t *testing.T) {
	answer := Answer{Status: 200, Body: map[string]any{"exists": true, "next": float64(2)}}

	if _, ok := answer.Reset(); ok {
		t.Fatal("an ordinary answer claimed the cursor was from another thread")
	}

	if _, ok := (Answer{Status: 200}).Reset(); ok {
		t.Fatal("an answer with no body at all claimed one too")
	}
}
