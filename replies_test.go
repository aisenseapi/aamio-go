package aamio

import (
	"testing"
)

// Replies used to take a post id and drop everything that did not match. The
// cursor it hands back is the service's, counted over every message read, so a
// caller looping on it never saw the dropped ones again, and a library keeps
// no archive to find them in. The filter is gone. Everything read comes back.
func TestRepliesReturnsEverythingItRead(t *testing.T) {
	board, _ := board(t, func(r recorded) (int, string) {
		return 200, `{"next":7,"messages":[
			{"seq":5,"at":1,"verified":true,"from":"k","sha256":"a","body":"{\"post\":\"p1\",\"reply_to\":\"wwwwwwwwwwwwwwwwwwww\",\"text\":\"for p1\"}"},
			{"seq":6,"at":2,"verified":true,"from":"k","sha256":"b","body":"{\"post\":\"p2\",\"text\":\"for another post\"}"},
			{"seq":7,"at":3,"verified":true,"from":"k","sha256":"c","body":"a stranger answering in words"}
		]}`
	})

	_, replies, next := board.Replies("w"+"wwwwwwwwwwwwwwwwwww", "read-key", 0, 0)

	if len(replies) != 3 {
		t.Fatalf("every message read is an answer the caller gets to see, got %d", len(replies))
	}
	if replies[0].Post != "p1" || replies[1].Post != "p2" {
		t.Fatalf("an answer to another post is still handed over: %q %q", replies[0].Post, replies[1].Post)
	}
	if replies[2].Text != "" && replies[2].Post != "" {
		t.Fatalf("a plain text answer keeps its message and names no post")
	}
	// The cursor covers exactly what came back, so a caller that walks it
	// loses nothing.
	if next != 7 || replies[len(replies)-1].Message.Seq != 7 {
		t.Fatalf("the cursor is past the last message handed over, next=%d", next)
	}
}
