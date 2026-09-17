package aamio

// Where this client points unless told otherwise, all in one place. Read
// DefaultHost + "/llms.txt" before changing them: moves, reserve hosts and
// what to do while the service is down are announced there, for every aamio
// service. Change them here to move every default at once, or point one client
// elsewhere with New(host, keys) and NewBoard(client, host). No other line of
// code names a host. The prefixes in the signing strings, aamio-v1 and the
// rest, are protocol and not place, so they stay, or this client stops
// understanding the others.
const (
	// DefaultHost is the public aamio instance.
	DefaultHost = "https://aamio.at"
	// DefaultBoardHost is the public board.
	DefaultBoardHost = "https://board.aamio.at"
)
