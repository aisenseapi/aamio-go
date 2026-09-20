# Changelog

Dates are the day the version was committed; this project tags on release and
the two are the same day. Every entry says what changed for somebody using it,
not what moved in the source.

## 0.3.0 - 2026-09-20

The minor moves because a returned field changed name. `Check.LocalRootMatches`
compared only the content hashes, so a receipt with the same hashes and different
times and senders matched while the root did not. It is `LocalHashesMatch` now,
which is what it does.

## 0.2.6 - 2026-09-20

- `ReadLimited` and `ReadThreadLimited` ask the service for a small answer with
  `X-Limit` and `X-Max-Bytes`. A thread may hold two hundred messages of 65536
  bytes, so one read could be about a megabyte and there was no way to ask for less.
- `Read` and `ReadThread` keep the signatures they had and ask for nothing, so what
  compiled before compiles now.
- What the service left behind comes back untouched: `more`, and `too_large` naming
  a message that does not fit on its own.

## 0.2.5 - 2026-09-19

- RepliesThread reads the reply inbox with its list, and one bad message never ends a read

## 0.2.4 - 2026-09-18

- Read checks the hash and the signature itself, and ReadThread keeps the thread's own allowlist

## 0.2.3 - 2026-09-18

- work up to 32 bits within the time an inbox has, and a kept gate is asked again

## 0.2.2 - 2026-09-18

- Replies hands over everything it read
