# Implementation Review Notes

This file records the implementation review context for the current completion
package. It replaces the older upstream gap summary, which described a partial
repository before the client/server integration was completed.

## Current Implementation Summary

The repository now contains a focused Unix raw-ICMP MVP:

- A SOCKS5 client binary that forwards `CONNECT` streams through ICMP Echo
  payloads.
- A server binary that receives IPv4 ICMP Echo and IPv6 ICMPv6 Echo traffic.
- An encrypted wire frame codec with direction-separated AEAD keys.
- Peer ACLs, target ACLs, target safety blocks, and rate limits.
- Per-peer session limits and per-session stream/pending queue limits.
- Async target connection setup using worker threads.
- Stream close auditing and idle cleanup.
- Optional SOCKS username/password authentication for non-loopback client
  listeners.

## Review Findings Already Addressed

The following issues were identified and fixed during review:

- Request and reply AEAD nonce/key reuse.
- Missing session-to-peer binding.
- Missing stale packet/replay rejection.
- Unbounded stream state, pending queues, and event queues.
- Stream/file descriptor leaks on normal `Fin` paths.
- Blocking target connection setup in the raw ICMP receive loop.
- Client accepting ICMP replies without checking the source address.
- Non-loopback SOCKS listener without mandatory authentication.
- Narrow default target blocking that allowed private/special ranges too
  easily.
- Lack of IPv6 ICMP transport support.
- README and docs lagging behind the implemented behavior.

## Remaining Design Limitations

These are known tradeoffs rather than accidental omissions:

- The client-driven polling model generates traffic for idle streams.
- The client serializes ICMP exchanges behind one raw socket mutex.
- The server uses one thread per target reader and one connector thread per
  pending open.
- Replay protection assumes serialized packet numbers. A future out-of-order
  transport needs a sliding replay window.
- The project is Linux/Unix-oriented. Windows support requires a separate ICMP
  API backend.
- CI can compile and test the code, but live raw ICMP tests require privileged
  hosts or VMs.

## Recommended Next Improvements

1. Add GitHub Actions for `fmt`, `clippy`, `test`, and release build.
2. Commit `Cargo.lock`.
3. Add integration tests using fake transports for session and stream state.
4. Add a `check-config` subcommand.
5. Add PSK loading from environment variables or a restricted file.
6. Add metrics for sessions, streams, pending bytes, rejects, and rate limits.
7. Consider an async/event-loop transport if higher concurrency becomes a goal.
