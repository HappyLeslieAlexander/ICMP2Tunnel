# ICMP2Tunnel TODO

This file tracks the implementation plan for ICMP2Tunnel.

The project should be implemented in stages. Each stage should produce a testable, reviewable, and mergeable result.

---

## Milestone 0: Repository Bootstrap

Goal: create a clean Rust workspace that can compile and test before any ICMP-specific logic exists.

### Tasks

- [x] Create root Rust workspace.
- [x] Add `README.md`.
- [x] Add `framework.md`.
- [x] Add `todo.md`.
- [x] Add `LICENSE-MIT`.
- [x] Add `LICENSE-APACHE`.
- [x] Add `SECURITY.md`.
- [x] Add `ACCEPTABLE_USE.md`.
- [x] Add `rust-toolchain.toml`.
- [x] Add `deny.toml`.
- [x] Add `.gitignore`.
- [x] Add `.github/workflows/ci.yml`.
- [x] Add `.github/workflows/audit.yml`.
- [x] Add `.github/workflows/release.yml`.
- [x] Create `docs/` directory.
- [x] Create `examples/` directory.
- [x] Create `crates/` directory.
- [x] Create `tests/` directory.
- [x] Create `fuzz/` directory.
- [x] Create `packaging/` directory.

### Acceptance Criteria

- [x] `cargo fmt --check` passes.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [x] `cargo test --workspace` passes.
- [ ] `cargo deny check` passes.

---

## Milestone 1: Protocol Crate

Goal: implement the pure wire-protocol layer.

Crate:

```text
crates/icmp2tunnel-proto
```

### Tasks

- [x] Define protocol magic value: `I2T1`.
- [x] Define protocol version: `1`.
- [x] Define plain ICMP payload header.
- [x] Implement header encoding.
- [x] Implement header decoding.
- [x] Implement strict header validation.
- [x] Define packet flags.
- [x] Define packet direction bits.
- [x] Define encrypted mux frame format.
- [x] Implement mux frame encoding.
- [x] Implement mux frame decoding.
- [x] Define mux operations:
  - [x] `HELLO`
  - [x] `HELLO_REPLY`
  - [x] `OPEN`
  - [x] `OPEN_OK`
  - [x] `OPEN_ERR`
  - [x] `DATA`
  - [x] `ACK`
  - [x] `WINDOW`
  - [x] `FIN`
  - [x] `RST`
  - [x] `PING`
  - [x] `PONG`
- [x] Implement AEAD seal function.
- [x] Implement AEAD open function.
- [x] Use plain header as AEAD AAD.
- [x] Implement nonce derivation.
- [x] Implement PSK-based key derivation.
- [x] Implement replay window.
- [x] Implement constant-time authentication checks where applicable.
- [x] Add golden test vectors.
- [x] Add invalid-input tests.
- [x] Add maximum-size frame tests.
- [x] Add malformed-header tests.
- [x] Add malformed-ciphertext tests.

### Acceptance Criteria

- [x] `cargo test -p icmp2tunnel-proto` passes.
- [x] Decoders never panic on malformed input.
- [x] Golden vectors are stable.
- [x] Header and frame encoders are endian-explicit.
- [x] AEAD rejects modified headers.
- [x] AEAD rejects modified ciphertext.
- [x] Replay window rejects duplicated packet numbers.

---

## Milestone 2: Fuzz Targets

Goal: harden parsers before adding network input.

### Tasks

- [x] Add `cargo-fuzz` setup.
- [x] Add `fuzz_targets/frame_decode.rs`.
- [x] Add `fuzz_targets/socks_decode.rs`.
- [x] Add fuzz dictionary for protocol magic and mux opcodes.
- [x] Add CI job or manual documented fuzz command.
- [x] Ensure no decoder allocates unbounded memory from attacker-controlled length fields.

### Acceptance Criteria

- [x] `cargo fuzz run frame_decode` runs without crash.
- [x] `cargo fuzz run socks_decode` runs without crash.
- [x] Malformed input does not cause panic.
- [x] Malformed input does not cause excessive allocation.

---

## Milestone 3: SOCKS5 Crate

Goal: implement local SOCKS5 `CONNECT` support.

Crate:

```text
crates/icmp2tunnel-socks
```

### Tasks

- [x] Implement SOCKS5 method negotiation parser.
- [x] Support `NO AUTHENTICATION REQUIRED` for loopback use.
- [x] Reject unsupported authentication methods.
- [x] Implement SOCKS5 request parser.
- [x] Support `CONNECT`.
- [x] Support IPv4 target addresses.
- [x] Support IPv6 target addresses.
- [x] Support domain-name target addresses.
- [x] Reject `BIND`.
- [x] Reject `UDP ASSOCIATE` in MVP.
- [x] Implement SOCKS5 success reply.
- [x] Implement SOCKS5 failure replies.
- [x] Add local listener helper.
- [x] Add parser unit tests.
- [x] Add integration test with local TCP echo server.

### Acceptance Criteria

- [x] `cargo test -p icmp2tunnel-socks` passes.
- [x] `CONNECT` request can be parsed into a target address.
- [x] Invalid SOCKS versions are rejected.
- [x] Unsupported commands receive correct failure reply.
- [x] Listener binds to `127.0.0.1` by default.
- [x] Listener does not bind to `0.0.0.0` unless explicitly configured.

---

## Milestone 4: Fake Transport

Goal: build end-to-end tunnel logic without raw sockets.

Crates:

```text
crates/icmp2tunnel-transport
crates/icmp2tunnel-core
```

### Tasks

- [x] Define `ClientIcmp` trait.
- [x] Define `ServerIcmp` trait.
- [x] Define `InboundEcho`.
- [x] Define `ReplyToken`.
- [x] Implement fake in-memory client transport.
- [x] Implement fake in-memory server transport.
- [x] Add packet loss simulation.
- [x] Add packet duplication simulation.
- [x] Add packet reordering simulation.
- [x] Add artificial latency simulation.
- [x] Add test-only deterministic scheduler.

### Acceptance Criteria

- [x] Client and server can exchange fake ICMP payloads.
- [x] Fake transport can simulate packet loss.
- [x] Fake transport can simulate reordering.
- [x] Fake transport can simulate duplicates.
- [x] Fake transport enables deterministic integration tests.

---

## Milestone 5: Core Session State Machine

Goal: implement the tunnel session lifecycle.

Crate:

```text
crates/icmp2tunnel-core
```

### Tasks

- [x] Define `SessionId`.
- [x] Define `PacketNo`.
- [x] Define session states:
  - [x] `New`
  - [x] `HelloSent`
  - [x] `Established`
  - [x] `Draining`
  - [x] `Closed`
- [x] Implement client `HELLO`.
- [x] Implement server `HELLO_REPLY`.
- [x] Implement session key derivation.
- [x] Implement packet number allocation.
- [x] Implement ACK generation.
- [x] Implement ACK processing.
- [x] Implement replay protection integration.
- [x] Implement idle timeout.
- [x] Implement graceful shutdown.
- [x] Add unit tests for valid state transitions.
- [x] Add unit tests for invalid state transitions.

### Acceptance Criteria

- [x] Client can establish a session with server over fake transport.
- [x] Duplicate packets are rejected.
- [x] Out-of-window packets are rejected.
- [x] Session times out after configured idle timeout.
- [x] Invalid state transitions are rejected.

---

## Milestone 6: Stream Multiplexing

Goal: support multiple logical byte streams over one ICMP session.

### Tasks

- [x] Define `StreamId`.
- [x] Define stream states:
  - [x] `Idle`
  - [x] `Opening`
  - [x] `Open`
  - [x] `LocalHalfClosed`
  - [x] `RemoteHalfClosed`
  - [x] `Closed`
- [x] Implement `OPEN`.
- [x] Implement `OPEN_OK`.
- [x] Implement `OPEN_ERR`.
- [x] Implement `DATA`.
- [x] Implement `FIN`.
- [x] Implement `RST`.
- [x] Implement per-stream send offset.
- [x] Implement per-stream receive offset.
- [x] Implement reorder buffer.
- [x] Implement per-stream ACK.
- [x] Implement stream-level window update.
- [x] Implement stream table.
- [x] Implement stream limit per session.
- [x] Add tests for one stream.
- [x] Add tests for many concurrent streams.
- [x] Add tests for stream reset.
- [x] Add tests for half-close behavior.

### Acceptance Criteria

- [x] One stream can transfer ordered bytes.
- [x] Multiple streams can transfer concurrently.
- [x] Reordered frames are delivered in order.
- [x] Duplicate frames are ignored.
- [x] Stream reset is propagated to the peer.
- [x] Half-close is propagated correctly.

---

## Milestone 7: Reliability Layer

Goal: make the tunnel tolerate ICMP packet loss, duplication, and reordering.

### Tasks

- [x] Implement retransmission queue.
- [x] Implement retransmission timeout.
- [x] Implement RTO backoff.
- [x] Implement maximum retransmission count.
- [x] Implement bounded inflight packets.
- [x] Implement packet-level ACK.
- [x] Implement stream-level ACK.
- [x] Implement flow-control window.
- [x] Implement client poll scheduler.
- [x] Implement empty poll packet.
- [x] Implement downstream delivery in Echo Reply.
- [x] Implement backpressure from local TCP to tunnel.
- [x] Implement backpressure from tunnel to local TCP.
- [x] Add integration test with loss.
- [x] Add integration test with reordering.
- [x] Add integration test with duplication.
- [x] Add integration test with delayed replies.

### Acceptance Criteria

- [x] End-to-end TCP echo works over fake transport with packet loss.
- [x] End-to-end TCP echo works over fake transport with reordering.
- [x] End-to-end TCP echo works over fake transport with duplicates.
- [x] Memory usage remains bounded under stalled peer conditions.
- [x] Inflight packet count never exceeds configured limit.

---

## Milestone 8: Server ACL and Rate Limiting

Goal: prevent open-proxy behavior.

### Tasks

- [ ] Implement peer allowlist parser.
- [ ] Implement target allowlist parser.
- [ ] Support CIDR + port target rules.
- [ ] Support explicit host + port target rules.
- [ ] Reject unmatched peers.
- [ ] Reject unmatched targets.
- [ ] Reject loopback targets by default.
- [ ] Reject link-local targets by default.
- [ ] Reject metadata-service style addresses by default.
- [ ] Re-check resolved domain IPs against target ACL.
- [ ] Implement max sessions per peer.
- [ ] Implement max streams per session.
- [ ] Implement packet-per-second limit.
- [ ] Implement byte-per-second limit.
- [ ] Implement audit log record.
- [ ] Add ACL unit tests.
- [ ] Add rate-limit unit tests.

### Acceptance Criteria

- [ ] Server refuses unauthenticated peers.
- [ ] Server refuses targets not in allowlist.
- [ ] Server refuses wildcard egress unless explicitly configured.
- [ ] Domain targets are checked after DNS resolution.
- [ ] Audit logs include peer, target, bytes, duration, and close reason.

---

## Milestone 9: Client Binary

Goal: provide a usable local SOCKS5 client.

Binary:

```text
icmp2tunnel-client
```

### Tasks

- [x] Add `clap` CLI.
- [x] Add config file loading.
- [x] Add environment variable overrides.
- [x] Add structured logging.
- [x] Bind local SOCKS5 listener.
- [x] Refuse non-loopback listen address unless explicitly configured.
- [ ] Create ICMP client backend from platform detection.
- [ ] Create session to server.
- [ ] Map SOCKS5 connections to tunnel streams.
- [ ] Handle local TCP read shutdown.
- [ ] Handle local TCP write shutdown.
- [ ] Handle SIGINT/SIGTERM on Unix.
- [ ] Handle Ctrl-C on Windows.
- [ ] Add integration test using fake transport.

### Acceptance Criteria

- [x] Client starts with `examples/client.toml`.
- [x] Client listens on `127.0.0.1:1080`.
- [ ] Client can open stream for SOCKS5 `CONNECT`.
- [ ] Client can shut down gracefully.
- [ ] Client logs connection lifecycle events.

---

## Milestone 10: Server Binary

Goal: provide a usable GNU/Linux and FreeBSD server.

Binary:

```text
icmp2tunnel-server
```

### Tasks

- [x] Add `clap` CLI.
- [x] Add config file loading.
- [x] Add environment variable overrides.
- [x] Add structured logging.
- [ ] Create raw ICMP server backend.
- [ ] Authenticate session handshake.
- [ ] Enforce peer ACL.
- [ ] Enforce target ACL.
- [ ] Open target TCP connection.
- [ ] Forward target TCP bytes into tunnel stream.
- [ ] Forward tunnel stream bytes into target TCP.
- [ ] Enforce session limits.
- [ ] Enforce stream limits.
- [ ] Enforce rate limits.
- [ ] Emit audit logs.
- [ ] Handle graceful shutdown.

### Acceptance Criteria

- [x] Server starts with `examples/server.toml`.
- [ ] Server refuses missing auth config.
- [ ] Server refuses missing target ACL.
- [ ] Server accepts authenticated client over fake transport.
- [ ] Server opens allowlisted TCP target.
- [ ] Server rejects disallowed TCP target.
- [ ] Server shuts down gracefully.

---

## Milestone 11: GNU/Linux Backend

Goal: implement GNU/Linux client and server ICMP support.

Files:

```text
crates/icmp2tunnel-transport/src/linux.rs
```

### Tasks

- [ ] Implement raw ICMP server socket.
- [x] Implement ICMP Echo Request parsing.
- [x] Implement ICMP Echo Reply construction.
- [x] Preserve request identifier and sequence in replies.
- [x] Parse IPv4 header on receive.
- [x] Calculate ICMP checksum.
- [ ] Implement nonblocking socket integration.
- [ ] Implement Tokio `AsyncFd` wrapper.
- [ ] Implement GNU/Linux datagram ICMP client if available.
- [ ] Implement GNU/Linux raw ICMP client fallback.
- [ ] Detect missing permissions.
- [ ] Emit useful permission error messages.
- [ ] Add privileged ignored tests.
- [ ] Add manual smoke-test instructions.

### Acceptance Criteria

- [ ] Linux server receives Echo Request payload.
- [ ] Linux server sends Echo Reply payload.
- [ ] Linux client can exchange payload with Linux server.
- [ ] Missing `CAP_NET_RAW` produces a clear error.
- [ ] Privileged tests are opt-in.

---

## Milestone 12: FreeBSD Backend

Goal: implement FreeBSD client and server ICMP support.

Files:

```text
crates/icmp2tunnel-transport/src/freebsd.rs
```

### Tasks

- [ ] Implement raw ICMP server socket.
- [ ] Implement raw ICMP client socket.
- [ ] Parse received IPv4 header.
- [ ] Parse ICMP header.
- [ ] Construct Echo Request.
- [ ] Construct Echo Reply.
- [x] Preserve request identifier and sequence in replies.
- [x] Calculate ICMP checksum.
- [ ] Implement nonblocking socket integration.
- [ ] Implement Tokio `AsyncFd` wrapper.
- [ ] Detect missing root privileges.
- [ ] Add FreeBSD smoke-test instructions.
- [ ] Add FreeBSD CI job if runner is available.

### Acceptance Criteria

- [ ] FreeBSD server receives Echo Request payload.
- [ ] FreeBSD server sends Echo Reply payload.
- [ ] FreeBSD client can exchange payload with FreeBSD server.
- [ ] FreeBSD client can exchange payload with GNU/Linux server.
- [ ] Missing privileges produce a clear error.

---

## Milestone 13: Windows Client Backend

Goal: implement Windows ICMP client support.

Files:

```text
crates/icmp2tunnel-transport/src/windows.rs
```

### Tasks

- [ ] Bind `IcmpCreateFile`.
- [ ] Bind `IcmpSendEcho2`.
- [ ] Bind `IcmpCloseHandle`.
- [ ] Implement client `exchange()`.
- [ ] Allocate reply buffer safely.
- [ ] Parse ICMP reply payload.
- [ ] Filter unrelated replies.
- [ ] Filter unauthenticated replies.
- [ ] Support synchronous implementation first.
- [ ] Move blocking calls into `spawn_blocking` if needed.
- [ ] Add async event-based implementation later if useful.
- [ ] Add Windows build CI.
- [ ] Add Windows smoke-test instructions.

### Acceptance Criteria

- [ ] Windows client builds.
- [ ] Windows client can send Echo Request with payload.
- [ ] Windows client can receive Echo Reply with payload.
- [ ] Windows client can connect to GNU/Linux server.
- [ ] Unrelated Echo Replies are ignored.
- [ ] Invalid AEAD replies are ignored.

---

## Milestone 14: XNU/Darwin Client Backend

Goal: implement macOS / XNU client support.

Files:

```text
crates/icmp2tunnel-transport/src/darwin.rs
```

### Tasks

- [ ] Implement datagram ICMP socket.
- [ ] Construct Echo Request payload.
- [ ] Receive Echo Reply payload.
- [ ] Filter unrelated replies.
- [ ] Filter unauthenticated replies.
- [ ] Implement nonblocking socket integration.
- [ ] Implement Tokio `AsyncFd` wrapper.
- [ ] Add Darwin build CI.
- [ ] Add macOS smoke-test instructions.

### Acceptance Criteria

- [ ] Darwin client builds.
- [ ] Darwin client can exchange payload with GNU/Linux server.
- [ ] Darwin client can exchange payload with FreeBSD server.
- [ ] Unrelated Echo Replies are ignored.
- [ ] Invalid AEAD replies are ignored.

---

## Milestone 15: End-to-End MVP

Goal: run real SOCKS5-over-ICMP using at least one supported server and one supported client.

### Tasks

- [ ] Start local test HTTP server.
- [ ] Start `icmp2tunnel-server` on GNU/Linux.
- [ ] Start `icmp2tunnel-client` on GNU/Linux.
- [ ] Configure target allowlist for test HTTP server.
- [ ] Run `curl --socks5-hostname 127.0.0.1:1080 http://target/`.
- [ ] Repeat with HTTPS target if available.
- [ ] Repeat with Windows client.
- [ ] Repeat with Darwin client.
- [ ] Repeat with FreeBSD client.
- [ ] Capture packet traces for debugging.
- [ ] Document known performance limits.

### Acceptance Criteria

- [ ] HTTP request succeeds through tunnel.
- [ ] HTTPS request succeeds through tunnel.
- [ ] Disallowed target is rejected.
- [ ] Invalid PSK is rejected.
- [ ] Server audit log records the stream.
- [ ] Client and server exit cleanly.

---

## Milestone 16: Packaging

Goal: make ICMP2Tunnel installable for practical testing.

### GNU/Linux

- [ ] Add `packaging/systemd/icmp2tunnel-server.service`.
- [ ] Add example `/etc/icmp2tunnel/server.toml`.
- [ ] Document `CAP_NET_RAW` setup.
- [ ] Document rootless limitations.
- [ ] Add release archive layout.

### FreeBSD

- [ ] Add `packaging/freebsd/rc.d/icmp2tunnel_server`.
- [ ] Add example `/usr/local/etc/icmp2tunnel/server.toml`.
- [ ] Document root requirement.
- [ ] Add FreeBSD build instructions.

### Windows

- [ ] Add `packaging/windows/install-service.ps1`.
- [ ] Add client config example.
- [ ] Document Windows ICMP backend.
- [ ] Document firewall prompts if applicable.

### Acceptance Criteria

- [ ] Linux server can be started by systemd.
- [ ] FreeBSD server can be started by rc.d.
- [ ] Windows client can be launched from packaged binary.
- [ ] Release artifacts include example configs.

---

## Milestone 17: Documentation

Goal: make the project understandable and auditable.

### Required Documents

- [ ] `README.md`
- [ ] `framework.md`
- [ ] `todo.md`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/WIRE_PROTOCOL.md`
- [ ] `docs/PLATFORM_BACKENDS.md`
- [ ] `docs/SECURITY_MODEL.md`
- [ ] `docs/PERFORMANCE.md`
- [ ] `docs/TESTING.md`
- [ ] `SECURITY.md`
- [ ] `ACCEPTABLE_USE.md`

### README Sections

- [ ] Project summary.
- [ ] Supported platforms.
- [ ] Security model.
- [ ] Non-goals.
- [ ] Build instructions.
- [ ] Client configuration.
- [ ] Server configuration.
- [ ] GNU/Linux permissions.
- [ ] FreeBSD permissions.
- [ ] Windows notes.
- [ ] Darwin notes.
- [ ] Troubleshooting.
- [ ] Development commands.
- [ ] License.

### Acceptance Criteria

- [ ] New contributor can understand the architecture.
- [ ] New contributor can run fake-transport tests.
- [ ] Operator can understand required privileges.
- [ ] Operator can configure ACLs safely.
- [ ] Security expectations are explicit.

---

## Milestone 18: Hardening

Goal: reduce attack surface and operational risk.

### Tasks

- [ ] Add structured audit logs.
- [ ] Add configurable log redaction.
- [ ] Add panic-free parser policy.
- [ ] Add memory bounds to all queues.
- [ ] Add stream buffer size limits.
- [ ] Add session expiration.
- [ ] Add peer rate limits.
- [ ] Add per-target connection limits.
- [ ] Add authentication failure backoff.
- [ ] Add optional Prometheus metrics.
- [ ] Add tests for resource exhaustion.
- [ ] Add tests for invalid authentication.
- [ ] Add tests for replay attempts.
- [ ] Add tests for oversized frames.
- [ ] Add tests for excessive stream creation.

### Acceptance Criteria

- [ ] Malformed packets do not crash the server.
- [ ] Malformed packets do not allocate unbounded memory.
- [ ] Unauthenticated peers cannot create streams.
- [ ] Replayed packets are rejected.
- [ ] Server remains responsive under rejected traffic.

---

## Milestone 19: Performance Work

Goal: improve throughput and latency after correctness is established.

### Tasks

- [ ] Measure baseline RTT.
- [ ] Measure payload efficiency.
- [ ] Measure effective throughput.
- [ ] Measure loss recovery time.
- [ ] Tune default poll interval.
- [ ] Tune default payload size.
- [ ] Tune inflight packet limit.
- [ ] Implement adaptive RTO.
- [ ] Implement PMTU probing.
- [ ] Implement pacing.
- [ ] Consider BBR-like delivery-rate estimation.
- [ ] Add benchmark harness.
- [ ] Add performance documentation.

### Acceptance Criteria

- [ ] Benchmark results are reproducible.
- [ ] Defaults are justified by measurements.
- [ ] Performance tuning does not break reliability.
- [ ] High-loss behavior remains bounded.

---

## Milestone 20: Post-MVP Features

These are not required for the first working version.

### Possible Extensions

- [ ] ICMPv6 support.
- [ ] SOCKS5 `UDP ASSOCIATE`.
- [ ] Public-key authentication.
- [ ] Noise protocol handshake.
- [ ] Multi-server failover.
- [ ] Session resumption.
- [ ] Prometheus exporter.
- [ ] Web admin status endpoint bound to loopback.
- [ ] Windows service mode.
- [ ] FreeBSD port skeleton.
- [ ] Homebrew formula.
- [ ] Debian package.
- [ ] RPM package.

---

## Current Recommended Implementation Order

Use this order unless there is a strong reason to change it:

```text
1. Repository bootstrap
2. Protocol crate
3. Fuzz targets
4. SOCKS5 crate
5. Fake transport
6. Core session state machine
7. Stream multiplexing
8. Reliability layer
9. Server ACL and rate limiting
10. Client binary
11. Server binary
12. GNU/Linux backend
13. [x] FreeBSD backend
14. [x] Windows client backend
15. XNU/Darwin client backend
16. End-to-end MVP
17. Packaging
18. Documentation
19. Hardening
20. Performance work
```
