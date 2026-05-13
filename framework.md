# ICMP2Tunnel Framework

ICMP2Tunnel is an experimental Rust implementation of an authenticated, auditable SOCKS5-over-ICMP Echo transport for controlled networks, diagnostic environments, and explicitly authorized infrastructure.

The project provides:

- A local SOCKS5 client.
- An ICMP Echo Request / Echo Reply transport layer.
- A reliable multiplexed stream protocol over ICMP.
- GNU/Linux and FreeBSD server support.
- GNU/Linux, FreeBSD, Windows, and XNU/Darwin client support.

ICMP2Tunnel is not designed as a stealth channel, an access-control bypass mechanism, or an open proxy. The server must require peer authentication, target allowlists, rate limits, and audit logging.

---

## 1. Design Summary

ICMP2Tunnel uses a client-driven polling architecture.

The client listens locally as a SOCKS5 server. Applications connect to the local SOCKS5 endpoint. Each SOCKS5 `CONNECT` request becomes a logical stream inside an authenticated encrypted ICMP tunnel.

The tunnel uses ICMP Echo Request and Echo Reply payloads.

The client sends:

```text
ICMP Echo Request:
  ICMP2Tunnel protocol frames
```

The server replies:

```text
ICMP Echo Reply:
  pending downstream protocol frames
```

The server does not rely on unsolicited ICMP packets for downstream delivery. Downstream traffic is returned only in response to client Echo Requests.

This model gives better portability, especially on Windows, where the preferred client backend is the operating system ICMP API rather than a raw socket receiver.

---

## 2. High-Level Data Path

```text
Client Host                                      Server Host
===========                                      ===========

┌─────────────────────────────┐                 ┌─────────────────────────────┐
│ Application                 │                 │ Target TCP Service          │
│ browser / curl / ssh / app  │                 │ 10.0.0.5:443, etc.         │
└──────────────┬──────────────┘                 └──────────────┬──────────────┘
               │ SOCKS5 CONNECT                                │ TCP
               │                                                │
┌──────────────▼──────────────┐                 ┌──────────────▼──────────────┐
│ icmp2tunnel-client          │                 │ icmp2tunnel-server          │
│                             │                 │                              │
│ - local SOCKS5 listener     │                 │ - raw ICMP listener         │
│ - SOCKS5 parser             │                 │ - peer authentication       │
│ - stream multiplexer        │                 │ - target ACL enforcement    │
│ - reliability layer         │                 │ - stream multiplexer        │
│ - ICMP client backend       │                 │ - TCP connector             │
└──────────────┬──────────────┘                 └──────────────┬──────────────┘
               │                                                │
               │ ICMP Echo Request / Echo Reply                  │
               └────────────────────────────────────────────────┘
```

---

## 3. Supported Platforms

| Platform | Client | Server | Preferred Backend |
|---|---:|---:|---|
| GNU/Linux | Yes | Yes | Datagram ICMP client if available, raw ICMP fallback; raw ICMP server |
| FreeBSD | Yes | Yes | Raw ICMP |
| Windows | Yes | No | Windows ICMP API |
| XNU/Darwin/macOS | Yes | No | Datagram ICMP where available |

Server support is intentionally limited to GNU/Linux and FreeBSD.

Client support targets GNU/Linux, FreeBSD, Windows, and XNU/Darwin.

---

## 4. Repository Layout

```text
ICMP2Tunnel/
├── Cargo.toml
├── README.md
├── framework.md
├── todo.md
├── LICENSE-APACHE
├── LICENSE-MIT
├── SECURITY.md
├── ACCEPTABLE_USE.md
├── deny.toml
├── rust-toolchain.toml
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── audit.yml
│       └── release.yml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── WIRE_PROTOCOL.md
│   ├── PLATFORM_BACKENDS.md
│   ├── SECURITY_MODEL.md
│   ├── PERFORMANCE.md
│   └── TESTING.md
├── examples/
│   ├── client.toml
│   └── server.toml
├── crates/
│   ├── icmp2tunnel-proto/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── frame.rs
│   │       ├── codec.rs
│   │       ├── crypto.rs
│   │       └── error.rs
│   ├── icmp2tunnel-socks/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── handshake.rs
│   │       ├── request.rs
│   │       └── server.rs
│   ├── icmp2tunnel-transport/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── traits.rs
│   │       ├── linux.rs
│   │       ├── freebsd.rs
│   │       ├── darwin.rs
│   │       └── windows.rs
│   ├── icmp2tunnel-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── session.rs
│   │       ├── stream.rs
│   │       ├── retransmit.rs
│   │       ├── scheduler.rs
│   │       ├── acl.rs
│   │       └── config.rs
│   ├── icmp2tunnel-client/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── app.rs
│   │       └── cli.rs
│   └── icmp2tunnel-server/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── app.rs
│           └── cli.rs
├── tests/
│   ├── integration_fake_transport.rs
│   └── golden_frames.rs
├── fuzz/
│   └── fuzz_targets/
│       ├── frame_decode.rs
│       └── socks_decode.rs
└── packaging/
    ├── systemd/
    │   └── icmp2tunnel-server.service
    ├── freebsd/
    │   └── rc.d/icmp2tunnel_server
    └── windows/
        └── install-service.ps1
```

---

## 5. Rust Workspace

Root `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
  "crates/icmp2tunnel-proto",
  "crates/icmp2tunnel-socks",
  "crates/icmp2tunnel-transport",
  "crates/icmp2tunnel-core",
  "crates/icmp2tunnel-client",
  "crates/icmp2tunnel-server",
]

[workspace.package]
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourname/ICMP2Tunnel"
rust-version = "1.75"

[workspace.dependencies]
tokio = { version = "1", features = [
  "rt-multi-thread",
  "macros",
  "net",
  "io-util",
  "time",
  "sync",
  "signal"
] }

bytes = "1"
async-trait = "0.1"

clap = { version = "4", features = ["derive", "env"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"

thiserror = "2"
anyhow = "1"

tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

socket2 = { version = "0.6", features = ["all"] }
libc = "0.2"

windows-sys = { version = "0.59", features = [
  "Win32_Foundation",
  "Win32_NetworkManagement_IpHelper",
  "Win32_Networking_WinSock",
  "Win32_System_Threading"
] }

rand = "0.8"
zeroize = "1"
hkdf = "0.12"
sha2 = "0.10"
chacha20poly1305 = "0.10"
constant_time_eq = "0.3"
```

---

## 6. Crate Responsibilities

### 6.1 `icmp2tunnel-proto`

Pure protocol crate.

Responsibilities:

- Wire header encoding and decoding.
- Multiplexed frame encoding and decoding.
- AEAD encryption and authentication.
- Replay-window verification.
- Protocol version negotiation.
- Golden test vectors.
- Fuzz-safe parsers.

This crate must not depend on platform-specific socket APIs.

---

### 6.2 `icmp2tunnel-socks`

Local SOCKS5 crate.

Responsibilities:

- SOCKS5 method negotiation.
- SOCKS5 `CONNECT` parsing.
- IPv4, IPv6, and domain-name target handling.
- Reply code generation.
- Local listener glue for the client binary.

MVP scope:

- Support `CONNECT`.
- Reject `BIND`.
- Reject `UDP ASSOCIATE`.
- Bind only to loopback by default.

---

### 6.3 `icmp2tunnel-transport`

Platform ICMP abstraction crate.

Responsibilities:

- Define client ICMP transport trait.
- Define server ICMP transport trait.
- Implement GNU/Linux client and server backends.
- Implement FreeBSD client and server backends.
- Implement Windows client backend.
- Implement XNU/Darwin client backend.
- Normalize packet metadata across platforms.

---

### 6.4 `icmp2tunnel-core`

Tunnel state machine crate.

Responsibilities:

- Session lifecycle.
- Stream lifecycle.
- Reliable retransmission.
- Packet ACK handling.
- Flow control.
- Client polling scheduler.
- Stream multiplexing.
- Server-side TCP connector.
- ACL and rate-limit enforcement.
- Graceful shutdown.

---

### 6.5 `icmp2tunnel-client`

Client binary.

Responsibilities:

- Read client config.
- Start local SOCKS5 listener.
- Start ICMP client backend.
- Create sessions to remote server.
- Map local SOCKS5 connections to tunnel streams.
- Maintain polling and retransmission loops.
- Emit structured logs.

---

### 6.6 `icmp2tunnel-server`

Server binary.

Responsibilities:

- Read server config.
- Start raw ICMP listener.
- Authenticate peers.
- Enforce target ACLs.
- Open target TCP connections.
- Forward TCP payloads through tunnel streams.
- Rate-limit peers and sessions.
- Emit audit logs.

---

## 7. Transport Traits

`crates/icmp2tunnel-transport/src/traits.rs`:

```rust
use bytes::Bytes;
use std::net::IpAddr;
use std::time::Duration;

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("timeout")]
    Timeout,

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("platform error: {0}")]
    Platform(String),
}

/// Client-side ICMP transport.
///
/// The abstraction is intentionally request/reply shaped because Windows
/// naturally exposes ICMP Echo as an exchange API.
#[async_trait::async_trait]
pub trait ClientIcmp: Send + Sync {
    async fn exchange(
        &self,
        dst: IpAddr,
        payload: Bytes,
        timeout: Duration,
    ) -> Result<Bytes>;
}

/// One inbound Echo Request received by the server.
pub struct InboundEcho {
    pub peer: IpAddr,
    pub payload: Bytes,
    pub reply_token: ReplyToken,
}

/// Opaque backend-specific reply metadata.
///
/// The server must preserve information such as peer address, ICMP identifier,
/// sequence number, and address-family-specific metadata.
pub struct ReplyToken {
    pub(crate) inner: ReplyTokenInner,
}

pub(crate) enum ReplyTokenInner {
    Linux,
    FreeBsd,
}

/// Server-side ICMP transport.
///
/// Only GNU/Linux and FreeBSD need to implement this trait.
#[async_trait::async_trait]
pub trait ServerIcmp: Send + Sync {
    async fn recv_request(&self) -> Result<InboundEcho>;

    async fn send_reply(
        &self,
        token: ReplyToken,
        payload: Bytes,
    ) -> Result<()>;
}
```

---

## 8. Wire Protocol

### 8.1 ICMP Payload Header

All ICMP2Tunnel packets use an explicit magic value and version.

```text
ICMP Echo Payload
=================

Plain Header
------------
magic        u32    0x49325431, ASCII-ish "I2T1"
version      u8     protocol version, initially 1
header_len   u8     length of plain header
flags        u16    direction, ack-only, fin, rst
session_id   u64    random per-session identifier
packet_no    u64    monotonically increasing packet number
ack_no       u64    highest contiguous packet received
window       u32    receiver credit in bytes
payload_len  u16    encrypted payload length
nonce_salt   u32    nonce derivation salt

Encrypted Body
--------------
AEAD ciphertext + authentication tag
```

Plain header fields are authenticated as AEAD additional authenticated data.

The target address, stream IDs, stream payloads, and control frames are inside the encrypted body.

---

### 8.2 Multiplexed Frame Format

```text
Encrypted Mux Frame
===================

op           u8     HELLO, OPEN, DATA, ACK, WINDOW, FIN, RST, PING, PONG
stream_id    u32    logical stream identifier
stream_seq   u64    per-stream byte offset
data_len     u16    payload size
data         bytes  operation-specific payload
```

Suggested operations:

```text
HELLO         session negotiation
HELLO_REPLY   session negotiation response
OPEN          open a target TCP connection
OPEN_OK       target TCP connection established
OPEN_ERR      target TCP connection failed
DATA          stream payload
ACK           stream-level acknowledgement
WINDOW        stream-level receive credit
FIN           half-close stream
RST           reset stream
PING          client polling frame
PONG          server keepalive response
```

---

## 9. Reliability Model

ICMP does not provide reliable delivery. ICMP2Tunnel therefore implements reliability above ICMP.

Core mechanisms:

- Packet numbers.
- ACK numbers.
- Retransmission queue.
- RTO timer.
- Duplicate suppression.
- Replay window.
- Per-stream sequence numbers.
- Per-stream reorder buffer.
- Flow-control windows.
- Client-driven polling for downstream delivery.

The client periodically sends `PING` or empty poll packets when there is no upstream data. The server uses the Echo Reply payload to return pending downstream frames.

Approximate throughput model:

```text
single_direction_throughput ≈ payload_size * completed_exchanges_per_second

downlink_latency_floor ≈ poll_interval + network_rtt
```

This protocol is not expected to compete with TCP-over-IP performance. Its purpose is controlled diagnostic transport, not high-throughput bulk transfer.

---

## 10. Session State Machine

```text
New
 └── HelloSent
      └── Established
           ├── Draining
           └── Closed
```

Session responsibilities:

- Peer authentication.
- Key derivation.
- Packet number allocation.
- ACK generation.
- Replay defense.
- Retransmission scheduling.
- Poll scheduling.
- Stream table ownership.

---

## 11. Stream State Machine

```text
Idle
 └── Opening
      └── Open
           ├── LocalHalfClosed
           ├── RemoteHalfClosed
           └── Closed
```

Each SOCKS5 `CONNECT` request maps to one stream.

Stream responsibilities:

- Target address binding.
- Ordered byte delivery.
- Per-stream ACK.
- Per-stream receive window.
- Local TCP half-close handling.
- Remote TCP half-close handling.
- Reset propagation.

---

## 12. Security Model

ICMP2Tunnel must be secure by default.

Mandatory server controls:

- Peer authentication.
- Target allowlist.
- Peer allowlist.
- Rate limits.
- Session limits.
- Stream limits.
- Replay protection.
- AEAD-protected payloads.
- Structured audit logs.

Server defaults:

- No unauthenticated peers.
- No open target policy.
- No wildcard egress by default.
- No non-loopback SOCKS binding on the client by default.

The server must reject traffic unless both conditions are true:

```text
peer is authorized
target is explicitly allowed
```

---

## 13. Example Client Config

`examples/client.toml`:

```toml
[client]
socks_listen = "127.0.0.1:1080"
server = "203.0.113.10"
poll_interval_ms = 20
request_timeout_ms = 1000
max_inflight = 16
max_payload = 960

[auth]
mode = "psk"
psk_file = "./client.psk"

[log]
level = "info"
format = "compact"
```

---

## 14. Example Server Config

`examples/server.toml`:

```toml
[server]
bind = "0.0.0.0"
max_sessions = 64
max_streams_per_session = 32
max_payload = 960
idle_timeout_secs = 120

[auth]
mode = "psk"
psk_file = "/etc/icmp2tunnel/server.psk"

[acl]
peer_allow = [
  "203.0.113.20/32"
]

target_allow = [
  "10.0.0.0/8:443",
  "10.0.0.0/8:22",
  "192.168.0.0/16:443"
]

[rate_limit]
max_pps_per_peer = 100
max_bps_per_peer = 1048576

[log]
level = "info"
format = "json"
```

---

## 15. Development Commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Fuzzing:

```bash
cargo fuzz run frame_decode
cargo fuzz run socks_decode
```

Privileged smoke tests should be opt-in:

```bash
ICMP2TUNNEL_PRIVILEGED_TESTS=1 cargo test --workspace -- --ignored
```

---

## 16. Initial Implementation Strategy

Recommended order:

1. Implement protocol codec.
2. Implement fake transport.
3. Implement SOCKS5 parser.
4. Implement session and stream state machines.
5. Run end-to-end tests over fake transport.
6. Implement GNU/Linux ICMP backend.
7. Implement FreeBSD ICMP backend.
8. Implement Windows client backend.
9. Implement XNU/Darwin client backend.
10. Add packaging and release automation.

Do not begin with platform raw sockets. Build the protocol and reliability layer against fake transport first.

---

## 17. Non-Goals

ICMP2Tunnel does not aim to provide:

- Stealth transport.
- Intrusion capability.
- Firewall bypass tooling.
- Open proxy operation.
- Traffic disguise.
- IDS evasion.
- High-throughput bulk transfer.
- Full SOCKS5 UDP support in the MVP.

---

## 18. Future Extensions

Possible post-MVP features:

- IPv6 ICMPv6 support.
- SOCKS5 `UDP ASSOCIATE`.
- Noise-based key exchange.
- Public-key peer authentication.
- Adaptive PMTU discovery.
- BBR-like pacing model.
- Prometheus metrics.
- systemd socket activation.
- Windows service packaging.
- FreeBSD port skeleton.
