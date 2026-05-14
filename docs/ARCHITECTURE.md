# Architecture and Protocol

ICMP2Tunnel carries SOCKS5 `CONNECT` TCP streams inside authenticated ICMP Echo
payloads. The client is always the active side of the ICMP exchange. The server
only replies to client Echo Requests.

## Components

```text
Local application
  |
  | SOCKS5 CONNECT
  v
icmp2tunnel-client
  |
  | encrypted frames in ICMP Echo Request
  v
network
  |
  | encrypted frames in ICMP Echo Reply
  v
icmp2tunnel-server
  |
  | allowlisted TCP connection
  v
Target service
```

### Client

The client:

- Listens for local SOCKS5 connections.
- Negotiates no-auth SOCKS on loopback, or username/password auth when
  configured for non-loopback listening.
- Converts each SOCKS `CONNECT` into an `Open` tunnel frame.
- Sends upstream data as `Data` frames.
- Sends `Ping` frames when the local TCP stream is idle so the server can
  return queued downstream data.
- Validates that ICMP replies come from the configured server address.

### Server

The server:

- Attempts to open both IPv4 ICMP and IPv6 ICMPv6 raw sockets.
- Applies the peer ACL before authentication work.
- Authenticates and decrypts each frame.
- Binds sessions to the peer address that created them.
- Rejects stale or replayed packet numbers.
- Opens allowlisted TCP targets asynchronously.
- Queues downstream data and returns it in future Echo Replies.
- Enforces per-peer and per-session resource limits.

## ICMP Transport

IPv4 transport uses ICMP Echo Request type `8` and Echo Reply type `0`.

IPv6 transport uses ICMPv6 Echo Request type `128` and Echo Reply type `129`.

The client chooses IPv4 or IPv6 based on `server_addr`. The server can listen
on both families at the same time if the host permits both raw socket types.

## Wire Frame

Each encrypted wire packet contains:

```text
0..4    magic: "I2T2"
4       version: 1
5       reserved flags
6..8    header length
8..16   session_id
16..24  packet_no
24..28  ciphertext length
28..32  reserved
32..    ChaCha20-Poly1305 ciphertext and tag
```

The plaintext inside the AEAD payload is:

```text
0       frame type
1..5    stream_id
5..9    payload length
9..     payload bytes
```

The header is authenticated as AEAD associated data.

## Key Derivation

Keys are derived from:

- The configured PSK.
- The configured salt.
- Direction (`client-to-server` or `server-to-client`).
- Session ID.

This prevents request and reply traffic from reusing the same AEAD key/nonce
space.

## Nonce and Packet Numbers

The AEAD nonce is derived from `packet_no`. Packet numbers are client-driven
and monotonically increase within a client session.

The server stores a bounded reply cache for retransmission tolerance. It also
tracks the highest processed packet number and rejects packets that are stale
or replayed. This is appropriate for the current serialized client exchange
model. If the protocol later supports parallel out-of-order exchanges, this
must be replaced with a sliding replay window.

## Frame Types

| Type | Name | Direction | Purpose |
| --- | --- | --- | --- |
| `1` | `Hello` | Client to server | Optional liveness frame. |
| `2` | `Open` | Client to server | Request opening a target TCP stream. |
| `3` | `OpenOk` | Server to client | Target stream opened. |
| `4` | `OpenErr` | Server to client | Target stream rejected or failed. |
| `5` | `Data` | Both | TCP bytes. |
| `6` | `Fin` | Both | Graceful stream close. |
| `7` | `Rst` | Both | Abort stream/session operation. |
| `8` | `Ping` | Client to server | Poll for queued downstream data. |
| `9` | `Pong` | Server to client | Empty response or keepalive. |

## Stream Lifecycle

1. Client receives a SOCKS5 `CONNECT`.
2. Client sends `Open(stream_id, target)`.
3. Server validates target ACL and starts asynchronous TCP connect.
4. While connect is pending, server returns `Pong`.
5. Client polls until it receives `OpenOk`, `OpenErr`, or timeout.
6. Client and server exchange `Data`.
7. Either side may close with `Fin` or abort with `Rst`.
8. Server removes stream state and closes the TCP socket.

## Backpressure Model

The server has bounded per-session pending frame and byte queues. If a target
produces downstream data faster than the client polls, the server eventually
resets that stream instead of growing memory without limit.

This is simple and safe, but not ideal for high-throughput workloads. A future
version should add explicit credit-based flow control or ACK windows.

## Concurrency Model

The current implementation uses standard library threads and blocking I/O:

- One thread per accepted local SOCKS client.
- One server connector thread for each pending target open.
- One server reader thread for each open target stream.
- A bounded server event queue.
- A mutex around the client's raw ICMP socket, which serializes ICMP exchanges.

The model is easy to reason about and suitable for small deployments. It is not
intended for high concurrency. A future `tokio` or event-loop implementation
could improve scalability.

## Platform Model

The raw socket backend is Unix-only. Non-Unix builds expose unsupported stubs
for the ICMP socket layer. Windows support would require a separate backend
using the Windows ICMP APIs.
