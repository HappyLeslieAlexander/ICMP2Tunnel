# Configuration Reference

ICMP2Tunnel uses TOML configuration files. The client and server have separate
schemas. The examples in `examples/client.toml` and `examples/server.toml`
include conservative defaults.

## Shared Fields

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `psk` | Yes | None | Pre-shared secret used to derive AEAD keys. Use a long random value. Minimum length is 16 bytes. |
| `salt` | No | `icmp2tunnel-v1` | HKDF salt. Use the same value on client and server. |
| `log_level` | No | `info` | Tracing filter, such as `error`, `warn`, `info`, `debug`, or module-specific filters. |

The `psk` and `salt` must match on both sides. A mismatched value causes
authentication/decryption failures and no response will be returned.

## Client Configuration

```toml
listen_addr = "127.0.0.1:1080"
server_addr = "203.0.113.10"
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
log_level = "info"
allow_non_loopback = false
poll_interval_ms = 20
request_timeout_ms = 1000
retries = 3
max_payload = 900
handshake_timeout_ms = 5000
open_timeout_ms = 10000
max_local_clients = 64
```

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `listen_addr` | Yes | None | Local SOCKS5 listener address. Use loopback unless you have a specific reason not to. |
| `server_addr` | Yes | None | Remote ICMP server address. Supports IPv4, IPv6, and scoped IPv6 such as `fe80::1%eth0`. |
| `allow_non_loopback` | No | CLI `--allow-non-loopback`, otherwise false | Required if `listen_addr` is not loopback. |
| `poll_interval_ms` | No | `20` | Local socket read timeout and idle poll interval. Lower values reduce latency but increase ICMP traffic. |
| `request_timeout_ms` | No | `1000` | ICMP exchange receive timeout. |
| `retries` | No | `3` | Retries for each ICMP exchange. |
| `max_payload` | No | `900`, clamped to `64..=1400` | Maximum upstream chunk size placed in one tunnel frame. |
| `icmp_identifier` | No | Process ID truncated to 16 bits | ICMP Echo identifier. Configure only if you need a stable identifier. |
| `handshake_timeout_ms` | No | `5000` | SOCKS negotiation and request timeout. |
| `open_timeout_ms` | No | `10000` | Maximum time to wait for the server to finish target connection setup. |
| `max_local_clients` | No | `64` | Maximum concurrent local SOCKS client connections. |
| `socks_username` | Conditional | None | SOCKS5 username. Required with `socks_password` when listening on non-loopback. |
| `socks_password` | Conditional | None | SOCKS5 password. Required with `socks_username` when listening on non-loopback. |

### Client Address Examples

IPv4 server:

```toml
server_addr = "203.0.113.10"
```

IPv6 server:

```toml
server_addr = "2001:db8::10"
```

IPv6 link-local server:

```toml
server_addr = "fe80::1%eth0"
```

Non-loopback SOCKS listener:

```toml
listen_addr = "0.0.0.0:1080"
allow_non_loopback = true
socks_username = "operator"
socks_password = "replace-with-a-long-random-password"
```

## Server Configuration

```toml
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
log_level = "info"
peer_acl = ["203.0.113.20/32"]
target_acl = ["198.51.100.10:443", "198.51.100.0/24:443"]
max_sessions_per_peer = 8
max_streams_per_session = 64
max_pending_frames_per_session = 512
max_pending_bytes_per_session = 524288
event_queue_capacity = 4096
max_rate_limiter_entries = 4096
packet_per_sec = 256
byte_per_sec = 262144
read_timeout_ms = 250
connect_timeout_ms = 5000
session_idle_timeout_ms = 300000
rate_limiter_ttl_ms = 300000
allow_private_targets = false
```

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `peer_acl` | Yes | None | CIDR allowlist for ICMP client source addresses. Must not be empty. |
| `target_acl` | Yes | None | Target allowlist in `host:port`, `[ipv6]:port`, or `cidr:port` form. Must not be empty. |
| `max_sessions_per_peer` | No | `8` | Maximum active sessions per peer address. |
| `max_streams_per_session` | No | `64` | Maximum active/opening streams per session. |
| `max_pending_frames_per_session` | No | `512` | Maximum queued downstream frames per session. |
| `max_pending_bytes_per_session` | No | `524288` | Maximum queued downstream payload bytes per session. |
| `event_queue_capacity` | No | `4096` | Bounded internal event queue capacity. |
| `max_rate_limiter_entries` | No | `4096` | Maximum number of peer rate limiter entries retained at once. |
| `packet_per_sec` | No | `256` | Per-peer packet rate limit. |
| `byte_per_sec` | No | `262144` | Per-peer byte rate limit, measured on received ICMP packets. |
| `read_timeout_ms` | No | `250` | Raw socket read timeout. |
| `connect_timeout_ms` | No | `5000` | TCP target connection timeout. |
| `session_idle_timeout_ms` | No | `300000` | Idle session cleanup timeout. |
| `rate_limiter_ttl_ms` | No | `300000` | Idle peer rate limiter cleanup timeout. |
| `allow_private_targets` | No | `false` | Allows RFC1918 IPv4, carrier-grade NAT, benchmarking ranges, and IPv6 ULA targets when true. |

All numeric limits and timeouts must be greater than zero.

## Peer ACL Syntax

Peer ACLs are CIDR rules:

```toml
peer_acl = ["203.0.113.20/32", "2001:db8:100::20/128"]
```

Only packets from matching peer addresses are processed. Packets from other
addresses are ignored after a warning log.

## Target ACL Syntax

Target ACL rules include a host or CIDR plus a port:

```toml
target_acl = [
  "198.51.100.10:443",
  "198.51.100.0/24:443",
  "[2001:db8:200::10]:443",
  "2001:db8:200::/64:443",
  "allowed.example:443",
]
```

Domain rules match the requested host string and then resolve it. IP and CIDR
rules match resolved addresses. The server rejects a target if no resolved
address satisfies the ACL and default target-block policy.

## Default Target Blocks

These target classes are always blocked:

- Loopback.
- Link-local.
- Cloud metadata addresses `169.254.169.254` and `169.254.169.253`.
- Multicast.
- Unspecified addresses.
- IPv4 `0.0.0.0/8`.

These are additionally blocked unless `allow_private_targets = true`:

- RFC1918 IPv4 private ranges.
- Carrier-grade NAT `100.64.0.0/10`.
- Benchmarking ranges `198.18.0.0/15`.
- IPv6 unique local addresses.

## Tuning Notes

For lower latency, decrease `poll_interval_ms`, but expect higher ICMP packet
rates. For quieter idle connections, increase it to `100` or higher.

For unreliable ICMP paths, increase `request_timeout_ms` and `retries`.

For high-throughput targets, increase `max_pending_bytes_per_session` and
`byte_per_sec`, but watch memory usage.

For small lab deployments, keep `peer_acl` narrow and avoid enabling
`allow_private_targets` unless internal target access is the explicit goal.
