# ICMP2Tunnel

ICMP2Tunnel is an authenticated SOCKS5-over-ICMP Echo tunnel for explicitly
authorized lab and administrative networks. A local SOCKS5 client accepts
`CONNECT` requests, carries stream data inside encrypted ICMP Echo payloads,
and a remote server opens only allowlisted TCP targets.

This project is intentionally conservative:

- ICMP transport supports both IPv4 Echo and IPv6 Echo Request/Reply on
  Unix-like systems.
- Payloads are encrypted and authenticated with ChaCha20-Poly1305.
- Client-to-server and server-to-client traffic use direction-separated keys.
- Server access requires both a peer ACL and a target ACL.
- Loopback, link-local, metadata, multicast, and unspecified targets are
  blocked. Private targets are blocked by default.
- Per-peer rate limits, session limits, stream limits, pending queue limits,
  and idle cleanup are enforced.
- If a binary starts as root, it opens raw sockets and drops privileges to the
  `nobody` account.

Use this only on systems and networks you own or are explicitly authorized to
operate. See [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

## Current Status

The code is usable as a focused MVP for small authorized environments. It is
not a production VPN and does not try to hide operational traces. ICMP may be
filtered, rate-limited, logged, or blocked by many networks.

Supported:

- Linux/Unix raw ICMP sockets.
- IPv4 ICMP Echo transport.
- IPv6 ICMPv6 Echo transport.
- SOCKS5 `CONNECT` over the tunnel.
- IPv4 and IPv6 TCP targets from the server side.
- Optional SOCKS username/password authentication for non-loopback client
  listeners.

Not supported:

- Windows ICMP APIs.
- SOCKS5 `BIND` or `UDP ASSOCIATE`.
- Transparent proxying or full-device VPN routing.
- High-concurrency production workloads.

## Repository Layout

```text
src/
  acl.rs                         Peer and target ACLs, rate limiter
  icmp.rs                        IPv4/IPv6 ICMP packet and raw socket helpers
  socks.rs                       SOCKS5 parsing and optional auth
  wire.rs                        Encrypted frame codec
  bin/
    icmp2tunnel-client.rs        Local SOCKS5 client and ICMP sender
    icmp2tunnel-server.rs        Raw ICMP server and TCP target connector
examples/
  client.toml                    Client configuration template
  server.toml                    Server configuration template
docs/
  ARCHITECTURE.md                Runtime and protocol design
  CONFIGURATION.md               All config fields and examples
  OPERATIONS.md                  Deployment and troubleshooting
  SECURITY.md                    Threat model and hardening notes
  TESTING.md                     CI, local, and live network testing
```

## Build

Install Rust 1.78 or newer, then run:

```bash
cargo fmt --all
cargo test
cargo build --release
```

The release binaries are created at:

```text
target/release/icmp2tunnel-client
target/release/icmp2tunnel-server
```

For reproducible application builds, generate and commit `Cargo.lock`:

```bash
cargo generate-lockfile
```

## Raw Socket Permissions

Raw ICMP sockets normally require `CAP_NET_RAW` on Linux. Prefer granting this
capability to the built binaries instead of running the whole process as root:

```bash
sudo setcap cap_net_raw+ep ./target/release/icmp2tunnel-server
sudo setcap cap_net_raw+ep ./target/release/icmp2tunnel-client
```

If either binary is started as root, it opens the required raw socket(s) and
then drops privileges to the `nobody` account.

## Quick Start

Edit `examples/server.toml` on the server:

```toml
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
peer_acl = ["203.0.113.20/32"]
target_acl = ["198.51.100.10:443"]
allow_private_targets = false
```

Run the server:

```bash
./target/release/icmp2tunnel-server --config examples/server.toml
```

Edit `examples/client.toml` on the client:

```toml
listen_addr = "127.0.0.1:1080"
server_addr = "203.0.113.10"
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
```

Run the client:

```bash
./target/release/icmp2tunnel-client --config examples/client.toml
```

Test a permitted target through SOCKS5:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://allowed.example/
```

## IPv6 Usage

For an IPv6 server address, set:

```toml
server_addr = "2001:db8::10"
```

For IPv6 link-local addresses, include a numeric or interface-name scope:

```toml
server_addr = "fe80::1%3"
server_addr = "fe80::1%eth0"
```

IPv6 peer ACL examples:

```toml
peer_acl = ["2001:db8:100::20/128"]
```

IPv6 target ACL examples:

```toml
target_acl = ["[2001:db8:200::10]:443", "2001:db8:200::/64:443"]
```

The server attempts to open both IPv4 and IPv6 raw ICMP sockets. It can serve
IPv4 clients, IPv6 clients, or both, depending on host permissions and network
support.

## Client Listener Safety

The client listens on loopback by default. If you bind the SOCKS listener to a
non-loopback address, you must explicitly opt in and configure SOCKS
username/password authentication:

```toml
listen_addr = "0.0.0.0:1080"
allow_non_loopback = true
socks_username = "operator"
socks_password = "replace-with-a-long-random-password"
```

## Documentation

- [Configuration Reference](docs/CONFIGURATION.md)
- [Architecture and Protocol](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Operations Guide](docs/OPERATIONS.md)
- [Testing Guide](docs/TESTING.md)
- [Implementation Review Notes](docs/REVIEW.md)

## Recommended CI

Use GitHub Actions or another CI runner to execute:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release --all-features
```

CI can compile and run unit tests without raw ICMP privileges. Live ICMP tests
require Linux hosts or VMs where raw IPv4/IPv6 ICMP sockets are allowed.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
