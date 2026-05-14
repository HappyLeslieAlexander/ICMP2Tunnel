# Testing Guide

This guide covers local checks, CI checks, and live network testing.

## Local Static Checks

Run these from the repository root:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release --all-features
```

If formatting fails:

```bash
cargo fmt --all
```

## Unit Tests

The unit tests cover:

- Wire encryption round trips.
- Direction-separated key behavior.
- Peer ACL CIDR matching.
- Target ACL default blocking.
- ICMPv4 Echo packet parsing.
- ICMPv6 Echo packet parsing.
- Scoped IPv6 server address parsing.

Run:

```bash
cargo test
```

## Dependency Reproducibility

This is an application, so commit `Cargo.lock`:

```bash
cargo generate-lockfile
git add Cargo.lock
git commit -m "Add Cargo lockfile"
```

Then CI and local builds resolve the same dependency graph.

## GitHub Actions Example

Create `.github/workflows/rust.yml`:

```yaml
name: Rust CI

on:
  push:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Check formatting
        run: cargo fmt --all --check

      - name: Run clippy
        run: cargo clippy --all-targets --all-features -- -D warnings

      - name: Run tests
        run: cargo test --all-features

      - name: Build release
        run: cargo build --release --all-features
```

GitHub Actions can compile and run unit tests without raw ICMP permissions.
Live ICMP tunnel tests require privileged hosts or VMs.

## Codespaces Build

If the Codespace image does not include Rust:

```bash
sudo apt-get update
sudo apt-get install -y curl build-essential ca-certificates
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
```

Then:

```bash
rustc --version
cargo --version
cargo fmt --all --check
cargo test
cargo build --release
```

## Live IPv4 Test

Requirements:

- A client Linux host.
- A server Linux host.
- ICMP Echo permitted between them.
- `CAP_NET_RAW` on both binaries or root for startup.
- A target TCP service reachable from the server.

On the server:

```toml
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
peer_acl = ["CLIENT_IPV4/32"]
target_acl = ["TARGET_IPV4:443"]
```

Run:

```bash
./target/release/icmp2tunnel-server --config examples/server.toml
```

On the client:

```toml
listen_addr = "127.0.0.1:1080"
server_addr = "SERVER_IPV4"
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
```

Run:

```bash
./target/release/icmp2tunnel-client --config examples/client.toml
curl --socks5-hostname 127.0.0.1:1080 https://allowed.example/
```

## Live IPv6 Test

First verify ordinary ICMPv6 reachability:

```bash
ping -6 -c 3 SERVER_IPV6
```

For link-local IPv6:

```bash
ping -6 -c 3 fe80::1%eth0
```

Server ACL:

```toml
peer_acl = ["CLIENT_IPV6/128"]
target_acl = ["[TARGET_IPV6]:443"]
```

Client:

```toml
server_addr = "SERVER_IPV6"
```

For link-local:

```toml
server_addr = "fe80::1%eth0"
```

Then run the same `curl --socks5-hostname` test.

## Packet Capture

IPv4:

```bash
sudo tcpdump -ni any icmp
```

IPv6:

```bash
sudo tcpdump -ni any icmp6
```

You should see Echo Requests from the client and Echo Replies from the server.
Payload bytes are encrypted.

## Negative Tests

Run these before trusting a deployment:

- Use a wrong PSK and confirm the server logs authentication failures.
- Use a client IP outside `peer_acl` and confirm it is rejected.
- Request a target outside `target_acl` and confirm it is rejected.
- Request loopback or metadata targets and confirm they are rejected.
- Exceed `max_local_clients` and confirm extra SOCKS connections are rejected.
- Stop polling while a target sends data and confirm pending queue limits reset
  the stream instead of growing unbounded.

## Known CI Limitations

CI runners normally cannot perform live raw ICMP tests. Keep live tests
separate from normal CI unless you control a privileged self-hosted runner.
