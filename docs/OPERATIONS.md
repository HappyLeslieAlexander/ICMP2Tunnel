# Operations Guide

This guide covers building, deploying, running, and troubleshooting
ICMP2Tunnel in authorized lab or administrative environments.

## Build Host

Install Rust 1.78 or newer:

```bash
rustc --version
cargo --version
```

Build:

```bash
cargo fmt --all
cargo test
cargo build --release
```

Artifacts:

```text
target/release/icmp2tunnel-client
target/release/icmp2tunnel-server
```

Generate a lockfile for reproducible builds:

```bash
cargo generate-lockfile
```

## Linux Permissions

Grant raw socket capability:

```bash
sudo setcap cap_net_raw+ep ./target/release/icmp2tunnel-server
sudo setcap cap_net_raw+ep ./target/release/icmp2tunnel-client
```

Verify:

```bash
getcap ./target/release/icmp2tunnel-server
getcap ./target/release/icmp2tunnel-client
```

If you run with `sudo`, the binaries attempt to drop privileges to `nobody`
after opening raw socket(s).

## Minimal Server Run

Edit `examples/server.toml`:

```toml
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
peer_acl = ["203.0.113.20/32"]
target_acl = ["198.51.100.10:443"]
```

Run:

```bash
./target/release/icmp2tunnel-server --config examples/server.toml
```

Expected logs include:

```text
raw ICMP socket opened
server ready
```

The server may warn if IPv4 or IPv6 raw socket setup fails. That is acceptable
when the other address family opens successfully.

## Minimal Client Run

Edit `examples/client.toml`:

```toml
listen_addr = "127.0.0.1:1080"
server_addr = "203.0.113.10"
psk = "replace-with-a-long-random-psk"
salt = "icmp2tunnel-v1-lab"
```

Run:

```bash
./target/release/icmp2tunnel-client --config examples/client.toml
```

Use:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://allowed.example/
```

## IPv6 Operations

For global IPv6:

```toml
server_addr = "2001:db8::10"
peer_acl = ["2001:db8:100::20/128"]
target_acl = ["[2001:db8:200::10]:443"]
```

For link-local IPv6:

```toml
server_addr = "fe80::1%eth0"
```

Make sure the host firewall permits ICMPv6 Echo Request and Echo Reply.
IPv6 neighbor discovery also depends on ICMPv6; do not blanket-drop all ICMPv6
on production systems.

## Systemd Example

Create `/etc/systemd/system/icmp2tunnel-server.service`:

```ini
[Unit]
Description=ICMP2Tunnel server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/icmp2tunnel/icmp2tunnel-server --config /etc/icmp2tunnel/server.toml
User=nobody
Group=nogroup
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/icmp2tunnel-client.service`:

```ini
[Unit]
Description=ICMP2Tunnel client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/icmp2tunnel/icmp2tunnel-client --config /etc/icmp2tunnel/client.toml
User=nobody
Group=nogroup
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now icmp2tunnel-server
sudo systemctl status icmp2tunnel-server
```

Some distributions use a different unprivileged group name, such as `nobody`
instead of `nogroup`. Adjust `Group=` if needed.

If you do not use systemd ambient capabilities and instead rely on file
capabilities, preserve them when copying binaries:

```bash
sudo setcap cap_net_raw+ep /opt/icmp2tunnel/icmp2tunnel-server
sudo setcap cap_net_raw+ep /opt/icmp2tunnel/icmp2tunnel-client
```

## Firewall Notes

For IPv4, permit ICMP Echo Request to the server and Echo Reply back to the
client.

For IPv6, permit ICMPv6 Echo Request to the server and Echo Reply back to the
client.

Also ensure the server can open TCP connections to every target in
`target_acl`.

## Troubleshooting

### `Permission denied` when opening raw socket

Grant `CAP_NET_RAW` or run as root:

```bash
sudo setcap cap_net_raw+ep ./target/release/icmp2tunnel-server
```

### Server logs `failed to open raw ICMP socket`

One address family may be unavailable. If at least one socket opens, the server
continues. If both fail, raw socket permission or platform support is missing.

### Client times out

Check:

- `server_addr` is correct.
- IPv4/IPv6 routing works.
- ICMP Echo is not blocked.
- `psk` and `salt` match.
- Server `peer_acl` includes the client source address.
- Server logs do not show authentication failures.

Useful commands:

```bash
ping -c 3 203.0.113.10
ping -6 -c 3 2001:db8::10
tcpdump -ni any icmp
tcpdump -ni any icmp6
```

### Target is rejected

Check:

- `target_acl` includes the exact host/IP/CIDR and port.
- DNS resolution returns an address allowed by the ACL.
- The target is not in a default-blocked range.
- `allow_private_targets = true` is set if private targets are intentional.

### SOCKS connection fails immediately

Check:

- The client is listening on the expected `listen_addr`.
- Non-loopback listeners have `allow_non_loopback = true`.
- Non-loopback listeners have both `socks_username` and `socks_password`.
- Your SOCKS tool is using SOCKS5, not SOCKS4.

### Throughput is low

This is expected for the current client-driven polling design. Consider:

- Increasing `max_payload`.
- Increasing `byte_per_sec`.
- Increasing pending queue limits.
- Increasing `poll_interval_ms` only if you prefer lower packet rate over
  latency.

## Log Levels

Use `info` for normal operation:

```toml
log_level = "info"
```

Use `debug` only while diagnosing:

```toml
log_level = "debug"
```

## Safe Rollout Checklist

1. Build with `cargo build --release`.
2. Generate and commit `Cargo.lock`.
3. Run unit tests and clippy.
4. Configure a random PSK.
5. Use narrow peer and target ACLs.
6. Grant `CAP_NET_RAW`.
7. Test ICMP reachability with `ping`.
8. Test one allowlisted target with `curl --socks5-hostname`.
9. Watch server logs for rejects and rate limits.
