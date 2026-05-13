# ICMP2Tunnel completion package

This is a self-contained MVP completion of the original partial ICMP2Tunnel idea: a local SOCKS5 `CONNECT` client maps TCP streams into authenticated ICMP Echo payloads, and a server receives ICMP Echo Requests, enforces ACL/rate-limit policy, opens allowlisted TCP targets, and returns downstream bytes in Echo Replies.

The design is client-driven: the client sends Echo Requests for upstream data and empty poll frames; the server only returns data in Echo Replies. Payloads are encrypted and authenticated with ChaCha20-Poly1305 using a PSK-derived key. The server refuses peers and targets not explicitly allowlisted.

## Build

```bash
cargo build --release
```

Raw ICMP sockets normally require root or `CAP_NET_RAW` on Linux.

## Server

Edit `examples/server.toml`, then run:

```bash
sudo ./target/release/icmp2tunnel-server --config examples/server.toml
```

## Client

Edit `examples/client.toml`, then run:

```bash
sudo ./target/release/icmp2tunnel-client --config examples/client.toml
curl --socks5-hostname 127.0.0.1:1080 https://allowed.example/
```

Use only in an explicitly authorized lab or administrative environment.
