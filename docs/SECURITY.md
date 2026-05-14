# Security Model

ICMP2Tunnel is designed for explicitly authorized lab and administrative
networks. It is not a stealth tool, malware component, censorship bypass tool,
or general-purpose open proxy.

## Security Goals

The implementation aims to provide:

- Authentication of tunnel frames using a pre-shared secret.
- Confidentiality and integrity for tunnel payloads.
- Separation between client-to-server and server-to-client AEAD key spaces.
- Peer allowlisting before expensive server-side work.
- Target allowlisting before TCP connections are opened.
- Default rejection of local, metadata, multicast, unspecified, and private
  target address classes.
- Per-peer rate limits and bounded resource usage.
- Audit logs for stream closes and rejected operations.

## Non-Goals

The implementation does not try to provide:

- Traffic invisibility.
- Resistance to network-level ICMP blocking or rate limiting.
- Full VPN semantics.
- Anonymous operation.
- Multi-user identity management.
- Protection if the PSK is leaked.

## Authentication and Encryption

Frames are encrypted with ChaCha20-Poly1305. Keys are derived with HKDF-SHA256
from:

- `psk`
- `salt`
- direction
- session ID

The frame header is included as AEAD associated data, so tampering with session
ID, packet number, length, or protocol metadata causes decryption failure.

Use a long random PSK. Do not reuse example values. Treat the PSK like a
password that grants access to every target permitted by the server ACL.

## Replay Handling

The server rejects packet number `0` and packets whose packet number is older
than or equal to the highest processed packet for that session, unless a cached
reply exists for retransmission.

This matches the current serialized client exchange model. If out-of-order
parallel exchanges are added later, replace this with a sliding replay window.

## Peer ACL

`peer_acl` is the first line of defense. It restricts which ICMP source
addresses may attempt authentication.

Keep it as narrow as possible:

```toml
peer_acl = ["203.0.113.20/32", "2001:db8:100::20/128"]
```

Do not use broad ranges like `0.0.0.0/0` or `::/0` outside a controlled test.

## Target ACL

`target_acl` controls where authenticated peers can connect. Prefer exact IPs
or narrow CIDRs and exact ports:

```toml
target_acl = ["198.51.100.10:443", "[2001:db8:200::10]:443"]
```

Domain ACLs are allowed but depend on DNS. Be careful with domains controlled
by third parties or with records that may change to internal addresses.

## Default Target Blocking

The server always rejects these target classes:

- Loopback.
- Link-local.
- Metadata addresses `169.254.169.254` and `169.254.169.253`.
- Multicast.
- Unspecified addresses.
- IPv4 `0.0.0.0/8`.

The server also rejects these by default:

- RFC1918 private IPv4 ranges.
- Carrier-grade NAT `100.64.0.0/10`.
- Benchmarking `198.18.0.0/15`.
- IPv6 unique local addresses.

Set `allow_private_targets = true` only when private/internal targets are the
explicit purpose of the deployment.

## SOCKS Listener Exposure

The client should normally bind to loopback:

```toml
listen_addr = "127.0.0.1:1080"
```

If binding to a non-loopback address, both of these are required:

```toml
allow_non_loopback = true
socks_username = "operator"
socks_password = "replace-with-a-long-random-password"
```

Also use host firewall rules. SOCKS authentication protects the client
listener, but it is not a replacement for network-level access control.

## Privileges

Raw ICMP sockets need elevated privileges on many systems. Prefer Linux file
capabilities:

```bash
sudo setcap cap_net_raw+ep ./target/release/icmp2tunnel-server
sudo setcap cap_net_raw+ep ./target/release/icmp2tunnel-client
```

If a binary starts as root, it opens raw socket(s) and drops privileges to
`nobody`. Ensure that account exists on your target system.

## Logging

The server logs:

- Peer ACL rejects.
- Rate limit events.
- Authentication or frame decode failures.
- Target ACL rejects.
- Target connection failures.
- Stream close audit records with target, byte counts, and duration.

Avoid setting `log_level = "debug"` in noisy or hostile environments unless
you are actively diagnosing an issue.

## Residual Risks

- ICMP may be monitored, filtered, or rate-limited by network equipment.
- A leaked PSK grants access to all server ACL-permitted targets.
- The thread-per-stream model is not suitable for high concurrency.
- Domain target ACLs depend on DNS correctness and freshness.
- Live IPv6 ICMP behavior can vary by OS and network policy.

## Hardening Checklist

- Use a random PSK of at least 32 bytes.
- Keep `peer_acl` narrow.
- Keep `target_acl` narrow.
- Keep `allow_private_targets = false` unless required.
- Bind the client listener to loopback whenever possible.
- Use SOCKS username/password for non-loopback listeners.
- Grant `CAP_NET_RAW` instead of running as root.
- Run with a dedicated service account where possible.
- Enable CI with `fmt`, `clippy`, `test`, and release build checks.
- Monitor logs for repeated auth failures and rate-limit events.
