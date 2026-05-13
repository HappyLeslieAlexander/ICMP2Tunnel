# Upstream review summary

The referenced repository already contains useful building blocks: protocol codec and AEAD functions, SOCKS5 parsing helpers, fake transport tests, partial session/multiplexing primitives, ACL/rate-limit primitives, and platform-specific ICMP packet parsing helpers.

The incomplete parts are the important integration layers:

- The client binary accepts SOCKS5 connections but connects directly to the requested TCP target instead of carrying streams through ICMP/session/transport.
- The server binary validates configuration and logs startup state, but still lacks a raw ICMP receive loop, session authentication, target TCP connector, stream forwarding, ACL enforcement in request processing, rate-limit enforcement in request processing, and graceful runtime shutdown.
- The Linux and FreeBSD transport modules only parse/build packets; they do not open sockets or integrate with a runtime.
- The Windows module parses replies but does not bind Windows ICMP APIs.
- Several TODO milestones are marked complete even though the corresponding production integration is absent.

This package implements a focused Linux/Unix raw-ICMP MVP rather than the entire multi-platform roadmap. It preserves the important safety properties: PSK authentication, encrypted payloads, peer ACL, target ACL, loopback/link-local/metadata target rejection, per-peer rate limits, and audit logs.
