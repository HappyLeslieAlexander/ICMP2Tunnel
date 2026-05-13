# Fuzzing

Install cargo-fuzz:

```bash
cargo install cargo-fuzz
```

Run frame decoder fuzzing:

```bash
(cd fuzz && cargo fuzz run frame_decode -- -max_total_time=60 -dict=dictionary.txt)
```

Run SOCKS decoder fuzzing:

```bash
(cd fuzz && cargo fuzz run socks_decode -- -max_total_time=60)
```
