# tameshi-watch -- Continuous compliance ingestion daemon

Watches external compliance sources (kensa results, InSpec reports) and feeds them into the tameshi attestation pipeline. Edition 2024, Rust 1.89.0, MIT.

## Build

```bash
cargo check
cargo test
cargo build --release
```

## Helm Charts

No flake.nix -- run helm commands directly:

```bash
# tameshi-watch chart
helm lint chart/tameshi-watch
helm template test chart/tameshi-watch
helm package chart/tameshi-watch

# pleme-attestation-framework umbrella chart
helm lint chart/pleme-attestation-framework
helm template test chart/pleme-attestation-framework
helm package chart/pleme-attestation-framework
```
