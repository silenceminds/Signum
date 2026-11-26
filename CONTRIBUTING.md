# Contributing to Signum

Thank you for contributing to **Signum**!

## Development Setup

### Rust (`signum-edge`)
```bash
cd signum-edge
cargo test
cargo build --release
```

### C11 (`signum-agent` & `signum-ctl`)
```bash
cd signum-agent
cmake -B build -G Ninja
cmake --build build
```

## Verification Before Opening a PR

1. Run Rust unit tests: `cd signum-edge && cargo test`
2. Run the end-to-end suite: `python scripts/e2e_test.py`
3. For concurrency or security-layer changes, run the 400-test stress suite: `python -u scripts/stress_400_test.py`
4. Never commit generated certificates (`certs/`), private keys, or build artifacts (`target/`, `build/`).

## Pull Requests

- Keep PRs focused and fill out the [PR template](.github/pull_request_template.md).
- C11 changes must compile cleanly with `-Wall -Wextra` under `-std=c11`.
- All changes are licensed under the [Apache License 2.0](LICENSE).
