## Summary
<!-- Describe what this PR changes and why. -->

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Security hardening / protocol change (`SMPv2` / TLS / Edge Filter / C11 Agent)
- [ ] Documentation / CI / Build update

## Security & Quality Checklist
- [ ] `cd signum-edge && cargo test` passes
- [ ] `cd signum-edge && cargo clippy --all-targets -- -D warnings` passes
- [ ] `signum-agent` and `signum-ctl` compile cleanly with `-Wall -Wextra` under C11
- [ ] `python scripts/e2e_test.py` passes (no regressions in mTLS, SPKI pinning, smuggling, or secret scanner)
- [ ] No private keys, certificates, or `.env` secrets committed
