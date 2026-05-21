# admina-core

Rust accelerator for the [Admina](https://github.com/admina-org/admina)
AI governance framework. Implements the performance-critical paths of
the four governance domains in Rust, exposed to Python via PyO3:

- **Injection firewall** — regex set + heuristic scorer
- **PII scanner** — regex + checksum validators (EU national IDs)
- **Loop breaker** — TF-IDF cosine similarity over a sliding window
- **Forensic hash chain** — SHA-256 append-only log with chain integrity

## Installation

```bash
pip install admina-core
```

The Python framework auto-detects the Rust engine at runtime and falls
back to a pure-Python implementation if `admina-core` is not installed,
so `admina-framework` always works on its own.

## License

Apache-2.0. See the
[main repository](https://github.com/admina-org/admina) for full
documentation, the model card, and the governance domain modules.
