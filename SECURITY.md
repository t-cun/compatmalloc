# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in compatmalloc, please report it responsibly.

**Email:** Open a [GitHub Security Advisory](https://github.com/t-cun/compatmalloc/security/advisories/new) (preferred) or email the maintainer directly.

**Do not** open a public GitHub issue for security vulnerabilities.

### What to include

- Description of the vulnerability
- Steps to reproduce (minimal test case preferred)
- Impact assessment (what an attacker could achieve)
- compatmalloc version or commit hash
- Host architecture (x86_64, aarch64) and glibc version

### Response timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 1 week
- **Fix or mitigation:** coordinated disclosure, typically within 30 days

## Scope

compatmalloc is a **defense-in-depth hardening layer**, not a sandbox. It mitigates common heap exploitation primitives but does not guarantee prevention of all memory safety violations. See [Limitations](README.md#limitations-honest-assessment) for what it does and does not catch.

Vulnerabilities in scope:

- Bypasses of hardening features (canary, quarantine, guard pages, double-free detection)
- Memory corruption in compatmalloc's own metadata or allocator logic
- Information leaks through compatmalloc's allocation patterns
- Denial of service via crafted allocation sequences

Out of scope:

- Bugs in programs being hardened (report those upstream)
- Performance regressions (open a regular issue)
- Vulnerabilities in dependencies (report to the dependency maintainer)

## Supported Versions

Only the latest release on the `main` branch is supported with security fixes.
