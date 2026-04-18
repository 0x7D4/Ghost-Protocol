# Security Policy

## Supported Versions

The latest release on `main` is the only actively supported version. Always run the latest commit.

| Version | Supported |
| :--- | :--- |
| `main` (latest) | ✅ Yes |
| older commits | ❌ No |

## Reporting a Vulnerability

If you find a vulnerability in Ghost-Protocol itself, please **do NOT open a public GitHub issue**.

Report privately via one of the following channels:

- **GitHub Private Advisory** (preferred):  
  [https://github.com/0x7d4/Ghost-Protocol/security/advisories/new](https://github.com/0x7d4/Ghost-Protocol/security/advisories/new)

- **Email**: `security@[your-domain]`

### What to Include

Please provide as much detail as possible:

1. **Description** — What is the vulnerability and which component is affected?
2. **Reproduction steps** — Minimal steps to reproduce the issue.
3. **Potential impact** — What can an attacker achieve if this is exploited?
4. **Suggested fix** — If you have one, include it. Patches are welcome.

### Response Timeline

We aim to respond within **48 hours** of receiving your report.  
Critical vulnerabilities affecting the eBPF data plane or TOTP key handling will be treated as highest priority.

## Scope

The following are **in scope** for security reports:

- eBPF program logic (`ghost-ebpf`)
- TOTP secret handling in `ghost-knock`
- Tarpit IP flagging bypass
- Allowlist bypass or privilege escalation in `ghostd`
- IPC socket (`/tmp/ghostd.sock`) access control

The following are **out of scope**:

- Denial-of-service via resource exhaustion (expected in a tarpit context)
- Issues in third-party dependencies (report upstream)
- WSL2 environment limitations
