# ADR-0001: eBPF Framework — aya-rs vs libbpf-rs

## Status

Accepted

## Date

2026-04-18

## Context

Ghost-Protocol is a Moving Target Defense (MTD) daemon for Linux that uses eBPF
to implement kernel-level packet interception. The system needs:

- **XDP (eXpress Data Path) hooks** for high-performance ingress packet
  inspection at the NIC driver level, used to detect and redirect knock
  sequences before they reach the network stack.
- **TC (Traffic Control) hooks** for egress packet manipulation, used by the
  tarpit engine to inject deceptive responses and by the moving-target logic to
  rewrite source ports on outbound traffic.
- **BPF maps** (HashMap, Array, RingBuf) shared between kernel-space eBPF
  programs and the userspace `ghostd` daemon for real-time state exchange
  (active ports, knock state machines, blocklists).

The entire Ghost-Protocol workspace is written in Rust. We need to choose an
eBPF framework that integrates cleanly with our Cargo-based build system and
allows the team to maintain a single-language codebase.

## Decision Drivers

* **Pure-Rust toolchain** — eliminate C/Clang dependency for reproducible builds
* **Cargo-native workflow** — `cargo build` should produce both userspace and
  BPF binaries without external build scripts calling `clang`
* **Program type coverage** — must support XDP, TC/classifier, and all map types
  we need (HashMap, PerCpuHashMap, Array, RingBuf)
* **Async runtime integration** — userspace loader must integrate with
  `tokio` for the daemon's async event loop
* **Cross-compilation simplicity** — single `cargo build` producing
  self-contained binaries for deployment to heterogeneous Linux hosts
* **Community momentum** — active maintenance, responsive issue tracker,
  regular releases

## Considered Options

### Option 1: aya-rs (aya 0.13.1 + aya-ebpf 0.1.1)

A pure-Rust eBPF library. Kernel-side programs are written in Rust and compiled
to BPF bytecode via `rustc` nightly + `bpf-linker`. Userspace loader interacts
with the kernel via raw `libc` syscalls — no C `libbpf` dependency.

- **Pros**:
  - Entire stack in Rust (kernel + userspace)
  - No C compiler, no `clang`, no kernel headers required
  - First-class Cargo integration; BPF programs are regular crate targets
  - Idiomatic Rust API for maps (`HashMap::get`, `HashMap::insert`)
  - Built-in async support (`features = ["async_tokio"]`)
  - Self-contained binaries — no shared library dependencies on target hosts
  - Active development: 1.7M+ downloads, regular releases through 2025
  - `aya-log` crate bridges BPF-side `log!()` macros to userspace `tracing`
- **Cons**:
  - Requires Rust nightly toolchain for BPF target (`bpfel-unknown-none`)
  - CO-RE (Compile Once — Run Everywhere) support is functional but less
    battle-tested than C `libbpf`'s BTF-based approach
  - Smaller ecosystem of examples compared to `libbpf` (which has decades of
    C examples)
  - `bpf-linker` is an additional build dependency
  - eBPF crate cannot compile on non-Linux hosts (Windows CI limitation)

### Option 2: libbpf-rs (v0.24+)

A Rust wrapper around the C `libbpf` library maintained by the Linux kernel
community. Kernel-side programs are written in C and compiled with `clang`.

- **Pros**:
  - Backed by upstream kernel community — maximum stability and compatibility
  - Excellent CO-RE support via BTF (the gold standard)
  - New kernel eBPF features available first
  - Large corpus of C BPF examples to reference
  - `libbpf-cargo` provides `cargo build` integration for C BPF sources
- **Cons**:
  - Kernel code must be written in C — breaks our single-language goal
  - Requires `clang`, `llvm`, and kernel headers in the build environment
  - FFI boundary between Rust userspace and C `libbpf` introduces `unsafe`
    blocks and potential memory safety gaps
  - Cross-compilation requires matching `clang` target triples
  - Build complexity: `build.rs` must invoke `clang` and manage header paths

### Option 3: Raw BPF syscalls (no framework)

Write BPF programs in Rust using inline assembly or raw `bpf()` syscalls,
managing program loading, map creation, and attachment manually.

- **Pros**:
  - Zero external dependencies
  - Maximum control over every BPF interaction
- **Cons**:
  - Enormous implementation effort for map management, BTF parsing, program
    loading, and attachment
  - No ecosystem support; every feature must be built from scratch
  - Maintenance burden is unsustainable for a small team
  - **Rejected immediately** — not viable for a production system

## Decision

We will use **aya-rs** (`aya = "0.13.1"` for userspace, `aya-ebpf = "0.1.1"`
for kernel-side programs).

## Rationale

1. **Single-language codebase**: aya lets us write both kernel and userspace
   code in Rust, maintaining type safety across the BPF boundary. Shared types
   live in `ghost-common` and are used by both `ghost-ebpf` and `ghostd`.

2. **Build simplicity**: The eBPF crate compiles with standard `cargo build`
   (targeting `bpfel-unknown-none` via nightly). No `clang`, no kernel headers,
   no `Makefile`. CI just needs `rustup` and `bpf-linker`.

3. **Async integration**: `aya`'s `async_tokio` feature integrates directly
   with our `tokio`-based daemon event loop for map polling and program
   lifecycle management.

4. **Deployment**: Produced binaries are fully self-contained — no shared
   library dependencies on target Linux hosts. This is critical for MTD
   deployment across heterogeneous infrastructure.

5. **Program type coverage**: aya supports all BPF program and map types
   Ghost-Protocol needs: `Xdp`, `SchedClassifier` (TC), `HashMap`,
   `PerCpuHashMap`, `Array`, `RingBuf`.

The nightly toolchain requirement for BPF compilation is acceptable because:
- Only `ghost-ebpf` needs nightly; all other crates use stable
- The BPF target is excluded from the workspace `members` and compiled
  separately in Linux CI
- `rust-toolchain.toml` in `ghost-ebpf` pins the nightly version for
  reproducibility

## Consequences

### Positive

- Unified Rust toolchain for the entire project
- Type-safe shared structs between kernel and userspace via `ghost-common`
- Self-contained deployment binaries with no runtime dependencies
- Cargo-native build process; new developers run `cargo build` and it works
- `aya-log` provides structured logging from BPF programs to userspace

### Negative

- `ghost-ebpf` requires Rust nightly + `bpf-linker` — pinned in
  `rust-toolchain.toml` to avoid breakage
- Cannot compile `ghost-ebpf` on non-Linux platforms — excluded from
  workspace, built only in Linux CI
- CO-RE story is less mature than `libbpf`; if we hit kernel version
  compatibility issues, we may need BTF workarounds
- Fewer community examples for advanced BPF patterns compared to C `libbpf`

### Risks

- **aya ecosystem stability**: aya is pre-1.0 (0.13.x). Breaking changes are
  possible between minor versions.
  - *Mitigation*: Pin exact versions in `Cargo.toml`, test upgrades in CI
    before merging.
- **BPF verifier rejections**: The Rust compiler may generate BPF bytecode
  patterns that the kernel verifier rejects (e.g., unbounded loops).
  - *Mitigation*: Keep BPF programs minimal; test against multiple kernel
    versions (5.15 LTS, 6.1 LTS, 6.6+) in CI.

## Implementation Notes

- `ghost-ebpf/Cargo.toml` depends on `aya-ebpf = "0.1.1"` and
  `aya-log-ebpf = "0.1.1"`
- `ghostd/Cargo.toml` depends on `aya = "0.13.1"` (workspace) with
  `features = ["async_tokio"]` and `aya-log = "0.2.1"`
- Shared BPF map key/value types live in `ghost-common` with
  `#[repr(C)]` for ABI compatibility
- `ghost-ebpf` is excluded from workspace `members`; Linux CI compiles it
  with: `cargo +nightly build -p ghost-ebpf --target bpfel-unknown-none -Z build-std=core`

## Related Decisions

- Future ADR: BPF map schema versioning strategy
- Future ADR: Kernel version support matrix

## References

- [aya-rs.dev](https://aya-rs.dev) — Official documentation
- [aya on crates.io](https://crates.io/crates/aya) — v0.13.1
- [aya-ebpf on crates.io](https://crates.io/crates/aya-ebpf) — v0.1.1
- [libbpf-rs on crates.io](https://crates.io/crates/libbpf-rs)
- [BPF CO-RE reference](https://nakryiko.com/posts/bpf-core-reference-guide/)
