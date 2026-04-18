//! eBPF XDP + TC programs for Ghost-Protocol.
//!
//! This is a BPF-target crate compiled for `bpfel-unknown-none`.
//! It cannot be compiled on Windows or with the stable toolchain.
//!
//! Build with:
//!   cargo +nightly build --target bpfel-unknown-none -Z build-std=core
#![no_std]
#![no_main]

mod checksum;
mod maps;
mod tc;
mod types;
mod xdp;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

#[xdp]
pub fn ghost_xdp(ctx: XdpContext) -> u32 {
    match xdp::try_ghost_xdp(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn ghost_tc(ctx: TcContext) -> i32 {
    match tc::try_ghost_tc(ctx) {
        Ok(action) => action,
        // TC_ACT_SHOT is usually defined as 2 or explicitly via bindings.
        // aya_ebpf::bindings provides TC_ACT_SHOT for tc actions.
        Err(_) => aya_ebpf::bindings::TC_ACT_SHOT,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
