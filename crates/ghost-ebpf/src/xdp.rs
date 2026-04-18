//! eBPF XDP program — Ingress scanner detection (Read-only).

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    programs::XdpContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

use crate::maps::{ALLOWLIST, SCANNER_MAP};
use crate::types::ReconStats;

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

pub fn try_ghost_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    
    // SAFETY: ptr_at performs bounds checks against ctx.data and ctx.data_end.
    // ethhdr is guaranteed to be within the packet buffer.
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // SAFETY: ptr_at performs bounds checks. ipv4hdr is within the packet buffer.
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    
    // Bypass for allowlisted IPs
    // SAFETY: BPF maps are thread-safe and verified by the kernel verifier.
    if unsafe { ALLOWLIST.get(&src_ip).is_some() } {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // SAFETY: ipv4hdr is validated within packet bounds at line 37.
    if unsafe { (*ipv4hdr).proto } == IpProto::Tcp {
        let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        // SAFETY: tcphdr is validated by ptr_at and within packet bounds.
        let is_syn = unsafe { (*tcphdr).syn() != 0 && (*tcphdr).ack() == 0 };
        
        if is_syn {
            // SAFETY: bpf_ktime_get_ns is a standard BPF helper verified by the kernel.
            let now = unsafe { bpf_ktime_get_ns() };
            
            // Record hit in scanner map for userspace to process
            // SAFETY: SCANNER_MAP is a BPF hash map verified by the kernel.
            let mut stats = match unsafe { SCANNER_MAP.get(&src_ip) } {
                Some(s) => *s,
                None => ReconStats { unique_ports_hit: 0, first_seen_ns: now },
            };

            stats.unique_ports_hit += 1;
            // SAFETY: SCANNER_MAP insertion is verified by the kernel verifier.
            let _ = SCANNER_MAP.insert(&src_ip, &stats, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}
