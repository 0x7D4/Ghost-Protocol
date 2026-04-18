//! eBPF TC program — Mutating egress hook for OS Persona spoofing.

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::bpf_ktime_get_ns,
    programs::TcContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

use crate::{
    checksum::{update_csum, update_csum_8},
    maps::{ALLOWLIST, CONNTRACK, PERSONAS},
    types::ConntrackKey,
};

// SAFETY: This function performs explicit bounds detection by comparing ctx.data() 
// and ctx.data_end(). Access is only valid if data + offset + len <= data_end.
#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

pub fn try_ghost_tc(ctx: TcContext) -> Result<i32, ()> {
    // SAFETY: ptr_at_mut performs bounds checks. ethhdr is within the packet buffer.
    let ethhdr = unsafe { ptr_at_mut::<EthHdr>(&ctx, 0)? };
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }
    
    // SAFETY: ptr_at_mut performs bounds checks. ipv4hdr is within the packet buffer.
    let ipv4hdr = unsafe { ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
    let dst_ip = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    
    // Bypass for allowlisted IPs
    // SAFETY: BPF maps are thread-safe and verified by the kernel verifier.
    if unsafe { ALLOWLIST.get(&dst_ip).is_some() } {
        return Ok(TC_ACT_OK);
    }
    
    // SAFETY: ipv4hdr was validated within packet bounds at line 39.
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(TC_ACT_OK);
    }

    // SAFETY: ptr_at_mut performs bounds checks. tcphdr is within the packet buffer.
    let tcphdr = unsafe { ptr_at_mut::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    
    // Only process SYN-ACK
    // SAFETY: tcphdr was validated at line 51.
    let is_syn = unsafe { (*tcphdr).syn() != 0 };
    let is_ack = unsafe { (*tcphdr).ack() != 0 };
    
    if !is_syn || !is_ack {
        return Ok(TC_ACT_OK);
    }

    // SAFETY: tcphdr was validated at line 51.
    let src_port = unsafe { (*tcphdr).source };
    let dst_port = unsafe { (*tcphdr).dest };

    let ct_key = ConntrackKey {
        src_ip: dst_ip,
        dst_port,
        _pad16: 0,
    };

    // Record in conntrack
    let _ = CONNTRACK.insert(&ct_key, &1, 0);

    // Persona Rotation: index every 60s
    // SAFETY: bpf_ktime_get_ns is a standard BPF helper verified by the kernel.
    let time_ns = unsafe { bpf_ktime_get_ns() };
    let persona_idx = ((time_ns / 60_000_000_000) % 4) as u32;
    
    if let Some(persona) = PERSONAS.get(persona_idx) {
        // Rewrite TTL
        // SAFETY: ipv4hdr was validated within packet bounds at line 39.
        let old_ttl = unsafe { (*ipv4hdr).ttl };
        let new_ttl = persona.ttl;
        if old_ttl != new_ttl {
            // SAFETY: In-place header modification is valid in TC ingress/egress hooks.
            unsafe { (*ipv4hdr).ttl = new_ttl };
            let mut csum = unsafe { (*ipv4hdr).check };
            update_csum_8(&mut csum, old_ttl, new_ttl, false);
            // SAFETY: Checksum update follows RFC 1071 incrementally.
            unsafe { (*ipv4hdr).check = csum };
        }

        // Rewrite IP ID
        // SAFETY: ipv4hdr was validated at line 39.
        let old_id = unsafe { (*ipv4hdr).id };
        let new_id = u16::to_be(persona.ip_id); // Simplified IP ID sequence spoofing
        if old_id != new_id {
            // SAFETY: Modifying IP ID for OS persona fingerprint spoofing.
            unsafe { (*ipv4hdr).id = new_id };
            let mut csum = unsafe { (*ipv4hdr).check };
            update_csum(&mut csum, old_id, new_id);
            unsafe { (*ipv4hdr).check = csum };
        }

        // Rewrite TCP Window Size
        // SAFETY: tcphdr was validated at line 51.
        let old_window = unsafe { (*tcphdr).window };
        let new_window = u16::to_be(persona.window_size);
        if old_window != new_window {
            // SAFETY: TCP Window modification for OS persona fingerprint spoofing.
            unsafe { (*tcphdr).window = new_window };
            let mut tcp_csum = unsafe { (*tcphdr).check };
            update_csum(&mut tcp_csum, old_window, new_window);
            unsafe { (*tcphdr).check = tcp_csum };
        }
        
        // Note: Detailed TCP options (wscale, SACK, timestamps) morphing logic 
        // would require buffer resizing or complex parsing here. 
        // For now, we fulfill the user's primary field requirements.
    }

    Ok(TC_ACT_OK)
}
