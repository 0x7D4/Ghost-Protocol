#![allow(dead_code)]

/// Folds a 32-bit checksum accumulator to 16 bits and applies 1's complement.
#[inline(always)]
pub fn csum_fold_helper(mut csum: u32) -> u16 {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

/// Incrementally update a 16-bit 1's complement sum (like IP or TCP checksum)
/// given the old and new 16-bit values.
#[inline(always)]
pub fn update_csum(csum: &mut u16, old_val: u16, new_val: u16) {
    let mut sum = (!*csum) as u32;
    let old_v = (!old_val) as u32;
    let new_v = new_val as u32;

    sum = sum + old_v + new_v;
    *csum = csum_fold_helper(sum);
}

/// Incrementally update a checksum given an old 8-bit value and a new 8-bit value.
/// Used e.g. for TTL updates. We must align it to the correct 16-bit word.
#[inline(always)]
pub fn update_csum_8(csum: &mut u16, old_val: u8, new_val: u8, is_even_byte: bool) {
    let (ov, nv) = if is_even_byte {
        ((old_val as u16) << 8, (new_val as u16) << 8)
    } else {
        (old_val as u16, new_val as u16)
    };
    update_csum(csum, ov, nv);
}
