use core::mem;

/// Represents a Multiprotocol Label Switching (MPLS) header to RFC 3032
/// https://www.rfc-editor.org/rfc/rfc3032.html.
/// This header format applies to all MPLS messages.
/// //   0                   1                   2                   3
/// //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //  |                 Label                 | TC  |S|      TTL      |
/// //  20 bits for Label - 3 for TC - 1 for S - 8 for TTL
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MPLS {
    /// First two bytes of Label field, final 4 bits in next combined field
    pub lbl_srt: [u8; 2],
    /// Combined field containing:
    /// - 4-bit end of label field
    /// - 3-bit traffic class field
    /// - 1-bit bottom of stack flag
    pub lbl_tc_s: u8,
    /// time to live field
    pub ttl: u8,
}

impl MPLS {
    pub const LEN: usize = mem::size_of::<MPLS>();

    // --- Constants for bit manipulation within lbl_tc_s ---
    // LLLLTTTS
    const LABEL_LOWER_MASK_IN_BYTE: u8 = 0b11110000; // 0xF0
    const LABEL_LOWER_SHIFT: u8 = 4;
    const LABEL_LOWER_VALUE_MASK: u8 = 0x0F; // For a 4-bit value

    const TC_MASK_IN_BYTE: u8 = 0b00001110; // 0x0E
    const TC_SHIFT: u8 = 1;
    const TC_VALUE_MASK: u8 = 0x07; // For a 3-bit value

    const S_MASK_IN_BYTE: u8 = 0b00000001; // 0x01
    const S_VALUE_MASK: u8 = 0x01; // For a 1-bit value

    /// Gets the 20-bit Label value.
    /// # Safety
    /// Assumes `self` points to a valid MPLS header.
    #[inline]
    pub fn label(&self) -> u32 {
        let high_bits = (self.lbl_srt[0] as u32) << 12;
        let mid_bits = (self.lbl_srt[1] as u32) << 4;
        // Mask high 4 bits belonging to label, shift right to align with high and mid bits
        let low_bits =
            ((self.lbl_tc_s & Self::LABEL_LOWER_MASK_IN_BYTE) >> Self::LABEL_LOWER_SHIFT) as u32;
        high_bits | mid_bits | low_bits
    }

    /// Sets the 20-bit Label value.
    /// Input `label_value` should be a 20-bit integer (0 to 0xFFFFF).
    /// Assumes `self` is a valid, mutable reference to an MPLS header.
    #[inline]
    pub fn set_label(&mut self, label: u32) {
        // Mask input value with 20 set bits
        let masked_label = label & 0xFFFFF;
    }
}
