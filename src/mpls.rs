use core::mem;

/// Represents a Multiprotocol Label Switching (MPLS) header to RFC 3032
/// https://www.rfc-editor.org/rfc/rfc3032.html.
/// This header format applies to all MPLS messages.
/// 20 bits for Label - 3 for TC - 1 for S - 8 for TTL
/// 
/// Example use implementation Conceptual eBPF code:
/// Assume `packet_ptr` is *const u8 pointing to the start of the MPLS header
/// and `packet_end_ptr` is the end of valid packet data.
/// ```rust
/// let mpls_header_size = core::mem::size_of::<Mpls>();
/// if (packet_ptr as *const u8).add(mpls_header_size) > packet_end_ptr {
///     // Error: packet too short for MPLS header
///     return /* appropriate eBPF action */;
/// }
///```
/// This is the unsafe step: creating the reference from a raw pointer.
/// The caller *must* ensure `packet_ptr` is valid and points to enough initialized data.
/// ```rust
/// let mpls_header_ref: &Mpls = unsafe { &*(packet_ptr as *const Mpls) };
///
/// // Now, method calls are safe:
/// 
/// let label = mpls_header_ref.label();
/// let ttl = mpls_header_ref.ttl();
/// aya_log_ebpf::info!(&ctx, "MPLS Label: {}, TTL: {}", label, ttl);
///
/// For mutable operations:
/// let mpls_header_mut_ref: &mut Mpls = unsafe { &mut *(packet_ptr as *mut Mpls) };
/// mpls_header_mut_ref.set_ttl(ttl - 1);
/// mpls_header_mut_ref.set_s(1);
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Mpls {
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


impl Mpls {
    pub const LEN: usize = mem::size_of::<Mpls>();

    // --- Constants for bit manipulation within lbl_tc_s ---
    // LLLLTTTS
    const LABEL_LOWER_MASK_IN_BYTE: u8 = 0b11110000; // 0xF0
    const LABEL_LOWER_SHIFT: u8 = 4;
    const LABEL_LOWER_VALUE_MASK: u32 = 0x0000000F; // For a 4-bit value

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
        self.lbl_srt[0] = ((masked_label >> 12) & 0xFF) as u8;
        self.lbl_srt[1] = ((masked_label >> 4) & 0xFF) as u8;
        
        let lower_4bits = (masked_label & Self::LABEL_LOWER_VALUE_MASK) as u8;
        let current_lbl_tc_s = self.lbl_tc_s;
        // Shift new bits to save into 4 MSB 
        let new_lbl_tc_s = lower_4bits << Self::LABEL_LOWER_SHIFT;
        // Remove old lbl value via mask, OR in new value
        self.lbl_tc_s = (current_lbl_tc_s & !Self::LABEL_LOWER_MASK_IN_BYTE) | new_lbl_tc_s;
    }

    /// Gets the 3-bit Traffic Class value.
    /// Assumes `self` is a valid reference to an MPLS header.
    #[inline]
    pub fn tc(&self) -> u8 {
        (self.lbl_tc_s & Self::TC_MASK_IN_BYTE) >> Self::TC_SHIFT
    }

    /// Sets the 3-bit Traffic Class value.
    /// Input `tc_value` should be a 3-bit integer (0-7).
    /// Assumes `self` is a valid, mutable reference to an MPLS header.
    #[inline]
    pub fn set_tc(&mut self, tc_value: u8) {
        let current_lbl_tc_s = self.lbl_tc_s;
        // Mask input value, shift to correct 3 bits
        let new_tc_val_bits = (tc_value & Self::TC_VALUE_MASK) << Self::TC_SHIFT;
        // Remove old TC value via mask, OR in new value
        self.lbl_tc_s = (current_lbl_tc_s & !Self::TC_MASK_IN_BYTE) | new_tc_val_bits;
    }

    /// Gets the 1-bit Bottom of Stack flag. Returns 0 or 1.
    /// Assumes `self` is a valid reference to an MPLS header.
    #[inline]
    pub fn get_s(&self) -> u8 {
        //No shift needed as it is already LSB
        self.lbl_tc_s & Self::S_MASK_IN_BYTE
    }

    /// Sets the 1-bit Bottom of Stack flag.
    /// Input `s_value` should be 0 or 1.
    /// Assumes `self` is a valid, mutable reference to an MPLS header.
    #[inline]
    pub fn set_s(&mut self, s_value: u8) {
        let current_lbl_tc_s = self.lbl_tc_s;
        let new_s_val_bit = s_value & Self::S_VALUE_MASK;
        self.lbl_tc_s = (current_lbl_tc_s & !Self::S_MASK_IN_BYTE) | new_s_val_bit;
    }

    /// Gets the 8-bit Time To Live (TTL) value.
    /// Assumes `self` is a valid reference to an MPLS header.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Sets the 8-bit Time To Live (TTL) value.
    /// Assumes `self` is a valid, mutable reference to an MPLS header.
    #[inline]
    pub fn set_ttl(&mut self, ttl_value: u8) {
        self.ttl = ttl_value;
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports Mpls struct and its impl block

    // Helper to create an MPLS reference from a byte array for testing getters
    unsafe fn mpls_from_bytes(bytes: &[u8; Mpls::LEN]) -> &Mpls {
        &*(bytes.as_ptr() as *const Mpls)
    }

    // Helper to create a mutable MPLS reference from a byte array for testing setters
    unsafe fn mpls_from_bytes_mut(bytes: &mut [u8; Mpls::LEN]) -> &mut Mpls {
        &mut *(bytes.as_mut_ptr() as *mut Mpls)
    }

    #[test]
    fn test_mpls_getters() {
        // Label = 0xABCDE (A=10, B=11, C=12, D=13, E=14)
        // lbl_srt[0] = 0xAB (bits 19-12 of label)
        // lbl_srt[1] = 0xCD (bits 11-4 of label)
        // lbl_tc_s:
        //   Label bits 3-0 = 0xE (high nibble)
        //   TC = 0x5 (0b101) (bits 3-1)
        //   S = 0x1 (bit 0)
        //   lbl_tc_s = 0b11101011 = 0xEB
        // TTL = 0x40 (64)
        let mpls_bytes: [u8; Mpls::LEN] = [0xAB, 0xCD, 0xEB, 0x40];
        let mpls_header = unsafe { mpls_from_bytes(&mpls_bytes) };

        assert_eq!(mpls_header.label(), 0xABCDE);
        assert_eq!(mpls_header.tc(), 0x05); // 0b101
        assert_eq!(mpls_header.get_s(), 0x01);
        assert_eq!(mpls_header.ttl(), 0x40);
    }

    #[test]
    fn test_mpls_set_label() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x00, 0x00, 0x00, 0x00]; // Initial state (TC=0, S=0)
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_label(0x12345); // Label = 0x12345
        // Expected:
        // lbl_srt[0] = 0x12
        // lbl_srt[1] = 0x34
        // lbl_tc_s (label part) = 0x50 (0b01010000)
        assert_eq!(mpls_header.label(), 0x12345);
        assert_eq!(mpls_bytes, [0x12, 0x34, 0x50, 0x00]);

        // Set label again, ensure TC and S bits are preserved if they were set
        mpls_bytes = [0xFF, 0xFF, 0x0F, 0xFF]; // Label=...F, TC=0, S=F (invalid S but tests preservation)
        // lbl_tc_s = 0b00001111 (L=0, TC=7, S=1) -> TC=7, S=1
        let mpls_header2 = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };
        mpls_header2.set_label(0xABCDE); // Label 0xABCDE, TC=7, S=1
        // Expected lbl_srt[0]=0xAB, lbl_srt[1]=0xCD
        // Expected lbl_tc_s: Label part = 0xE0. Original TC=7 (0b111), S=1 (0b1). So 0b11101111.
        // lbl_tc_s should become 0b1110 (E from label) | 0b1111 (preserved TC+S) = 0xEF
        assert_eq!(mpls_header2.label(), 0xABCDE);
        assert_eq!(mpls_header2.tc(), 0x07); // Preserved
        assert_eq!(mpls_header2.get_s(), 0x01); // Preserved
        assert_eq!(mpls_bytes, [0xAB, 0xCD, 0xEF, 0xFF]);
    }

    #[test]
    fn test_mpls_set_tc() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x00, 0x00, 0xA5, 0x00]; // lbl_tc_s = 0b10100101 (L=A, TC=2, S=1)
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_tc(0x06); // Set TC to 6 (0b110)
        // Expected lbl_tc_s: L=A (0b1010....), new TC=6 (0b..0110..), S=1 (0b.......1)
        // lbl_tc_s should be 0b10101101 = 0xAD
        assert_eq!(mpls_header.tc(), 0x06);
        assert_eq!(((mpls_bytes[2] & Mpls::LABEL_LOWER_MASK_IN_BYTE) >> Mpls::LABEL_LOWER_SHIFT), 0x0A); // Label part preserved
        assert_eq!((mpls_bytes[2] & Mpls::S_MASK_IN_BYTE), 0x01); // S bit preserved
        assert_eq!(mpls_bytes, [0x00, 0x00, 0xAD, 0x00]);
    }

    #[test]
    fn test_mpls_set_s() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x00, 0x00, 0xA6, 0x00]; // lbl_tc_s = 0b10100110 (L=A, TC=3, S=0)
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_s(0x01); // Set S to 1
        // Expected lbl_tc_s: L=A (0b1010....), TC=3 (0b..0011..), new S=1 (0bاريات1)
        // lbl_tc_s should be 0b10100111 = 0xA7
        assert_eq!(mpls_header.get_s(), 0x01);
        assert_eq!(((mpls_bytes[2] & Mpls::LABEL_LOWER_MASK_IN_BYTE) >> Mpls::LABEL_LOWER_SHIFT), 0x0A); // Label part preserved
        assert_eq!(((mpls_bytes[2] & Mpls::TC_MASK_IN_BYTE) >> Mpls::TC_SHIFT), 0x03); // TC preserved
        assert_eq!(mpls_bytes, [0x00, 0x00, 0xA7, 0x00]);
    }

    #[test]
    fn test_mpls_set_ttl() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x12, 0x34, 0x56, 0x00];
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_ttl(0xFF);
        assert_eq!(mpls_header.ttl(), 0xFF);
        assert_eq!(mpls_bytes, [0x12, 0x34, 0x56, 0xFF]);
    }

    #[test]
    fn test_mpls_combined_setters_and_getters() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x00; Mpls::LEN];
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_label(0x98765);
        mpls_header.set_tc(0x03);
        mpls_header.set_s(0x01);
        mpls_header.set_ttl(0xAA);

        // First verify all getter values
        assert_eq!(mpls_header.label(), 0x98765);
        assert_eq!(mpls_header.tc(), 0x03);
        assert_eq!(mpls_header.get_s(), 0x01);
        assert_eq!(mpls_header.ttl(), 0xAA);

        // Drop the mutable borrow before comparing bytes
        drop(mpls_header);
        
        // Now check the byte representation
        let expected_bytes: [u8; Mpls::LEN] = [0x98, 0x76, 0x57, 0xAA];
        assert_eq!(mpls_bytes, expected_bytes);

        // Create a new mutable borrow for the next operations
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };
        mpls_header.set_tc(0x05);
        
        // Drop the mutable borrow again before final comparison
        drop(mpls_header);
        
        let expected_bytes_after_tc_change: [u8; Mpls::LEN] = [0x98, 0x76, 0x5B, 0xAA];
        assert_eq!(mpls_bytes, expected_bytes_after_tc_change);
    }
}