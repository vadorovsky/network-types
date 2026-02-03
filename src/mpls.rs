use core::mem;

/// Represents a Multiprotocol Label Switching (MPLS) header to RFC 3032
/// https://www.rfc-editor.org/rfc/rfc3032.html.
/// This header format applies to all MPLS messages.
/// 20 bits for Label - 3 for TC - 1 for S - 8 for TTL
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mpls {
    /// The first 3 bytes of the MPLS header containing Label (20 bits), Traffic Class (3 bits),
    /// and Bottom of Stack (1 bit) fields in network byte order
    pub lbl_tc_s: [u8; 3],
    /// The Time to Live (TTL) field indicating maximum hop count
    pub ttl: u8,
}

impl Mpls {
    pub const LEN: usize = mem::size_of::<Mpls>();

    /// Gets the 20-bit Label value.
    #[inline]
    pub fn label(&self) -> u32 {
        let upper_bits = (self.lbl_tc_s[0] as u32) << 12;
        let middle_bits = (self.lbl_tc_s[1] as u32) << 4;
        let lower_bits = ((self.lbl_tc_s[2] & 0xF0) >> 4) as u32;
        upper_bits | middle_bits | lower_bits
    }

    /// Sets the 20-bit Label value.
    /// Input `label_value` should be a 20-bit integer (0 to 0xFFFFF).
    #[inline]
    pub fn set_label(&mut self, label: u32) {
        self.lbl_tc_s[0] = ((label >> 12) & 0xFF) as u8;
        self.lbl_tc_s[1] = ((label >> 4) & 0xFF) as u8;

        // For the last byte, preserve TC and S bits
        let preserved_bits = self.lbl_tc_s[2] & 0x0F;
        self.lbl_tc_s[2] = ((label & 0x0F) << 4) as u8 | preserved_bits;
    }

    /// Gets the 3-bit Traffic Class value.
    /// Assumes `self` is a valid reference to an MPLS header.
    #[inline]
    pub fn tc(&self) -> u8 {
        (self.lbl_tc_s[2] & 0xE) >> 1
    }

    /// Sets the 3-bit Traffic Class value.
    /// Input `tc_value` should be a 3-bit integer (0-7).
    /// Assumes `self` is a valid, mutable reference to an MPLS header.
    #[inline]
    pub fn set_tc(&mut self, tc_value: u8) {
        let preserved_bits = self.lbl_tc_s[2] & 0xF1;
        self.lbl_tc_s[2] = preserved_bits | ((tc_value & 0x07) << 1);
    }

    /// Gets the 1-bit Bottom of Stack flag. Returns 0 or 1.
    /// Assumes `self` is a valid reference to an MPLS header.
    #[inline]
    pub fn s(&self) -> u8 {
        self.lbl_tc_s[2] & 0x01
    }

    /// Sets the 1-bit Bottom of Stack flag.
    /// Input `s_value` should be 0 or 1.
    /// Assumes `self` is a valid, mutable reference to an MPLS header.
    #[inline]
    pub fn set_s(&mut self, s_value: u8) {
        let preserved_bits = self.lbl_tc_s[2] & 0xFE;
        self.lbl_tc_s[2] = preserved_bits | (s_value & 0x01);
    }

    /// Gets the 8-bit Time to Live value.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Sets the 8-bit Time to Live value.
    /// Input `ttl_value` is the new TTL value (0-255).
    #[inline]
    pub fn set_ttl(&mut self, ttl_value: u8) {
        self.ttl = ttl_value;
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports Mpls struct and its impl block

    unsafe fn mpls_from_bytes(bytes: &[u8; Mpls::LEN]) -> &Mpls {
        &*(bytes.as_ptr() as *const Mpls)
    }

    unsafe fn mpls_from_bytes_mut(bytes: &mut [u8; Mpls::LEN]) -> &mut Mpls {
        &mut *(bytes.as_mut_ptr() as *mut Mpls)
    }

    #[test]
    fn test_mpls_getters() {
        // Label = 0xABCDE (A=10, B=11, C=12, D=13, E=14)
        // lbl_tc_s[0] = 0xAB (bits 19-12 of label)
        // lbl_tc_s[1] = 0xCD (bits 11-4 of label)
        // lbl_tc_s[2] = 0xEB
        let mpls_bytes: [u8; Mpls::LEN] = [0xAB, 0xCD, 0xEB, 0x40];
        let mpls_header = unsafe { mpls_from_bytes(&mpls_bytes) };

        assert_eq!(mpls_header.label(), 0xABCDE);
        assert_eq!(mpls_header.tc(), 0x05); // 0b101
        assert_eq!(mpls_header.s(), 0x01);
        assert_eq!(mpls_header.ttl(), 0x40);
    }

    #[test]
    fn test_mpls_set_label() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x00, 0x00, 0x00, 0x00];
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_label(0x12345);
        // Expected:
        // lbl_tc_s[0] = 0x12
        // lbl_tc_s[1] = 0x34
        // lbl_tc_s[2] = 0x50
        assert_eq!(mpls_header.label(), 0x12345);
        assert_eq!(mpls_bytes, [0x12, 0x34, 0x50, 0x00]);

        // Set label again, ensure TC and S bits are preserved if they were set
        mpls_bytes = [0xFF, 0xFF, 0x0F, 0xFF];
        let mpls_header2 = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };
        mpls_header2.set_label(0xABCDE);
        // Expected:
        // lbl_tc_s[0]=0xAB
        // lbl_tc_s[1]=0xCD
        // lbl_tc_s[2]=0xE0
        assert_eq!(mpls_header2.label(), 0xABCDE);
        assert_eq!(mpls_header2.tc(), 0x07); // Preserved
        assert_eq!(mpls_header2.s(), 0x01); // Preserved
        assert_eq!(mpls_bytes, [0xAB, 0xCD, 0xEF, 0xFF]);
    }

    #[test]
    fn test_mpls_set_tc() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x00, 0x00, 0xA5, 0x00];
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_tc(0x06);
        assert_eq!(mpls_header.tc(), 0x06);
        assert_eq!(((mpls_bytes[2] & 0xF0) >> 4), 0x0A);
        assert_eq!((mpls_bytes[2] & 0x01), 0x01);
        assert_eq!(mpls_bytes, [0x00, 0x00, 0xAD, 0x00]);
    }

    #[test]
    fn test_mpls_set_s() {
        let mut mpls_bytes: [u8; Mpls::LEN] = [0x00, 0x00, 0xA6, 0x00];
        let mpls_header = unsafe { mpls_from_bytes_mut(&mut mpls_bytes) };

        mpls_header.set_s(0x01);
        assert_eq!(mpls_header.s(), 0x01);
        assert_eq!(((mpls_bytes[2] & 0xF0) >> 4), 0x0A); // Label part preserved
        assert_eq!(((mpls_bytes[2] & 0x0E) >> 1), 0x03); // TC preserved
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
}
