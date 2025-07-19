use crate::{getter_be, setter_be};

/// Represents a Geneve (Generic Network Virtualization Encapsulation) header, according to RFC 8926.
/// Geneve is an encapsulation protocol designed for network virtualization.
///
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]

pub struct GeneveHdr {
    /// Combined field: Version (2 bits) and Option Length (6 bits).
    pub ver_opt_len: u8,
    /// Combined field: OAM flag (1 bit), Critical flag (1 bit), Reserved (6 bits).
    pub o_c_rsvd: u8,
    /// Protocol Type of the encapsulated payload (16 bits).
    pub protocol_type: [u8; 2],
    /// Virtual Network Identifier (VNI) (24 bits).
    pub vni: [u8; 3],
    /// Reserved field (8 bits). MUST be zero on transmission.
    pub reserved2: u8,
}

impl GeneveHdr {
    /// The length of the Geneve header in bytes.
    pub const LEN: usize = core::mem::size_of::<GeneveHdr>();

    /// Returns the Geneve protocol version (2 bits).
    ///
    /// According to RFC 8926, the current version is 0.
    #[inline]
    pub fn ver(&self) -> u8 {
        (self.ver_opt_len >> 6) & 0x03
    }

    /// Sets the Geneve protocol version (2 bits).
    ///
    /// `ver` should be a 2-bit value (0-3).
    #[inline]
    pub fn set_ver(&mut self, ver: u8) {
        let preserved_bits = self.ver_opt_len & 0x3F;
        self.ver_opt_len = preserved_bits | ((ver & 0x03) << 6);
    }

    /// Returns the length of the option fields in 4-byte multiples (6 bits).
    #[inline]
    pub fn opt_len(&self) -> u8 {
        self.ver_opt_len & 0x3F
    }

    /// Sets the length of the option fields (6 bits).
    ///
    /// `opt_len` should be a 6-bit value (0-63).
    #[inline]
    pub fn set_opt_len(&mut self, opt_len: u8) {
        let preserved_bits = self.ver_opt_len & 0xC0;
        self.ver_opt_len = preserved_bits | (opt_len & 0x3F);
    }

    /// Returns the OAM (Operations, Administration, and Maintenance) packet flag (1 bit).
    ///
    /// If set (1), this packet is an OAM packet. Referred to as 'O' bit in RFC 8926.
    #[inline]
    pub fn o_flag(&self) -> u8 {
        (self.o_c_rsvd >> 7) & 0x01
    }

    /// Sets the OAM packet flag (1 bit).
    ///
    /// `o_flag` should be a 1-bit value (0 or 1).
    #[inline]
    pub fn set_o_flag(&mut self, o_flag: u8) {
        let preserved_bits = self.o_c_rsvd & 0x7F;
        self.o_c_rsvd = preserved_bits | ((o_flag & 0x01) << 7);
    }

    /// Returns the Critical Options Present flag (1 bit).
    ///
    /// If set (1), one or more options are marked as critical. Referred to as 'C' bit in RFC 8926.
    #[inline]
    pub fn c_flag(&self) -> u8 {
        (self.o_c_rsvd >> 6) & 0x01
    }

    /// Sets the Critical Options Present flag (1 bit).
    ///
    /// `c_flag` should be a 1-bit value (0 or 1).
    #[inline]
    pub fn set_c_flag(&mut self, c_flag: u8) {
        let preserved_bits = self.o_c_rsvd & 0xBF;
        self.o_c_rsvd = preserved_bits | ((c_flag & 0x01) << 6);
    }

    /// Returns the Protocol Type of the encapsulated payload (16 bits, network byte order).
    ///
    /// This follows the Ethertype convention.
    #[inline]
    pub fn protocol_type(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, protocol_type, u16) }
    }

    /// Sets the Protocol Type (16 bits).
    ///
    /// The value is stored in network byte order.
    #[inline]
    pub fn set_protocol_type(&mut self, protocol_type: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, protocol_type, protocol_type) }
    }

    /// Returns the Virtual Network Identifier (VNI) (24 bits).
    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be_bytes([0, self.vni[0], self.vni[1], self.vni[2]])
    }

    /// Sets the Virtual Network Identifier (VNI) (24 bits).
    ///
    /// `vni` should be a 24-bit value. Higher bits are masked.
    /// The value is stored in network byte order.
    #[inline]
    pub fn set_vni(&mut self, vni: u32) {
        let vni_val = vni & 0x00FFFFFF;
        let bytes = vni_val.to_be_bytes();
        self.vni[0] = bytes[1];
        self.vni[1] = bytes[2];
        self.vni[2] = bytes[3]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_len() {
        assert_eq!(GeneveHdr::LEN, 8);
    }

    #[test]
    fn test_default() {
        let hdr = GeneveHdr::default();
        assert_eq!(hdr.ver_opt_len, 0);
        assert_eq!(hdr.o_c_rsvd, 0);
        assert_eq!(hdr.protocol_type, [0, 0]);
        assert_eq!(hdr.vni, [0, 0, 0]);
        assert_eq!(hdr.reserved2, 0);

        assert_eq!(hdr.ver(), 0);
        assert_eq!(hdr.opt_len(), 0);
        assert_eq!(hdr.o_flag(), 0);
        assert_eq!(hdr.c_flag(), 0);
        assert_eq!(hdr.protocol_type(), 0);
        assert_eq!(hdr.vni(), 0);
    }

    #[test]
    fn test_ver() {
        let mut hdr = GeneveHdr::default();
        hdr.set_ver(0b10); // Version 2
        assert_eq!(hdr.ver(), 0b10);
        assert_eq!(hdr.ver_opt_len, 0b10000000, "Raw byte for ver failed");

        hdr.set_ver(0b111); // Input 7 (3 bits), should be masked to 0b11 (3)
        assert_eq!(hdr.ver(), 0b11);
        assert_eq!(hdr.ver_opt_len, 0b11000000, "Masking for ver failed");

        // Test interaction with opt_len
        hdr.ver_opt_len = 0; // Reset
        hdr.set_opt_len(0x3F); // Max opt_len (all lower 6 bits set)
        hdr.set_ver(0b01);
        assert_eq!(hdr.ver(), 0b01);
        assert_eq!(hdr.opt_len(), 0x3F, "opt_len altered by set_ver");
        assert_eq!(
            hdr.ver_opt_len, 0b01111111,
            "Interaction with opt_len failed"
        );
    }

    #[test]
    fn test_opt_len() {
        let mut hdr = GeneveHdr::default();
        hdr.set_opt_len(0x2A); // 42
        assert_eq!(hdr.opt_len(), 0x2A);
        assert_eq!(hdr.ver_opt_len, 0b00101010, "Raw byte for opt_len failed");

        hdr.set_opt_len(0xFF); // Input 255, should be masked to 0x3F (63)
        assert_eq!(hdr.opt_len(), 0x3F);
        assert_eq!(hdr.ver_opt_len, 0b00111111, "Masking for opt_len failed");

        // Test interaction with ver
        hdr.ver_opt_len = 0; // Reset
        hdr.set_ver(0b11); // Max ver (top 2 bits set)
        hdr.set_opt_len(0x15); // 21
        assert_eq!(hdr.ver(), 0b11, "ver altered by set_opt_len");
        assert_eq!(hdr.opt_len(), 0x15);
        assert_eq!(hdr.ver_opt_len, 0b11010101, "Interaction with ver failed");
    }

    #[test]
    fn test_o_flag() {
        let mut hdr = GeneveHdr::default();
        hdr.set_o_flag(1);
        assert_eq!(hdr.o_flag(), 1);
        assert_eq!(hdr.o_c_rsvd, 0b10000000, "Raw byte for o_flag failed");

        // The implementation correctly masks the input, so an input of 2 (0b10) becomes 0.
        // This sets the o_flag back to 0.
        hdr.set_o_flag(0b10);
        assert_eq!(hdr.o_flag(), 0);
        assert_eq!(hdr.o_c_rsvd, 0b00000000, "Masking for o_flag failed");

        // Test that setting the O flag preserves the C flag and reserved bits.
        hdr.o_c_rsvd = 0; // Reset
        hdr.set_c_flag(1); // o_c_rsvd is now 0b01000000

        // Now, set the O flag.
        hdr.set_o_flag(1);

        // Verify that only the O flag bit changed.
        assert_eq!(hdr.o_flag(), 1, "o_flag should be 1");
        assert_eq!(hdr.c_flag(), 1, "c_flag should be preserved");
    }

    #[test]
    fn test_c_flag() {
        let mut hdr = GeneveHdr::default();
        hdr.set_c_flag(1);
        assert_eq!(hdr.c_flag(), 1);
        assert_eq!(hdr.o_c_rsvd, 0b01000000, "Raw byte for c_flag failed");

        // The implementation correctly masks the input, so an input of 2 (0b10) becomes 0.
        // This sets the c_flag back to 0.
        hdr.set_c_flag(0b10);
        assert_eq!(hdr.c_flag(), 0);
        assert_eq!(hdr.o_c_rsvd, 0b00000000, "Masking for c_flag failed");

        // Test that setting the C flag preserves the O flag and reserved bits.
        hdr.o_c_rsvd = 0; // Reset
        hdr.set_o_flag(1); // o_c_rsvd is now 0b10000000

        // Now, set the C flag.
        hdr.set_c_flag(1);

        // Verify that only the C flag bit changed.
        assert_eq!(hdr.c_flag(), 1, "c_flag should be 1");
        assert_eq!(hdr.o_flag(), 1, "o_flag should be preserved");
    }

    #[test]
    fn test_protocol_type() {
        let mut hdr = GeneveHdr::default();
        hdr.set_protocol_type(0xABCD);
        assert_eq!(hdr.protocol_type(), 0xABCD);
        assert_eq!(
            hdr.protocol_type,
            [0xAB, 0xCD],
            "Raw bytes for protocol_type failed (Big Endian check)"
        );
    }

    #[test]
    fn test_vni() {
        let mut hdr = GeneveHdr::default();
        hdr.set_vni(0x00123456);
        assert_eq!(hdr.vni(), 0x00123456);
        assert_eq!(
            hdr.vni,
            [0x12, 0x34, 0x56],
            "Raw bytes for VNI failed (Big Endian check)"
        );

        hdr.set_vni(0xFF123456); // Input with >24 bits
        assert_eq!(hdr.vni(), 0x00123456, "Masking for VNI failed");
        assert_eq!(
            hdr.vni,
            [0x12, 0x34, 0x56],
            "Raw bytes after VNI masking failed"
        );
    }
}
