use core::mem;

/// Represents the VXLAN (Virtual eXtensible Local Area Network) header.
///
/// VXLAN is a network virtualization technology that attempts to address the
/// scalability problems associated with large cloud computing deployments.
/// It uses a VLAN-like encapsulation technique to encapsulate OSI layer 2
/// Ethernet frames within layer 4 UDP packets, using a 24-bit VXLAN Network
/// Identifier (VNI) to segregate traffic.
///
/// The VXLAN header is 8 bytes long.
/// Reference: RFC 7348.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VxlanHdr {
    /// Flags (8 bits).
    /// In a standard VXLAN header, Bit 3 (I flag) must be 1 if VNI is present.
    /// Other flag bits (R) are reserved and should be 0 on transmission.
    pub flags: u8,
    /// Reserved field (24 bits).
    /// According to RFC 7348, these bits MUST be set to zero on transmission.
    pub reserved1: [u8; 3],
    /// This field contains the 24-bit VXLAN Network Identifier (VNI) in its
    /// upper 3 bytes, and an 8-bit reserved field in its lowest byte.
    /// - VNI: `[vni_and_reserved2[0], vni_and_reserved2[1], vni_and_reserved2[2]]`
    /// - Reserved2: `vni_and_reserved2[3]` (MUST be 0 on transmission)
    pub vni_and_reserved2: [u8; 4],
}

/// Mask for the I-flag (VNI Present flag) in the flags field.
/// This corresponds to bit 3 of the flags byte (0-indexed from LSB, value `00001000`).
/// As per RFC 7348, diagram on page 12: `|R|R|R|R|I|R|R|R|`, where `I` is bit 3.
pub const VXLAN_I_FLAG_MASK: u8 = 0x08;

impl VxlanHdr {
    /// The length of the VXLAN header in bytes.
    pub const LEN: usize = mem::size_of::<VxlanHdr>();

    /// Creates a new `VxlanHdr` with the specified VNI.
    ///
    /// Initializes the header with the I-flag set, all reserved bits (in flags,
    /// reserved1, and reserved2 fields) set to 0, and the given VNI.
    pub fn new(vni: u32) -> Self {
        let mut hdr = VxlanHdr {
            flags: VXLAN_I_FLAG_MASK, // I-flag set, other reserved flag bits are 0.
            reserved1: [0u8; 3],      // Reserved, must be 0.
            vni_and_reserved2: [0u8; 4], // VNI part will be set, reserved2 part is 0.
        };
        hdr.set_vni(vni);
        // The lower 8 bits of vni_and_reserved2 (reserved2) are ensured to be 0
        // by the initial [0u8; 4] and set_vni only modifying the top 3 bytes.
        hdr
    }

    /// Returns the raw flags byte.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Sets the raw flags byte.
    ///
    /// Note: For a valid VXLAN header, the I-flag (bit 3) should be set if a VNI
    /// is present, and other reserved bits in the flags field should be 0.
    /// Consider using `set_vni_present()` for managing the I-flag and ensuring
    /// reserved flag bits are appropriately handled if building a packet for transmission.
    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    /// Checks if the I-flag (VNI Present) is set in the flags byte.
    #[inline]
    pub fn vni_present(&self) -> bool {
        (self.flags & VXLAN_I_FLAG_MASK) == VXLAN_I_FLAG_MASK
    }

    /// Sets or clears the I-flag (VNI Present) in the flags byte.
    ///
    /// If `present` is true, the I-flag is set.
    /// If `present` is false, the I-flag is cleared.
    /// This operation preserves other bits in the flags byte.
    #[inline]
    pub fn set_vni_present(&mut self, present: bool) {
        if present {
            self.flags |= VXLAN_I_FLAG_MASK;
        } else {
            self.flags &= !VXLAN_I_FLAG_MASK;
        }
    }

    /// Returns the first reserved field (24 bits).
    /// According to RFC 7348, these bits MUST be set to zero on transmission.
    #[inline]
    pub fn reserved1(&self) -> [u8; 3] {
        self.reserved1
    }

    /// Sets the first reserved field (24 bits).
    /// According to RFC 7348, these bits MUST be set to zero on transmission.
    #[inline]
    pub fn set_reserved1(&mut self, reserved: [u8; 3]) {
        self.reserved1 = reserved;
    }

    /// Returns the VXLAN Network Identifier (VNI) as a 24-bit value (in a u32).
    /// The VNI is stored in the upper 3 bytes of the `vni_and_reserved2` field.
    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be_bytes([
            0, // Pad to 32 bits
            self.vni_and_reserved2[0],
            self.vni_and_reserved2[1],
            self.vni_and_reserved2[2],
        ])
    }

    /// Sets the VXLAN Network Identifier (VNI).
    /// The input `vni` should be a 24-bit value; any higher bits are masked off.
    /// This operation preserves the `reserved2` field (the last byte of `vni_and_reserved2`).
    #[inline]
    pub fn set_vni(&mut self, vni: u32) {
        let vni_24bit = vni & 0x00FF_FFFF; // Ensure it's a 24-bit value
        let vni_bytes = vni_24bit.to_be_bytes(); // Converts to [0x00, B1, B2, B3]
        self.vni_and_reserved2[0] = vni_bytes[1]; // B1
        self.vni_and_reserved2[1] = vni_bytes[2]; // B2
        self.vni_and_reserved2[2] = vni_bytes[3]; // B3
        // self.vni_and_reserved2[3] (reserved2) remains unchanged by this call.
    }

    /// Returns the second reserved field (8 bits).
    /// This field is the last byte of `vni_and_reserved2`.
    /// According to RFC 7348, these bits MUST be set to zero on transmission.
    #[inline]
    pub fn reserved2(&self) -> u8 {
        self.vni_and_reserved2[3]
    }

    /// Sets the second reserved field (8 bits).
    /// This operation preserves the VNI part of `vni_and_reserved2`.
    /// According to RFC 7348, these bits MUST be set to zero on transmission.
    #[inline]
    pub fn set_reserved2(&mut self, reserved: u8) {
        self.vni_and_reserved2[3] = reserved;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlanhdr_len() {
        assert_eq!(VxlanHdr::LEN, 8, "VXLAN header length should be 8 bytes");
    }

    #[test]
    fn test_vxlanhdr_new() {
        let vni_val: u32 = 0xABCDEF;
        let hdr = VxlanHdr::new(vni_val);

        assert_eq!(hdr.flags(), VXLAN_I_FLAG_MASK, "Flags should have I-flag set and others zero");
        assert!(hdr.vni_present(), "VNI present flag should be set by new()");
        assert_eq!(hdr.reserved1(), [0u8; 3], "Reserved1 should be zeroed by new()");
        assert_eq!(hdr.vni(), vni_val, "VNI should be set correctly by new()");
        assert_eq!(hdr.reserved2(), 0u8, "Reserved2 should be zeroed by new()");
    }
    
    #[test]
    fn test_vxlanhdr_default() {
        let hdr = VxlanHdr::default();
        assert_eq!(hdr.flags, 0, "Default flags should be 0");
        assert!(!hdr.vni_present(), "Default VNI present flag should be false");
        assert_eq!(hdr.reserved1, [0,0,0], "Default reserved1 should be zero");
        assert_eq!(hdr.vni_and_reserved2, [0,0,0,0], "Default vni_and_reserved2 should be zero");
        assert_eq!(hdr.vni(), 0, "Default VNI should be 0");
        assert_eq!(hdr.reserved2(), 0, "Default reserved2 should be 0");
    }

    #[test]
    fn test_flags_management() {
        let mut hdr = VxlanHdr::new(0x123); // Starts with flags = VXLAN_I_FLAG_MASK

        // Test raw flags getter/setter
        hdr.set_flags(0xFF);
        assert_eq!(hdr.flags(), 0xFF);

        // Test vni_present getter
        assert!(hdr.vni_present(), "I-flag should be set if flags byte is 0xFF");
        
        hdr.set_flags(0x00); // Clear all flags
        assert!(!hdr.vni_present(), "I-flag should be clear if flags byte is 0x00");

        // Test set_vni_present
        hdr.set_vni_present(true);
        assert_eq!(hdr.flags(), VXLAN_I_FLAG_MASK, "set_vni_present(true) should set I-flag");
        assert!(hdr.vni_present());

        hdr.set_vni_present(false);
        assert_eq!(hdr.flags(), 0x00, "set_vni_present(false) should clear I-flag");
        assert!(!hdr.vni_present());

        // Test interaction of set_vni_present with other bits in flags byte
        hdr.set_flags(0xF0); // Some other bits set, I-flag (0x08) is not set
        assert!(!hdr.vni_present());
        hdr.set_vni_present(true); // Should only affect I-flag bit
        assert_eq!(hdr.flags(), 0xF0 | VXLAN_I_FLAG_MASK, "Setting I-flag should preserve other bits"); // 0xF8
        assert!(hdr.vni_present());
        hdr.set_vni_present(false); // Should only affect I-flag bit
        assert_eq!(hdr.flags(), 0xF0 & !VXLAN_I_FLAG_MASK, "Clearing I-flag should preserve other bits"); // 0xF0
        assert!(!hdr.vni_present());
    }

    #[test]
    fn test_reserved1_management() {
        let mut hdr = VxlanHdr::new(0); // reserved1 is [0,0,0]
        let new_reserved1 = [0x11, 0x22, 0x33];
        hdr.set_reserved1(new_reserved1);
        assert_eq!(hdr.reserved1(), new_reserved1, "reserved1 should be updatable");
    }

    #[test]
    fn test_vni_management() {
        let mut hdr = VxlanHdr::new(0); // Initial VNI is 0, reserved2 is 0

        // Test VNI getter/setter
        let vni_val: u32 = 0xABCDEF;
        hdr.set_vni(vni_val);
        assert_eq!(hdr.vni(), vni_val, "VNI should be set correctly");

        // Test with VNI > 24 bits (should be truncated/masked)
        let large_vni: u32 = 0x12ABCDEF;
        hdr.set_vni(large_vni);
        assert_eq!(hdr.vni(), 0xABCDEF, "VNI should be masked to 24 bits");

        // Test with VNI = 0
        hdr.set_vni(0);
        assert_eq!(hdr.vni(), 0, "VNI should be settable to 0");

        // Test with max 24-bit VNI
        let max_vni: u32 = 0xFFFFFF;
        hdr.set_vni(max_vni);
        assert_eq!(hdr.vni(), max_vni, "Max 24-bit VNI should be settable");
        
        // Ensure reserved2 is not affected by set_vni
        hdr.set_reserved2(0xAA); // Set reserved2 to a known value
        hdr.set_vni(0x123456);   // Change VNI
        assert_eq!(hdr.vni(), 0x123456, "VNI should be updated");
        assert_eq!(hdr.reserved2(), 0xAA, "set_vni should not change reserved2 field");
    }

    #[test]
    fn test_reserved2_management() {
        let mut hdr = VxlanHdr::new(0); // Initial VNI is 0, reserved2 is 0
        
        assert_eq!(hdr.reserved2(), 0u8, "Initial reserved2 from new() should be 0");

        hdr.set_reserved2(0xFF);
        assert_eq!(hdr.reserved2(), 0xFF, "reserved2 should be updatable");
        
        // Ensure VNI is not affected by set_reserved2
        hdr.set_vni(0x123456); // Set VNI to a known value
        hdr.set_reserved2(0xBB); // Change reserved2
        assert_eq!(hdr.reserved2(), 0xBB, "reserved2 should be updated");
        assert_eq!(hdr.vni(), 0x123456, "set_reserved2 should not change VNI field");
    }

    #[test]
    fn test_field_storage_and_retrieval_direct_manipulation() {
        // This test checks behavior if fields are manipulated directly,
        // then accessed via getters.
        let mut hdr = VxlanHdr::default();

        hdr.flags = 0x08; // I-flag set, others 0
        hdr.reserved1 = [0x01, 0x02, 0x03];
        // For vni_and_reserved2: VNI = 0xABCDEF, Reserved2 = 0x55
        hdr.vni_and_reserved2 = [0xAB, 0xCD, 0xEF, 0x55];

        assert_eq!(hdr.flags(), 0x08);
        assert!(hdr.vni_present());
        assert_eq!(hdr.reserved1(), [0x01, 0x02, 0x03]);
        assert_eq!(hdr.vni(), 0xABCDEF);
        assert_eq!(hdr.reserved2(), 0x55);

        // Now modify parts using setters and check raw field values
        hdr.set_vni_present(false); // flags becomes 0x00
        assert_eq!(hdr.flags, 0x00, "Direct field check after set_vni_present(false)");

        hdr.set_reserved1([0x10, 0x20, 0x30]);
        assert_eq!(hdr.reserved1[0], 0x10, "Direct field check after set_reserved1");

        hdr.set_vni(0x654321);
        // vni_and_reserved2 was [0xAB, 0xCD, 0xEF, 0x55]
        // after set_vni(0x654321), it should be [0x65, 0x43, 0x21, 0x55] (reserved2 preserved)
        assert_eq!(hdr.vni_and_reserved2[0], 0x65, "Byte 0 of vni_and_reserved2 after set_vni");
        assert_eq!(hdr.vni_and_reserved2[1], 0x43, "Byte 1 of vni_and_reserved2 after set_vni");
        assert_eq!(hdr.vni_and_reserved2[2], 0x21, "Byte 2 of vni_and_reserved2 after set_vni");
        assert_eq!(hdr.vni_and_reserved2[3], 0x55, "Byte 3 (reserved2) of vni_and_reserved2 preserved after set_vni");
        assert_eq!(hdr.vni(), 0x654321);

        hdr.set_reserved2(0xCC);
        assert_eq!(hdr.vni_and_reserved2[3], 0xCC, "Byte 3 (reserved2) updated by set_reserved2");
        // VNI part should be preserved
        assert_eq!(hdr.vni_and_reserved2[0], 0x65, "Byte 0 (VNI part) preserved after set_reserved2");
        assert_eq!(hdr.vni(), 0x654321); 
    }
}