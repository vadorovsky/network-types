use core::mem;

/// VXLAN (Virtual eXtensible Local Area Network) header.
///
/// Encapsulates OSI layer 2 Ethernet frames within layer 4 UDP packets.
/// Uses a 24-bit VXLAN Network Identifier (VNI) for traffic segregation.
/// Header length: 8 bytes.
/// Reference: RFC 7348.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VxlanHdr {
    /// Flags (8 bits). Bit 3 (I flag) must be 1 if VNI is present. Other bits are reserved (R).
    pub flags: u8,
    /// Reserved field (24 bits). Must be zero on transmission.
    pub _reserved1: [u8; 3],
    /// Contains the 24-bit VNI (upper 3 bytes) and an 8-bit reserved field (the lowest byte).
    /// The reserved field (the lowest byte) must be zero on transmission.
    pub vni: [u8; 3],
    pub _reserved2: u8,
}

/// Mask for the I-flag (VNI Present flag, bit 3) in the `flags` field.
pub const VXLAN_I_FLAG_MASK: u8 = 0x08;

impl VxlanHdr {
    /// Length of the VXLAN header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<VxlanHdr>();

    /// Creates a new `VxlanHdr`.
    ///
    /// Sets the I-flag, zeros reserved fields, and sets the VNI.
    ///
    /// # Parameters
    /// - `vni`: The 24-bit VXLAN Network Identifier.
    ///
    /// # Returns
    /// A new `VxlanHdr` instance.
    pub fn new(vni: u32) -> Self {
        let mut hdr = VxlanHdr {
            flags: VXLAN_I_FLAG_MASK,
            _reserved1: [0u8; 3],
            vni: [0u8; 3],
            _reserved2: 0u8,
        };
        hdr.set_vni(vni);
        hdr
    }

    /// Creates a new `VxlanHdr`.
    ///
    /// Sets the I-flag, zeros reserved fields, and sets the VNI.
    ///
    /// # Parameters
    /// - `flags`: The 8-bit value to set for the flag field.
    /// - `vni`: The 24-bit VXLAN Network Identifier.
    ///
    /// # Returns
    /// A new `VxlanHdr` instance.
    pub fn with_flags(flags: u8, vni: [u8; 3]) -> Self {
        Self {
            flags,
            _reserved1: [0; 3],
            vni,
            _reserved2: 0,
        }
    }

    /// Returns the raw flags' byte.
    ///
    /// # Returns
    /// The 8-bit flags field.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Sets the raw flags byte.
    ///
    /// # Parameters
    /// - `flags`: The 8-bit value to set for the flags field.
    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    /// Checks if the I-flag (VNI Present) is set.
    ///
    /// # Returns
    /// `true` if the I-flag is set, `false` otherwise.
    #[inline]
    pub fn vni_present(&self) -> bool {
        (self.flags & VXLAN_I_FLAG_MASK) == VXLAN_I_FLAG_MASK
    }

    /// Sets or clears the I-flag (VNI Present).
    ///
    /// Preserves other flag bits.
    ///
    /// # Parameters
    /// - `present`: If `true`, sets the I-flag; otherwise, clears it.
    #[inline]
    pub fn set_vni_present(&mut self, present: bool) {
        if present {
            self.flags |= VXLAN_I_FLAG_MASK;
        } else {
            self.flags &= !VXLAN_I_FLAG_MASK;
        }
    }

    /// Returns the VXLAN Network Identifier (VNI).
    ///
    /// # Returns
    /// The 24-bit VNI as a `u32`.
    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be_bytes([0, self.vni[0], self.vni[1], self.vni[2]])
    }

    /// Sets the VXLAN Network Identifier (VNI).
    ///
    /// Masks the input `vni` to 24 bits. Preserves the `reserved2` field.
    ///
    /// # Parameters
    /// - `vni`: The 24-bit VNI value.
    #[inline]
    pub fn set_vni(&mut self, vni: u32) {
        let vni_24bit = vni & 0x00FF_FFFF;
        let vni_bytes = vni_24bit.to_be_bytes();
        self.vni[0] = vni_bytes[1];
        self.vni[1] = vni_bytes[2];
        self.vni[2] = vni_bytes[3];
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
        assert_eq!(
            hdr.flags(),
            VXLAN_I_FLAG_MASK,
            "Flags should have I-flag set and others zero"
        );
        assert!(hdr.vni_present(), "VNI present flag should be set by new()");
        assert_eq!(hdr.vni(), vni_val, "VNI should be set correctly by new()");
    }

    #[test]
    fn test_flags_management() {
        let mut hdr = VxlanHdr::new(0x123);
        hdr.set_flags(0xFF);
        assert_eq!(hdr.flags(), 0xFF);
        assert!(
            hdr.vni_present(),
            "I-flag should be set if flags byte is 0xFF"
        );
        hdr.set_flags(0x00);
        assert!(
            !hdr.vni_present(),
            "I-flag should be clear if flags byte is 0x00"
        );
        hdr.set_vni_present(true);
        assert_eq!(
            hdr.flags(),
            VXLAN_I_FLAG_MASK,
            "set_vni_present(true) should set I-flag"
        );
        assert!(hdr.vni_present());
        hdr.set_vni_present(false);
        assert_eq!(
            hdr.flags(),
            0x00,
            "set_vni_present(false) should clear I-flag"
        );
        assert!(!hdr.vni_present());
        hdr.set_flags(0xF0);
        assert!(!hdr.vni_present());
        hdr.set_vni_present(true);
        assert_eq!(
            hdr.flags(),
            0xF0 | VXLAN_I_FLAG_MASK,
            "Setting I-flag should preserve other bits"
        );
        assert!(hdr.vni_present());
        hdr.set_vni_present(false);
        assert_eq!(
            hdr.flags(),
            0xF0 & !VXLAN_I_FLAG_MASK,
            "Clearing I-flag should preserve other bits"
        );
        assert!(!hdr.vni_present());
    }

    #[test]
    fn test_vni_management() {
        let mut hdr = VxlanHdr::new(0);
        let vni_val: u32 = 0xABCDEF;
        hdr.set_vni(vni_val);
        assert_eq!(hdr.vni(), vni_val, "VNI should be set correctly");
        let large_vni: u32 = 0x12ABCDEF;
        hdr.set_vni(large_vni);
        assert_eq!(hdr.vni(), 0xABCDEF, "VNI should be masked to 24 bits");
        hdr.set_vni(0);
        assert_eq!(hdr.vni(), 0, "VNI should be settable to 0");
        let max_vni: u32 = 0xFFFFFF;
        hdr.set_vni(max_vni);
        assert_eq!(hdr.vni(), max_vni, "Max 24-bit VNI should be settable");
        hdr.set_vni(0x123456);
        assert_eq!(hdr.vni(), 0x123456, "VNI should be updated");
    }

    #[test]
    fn test_field_storage_and_retrieval_direct_manipulation() {
        let mut hdr = VxlanHdr::with_flags(0x08, [0xAB, 0xCD, 0xEF]);
        hdr.flags = 0x08;
        hdr.vni = [0xAB, 0xCD, 0xEF];
        assert_eq!(hdr.flags(), 0x08);
        assert!(hdr.vni_present());
        assert_eq!(hdr.vni(), 0xABCDEF);
        hdr.set_vni_present(false);
        assert_eq!(
            hdr.flags, 0x00,
            "Direct field check after set_vni_present(false)"
        );
        hdr.set_vni(0x654321);
        assert_eq!(hdr.vni[0], 0x65, "Byte 0 of vni after set_vni");
        assert_eq!(hdr.vni[1], 0x43, "Byte 1 of vni after set_vni");
        assert_eq!(hdr.vni[2], 0x21, "Byte 2 of vni after set_vni");
        assert_eq!(hdr.vni(), 0x654321);
        assert_eq!(
            hdr.vni[0], 0x65,
            "Byte 0 of vni preserved after set_reserved2"
        );
        assert_eq!(hdr.vni(), 0x654321);
    }
}
