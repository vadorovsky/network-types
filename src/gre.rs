/// Represents a Generic Routing Encapsulation (GRE) header as defined in RFC 2784.
///
/// GRE is a tunneling protocol that encapsulates a wide variety of network layer
/// protocols inside virtual point-to-point links over an Internet Protocol network.
///
/// This struct represents the maximum possible size of the GRE header, including
/// the optional checksum and reserved fields. The presence of these optional fields
/// is determined by the `checksum_present` flag. The `header_len()` method can be
/// used to determine the actual length of the header at runtime (4 or 8 bytes).
///
/// For more details, see RFC 2784: https://www.rfc-editor.org/rfc/rfc2784.html
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GreHdr {
    /// A 16-bit field containing the Checksum Present flag (1 bit),
    /// Reserved0 (12 bits), and Version (3 bits).
    /// In a compliant packet, Reserved0 and Version MUST be 0.
    flag_reserved0_ver: u16,
    /// The protocol type of the encapsulated payload packet.
    protocol_type: [u8; 2],
    /// The checksum for the GRE header and payload (optional).
    /// This field is only valid if the Checksum Present flag is set.
    checksum: [u8; 2],
    /// A reserved field for future use, which must be transmitted as zero (optional).
    /// This field is only present if the Checksum Present flag is set.
    reserved1: [u8; 2],
}

impl GreHdr {
    /// Checks if the Checksum Present bit (C) is set.
    /// If true, the header is 8 bytes long and includes the `checksum` and `reserved1` fields.
    #[inline]
    pub fn checksum_present(&self) -> bool {
        (u16::from_be(self.flag_reserved0_ver) & 0x8000) != 0
    }

    /// Sets or clears the Checksum Present bit (C).
    /// All other flags and the version number are preserved.
    #[inline]
    pub fn set_checksum_present(&mut self, present: bool) {
        let current_flags = u16::from_be(self.flag_reserved0_ver);
        let new_flags = if present {
            current_flags | 0x8000
        } else {
            current_flags & !0x8000
        };
        self.flag_reserved0_ver = u16::to_be(new_flags);
    }

    /// Gets the 3-bit Version number. For RFC 2784, this value must be 0.
    #[inline]
    pub fn version(&self) -> u8 {
        (u16::from_be(self.flag_reserved0_ver) & 0x0007) as u8
    }

    /// Sets the 3-bit Version number.
    /// According to RFC 2784, this value MUST be 0.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        let version_val = (version & 0x07) as u16;
        let current_flags = u16::from_be(self.flag_reserved0_ver);
        let new_flags = (current_flags & !0x0007) | version_val;
        self.flag_reserved0_ver = u16::to_be(new_flags);
    }

    /// Gets the Protocol Type of the payload packet.
    #[inline]
    pub fn protocol_type(&self) -> [u8; 2] {
        self.protocol_type
    }

    /// Sets the Protocol Type of the payload packet.
    #[inline]
    pub fn set_protocol_type(&mut self, protocol_type: [u8; 2]) {
        // self.protocol_type = u16::to_be(protocol_type);
        self.protocol_type = [protocol_type[0], protocol_type[1]];
    }

    /// Gets the checksum value.
    /// This field is only valid if `checksum_present()` returns true.
    #[inline]
    pub fn checksum(&self) -> [u8; 2] {
        self.checksum
    }

    /// Sets the checksum value.
    /// This is only meaningful to a receiver if `checksum_present()` is set to true.
    #[inline]
    pub fn set_checksum(&mut self, checksum: [u8; 2]) {
        self.checksum = [checksum[0], checksum[1]];
    }

    /// Gets the Reserved1 field.
    /// This field is only valid if `checksum_present()` returns true.
    #[inline]
    pub fn reserved1(&self) -> [u8; 2] {
        self.reserved1
    }

    /// Sets the Reserved1 field.
    /// According to RFC 2784, this value MUST be transmitted as zero.
    #[inline]
    pub fn set_reserved1(&mut self, value: [u8; 2]) {
        self.reserved1 = [value[0], value[1]];
    }

    /// Returns the total length of the GRE header in bytes based on the Checksum Present flag.
    #[inline]
    pub fn header_len(&self) -> usize {
        if self.checksum_present() {
            8
        } else {
            4
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe fn gre_from_bytes(bytes: &[u8; 8]) -> &GreHdr {
        &*(bytes.as_ptr() as *const GreHdr)
    }
    unsafe fn gre_from_bytes_mut(bytes: &mut [u8; 8]) -> &mut GreHdr {
        &mut *(bytes.as_mut_ptr() as *mut GreHdr)
    }
    
    #[test]
    fn test_get_checksum_present() {
        let received_bytes: [u8; 8] = [0x80, 0x00, 0,0,0,0,0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert!(received_header.checksum_present());

        let received_bytes_off: [u8; 8] = [0x00, 0x00, 0,0,0,0,0,0];
        let received_header_off = unsafe { gre_from_bytes(&received_bytes_off) };
        assert!(!received_header_off.checksum_present());
    }

    #[test]
    fn test_set_checksum_present() {
        let mut gre_bytes = [0u8; 8];
        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.set_checksum_present(true);
        }
        assert_eq!(gre_bytes[0], 0x80);
        
        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.set_checksum_present(false);
        }
        assert_eq!(gre_bytes[0], 0x00);
    }

    #[test]
    fn test_get_version() {
        let received_bytes: [u8; 8] = [0x00, 0x07, 0,0,0,0,0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert_eq!(received_header.version(), 7);
    }

    #[test]
    fn test_set_version() {
        let mut gre_bytes = [0u8; 8];
        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.set_version(5);
        }
        assert_eq!(gre_bytes[1], 0x05);

        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.flag_reserved0_ver = u16::to_be(0x8000);
            gre_header.set_version(3);
        }
        assert_eq!([gre_bytes[0], gre_bytes[1]], [0x80, 0x03]);
    }

    #[test]
    fn test_get_protocol_type() {
        let received_bytes: [u8; 8] = [0,0, 0x86, 0xDD, 0,0,0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert_eq!(received_header.protocol_type(), [0x86, 0xDD]);
    }

    #[test]
    fn test_set_protocol_type() {
        let mut gre_bytes = [0u8; 8];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };

        gre_header.set_protocol_type([0x08, 0x00]);
        assert_eq!([gre_bytes[2], gre_bytes[3]], [0x08, 0x00]);
    }

    #[test]
    fn test_get_checksum() {
        let received_bytes: [u8; 8] = [0,0,0,0, 0xFE, 0xDC, 0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert_eq!(received_header.checksum(), [0xFE, 0xDC]);
    }

    #[test]
    fn test_set_checksum() {
        let mut gre_bytes = [0u8; 8];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };

        gre_header.set_checksum([0xAB, 0xCD]);
        assert_eq!([gre_bytes[4], gre_bytes[5]], [0xAB, 0xCD]);
    }

    #[test]
    fn test_get_reserved1() {
        let received_bytes: [u8; 8] = [0,0,0,0,0,0, 0xBE, 0xEF];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert_eq!(received_header.reserved1(), [0xBE, 0xEF]);
    }

    #[test]
    fn test_set_reserved1() {
        let mut gre_bytes = [0u8; 8];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };

        gre_header.set_reserved1([0x12, 0x34]);
        assert_eq!([gre_bytes[6], gre_bytes[7]], [0x12, 0x34]);
    }

    #[test]
    fn test_header_len() {
        let mut gre_bytes = [0u8; 8];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };

        gre_header.set_checksum_present(false);
        assert_eq!(gre_header.header_len(), 4);

        gre_header.set_checksum_present(true);
        assert_eq!(gre_header.header_len(), 8);
    }
}