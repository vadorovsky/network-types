use crate::eth::EtherType;
use core::fmt;

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
/// 
/// /// A struct containing the optional checksum and reserved fields.

#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GreHdr {
    /// A 16-bit field containing the Checksum Present flag (1 bit),
    /// Reserved0 (12 bits), and Version (3 bits).
    /// In a compliant packet, Reserved0 and Version MUST be 0.
    pub flag_reserved0_ver: [u8; 2],
    /// The protocol type of the encapsulated payload packet.
    pub protocol_type: EtherType,
    /// This field is only valid if the Checksum Present flag is set.
    pub data: GreDataUnion,
}

impl GreHdr {

    pub const LEN: usize = size_of::<GreHdr>();
    
    /// Checks if the Checksum Present bit (C) is set.
    #[inline]
    pub fn checksum_present(&self) -> bool {
        (self.flag_reserved0_ver[0] & 0x80) != 0
    }

    /// Sets or clears the Checksum Present bit (C).
    #[inline]
    pub fn set_checksum_present(&mut self, present: bool) {
        if present {
            self.flag_reserved0_ver[0] |= 0x80;
        } else {
            self.flag_reserved0_ver[0] &= !0x80;
        }
    }

    /// Gets the 3-bit Version number.
    #[inline]
    pub fn get_version(&self) -> u8 {
        self.flag_reserved0_ver[1] & 0x07
    }

    /// Sets the 3-bit Version number. Per RFC 2784, this MUST be 0.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.flag_reserved0_ver[1] = (self.flag_reserved0_ver[1] & 0xF8) | (version & 0x07);
    }

    /// Gets the Protocol Type as a big-endian 2-byte array.
    #[inline]
    pub fn get_protocol_type(&self) -> EtherType {
        self.protocol_type
    }

    /// Sets the Protocol Type from a big-endian 2-byte array.
    #[inline]
    pub fn set_protocol_type(&mut self, protocol_type: EtherType) {
        self.protocol_type = protocol_type;
    }

    /// Gets the checksum as a big-endian 2-byte array.
    #[inline]
    pub fn get_checksum(&self) -> Option<[u8; 2]> {
        if self.checksum_present() {
            // SAFETY: Unsafe access to check field made safe by the guard above.
            Some(unsafe { self.data.fields.check })
        } else {
            None
        }
    }

    /// Sets the checksum from a big-endian 2-byte array.
    #[inline]
    pub fn set_checksum(&mut self, checksum: [u8; 2]) {
        self.set_checksum_present(true);
        // SAFETY: Unsafe set to check field made safe by the set above.
        unsafe {
            self.data.fields.check = checksum;
        }
    }

    /// Returns the total length of the GRE header based on the RFC specification.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        if self.checksum_present() {
            8
        } else {
            4
        }
    }
}

/// Custom Debug implementation for GreHdr to correctly format the inner union.
impl fmt::Debug for GreHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("GreHdr");
        let protocol_type = self.protocol_type;

        debug_struct.field("flag_reserved0_ver", &self.flag_reserved0_ver);
        debug_struct.field("protocol_type", &protocol_type);

        // Check the flag to decide how to safely interpret and format the union.
        if self.checksum_present() {
            // SAFETY: It is safe to access the `fields` variant because we have
            // confirmed the Checksum Present bit is set.
            debug_struct.field("data", unsafe { &self.data.fields });
        } else {
            // SAFETY: It is safe to access the `payload_start` variant because
            // we have confirmed the Checksum Present bit is not set.
            debug_struct.field("data", unsafe { &self.data.payload_start });
        }

        debug_struct.finish()
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct GreOptionalFields {
    /// This field is only valid if the Checksum Present flag is set.
    pub check: [u8; 2],
    /// A reserved field for future use, which MUST be transmitted as zero (optional).
    /// This field is only present if the Checksum Present flag is set.
    pub _reserved1: [u8; 2],
}

/// A union representing the 4 bytes that can either be optional GRE fields
/// or the start of the payload data.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union GreDataUnion {
    /// The interpretation when checksum_present() is true.
    fields: GreOptionalFields,
    /// The interpretation when checksum_present() is false.
    payload_start: [u8; 4],
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
        assert_eq!(received_header.get_version(), 7);
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
            gre_header.flag_reserved0_ver = [0x80, 0x00];
            gre_header.set_version(3);
        }
        assert_eq!([gre_bytes[0], gre_bytes[1]], [0x80, 0x03]);
    }

    #[test]
    fn test_get_protocol_type() {
        let received_bytes: [u8; 8] = [0,0, 0x86, 0xDD, 0,0,0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert_eq!(received_header.get_protocol_type(), EtherType::Ipv6);
    }

    #[test]
    fn test_set_protocol_type() {
        let mut gre_bytes = [0u8; 8];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };

        gre_header.set_protocol_type(EtherType::Arp);
        assert_eq!([gre_bytes[2], gre_bytes[3]], [0x08, 0x06]);
    }

    #[test]
    fn test_get_checksum() {
        let received_bytes: [u8; 8] = [0x80, 0x00,0,0, 0xFE, 0xDC, 0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert_eq!(received_header.get_checksum(), Some([0xFE, 0xDC]));
    }

    #[test]
    fn test_set_checksum() {
        let mut gre_bytes = [0u8; 8];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };

        gre_header.set_checksum([0xAB, 0xCD]);
        assert_eq!([gre_bytes[4], gre_bytes[5]], [0xAB, 0xCD]);
    }

    #[test]
    fn test_header_len() {
        let mut gre_bytes = [0u8; 8];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };

        gre_header.set_checksum_present(false);
        assert_eq!(gre_header.total_hdr_len(), 4);

        gre_header.set_checksum_present(true);
        assert_eq!(gre_header.total_hdr_len(), 8);
    }
}