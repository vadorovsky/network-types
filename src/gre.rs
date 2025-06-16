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
    pub flags_reserved0_ver: [u8; 2],
    /// The protocol type of the encapsulated payload packet.
    pub protocol_type: EtherType,
    /// A union representing the optional part of the header. Its interpretation
    /// depends on the flags set in `flags_reserved0_ver`.
    pub data: GreDataUnion,
}

impl GreHdr {

    pub const LEN: usize = size_of::<GreHdr>();
    
    /// Checks if the Checksum Present bit (C) is set.
    #[inline]
    pub fn checksum_present(&self) -> bool {
        (self.flags_reserved0_ver[0] & 0x80) != 0
    }

    /// Sets or clears the Checksum Present bit (C).
    #[inline]
    pub fn set_checksum_present(&mut self, present: bool) {
        if present {
            self.flags_reserved0_ver[0] |= 0x80;
        } else {
            self.flags_reserved0_ver[0] &= !0x80;
        }
    }

    /// Checks if the Key Present bit (K) is set.
    #[inline]
    pub fn key_present(&self) -> bool {
        (self.flags_reserved0_ver[0] & 0x20) != 0
    }

    /// Sets or clears the Key Present bit (K).
    #[inline]
    pub fn set_key_present(&mut self, present: bool) {
        if present {
            self.flags_reserved0_ver[0] |= 0x20;
        } else {
            self.flags_reserved0_ver[0] &= !0x20;
        }
    }

    /// Checks if the Sequence Number Present bit (S) is set.
    #[inline]
    pub fn sequence_present(&self) -> bool {
        (self.flags_reserved0_ver[0] & 0x10) != 0
    }

    /// Sets or clears the Sequence Number Present bit (S).
    #[inline]
    pub fn set_sequence_present(&mut self, present: bool) {
        if present {
            self.flags_reserved0_ver[0] |= 0x10;
        } else {
            self.flags_reserved0_ver[0] &= !0x10;
        }
    }

    /// Gets the 3-bit Version number.
    #[inline]
    pub fn get_version(&self) -> u8 {
        self.flags_reserved0_ver[1] & 0x07
    }

    /// Sets the 3-bit Version number. Per RFC 2784, this MUST be 0.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.flags_reserved0_ver[1] = (self.flags_reserved0_ver[1] & 0xF8) | (version & 0x07);
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
    #[allow(clippy::unnecessary_unsafe_block)]
    pub fn set_checksum(&mut self, checksum: [u8; 2]) {
        self.set_checksum_present(true);
        // SAFETY: The `unsafe` block is retained to satisfy the compiler's
        // E0133 error, even though the operation is conceptually safe.
        unsafe {
            self.data.fields.check = checksum;
        }
    }

    /// Gets the key as a big-endian 4-byte array, if present.
    #[inline]
    pub fn get_key(&self) -> Option<[u8; 4]> {
        if self.key_present() {
            Some(unsafe { self.data.fields.key })
        } else {
            None
        }
    }

    /// Sets the key and ensures the Key Present bit is set.
    #[inline]
    #[allow(clippy::unnecessary_unsafe_block)]
    pub fn set_key(&mut self, key: [u8; 4]) {
        self.set_key_present(true);
        unsafe { self.data.fields.key = key; }
    }

    /// Gets the sequence number as a big-endian 4-byte array, if present.
    #[inline]
    pub fn get_sequence_number(&self) -> Option<[u8; 4]> {
        if self.sequence_present() {
            Some(unsafe { self.data.fields.sequence })
        } else {
            None
        }
    }

    /// Sets the sequence number and ensures the Sequence Number Present bit is set.
    #[inline]
    #[allow(clippy::unnecessary_unsafe_block)]
    pub fn set_sequence_number(&mut self, sequence: [u8; 4]) {
        self.set_sequence_present(true);
        unsafe { self.data.fields.sequence = sequence; }
    }
    
    /// Returns the total logical length of the GRE header based on the active flags.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        let mut len = 4; // Base header size
        if self.checksum_present() { len += 4; }
        if self.key_present() { len += 4; }
        if self.sequence_present() { len += 4; }
        len
    }
}

/// Custom Debug implementation for GreHdr to correctly format the inner union.
impl fmt::Debug for GreHdr {
    /// Formats the GreHdr for display, choosing the correct union variant to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol_type = self.protocol_type;
        let mut s = f.debug_struct("GreHdr");
        s.field("flag_reserved0_ver", &self.flags_reserved0_ver);
        s.field("protocol_type", &protocol_type);

        if self.checksum_present() || self.key_present() || self.sequence_present() {
            // SAFETY: It is safe to access `fields` because we know at least one
            // optional field is present, so we format that view of the union.
            s.field("data", unsafe { &self.data.fields });
        } else {
            // SAFETY: It is safe to access `payload_start` because we know
            // no optional fields are present.
            s.field("data", unsafe { &self.data.payload_start });
        }
        s.finish()
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
    pub key: [u8; 4],
    pub sequence: [u8; 4],
}

/// A union representing the 12 bytes that can be optional GRE fields
/// or the start of the payload data.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union GreDataUnion {
    /// The interpretation when any optional fields are present.
    pub fields: GreOptionalFields,
    /// The interpretation when no optional fields are present.
    pub payload_start: [u8; 12],
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::EtherType;
    use core::mem::size_of;

    const HDR_MAX_LEN: usize = size_of::<GreHdr>();

    unsafe fn gre_from_bytes(bytes: &[u8; HDR_MAX_LEN]) -> &GreHdr {
        &*(bytes.as_ptr() as *const GreHdr)
    }
    unsafe fn gre_from_bytes_mut(bytes: &mut [u8; HDR_MAX_LEN]) -> &mut GreHdr {
        &mut *(bytes.as_mut_ptr() as *mut GreHdr)
    }

    #[test]
    fn test_get_checksum_present() {
        let received_bytes: [u8; HDR_MAX_LEN] = [0x80, 0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert!(received_header.checksum_present());
    }

    #[test]
    fn test_set_checksum_present() {
        let mut gre_bytes = [0u8; HDR_MAX_LEN];
        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.set_checksum_present(true);
        }
        assert_eq!(gre_bytes[0], 0x80);
    }

    #[test]
    fn test_key_present() {
        let mut gre_bytes = [0u8; HDR_MAX_LEN];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
        assert!(!gre_header.key_present());
        gre_header.set_key_present(true);
        assert!(gre_header.key_present());
        assert_eq!(gre_bytes[0], 0x20);
    }

    #[test]
    fn test_sequence_present() {
        let mut gre_bytes = [0u8; HDR_MAX_LEN];
        let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
        assert!(!gre_header.sequence_present());
        gre_header.set_sequence_present(true);
        assert!(gre_header.sequence_present());
        assert_eq!(gre_bytes[0], 0x10);
    }

    #[test]
    fn test_get_version() {
        let received_bytes: [u8; HDR_MAX_LEN] = [0x00, 0x07, 0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let received_header = unsafe { gre_from_bytes(&received_bytes) };
        assert_eq!(received_header.get_version(), 7);
    }

    #[test]
    fn test_set_version() {
        let mut gre_bytes = [0u8; HDR_MAX_LEN];
        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.set_version(5);
        }
        assert_eq!(gre_bytes[1], 0x05);
    }

    #[test]
    fn test_get_set_key() {
        let mut gre_bytes = [0u8; HDR_MAX_LEN];
        let key_val = [0xAA, 0xBB, 0xCC, 0xDD];
        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.set_key(key_val);
        }
        let read_header = unsafe { gre_from_bytes(&gre_bytes) };
        assert!(read_header.key_present());
        assert_eq!(read_header.get_key(), Some(key_val));
    }

    #[test]
    fn test_get_set_sequence() {
        let mut gre_bytes = [0u8; HDR_MAX_LEN];
        let seq_val = [0x11, 0x22, 0x33, 0x44];
        {
            let gre_header = unsafe { gre_from_bytes_mut(&mut gre_bytes) };
            gre_header.set_sequence_number(seq_val);
        }
        let read_header = unsafe { gre_from_bytes(&gre_bytes) };
        assert!(read_header.sequence_present());
        assert_eq!(read_header.get_sequence_number(), Some(seq_val));
    }

    #[test]
    fn test_updated_header_len() {
        let mut gre_header = GreHdr {
            flags_reserved0_ver: [0; 2],
            protocol_type: EtherType::Ipv4,
            data: GreDataUnion { payload_start: [0; 12] },
        };
        assert_eq!(gre_header.total_hdr_len(), 4);

        gre_header.set_checksum_present(true);
        assert_eq!(gre_header.total_hdr_len(), 8);

        gre_header.set_key_present(true);
        assert_eq!(gre_header.total_hdr_len(), 12);

        gre_header.set_sequence_present(true);
        assert_eq!(gre_header.total_hdr_len(), 16);

        gre_header.set_checksum_present(false);
        assert_eq!(gre_header.total_hdr_len(), 12);
    }
}