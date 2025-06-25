use crate::eth::EtherType;
use core::fmt;

/// Represents a Generic Routing Encapsulation (GRE) header as defined in RFC 2784.
///
/// GRE is a tunneling protocol that encapsulates a wide variety of network layer
/// protocols inside virtual point-to-point links over an Internet Protocol network.
///
/// This struct represents the maximum possible size of the GRE header, including
/// the optional checksum, key, sequence, and reserved fields. The flags at the start of the header
/// determine the presence of these fields. The `header_len()` method can be
/// used to determine the actual length of the header at runtime (4, 8, 12, or 16 bytes).
///
/// For more details, see RFC 2784: https://www.rfc-editor.org/rfc/rfc2784.html
///
/// /// A struct containing the optional checksum and reserved fields.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct GreHdr{
    /// A 16-bit field containing the flags and version number.
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

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use core::fmt;
    use serde::{de::Error, Deserializer, Serializer};

    impl<'a> serde::Serialize for GreHdr {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let len = self.total_hdr_len();
            // SAFETY: GreHdr is repr(C, packed) and we only serialize
            // the valid part of the header as determined by `total_hdr_len`.
            let bytes =
                unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, len) };
            serializer.serialize_bytes(bytes)
        }
    }

    struct GreHdrVisitor;

    impl<'de> serde::de::Visitor<'de> for GreHdrVisitor {
        type Value = GreHdr;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a byte slice representing a GRE header")
        }

        fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            const MIN_HDR_LEN: usize = 4;
            if v.len() < MIN_HDR_LEN {
                return Err(E::custom("GRE header too short, must be at least 4 bytes"));
            }

            let flags = v[0];
            let mut expected_len = MIN_HDR_LEN;
            if (flags & 0x80) != 0 {
                expected_len += 4;
            } // Checksum
            if (flags & 0x20) != 0 {
                expected_len += 4;
            } // Key
            if (flags & 0x10) != 0 {
                expected_len += 4;
            } // Sequence

            if v.len() < expected_len {
                return Err(E::custom("Incomplete GRE header for flags set"));
            }

            // The input slice `v` may be longer than the actual header. We only want
            // to copy `expected_len` bytes. We copy to a zero-padded, 16-byte
            // array that matches the full size of GreHdr to safely cast it.
            // SAFETY: 
            let mut hdr_bytes = [0u8; GreHdr::LEN];
            hdr_bytes[..expected_len].copy_from_slice(&v[..expected_len]);

            // Safety: We've created a 16-byte buffer on the stack and copied the
            // received bytes into it. It's now safe to interpret these bytes
            // as a GreHdr. The struct is `Copy`, so we are creating a new owned
            // value.
            let hdr = unsafe { *(hdr_bytes.as_ptr() as *const GreHdr) };

            Ok(hdr)
        }
    }

    impl<'de> serde::Deserialize<'de> for GreHdr {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(GreHdrVisitor)
        }
    }
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

    #[test]
    #[cfg(feature = "serde")]
    fn test_custom_serialize() {
        use bincode::{config::standard, serde::encode_to_vec};

        let mut gre_header = GreHdr {
            flags_reserved0_ver: [0; 2],
            protocol_type: EtherType::Ipv4,
            data: GreDataUnion { payload_start: [0; 12] },
        };

        gre_header.set_checksum_present(true);
        gre_header.set_key_present(true);
        gre_header.set_sequence_present(true);
        gre_header.set_version(0);

        gre_header.set_checksum([0x12, 0x34]);
        gre_header.set_key([0xAA, 0xBB, 0xCC, 0xDD]);
        gre_header.set_sequence_number([0x11, 0x22, 0x33, 0x44]);

        let options = standard().with_fixed_int_encoding().with_big_endian();
        let serialized = encode_to_vec(&gre_header, options).unwrap();

        assert_eq!(serialized.len(), gre_header.total_hdr_len());

        assert_eq!(serialized[0], 0xB0);
        assert_eq!(serialized[1], 0x00);
        assert_eq!(serialized[2], 0x08);
        assert_eq!(serialized[3], 0x00);
        assert_eq!(serialized[4], 0x12);
        assert_eq!(serialized[5], 0x34);
        assert_eq!(serialized[8], 0xAA);
        assert_eq!(serialized[9], 0xBB);
        assert_eq!(serialized[10], 0xCC);
        assert_eq!(serialized[11], 0xDD);
        assert_eq!(serialized[12], 0x11);
        assert_eq!(serialized[13], 0x22);
        assert_eq!(serialized[14], 0x33);
        assert_eq!(serialized[15], 0x44);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_custom_deserialize_valid() {
        use bincode::{config::standard, serde::decode_from_slice};

        let mut gre_bytes = [0u8; HDR_MAX_LEN];

        // Set flags and protocol type
        gre_bytes[0] = 0xB0;
        gre_bytes[1] = 0x00;
        gre_bytes[2] = 0x08;
        gre_bytes[3] = 0x00;

        // Checksum
        gre_bytes[4] = 0x12;
        gre_bytes[5] = 0x34;

        // Key
        gre_bytes[8] = 0xAA;
        gre_bytes[9] = 0xBB;
        gre_bytes[10] = 0xCC;
        gre_bytes[11] = 0xDD;

        // Sequence number
        gre_bytes[12] = 0x11;
        gre_bytes[13] = 0x22;
        gre_bytes[14] = 0x33;
        gre_bytes[15] = 0x44;

        let options = standard().with_fixed_int_encoding().with_big_endian();
        let (deserialized, bytes_consumed) = decode_from_slice::<GreHdr, _>(&gre_bytes, options).unwrap();

        assert_eq!(bytes_consumed, 16);
        assert!(deserialized.checksum_present());
        assert!(deserialized.key_present());
        assert!(deserialized.sequence_present());
        assert_eq!(deserialized.get_version(), 0);
        assert_eq!(deserialized.get_protocol_type(), EtherType::Ipv4);
        assert_eq!(deserialized.get_checksum(), Some([0x12, 0x34]));
        assert_eq!(deserialized.get_key(), Some([0xAA, 0xBB, 0xCC, 0xDD]));
        assert_eq!(deserialized.get_sequence_number(), Some([0x11, 0x22, 0x33, 0x44]));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_custom_deserialize_invalid() {
        use bincode::{config::standard, error::DecodeError, serde::decode_from_slice};

        let empty_bytes: [u8; 0] = [];
        let options = standard().with_fixed_int_encoding().with_big_endian();
        let result = decode_from_slice::<GreHdr, _>(&empty_bytes, options);
        assert!(matches!(result, Err(DecodeError::Other(_))));

        let short_bytes = [0x80, 0x00, 0x08];
        let result = decode_from_slice::<GreHdr, _>(&short_bytes, options);
        assert!(matches!(result, Err(DecodeError::Other(_))));

        let incomplete_checksum = [0x80, 0x00, 0x08, 0x00, 0x12];
        let result = decode_from_slice::<GreHdr, _>(&incomplete_checksum, options);
        assert!(matches!(result, Err(DecodeError::Other(_))));

        let incomplete_key = [0x20, 0x00, 0x08, 0x00, 0x12, 0x34, 0x00, 0x00, 0xAA];
        let result = decode_from_slice::<GreHdr, _>(&incomplete_key, options);
        assert!(matches!(result, Err(DecodeError::Other(_))));

        let incomplete_seq = [
            0x10, 0x00, 0x08, 0x00, 0x12, 0x34, 0x00, 0x00,
            0xAA, 0xBB, 0xCC, 0xDD, 0x11
        ];
        let result = decode_from_slice::<GreHdr, _>(&incomplete_seq, options);
        assert!(matches!(result, Err(DecodeError::Other(_))));
    }
}
