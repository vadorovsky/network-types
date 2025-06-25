#![no_std]

use core::ptr;

/// Length of the base GRE header in bytes.
const GRE_BASE_HDR_LEN: usize = 4;
/// Length of the Checksum and Reserved1 fields in bytes.
const GRE_CHECKSUM_HDR_LEN: usize = 4; // Checksum (2 bytes) + Reserved1 (2 bytes)
/// Length of the Key field in bytes.
const GRE_KEY_HDR_LEN: usize = 4;
/// Length of the Sequence Number field in bytes.
const GRE_SEQ_HDR_LEN: usize = 4;
/// Bitmask for the Checksum Present flag (C flag).
const C_FLAG_MASK: u8 = 0x80;
/// Bitmask for the Key Present flag (K flag).
const K_FLAG_MASK: u8 = 0x20;
/// Bitmask for the Sequence Number Present flag (S flag).
const S_FLAG_MASK: u8 = 0x10;
/// Bitmask for the Version field.
const VER_MASK: u8 = 0x07;

/// A custom error type for parsing failures.
#[derive(Debug, PartialEq)]
pub enum GreParseError {
    /// The provided slice is too short to contain even the base GRE header.
    TooShortForBaseHeader,
    /// The provided slice is too short for the fields indicated by the flags.
    TooShortForOptionalFields,
}

/// A custom error type for write operations.
#[derive(Debug, PartialEq)]
pub enum GreWriteError {
    /// The field you are trying to write to is not present in the header.
    FieldNotPresent,
}

/// A safe wrapper for a GRE packet that provides read/write access.
///
/// This struct holds a mutable reference to a byte buffer and allows safe
/// manipulation of the GRE header fields by calculating field offsets based
/// on the header flags and using pointer arithmetic.
pub struct GreHdr<'a> {
    buffer: &'a mut [u8],
}

impl<'a> GreHdr<'a> {
    /// Creates a new `GreHdr` wrapper from a mutable byte slice.
    ///
    /// This function performs the critical validation: ensuring the slice is
    /// long enough for the fixed portion and all optional fields indicated
    /// by the C, K, and S flags. This check is essential for the eBPF verifier.
    pub fn new(buffer: &'a mut [u8]) -> Result<Self, GreParseError> {
        if buffer.len() < GRE_BASE_HDR_LEN {
            return Err(GreParseError::TooShortForBaseHeader);
        }

        // Read the first byte for flags to determine expected length
        let flags = buffer[0];
        let mut expected_len = GRE_BASE_HDR_LEN;
        if (flags & C_FLAG_MASK) != 0 { expected_len += GRE_CHECKSUM_HDR_LEN; }
        if (flags & K_FLAG_MASK) != 0 { expected_len += GRE_KEY_HDR_LEN; }
        if (flags & S_FLAG_MASK) != 0 { expected_len += GRE_SEQ_HDR_LEN; }

        if buffer.len() < expected_len {
            return Err(GreParseError::TooShortForOptionalFields);
        }

        Ok(Self { buffer })
    }

    /// Calculates the total length of the GRE header based on the flags.
    ///
    /// The length depends on which optional fields are present, as indicated by
    /// the C, K, and S flags. The base header is always 4 bytes, and each optional
    /// field adds additional bytes to the total length.
    pub fn header_len(&self) -> usize {
        let mut len = GRE_BASE_HDR_LEN;
        if self.c_flag() { len += GRE_CHECKSUM_HDR_LEN; }
        if self.k_flag() { len += GRE_KEY_HDR_LEN; }
        if self.s_flag() { len += GRE_SEQ_HDR_LEN; }
        len
    }

    /// Returns the flags byte from the GRE header.
    ///
    /// This byte contains the C, K, and S flags that indicate which optional fields are present.
    #[inline(always)]
    pub fn flags(&self) -> u8 {
        // Safe because `new()` confirmed the buffer is at least 4 bytes long.
        self.buffer[0]
    }

    /// Returns the GRE version field (3 bits).
    ///
    /// The version field indicates the GRE protocol version.
    #[inline(always)]
    pub fn version(&self) -> u8 {
        // Safe because `new()` confirmed the buffer is at least 4 bytes long.
        self.buffer[1] & VER_MASK
    }

    /// Returns true if the Checksum Present flag (C flag) is set.
    ///
    /// When this flag is set, the Checksum and Reserved1 fields are present in the header.
    #[inline(always)]
    pub fn c_flag(&self) -> bool { (self.flags() & C_FLAG_MASK) != 0 }

    /// Returns true if the Key Present flag (K flag) is set.
    ///
    /// When this flag is set, the Key field is present in the header.
    #[inline(always)]
    pub fn k_flag(&self) -> bool { (self.flags() & K_FLAG_MASK) != 0 }

    /// Returns true if the Sequence Number Present flag (S flag) is set.
    ///
    /// When this flag is set, the Sequence Number field is present in the header.
    #[inline(always)]
    pub fn s_flag(&self) -> bool { (self.flags() & S_FLAG_MASK) != 0 }

    /// Returns the Protocol Type field from the GRE header.
    ///
    /// This field indicates the protocol type of the payload packet.
    #[inline(always)]
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Returns the Checksum and Reserved1 fields if the C flag is set.
    ///
    /// These fields are only present when the C flag is set. The Checksum field
    /// contains the checksum of the GRE header and payload, and the Reserved1 field
    /// is reserved for future use.
    ///
    /// Returns `None` if the C flag is not set.
    pub fn checksum_and_reserved(&self) -> Option<(u16, u16)> {
        if !self.c_flag() { return None; }
        let offset = GRE_BASE_HDR_LEN;
        // The `new()` constructor guarantees the buffer is long enough for this read.
        unsafe {
            let checksum_ptr = self.buffer.as_ptr().add(offset) as *const u16;
            let reserved_ptr = self.buffer.as_ptr().add(offset + 2) as *const u16;
            let checksum = u16::from_be(ptr::read_unaligned(checksum_ptr));
            let reserved = u16::from_be(ptr::read_unaligned(reserved_ptr));
            Some((checksum, reserved))
        }
    }

    /// Returns the Key field if the K flag is set.
    ///
    /// The Key field is only present when the K flag is set. It contains a key
    /// value that can be used to identify a particular GRE tunnel.
    ///
    /// Returns `None` if the K flag is not set.
    pub fn key(&self) -> Option<u32> {
        if !self.k_flag() { return None; }
        let mut offset = GRE_BASE_HDR_LEN;
        if self.c_flag() { offset += GRE_CHECKSUM_HDR_LEN; }
        unsafe {
            let key_ptr = self.buffer.as_ptr().add(offset) as *const u32;
            Some(u32::from_be(ptr::read_unaligned(key_ptr)))
        }
    }

    /// Returns the Sequence Number field if the S flag is set.
    ///
    /// The Sequence Number field is only present when the S flag is set. It contains
    /// a sequence number that can be used to maintain packet order.
    ///
    /// Returns `None` if the S flag is not set.
    pub fn sequence_num(&self) -> Option<u32> {
        if !self.s_flag() { return None; }
        let mut offset = GRE_BASE_HDR_LEN;
        if self.c_flag() { offset += GRE_CHECKSUM_HDR_LEN; }
        if self.k_flag() { offset += GRE_KEY_HDR_LEN; }
        unsafe {
            let seq_ptr = self.buffer.as_ptr().add(offset) as *const u32;
            Some(u32::from_be(ptr::read_unaligned(seq_ptr)))
        }
    }
    
    /// Sets the 3-bit version number.
    ///
    /// This method updates the version field in the GRE header, ensuring that
    /// only the 3 bits of the version field are modified.
    pub fn set_version(&mut self, version: u8) {
        let mut second_byte = self.buffer[1];
        second_byte &= !VER_MASK;
        second_byte |= version & VER_MASK;
        self.buffer[1] = second_byte;
    }

    /// Sets the Protocol Type field in the GRE header.
    ///
    /// This field indicates the protocol type of the payload packet.
    pub fn set_protocol_type(&mut self, protocol_type: u16) {
        self.buffer[2..4].copy_from_slice(&protocol_type.to_be_bytes());
    }

    /// Sets the Checksum and Reserved1 fields.
    ///
    /// These fields can only be set when the C flag is set. The Checksum field
    /// contains the checksum of the GRE header and payload, and the Reserved1 field
    /// is reserved for future use.
    ///
    /// Returns an error if the C flag is not set.
    pub fn set_checksum_and_reserved(&mut self, checksum: u16, reserved: u16) -> Result<(), GreWriteError> {
        if !self.c_flag() { return Err(GreWriteError::FieldNotPresent); }
        let offset = GRE_BASE_HDR_LEN;
        unsafe {
            let checksum_ptr = self.buffer.as_mut_ptr().add(offset) as *mut u16;
            let reserved_ptr = self.buffer.as_mut_ptr().add(offset + 2) as *mut u16;
            ptr::write_unaligned(checksum_ptr, checksum.to_be());
            ptr::write_unaligned(reserved_ptr, reserved.to_be());
        }
        Ok(())
    }

    /// Sets the Key field.
    ///
    /// The Key field can only be set when the K flag is set. It contains a key
    /// value that can be used to identify a particular GRE tunnel.
    ///
    /// Returns an error if the K flag is not set.
    pub fn set_key(&mut self, key: u32) -> Result<(), GreWriteError> {
        if !self.k_flag() { return Err(GreWriteError::FieldNotPresent); }
        let mut offset = GRE_BASE_HDR_LEN;
        if self.c_flag() { offset += GRE_CHECKSUM_HDR_LEN; }
        unsafe {
            let key_ptr = self.buffer.as_mut_ptr().add(offset) as *mut u32;
            ptr::write_unaligned(key_ptr, key.to_be());
        }
        Ok(())
    }

    /// Sets the Sequence Number field.
    ///
    /// The Sequence Number field can only be set when the S flag is set. It contains
    /// a sequence number that can be used to maintain packet order.
    ///
    /// Returns an error if the S flag is not set.
    pub fn set_sequence_num(&mut self, seq: u32) -> Result<(), GreWriteError> {
        if !self.s_flag() { return Err(GreWriteError::FieldNotPresent); }
        let mut offset = GRE_BASE_HDR_LEN;
        if self.c_flag() { offset += GRE_CHECKSUM_HDR_LEN; }
        if self.k_flag() { offset += GRE_KEY_HDR_LEN; }
        unsafe {
            let seq_ptr = self.buffer.as_mut_ptr().add(offset) as *mut u32;
            ptr::write_unaligned(seq_ptr, seq.to_be());
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    fn create_test_gre_packet() -> [u8; 16] {
        [
            0xB0, 0x01, 0x86, 0xDD, // Flags (C,K,S=1), Ver=1, Proto=IPv6
            0xAA, 0xAA, 0xBB, 0xBB, // Checksum, Reserved1
            0xDE, 0xAD, 0xBE, 0xEF, // Key
            0x12, 0x34, 0x56, 0x78, // Sequence Number
        ]
    }

    #[test]
    fn test_gre_header_creation() {
        let mut buffer = create_test_gre_packet();
        let packet = GreHdr::new(&mut buffer);
        assert!(packet.is_ok(), "Failed to create GRE header");
    }

    #[test]
    fn test_gre_flags() {
        let mut buffer = create_test_gre_packet();
        let packet = GreHdr::new(&mut buffer).unwrap();

        assert_eq!(packet.c_flag(), true, "C flag should be set");
        assert_eq!(packet.k_flag(), true, "K flag should be set");
        assert_eq!(packet.s_flag(), true, "S flag should be set");
    }

    #[test]
    fn test_gre_version() {
        let mut buffer = create_test_gre_packet();
        let packet = GreHdr::new(&mut buffer).unwrap();

        assert_eq!(packet.version(), 1, "Version should be 1");
    }

    #[test]
    fn test_gre_protocol_type() {
        let mut buffer = create_test_gre_packet();
        let packet = GreHdr::new(&mut buffer).unwrap();

        assert_eq!(packet.protocol_type(), 0x86DD, "Protocol type should be IPv6 (0x86DD)");
    }

    #[test]
    fn test_gre_optional_fields_reading() {
        let mut buffer = create_test_gre_packet();
        let packet = GreHdr::new(&mut buffer).unwrap();

        assert_eq!(packet.checksum_and_reserved(), Some((0xAAAA, 0xBBBB)), 
                   "Checksum and reserved fields should be correctly read");
        assert_eq!(packet.key(), Some(0xDEADBEEF), 
                   "Key field should be correctly read");
        assert_eq!(packet.sequence_num(), Some(0x12345678), 
                   "Sequence number field should be correctly read");
    }

    #[test]
    fn test_gre_set_version() {
        let mut buffer = create_test_gre_packet();
        let mut packet = GreHdr::new(&mut buffer).unwrap();

        packet.set_version(7);
        assert_eq!(packet.version(), 7, "Version should be updated to 7");
        assert_eq!(buffer[1], 0x07, "Version in buffer should be updated to 7");
    }

    #[test]
    fn test_gre_set_protocol_type() {
        let mut buffer = create_test_gre_packet();
        let mut packet = GreHdr::new(&mut buffer).unwrap();

        packet.set_protocol_type(0x0800); // Change to IPv4
        assert_eq!(packet.protocol_type(), 0x0800, "Protocol type should be updated to IPv4 (0x0800)");
        assert_eq!(buffer[2..4], [0x08, 0x00], "Protocol type in buffer should be updated");
    }

    #[test]
    fn test_gre_set_checksum_and_reserved() {
        let mut buffer = create_test_gre_packet();
        let mut packet = GreHdr::new(&mut buffer).unwrap();

        let result = packet.set_checksum_and_reserved(0x1111, 0x2222);
        assert_eq!(result, Ok(()), "Setting checksum and reserved should succeed");
        assert_eq!(packet.checksum_and_reserved(), Some((0x1111, 0x2222)), 
                   "Checksum and reserved fields should be updated");
        assert_eq!(buffer[4..8], [0x11, 0x11, 0x22, 0x22], 
                   "Checksum and reserved in buffer should be updated");
    }

    #[test]
    fn test_gre_set_key() {
        let mut buffer = create_test_gre_packet();
        let mut packet = GreHdr::new(&mut buffer).unwrap();

        let result = packet.set_key(0x11223344);
        assert_eq!(result, Ok(()), "Setting key should succeed");
        assert_eq!(packet.key(), Some(0x11223344), "Key field should be updated");
        assert_eq!(buffer[8..12], [0x11, 0x22, 0x33, 0x44], "Key in buffer should be updated");
    }

    #[test]
    fn test_gre_set_sequence_num() {
        let mut buffer = create_test_gre_packet();
        let mut packet = GreHdr::new(&mut buffer).unwrap();

        let result = packet.set_sequence_num(0xAABBCCDD);
        assert_eq!(result, Ok(()), "Setting sequence number should succeed");
        assert_eq!(packet.sequence_num(), Some(0xAABBCCDD), "Sequence number field should be updated");
        assert_eq!(buffer[12..16], [0xAA, 0xBB, 0xCC, 0xDD], 
                   "Sequence number in buffer should be updated");
    }

    #[test]
    fn test_gre_header_length() {
        let mut buffer = create_test_gre_packet();
        let packet = GreHdr::new(&mut buffer).unwrap();

        assert_eq!(packet.header_len(), 16, 
                   "Header length should be 16 bytes with all flags set");
    }

    #[test]
    fn test_gre_field_not_present_error() {
        // Create a GRE packet with no flags set
        let mut buffer = [0x00, 0x01, 0x86, 0xDD, 0x00, 0x00, 0x00, 0x00];
        let mut packet = GreHdr::new(&mut buffer).unwrap();

        // Attempt to set fields that aren't present
        let checksum_result = packet.set_checksum_and_reserved(0x1111, 0x2222);
        let key_result = packet.set_key(0x11223344);
        let seq_result = packet.set_sequence_num(0xAABBCCDD);

        assert_eq!(checksum_result, Err(GreWriteError::FieldNotPresent), 
                   "Setting checksum should fail when C flag is not set");
        assert_eq!(key_result, Err(GreWriteError::FieldNotPresent), 
                   "Setting key should fail when K flag is not set");
        assert_eq!(seq_result, Err(GreWriteError::FieldNotPresent), 
                   "Setting sequence number should fail when S flag is not set");
    }
}
