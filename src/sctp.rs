/// Represents an SCTP (Stream Control Transmission Protocol) header.
///
/// The SCTP common header is defined in RFC 9260, Section 3.1.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SctpHdr {
    /// The source port number.
    pub src_port: [u8; 2],
    /// The destination port number.
    pub dst_port: [u8; 2],
    /// The verification tag of the packet.
    pub verification_tag: [u8; 4],
    /// The checksum of the packet.
    pub checksum: [u8; 4],
}

impl SctpHdr {
    /// The length of the SCTP header in bytes.
    pub const LEN: usize = core::mem::size_of::<SctpHdr>();

    /// Creates a new SCTP header with all fields set to zero.
    #[inline]
    pub fn new() -> Self {
        Self {
            src_port: [0; 2],
            dst_port: [0; 2],
            verification_tag: [0; 4],
            checksum: [0; 4],
        }
    }

    /// Returns the source port number in host byte order.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    /// Sets the source port number from a value in host byte order.
    #[inline]
    pub fn set_src_port(&mut self, port: u16) {
        self.src_port = port.to_be_bytes();
    }

    /// Returns the destination port number in host byte order.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    /// Sets the destination port number from a value in host byte order.
    #[inline]
    pub fn set_dst_port(&mut self, port: u16) {
        self.dst_port = port.to_be_bytes();
    }

    /// Returns the verification tag in host byte order.
    #[inline]
    pub fn verification_tag(&self) -> u32 {
        u32::from_be_bytes(self.verification_tag)
    }

    /// Sets the verification tag from a value in host byte order.
    #[inline]
    pub fn set_verification_tag(&mut self, tag: u32) {
        self.verification_tag = tag.to_be_bytes();
    }

    /// Returns the checksum in host byte order.
    #[inline]
    pub fn checksum(&self) -> u32 {
        u32::from_be_bytes(self.checksum)
    }

    /// Sets the checksum from a value in host byte order.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u32) {
        self.checksum = checksum.to_be_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A static SCTP header for testing.
    // Values are arbitrary but chosen to be non-zero.
    const TEST_SRC_PORT: u16 = 2048;
    const TEST_DST_PORT: u16 = 9; // Discard Protocol
    const TEST_VERIFICATION_TAG: u32 = 0xDEADBEEF;
    const TEST_CHECKSUM: u32 = 0x12345678;

    #[test]
    fn test_sctp_hdr_len() {
        // The SCTP common header is 12 bytes long.
        // 2 (src) + 2 (dst) + 4 (tag) + 4 (checksum) = 12
        assert_eq!(SctpHdr::LEN, 12);
        assert_eq!(core::mem::size_of::<SctpHdr>(), SctpHdr::LEN);
    }

    #[test]
    fn test_sctp_hdr_getters_and_setters() {
        // Create a zeroed header.
        let mut sctp_hdr = SctpHdr::new();

        // Use setters to populate the header.
        sctp_hdr.set_src_port(TEST_SRC_PORT);
        sctp_hdr.set_dst_port(TEST_DST_PORT);
        sctp_hdr.set_verification_tag(TEST_VERIFICATION_TAG);
        sctp_hdr.set_checksum(TEST_CHECKSUM);

        // Verify that the getters return the correct values.
        assert_eq!(sctp_hdr.src_port(), TEST_SRC_PORT);
        assert_eq!(sctp_hdr.dst_port(), TEST_DST_PORT);
        assert_eq!(sctp_hdr.verification_tag(), TEST_VERIFICATION_TAG);
        assert_eq!(sctp_hdr.checksum(), TEST_CHECKSUM);
    }

    #[test]
    fn test_sctp_hdr_raw_bytes() {
        // Create a header and populate it using setters.
        let mut sctp_hdr = SctpHdr::new();
        sctp_hdr.set_src_port(TEST_SRC_PORT); // 0x0800
        sctp_hdr.set_dst_port(TEST_DST_PORT); // 0x0009
        sctp_hdr.set_verification_tag(TEST_VERIFICATION_TAG); // 0xDEADBEEF
        sctp_hdr.set_checksum(TEST_CHECKSUM); // 0x12345678

        // Verify that the underlying byte arrays are in network (big-endian) order.
        assert_eq!(sctp_hdr.src_port, [0x08, 0x00]);
        assert_eq!(sctp_hdr.dst_port, [0x00, 0x09]);
        assert_eq!(sctp_hdr.verification_tag, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(sctp_hdr.checksum, [0x12, 0x34, 0x56, 0x78]);
    }
}