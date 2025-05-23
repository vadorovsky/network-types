use core::mem;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SctpHdr {
    /// Source port in network byte order (big-endian)
    pub src: u16,

    /// Destination port in network byte order (big-endian)
    pub dst: u16,

    /// Verification tag
    pub verification_tag: u32,

    /// Checksum
    pub checksum: u32,
}

impl SctpHdr {
    /// The size of the Sctp header in bytes (12 bytes).
    pub const LEN: usize = mem::size_of::<SctpHdr>();
}

#[cfg(test)]
mod test {
    use super::SctpHdr;
    use core::mem;

    #[test]
    fn test_sctp_hdr_size() {
        // SctpHdr should be exactly 12 bytes
        assert_eq!(SctpHdr::LEN, 12);
        assert_eq!(SctpHdr::LEN, mem::size_of::<SctpHdr>());
    }
}
