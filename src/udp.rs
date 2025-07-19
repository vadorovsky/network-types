use core::mem;

use crate::{getter_be, setter_be};

/// UDP header, which is present after the IP header.
///
/// This struct represents the User Datagram Protocol (UDP) header as defined in RFC 768.
/// The UDP header is 8 bytes long and contains source and destination ports, length, and checksum fields.
/// All fields are stored in network byte order (big-endian).
///
/// # Example
/// ```
/// use network_types::udp::UdpHdr;
///
/// let mut udp_header = UdpHdr {
///     src: [0, 0],
///     dst: [0, 0],
///     len: [0, 0],
///     check: [0, 0],
/// };
///
/// udp_header.set_src_port(12345);
/// udp_header.set_dst_port(80);
/// udp_header.set_len(28); // 8 bytes header + 20 bytes payload
/// udp_header.set_checksum(0); // Checksum calculation would be done separately
/// ```
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct UdpHdr {
    /// Source port in network byte order (big-endian)
    pub src: [u8; 2],
    /// Destination port in network byte order (big-endian)
    pub dst: [u8; 2],
    /// Length of UDP header and data in bytes, in network byte order (big-endian)
    pub len: [u8; 2],
    /// Checksum of UDP header and data, in network byte order (big-endian)
    pub check: [u8; 2],
}

impl UdpHdr {
    /// The size of the UDP header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<UdpHdr>();

    /// Returns the source port number.
    ///
    /// This method converts the source port from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The source port as a u16 value.
    #[inline]
    pub fn src_port(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, src, u16) }
    }

    /// Sets the source port number.
    ///
    /// This method converts the source port from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `source` - The source port number to set.
    #[inline]
    pub fn set_src_port(&mut self, src: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, src, src) }
    }

    /// Returns the destination port number.
    ///
    /// This method converts the destination port from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The destination port as a u16 value.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, dst, u16) }
    }

    /// Sets the destination port number.
    ///
    /// This method converts the destination port from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `dest` - The destination port number to set.
    /// ```
    #[inline]
    pub fn set_dst_port(&mut self, dst: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, dst, dst) }
    }

    /// Returns the length of the UDP datagram in bytes.
    ///
    /// The length includes both the UDP header (8 bytes) and the UDP payload.
    /// This method converts the length from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The length as a u16 value.
    #[inline]
    pub fn len(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, len, u16) }
    }

    /// Returns true if the UDP length field is zero.
    ///
    /// A zero length indicates an invalid or empty UDP datagram, as the minimum valid length
    /// is 8 bytes (the size of the UDP header).
    ///
    /// # Returns
    /// `true` if length is zero, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.len == [0, 0]
    }

    /// Sets the length of the UDP datagram in bytes.
    ///
    /// The length should include both the UDP header (8 bytes) and the UDP payload.
    /// This method converts the length from host byte order to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `len` - The length to set in bytes.
    #[inline]
    pub fn set_len(&mut self, len: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, len, len) }
    }

    /// Returns the UDP checksum.
    ///
    /// The checksum is calculated over the UDP header, the UDP payload, and a pseudo-header
    /// derived from the IP header. This method converts the checksum from network byte order
    /// (big-endian) to host byte order.
    ///
    /// # Returns
    /// The checksum as a u16 value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, check, u16) }
    }

    /// Sets the UDP checksum.
    ///
    /// The checksum should be calculated over the UDP header, the UDP payload, and a pseudo-header
    /// derived from the IP header. This method converts the checksum from host byte order to
    /// network byte order (big-endian).
    ///
    /// A value of 0 indicates that the checksum is not used (IPv4 only).
    ///
    /// # Parameters
    /// * `check` - The checksum value to set.
    #[inline]
    pub fn set_checksum(&mut self, check: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, check, check) }
    }
}

#[cfg(test)]
mod test {
    use super::UdpHdr;
    use core::mem;

    #[test]
    fn test_udp_hdr_size() {
        // UdpHdr should be exactly 8 bytes
        assert_eq!(UdpHdr::LEN, 8);
        assert_eq!(UdpHdr::LEN, mem::size_of::<UdpHdr>());
    }

    #[test]
    fn test_source_port() {
        let mut udp_hdr = UdpHdr {
            src: [0, 0],
            dst: [0, 0],
            len: [0, 0],
            check: [0, 0],
        };

        // Test with a standard value
        let test_port: u16 = 12345;
        udp_hdr.set_src_port(test_port);
        assert_eq!(udp_hdr.src_port(), test_port);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(udp_hdr.src, [0x30, 0x39]); // 12345 in big-endian

        // Test with zero
        udp_hdr.set_src_port(0);
        assert_eq!(udp_hdr.src_port(), 0);
        assert_eq!(udp_hdr.src, [0, 0]);

        // Test with max value
        udp_hdr.set_src_port(u16::MAX);
        assert_eq!(udp_hdr.src_port(), u16::MAX);
        assert_eq!(udp_hdr.src, [0xFF, 0xFF]);
    }

    #[test]
    fn test_dest_port() {
        let mut udp_hdr = UdpHdr {
            src: [0, 0],
            dst: [0, 0],
            len: [0, 0],
            check: [0, 0],
        };

        // Test with a standard value
        let test_port: u16 = 80;
        udp_hdr.set_dst_port(test_port);
        assert_eq!(udp_hdr.dst_port(), test_port);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(udp_hdr.dst, [0x00, 0x50]); // 80 in big-endian

        // Test with zero
        udp_hdr.set_dst_port(0);
        assert_eq!(udp_hdr.dst_port(), 0);
        assert_eq!(udp_hdr.dst, [0, 0]);

        // Test with max value
        udp_hdr.set_dst_port(u16::MAX);
        assert_eq!(udp_hdr.dst_port(), u16::MAX);
        assert_eq!(udp_hdr.dst, [0xFF, 0xFF]);
    }

    #[test]
    fn test_length() {
        let mut udp_hdr = UdpHdr {
            src: [0, 0],
            dst: [0, 0],
            len: [0, 0],
            check: [0, 0],
        };

        // Test with a standard value (8 bytes header + 20 bytes payload)
        let test_len: u16 = 28;
        udp_hdr.set_len(test_len);
        assert_eq!(udp_hdr.len(), test_len);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(udp_hdr.len, [0x00, 0x1C]); // 28 in big-endian

        // Test with minimum valid value (just the header)
        udp_hdr.set_len(8);
        assert_eq!(udp_hdr.len(), 8);
        assert_eq!(udp_hdr.len, [0x00, 0x08]);

        // Test with max value
        udp_hdr.set_len(u16::MAX);
        assert_eq!(udp_hdr.len(), u16::MAX);
        assert_eq!(udp_hdr.len, [0xFF, 0xFF]);
    }

    #[test]
    fn test_empty() {
        let mut udp_hdr = UdpHdr {
            src: [0, 0],
            dst: [0, 0],
            len: [0, 0],
            check: [0, 0],
        };
        assert!(udp_hdr.is_empty());
        udp_hdr.set_len(8);
        assert!(!udp_hdr.is_empty());
        udp_hdr.set_len(0);
        assert!(udp_hdr.is_empty());
    }

    #[test]
    fn test_checksum() {
        let mut udp_hdr = UdpHdr {
            src: [0, 0],
            dst: [0, 0],
            len: [0, 0],
            check: [0, 0],
        };

        // Test with a standard value
        let test_checksum: u16 = 0x1234;
        udp_hdr.set_checksum(test_checksum);
        assert_eq!(udp_hdr.checksum(), test_checksum);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(udp_hdr.check, [0x12, 0x34]);

        // Test with zero (indicating checksum not used in IPv4)
        udp_hdr.set_checksum(0);
        assert_eq!(udp_hdr.checksum(), 0);
        assert_eq!(udp_hdr.check, [0, 0]);

        // Test with max value
        udp_hdr.set_checksum(u16::MAX);
        assert_eq!(udp_hdr.checksum(), u16::MAX);
        assert_eq!(udp_hdr.check, [0xFF, 0xFF]);
    }

    #[test]
    fn test_complete_udp_header() {
        // Test creating a complete UDP header
        let mut udp_hdr = UdpHdr {
            src: [0, 0],
            dst: [0, 0],
            len: [0, 0],
            check: [0, 0],
        };

        // Set all fields
        udp_hdr.set_src_port(12345);
        udp_hdr.set_dst_port(80);
        udp_hdr.set_len(28); // 8 bytes header + 20 bytes payload
        udp_hdr.set_checksum(0x1234);

        // Verify all values are correctly set and retrieved
        assert_eq!(udp_hdr.src_port(), 12345);
        assert_eq!(udp_hdr.dst_port(), 80);
        assert_eq!(udp_hdr.len(), 28);
        assert_eq!(udp_hdr.checksum(), 0x1234);

        // Verify raw byte storage
        assert_eq!(udp_hdr.src, [0x30, 0x39]); // 12345 in big-endian
        assert_eq!(udp_hdr.dst, [0x00, 0x50]); // 80 in big-endian
        assert_eq!(udp_hdr.len, [0x00, 0x1C]); // 28 in big-endian
        assert_eq!(udp_hdr.check, [0x12, 0x34]); // 0x1234 in big-endian
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialize() {
        use bincode::{config::standard, serde::encode_to_vec};

        let udp = UdpHdr {
            src: 4242_u16.to_be_bytes(),
            dst: 4789_u16.to_be_bytes(),
            len: 42_u16.to_be_bytes(),
            check: 0_u16.to_be_bytes(),
        };

        let options = standard().with_fixed_int_encoding().with_big_endian();

        encode_to_vec(udp, options).unwrap();
    }
}
