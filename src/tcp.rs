use core::mem;

use crate::bitfield::BitfieldUnit;

/// TCP header, which is present after the IP header.
///
/// This struct represents the Transmission Control Protocol (TCP) header as defined in RFC 793.
/// The TCP header is 20 bytes long (without options) and contains various fields for connection
/// management, flow control, and reliability.
/// All fields are stored in network byte order (big-endian).
///
/// # Example
/// ```
/// use network_types::tcp::TcpHdr;
///
/// let mut tcp_header = TcpHdr {
///     src: [0, 0],
///     dst: [0, 0],
///     seq: [0, 0, 0, 0],
///     ack_seq: [0, 0, 0, 0],
///     off_res_flags: [0, 0],
///     window: [0, 0],
///     check: [0, 0],
///     urg_ptr: [0, 0],
/// };
///
/// tcp_header.set_src_port(12345);
/// tcp_header.set_dst_port(80);
/// tcp_header.set_seq(1000);
/// tcp_header.set_ack_seq(2000);
/// tcp_header.set_window(5840);
/// tcp_header.set_checksum(0); // Checksum calculation would be done separately
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TcpHdr {
    /// Source port in network byte order (big-endian)
    pub src: [u8; 2],
    /// Destination port in network byte order (big-endian)
    pub dst: [u8; 2],
    /// Sequence number in network byte order (big-endian)
    pub seq: [u8; 4],
    /// Acknowledgment number in network byte order (big-endian)
    pub ack_seq: [u8; 4],
    /// Data offset, reserved bits, and flags in network byte order (big-endian)
    pub off_res_flags: [u8; 2],
    /// Window size in network byte order (big-endian)
    pub window: [u8; 2],
    /// Checksum in network byte order (big-endian)
    pub check: [u8; 2],
    /// Urgent pointer in network byte order (big-endian)
    pub urg_ptr: [u8; 2],
}

// Associated constants for TCP flags
// These would typically be part of the `impl TcpHdr` block.
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_URG: u8 = 0x20;
const TCP_FLAG_ECE: u8 = 0x40;
const TCP_FLAG_CWR: u8 = 0x80;

impl TcpHdr {
    /// The size of the TCP header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<TcpHdr>();

    /// Returns the source port number.
    ///
    /// This method converts the source port from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The source port as a u16 value.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src)
    }

    /// Sets the source port number.
    ///
    /// This method converts the source port from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `source` - The source port number to set.
    #[inline]
    pub fn set_src_port(&mut self, source: u16) {
        self.src = source.to_be_bytes();
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
        u16::from_be_bytes(self.dst)
    }

    /// Sets the destination port number.
    ///
    /// This method converts the destination port from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `dest` - The destination port number to set.
    #[inline]
    pub fn set_dst_port(&mut self, dest: u16) {
        self.dst = dest.to_be_bytes();
    }

    /// Returns the sequence number.
    ///
    /// This method converts the sequence number from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The sequence number as a u32 value.
    #[inline]
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(self.seq)
    }

    /// Sets the sequence number.
    ///
    /// This method converts the sequence number from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `seq` - The sequence number to set.
    #[inline]
    pub fn set_seq(&mut self, seq: u32) {
        self.seq = seq.to_be_bytes();
    }

    /// Returns the acknowledgment sequence number.
    ///
    /// This method converts the acknowledgment sequence number from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The acknowledgment sequence number as a u32 value.
    #[inline]
    pub fn ack_seq(&self) -> u32 {
        u32::from_be_bytes(self.ack_seq)
    }

    /// Sets the acknowledgment sequence number.
    ///
    /// This method converts the acknowledgment sequence number from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `ack_seq` - The acknowledgment sequence number to set.
    #[inline]
    pub fn set_ack_seq(&mut self, ack_seq: u32) {
        self.ack_seq = ack_seq.to_be_bytes();
    }

    /// Returns the window size.
    ///
    /// This method converts the window size from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The window size as a u16 value.
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(self.window)
    }

    /// Sets the window size.
    ///
    /// This method converts the window size from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `window` - The window size to set.
    #[inline]
    pub fn set_window(&mut self, window: u16) {
        self.window = window.to_be_bytes();
    }

    /// Returns the checksum.
    ///
    /// This method converts the checksum from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The checksum as a u16 value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    /// Sets the checksum.
    ///
    /// This method converts the checksum from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `check` - The checksum to set.
    #[inline]
    pub fn set_checksum(&mut self, check: u16) {
        self.check = check.to_be_bytes();
    }

    /// Returns the urgent pointer.
    ///
    /// This method converts the urgent pointer from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The urgent pointer as a u16 value.
    #[inline]
    pub fn urg_ptr(&self) -> u16 {
        u16::from_be_bytes(self.urg_ptr)
    }

    /// Sets the urgent pointer.
    ///
    /// This method converts the urgent pointer from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `urg_ptr` - The urgent pointer to set.
    #[inline]
    pub fn set_urg_ptr(&mut self, urg_ptr: u16) {
        self.urg_ptr = urg_ptr.to_be_bytes();
    }

    /// Returns the data offset value (header length in 32-bit words).
    ///
    /// This method extracts the data offset field from the off_res_flags field.
    /// The data offset is the high 4 bits of the first byte.
    ///
    /// # Returns
    /// The data offset value (header length in 32-bit words).
    #[inline]
    pub fn data_offset(&self) -> u8 {
        (self.off_res_flags[0] >> 4) & 0x0F
    }

    /// Sets the data offset value (header length in 32-bit words).
    ///
    /// This method sets the data offset field in the off_res_flags field.
    /// The data offset is the high 4 bits of the first byte.
    ///
    /// # Parameters
    /// * `doff` - The data offset value to set (header length in 32-bit words).
    #[inline]
    pub fn set_data_offset(&mut self, doff: u8) {
        self.off_res_flags[0] = (self.off_res_flags[0] & 0x0F) | ((doff & 0x0F) << 4);
    }

    /// Returns the header length in bytes.
    ///
    /// This method calculates the header length in bytes from the data offset field.
    /// The data offset field specifies the header length in 32-bit words.
    ///
    /// # Returns
    /// The header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.data_offset() as usize) * 4
    }

    /// Private helper method to get a flag bit from the second byte of `off_res_flags`.
    #[inline]
    fn get_flag(&self, mask: u8) -> bool {
        (self.off_res_flags[1] & mask) != 0
    }

    /// Private helper method to set or clear a flag bit in the second byte of `off_res_flags`.
    #[inline]
    fn set_flag(&mut self, mask: u8, value: bool) {
        if value {
            self.off_res_flags[1] |= mask;
        } else {
            self.off_res_flags[1] &= !mask;
        }
    }

    /// Returns true if the FIN flag is set.
    ///
    /// # Returns
    /// `true` if the FIN flag is set, `false` otherwise.
    #[inline]
    pub fn fin(&self) -> bool {
        // Assuming Self::TCP_FLAG_FIN if constants are associated with TcpHdr struct
        // For this standalone snippet, we use the module-level const.
        self.get_flag(TCP_FLAG_FIN)
    }

    /// Sets the FIN flag.
    ///
    /// # Parameters
    /// * `fin` - `true` to set the FIN flag, `false` to clear it.
    #[inline]
    pub fn set_fin(&mut self, fin: bool) {
        self.set_flag(TCP_FLAG_FIN, fin)
    }

    /// Returns true if the SYN flag is set.
    ///
    /// # Returns
    /// `true` if the SYN flag is set, `false` otherwise.
    #[inline]
    pub fn syn(&self) -> bool {
        self.get_flag(TCP_FLAG_SYN)
    }

    /// Sets the SYN flag.
    ///
    /// # Parameters
    /// * `syn` - `true` to set the SYN flag, `false` to clear it.
    #[inline]
    pub fn set_syn(&mut self, syn: bool) {
        self.set_flag(TCP_FLAG_SYN, syn)
    }

    /// Returns true if the RST flag is set.
    ///
    /// # Returns
    /// `true` if the RST flag is set, `false` otherwise.
    #[inline]
    pub fn rst(&self) -> bool {
        self.get_flag(TCP_FLAG_RST)
    }

    /// Sets the RST flag.
    ///
    /// # Parameters
    /// * `rst` - `true` to set the RST flag, `false` to clear it.
    #[inline]
    pub fn set_rst(&mut self, rst: bool) {
        self.set_flag(TCP_FLAG_RST, rst)
    }

    /// Returns true if the PSH flag is set.
    ///
    /// # Returns
    /// `true` if the PSH flag is set, `false` otherwise.
    #[inline]
    pub fn psh(&self) -> bool {
        self.get_flag(TCP_FLAG_PSH)
    }

    /// Sets the PSH flag.
    ///
    /// # Parameters
    /// * `psh` - `true` to set the PSH flag, `false` to clear it.
    #[inline]
    pub fn set_psh(&mut self, psh: bool) {
        self.set_flag(TCP_FLAG_PSH, psh)
    }

    /// Returns true if the ACK flag is set.
    ///
    /// # Returns
    /// `true` if the ACK flag is set, `false` otherwise.
    #[inline]
    pub fn ack(&self) -> bool {
        self.get_flag(TCP_FLAG_ACK)
    }

    /// Sets the ACK flag.
    ///
    /// # Parameters
    /// * `ack` - `true` to set the ACK flag, `false` to clear it.
    #[inline]
    pub fn set_ack(&mut self, ack: bool) {
        self.set_flag(TCP_FLAG_ACK, ack)
    }

    /// Returns true if the URG flag is set.
    ///
    /// # Returns
    /// `true` if the URG flag is set, `false` otherwise.
    #[inline]
    pub fn urg(&self) -> bool {
        self.get_flag(TCP_FLAG_URG)
    }

    /// Sets the URG flag.
    ///
    /// # Parameters
    /// * `urg` - `true` to set the URG flag, `false` to clear it.
    #[inline]
    pub fn set_urg(&mut self, urg: bool) {
        self.set_flag(TCP_FLAG_URG, urg)
    }

    /// Returns true if the ECE flag is set.
    ///
    /// # Returns
    /// `true` if the ECE flag is set, `false` otherwise.
    #[inline]
    pub fn ece(&self) -> bool {
        self.get_flag(TCP_FLAG_ECE)
    }

    /// Sets the ECE flag.
    ///
    /// # Parameters
    /// * `ece` - `true` to set the ECE flag, `false` to clear it.
    #[inline]
    pub fn set_ece(&mut self, ece: bool) {
        self.set_flag(TCP_FLAG_ECE, ece)
    }

    /// Returns true if the CWR flag is set.
    ///
    /// # Returns
    /// `true` if the CWR flag is set, `false` otherwise.
    #[inline]
    pub fn cwr(&self) -> bool {
        self.get_flag(TCP_FLAG_CWR)
    }

    /// Sets the CWR flag.
    ///
    /// # Parameters
    /// * `cwr` - `true` to set the CWR flag, `false` to clear it.
    #[inline]
    pub fn set_cwr(&mut self, cwr: bool) {
        self.set_flag(TCP_FLAG_CWR, cwr)
    }
}

#[cfg(test)]
mod test {
    use super::TcpHdr;
    use core::mem;

    #[test]
    fn test_tcp_hdr_size() {
        // TcpHdr should be exactly 20 bytes
        assert_eq!(TcpHdr::LEN, 20);
        assert_eq!(TcpHdr::LEN, mem::size_of::<TcpHdr>());
    }

    #[test]
    fn test_source_port() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_port: u16 = 12345;
        tcp_hdr.set_src_port(test_port);
        assert_eq!(tcp_hdr.src_port(), test_port);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.src, [0x30, 0x39]); // 12345 in big-endian

        // Test with zero
        tcp_hdr.set_src_port(0);
        assert_eq!(tcp_hdr.src_port(), 0);
        assert_eq!(tcp_hdr.src, [0, 0]);

        // Test with max value
        tcp_hdr.set_src_port(u16::MAX);
        assert_eq!(tcp_hdr.src_port(), u16::MAX);
        assert_eq!(tcp_hdr.src, [0xFF, 0xFF]);
    }

    #[test]
    fn test_dest_port() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_port: u16 = 80;
        tcp_hdr.set_dst_port(test_port);
        assert_eq!(tcp_hdr.dst_port(), test_port);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.dst, [0x00, 0x50]); // 80 in big-endian

        // Test with zero
        tcp_hdr.set_dst_port(0);
        assert_eq!(tcp_hdr.dst_port(), 0);
        assert_eq!(tcp_hdr.dst, [0, 0]);

        // Test with max value
        tcp_hdr.set_dst_port(u16::MAX);
        assert_eq!(tcp_hdr.dst_port(), u16::MAX);
        assert_eq!(tcp_hdr.dst, [0xFF, 0xFF]);
    }

    #[test]
    fn test_sequence_number() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_seq: u32 = 1234567890;
        tcp_hdr.set_seq(test_seq);
        assert_eq!(tcp_hdr.seq(), test_seq);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.seq, [0x49, 0x96, 0x02, 0xD2]); // 1234567890 in big-endian

        // Test with zero
        tcp_hdr.set_seq(0);
        assert_eq!(tcp_hdr.seq(), 0);
        assert_eq!(tcp_hdr.seq, [0, 0, 0, 0]);

        // Test with max value
        tcp_hdr.set_seq(u32::MAX);
        assert_eq!(tcp_hdr.seq(), u32::MAX);
        assert_eq!(tcp_hdr.seq, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_acknowledgment_number() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_ack_seq: u32 = 2345678901;
        tcp_hdr.set_ack_seq(test_ack_seq);
        assert_eq!(tcp_hdr.ack_seq(), test_ack_seq);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.ack_seq, [0x8B, 0xD0, 0x38, 0x35]); // 2345678901 in big-endian

        // Test with zero
        tcp_hdr.set_ack_seq(0);
        assert_eq!(tcp_hdr.ack_seq(), 0);
        assert_eq!(tcp_hdr.ack_seq, [0, 0, 0, 0]);

        // Test with max value
        tcp_hdr.set_ack_seq(u32::MAX);
        assert_eq!(tcp_hdr.ack_seq(), u32::MAX);
        assert_eq!(tcp_hdr.ack_seq, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_data_offset() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with minimum valid value (5 = 20 bytes header)
        tcp_hdr.set_data_offset(5);
        assert_eq!(tcp_hdr.data_offset(), 5);
        assert_eq!(tcp_hdr.header_len(), 20);
        assert_eq!(tcp_hdr.off_res_flags[0] & 0xF0, 0x50);

        // Test with maximum value (15 = 60 bytes header)
        tcp_hdr.set_data_offset(15);
        assert_eq!(tcp_hdr.data_offset(), 15);
        assert_eq!(tcp_hdr.header_len(), 60);
        assert_eq!(tcp_hdr.off_res_flags[0] & 0xF0, 0xF0);

        // Test that only the top 4 bits are affected
        tcp_hdr.off_res_flags[0] = 0xFF;
        tcp_hdr.set_data_offset(5);
        assert_eq!(tcp_hdr.off_res_flags[0], 0x5F);
    }

    #[test]
    fn test_flags() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test FIN flag
        assert_eq!(tcp_hdr.fin(), false);
        tcp_hdr.set_fin(true);
        assert_eq!(tcp_hdr.fin(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x01, 0x01);
        tcp_hdr.set_fin(false);
        assert_eq!(tcp_hdr.fin(), false);

        // Test SYN flag
        assert_eq!(tcp_hdr.syn(), false);
        tcp_hdr.set_syn(true);
        assert_eq!(tcp_hdr.syn(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x02, 0x02);
        tcp_hdr.set_syn(false);
        assert_eq!(tcp_hdr.syn(), false);

        // Test RST flag
        assert_eq!(tcp_hdr.rst(), false);
        tcp_hdr.set_rst(true);
        assert_eq!(tcp_hdr.rst(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x04, 0x04);
        tcp_hdr.set_rst(false);
        assert_eq!(tcp_hdr.rst(), false);

        // Test PSH flag
        assert_eq!(tcp_hdr.psh(), false);
        tcp_hdr.set_psh(true);
        assert_eq!(tcp_hdr.psh(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x08, 0x08);
        tcp_hdr.set_psh(false);
        assert_eq!(tcp_hdr.psh(), false);

        // Test ACK flag
        assert_eq!(tcp_hdr.ack(), false);
        tcp_hdr.set_ack(true);
        assert_eq!(tcp_hdr.ack(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x10, 0x10);
        tcp_hdr.set_ack(false);
        assert_eq!(tcp_hdr.ack(), false);

        // Test URG flag
        assert_eq!(tcp_hdr.urg(), false);
        tcp_hdr.set_urg(true);
        assert_eq!(tcp_hdr.urg(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x20, 0x20);
        tcp_hdr.set_urg(false);
        assert_eq!(tcp_hdr.urg(), false);

        // Test ECE flag
        assert_eq!(tcp_hdr.ece(), false);
        tcp_hdr.set_ece(true);
        assert_eq!(tcp_hdr.ece(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x40, 0x40);
        tcp_hdr.set_ece(false);
        assert_eq!(tcp_hdr.ece(), false);

        // Test CWR flag
        assert_eq!(tcp_hdr.cwr(), false);
        tcp_hdr.set_cwr(true);
        assert_eq!(tcp_hdr.cwr(), true);
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x80, 0x80);
        tcp_hdr.set_cwr(false);
        assert_eq!(tcp_hdr.cwr(), false);

        // Test setting multiple flags
        tcp_hdr.set_syn(true);
        tcp_hdr.set_ack(true);
        assert_eq!(tcp_hdr.syn(), true);
        assert_eq!(tcp_hdr.ack(), true);
        assert_eq!(tcp_hdr.off_res_flags[1], 0x12);
    }

    #[test]
    fn test_window() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_window: u16 = 5840;
        tcp_hdr.set_window(test_window);
        assert_eq!(tcp_hdr.window(), test_window);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.window, [0x16, 0xD0]); // 5840 in big-endian

        // Test with zero
        tcp_hdr.set_window(0);
        assert_eq!(tcp_hdr.window(), 0);
        assert_eq!(tcp_hdr.window, [0, 0]);

        // Test with max value
        tcp_hdr.set_window(u16::MAX);
        assert_eq!(tcp_hdr.window(), u16::MAX);
        assert_eq!(tcp_hdr.window, [0xFF, 0xFF]);
    }

    #[test]
    fn test_checksum() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_checksum: u16 = 0x1234;
        tcp_hdr.set_checksum(test_checksum);
        assert_eq!(tcp_hdr.checksum(), test_checksum);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.check, [0x12, 0x34]);

        // Test with zero
        tcp_hdr.set_checksum(0);
        assert_eq!(tcp_hdr.checksum(), 0);
        assert_eq!(tcp_hdr.check, [0, 0]);

        // Test with max value
        tcp_hdr.set_checksum(u16::MAX);
        assert_eq!(tcp_hdr.checksum(), u16::MAX);
        assert_eq!(tcp_hdr.check, [0xFF, 0xFF]);
    }

    #[test]
    fn test_urgent_pointer() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_urg_ptr: u16 = 1000;
        tcp_hdr.set_urg_ptr(test_urg_ptr);
        assert_eq!(tcp_hdr.urg_ptr(), test_urg_ptr);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.urg_ptr, [0x03, 0xE8]); // 1000 in big-endian

        // Test with zero
        tcp_hdr.set_urg_ptr(0);
        assert_eq!(tcp_hdr.urg_ptr(), 0);
        assert_eq!(tcp_hdr.urg_ptr, [0, 0]);

        // Test with max value
        tcp_hdr.set_urg_ptr(u16::MAX);
        assert_eq!(tcp_hdr.urg_ptr(), u16::MAX);
        assert_eq!(tcp_hdr.urg_ptr, [0xFF, 0xFF]);
    }
}
