use crate::chunk_reader;
use core::mem;

/// Represents an IGMPv2 header according to RFC 2236.
/// This header format applies to all IGMPv2 messages.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IgmpV2Hdr {
    /// The IGMP message type
    pub type_: u8,
    /// Maximum time allowed before sending a responding report, in 1/10 seconds
    pub max_res_time: u8,
    /// The 16-bit checksum used to detect data corruption
    pub check: [u8; 2],
    /// The multicast group address this message refers to
    pub group_addr: [u8; 4],
}

impl IgmpV2Hdr {
    pub const LEN: usize = mem::size_of::<IgmpV2Hdr>();

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    /// Sets the checksum field
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.check = checksum.to_be_bytes();
    }

    /// Returns the group_addr field
    #[inline]
    pub fn group_addr(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.group_addr)
    }

    /// Sets the group_addr field
    #[inline]
    pub fn set_group_addr(&mut self, group_addr: core::net::Ipv4Addr) {
        self.group_addr = group_addr.octets();
    }
}

/// Represents an IGMPv3 header according to RFC 3376.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IgmpV3Hdr {
    /// The IGMP message type
    pub type_: u8,
    /// Maximum time allowed before sending a response in tenths of a second
    pub max_res_time: u8,
    /// The 16-bit checksum used for error detection
    pub check: [u8; 2],
    /// The multicast group address for this message
    pub group_addr: [u8; 4],
    /// Combined field containing:
    /// - 4-bit Reserved field (high nibble)
    /// - 1-bit S flag for Suppress Router-side Processing
    /// - 3-bit QRV (Querier's Robustness Variable)  
    pub rsrv_supp_qrv: u8,
    /// Querier's Query Interval Code
    pub qqic: u8,
    /// Number of source addresses that follow this header
    pub num_src: [u8; 2],
}

const SRC_ADDRESSES_CHUNK_LEN: usize = mem::size_of::<u32>();

impl IgmpV3Hdr {
    pub const LEN: usize = mem::size_of::<IgmpV3Hdr>();

    // --- Bitfield Constants ---
    const RSRV_SHIFT: u8 = 4;
    const RSRV_MASK_IN_BYTE: u8 = 0b11110000; // Masks Reserved field bits in the rsrv_supp_qrv byte
    const RSRV_VALUE_MASK: u8 = 0x0F; // Masks a 4-bit value

    const SUPP_SHIFT: u8 = 3;
    const SUPP_MASK_IN_BYTE: u8 = 0b00001000; // Masks S bit in the rsrv_supp_qrv byte
    const SUPP_VALUE_MASK: u8 = 0x01; // Masks a 1-bit value

    const QRV_MASK_IN_BYTE: u8 = 0b00000111; // Masks QRV bits in the rsrv_supp_qrv byte
    const QRV_VALUE_MASK: u8 = 0x07; // Masks a 3-bit value

    /// Extracts the 4-bit value for Reserved
    #[inline]
    pub fn rsrv(&self) -> u8 {
        (self.rsrv_supp_qrv & Self::RSRV_MASK_IN_BYTE) >> Self::RSRV_SHIFT
    }

    /// Sets the 4-bit Reserved (Resv) value.
    /// `value` should be a 4-bit number (0-15). Values outside this range will be masked.
    #[inline]
    pub fn set_rsrv(&mut self, rsrv: u8) {
        let current_val = self.rsrv_supp_qrv;
        // Apply mask to ensure only relevant bits are set, left shift into correct position
        let new_val = (rsrv & Self::RSRV_VALUE_MASK) << Self::RSRV_SHIFT;
        // Clear old values from current_val, OR to insert new values
        self.rsrv_supp_qrv = (current_val & !Self::RSRV_MASK_IN_BYTE) | new_val;
    }

    /// Extracts the 1-bit value for Suppress Router-side Processing
    #[inline]
    pub fn supp(&self) -> u8 {
        (self.rsrv_supp_qrv & Self::SUPP_MASK_IN_BYTE) >> Self::SUPP_SHIFT
    }

    /// Sets the 1-bit S flag (Suppress Router-side Processing).
    /// `value` should be 0 or 1. Values outside this range will be masked.
    #[inline]
    pub fn set_supp(&mut self, supp: u8) {
        let current_val = self.rsrv_supp_qrv;
        // Apply mask to ensure only relevant bit is set, left shift into correct position
        let new_val = (supp & Self::SUPP_VALUE_MASK) << Self::SUPP_SHIFT;
        // Clear old value from current_val, OR to insert new value
        self.rsrv_supp_qrv = (current_val & !Self::SUPP_MASK_IN_BYTE) | new_val;
    }

    /// Extracts the 3-bit value for QRV
    #[inline]
    pub fn qrv(&self) -> u8 {
        // Mask last three bits to ensure value
        self.rsrv_supp_qrv & Self::QRV_MASK_IN_BYTE
    }

    /// Sets the 3-bit QRV (Querier's Robustness Variable) value.
    /// `value` should be a 3-bit number (0-7). Values outside this range will be masked.
    #[inline]
    pub fn set_qrv(&mut self, qrv: u8) {
        let current_val = self.rsrv_supp_qrv;
        // Apply mask to ensure only relevant bits are set, no shift needed as they are LSB
        let new_val = qrv & !Self::QRV_VALUE_MASK;
        // Clear old values from current_val, OR to insert new values
        self.rsrv_supp_qrv = (current_val & !Self::QRV_MASK_IN_BYTE) | new_val;
    }

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    /// Sets the checksum field
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.check = checksum.to_be_bytes();
    }

    /// Returns the group_addr field
    #[inline]
    pub fn group_addr(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.group_addr)
    }

    /// Sets the group_addr field
    #[inline]
    pub fn set_group_addr(&mut self, group_addr: core::net::Ipv4Addr) {
        self.group_addr = group_addr.octets();
    }

    /// Returns the num_src field.
    #[inline]
    pub fn num_src(&self) -> u16 {
        u16::from_be_bytes(self.num_src)
    }

    /// Sets the num_src field
    #[inline]
    pub fn set_num_src(&mut self, num_src: u16) {
        self.num_src = num_src.to_be_bytes();
    }
}

/// These are the unsafe functions on `IgmpV3Hdr` that do not prevent undefined behavior.
impl IgmpV3Hdr {
    /// Reads IGMPv3 source addresses from packet data into a caller-provided slice.
    /// This is a convenience method that uses the instance as the header pointer.
    ///
    /// # Safety
    /// - `self` must be a valid reference to an `IgmpV3Hdr` header within properly aligned packet data
    /// - The memory region starting at `self` and extending to include all source addresses must be
    ///   valid and accessible
    ///
    /// # Arguments
    /// - `src_addr_buffer`: A mutable slice where source IP addresses will be written in network byte order.
    ///   The length of this slice determines the maximum number of addresses that can be read.
    ///
    /// # Returns
    /// - `Ok(count)`: The number of source addresses successfully read and written to the buffer
    /// - `Err(IgmpV3Error)`: If an error occurs reading the packet data
    pub unsafe fn src_addresses_buffer(
        &self,
        src_addr_buffer: &mut [u32],
    ) -> Result<usize, chunk_reader::ChunkReaderError> {
        let self_ptr: *const IgmpV3Hdr = self;
        let self_ptr_u8: *const u8 = self_ptr as *const u8;
        let num_src = self.num_src() as usize;
        let total_hdr_len = num_src * SRC_ADDRESSES_CHUNK_LEN + IgmpV3Hdr::LEN;
        let start_data_ptr = (self_ptr_u8).add(IgmpV3Hdr::LEN);
        let end_data_ptr = (self_ptr_u8).add(total_hdr_len);

        chunk_reader::read_chunks(
            start_data_ptr,
            end_data_ptr,
            src_addr_buffer,
            SRC_ADDRESSES_CHUNK_LEN,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports IgmpV3Hdr, IgmpV3Error (assuming it's defined in parent)
    use core::net::Ipv4Addr;
    use core::ptr;

    const IGMPV3_HDR_LEN: usize = core::mem::size_of::<IgmpV3Hdr>();
    // Define a common buffer size for packet data in tests, ensure it's large enough.
    const MAX_TEST_PACKET_BUFFER_SIZE: usize = 64;

    #[test]
    fn test_igmpv3_hdr_fields_deserialization() {
        let header_bytes: [u8; IGMPV3_HDR_LEN] = [
            0x22, // igmp_type
            0x50, // max_res_time
            0xFE, 0xDC, // check (BE)
            0xE0, 0x00, 0x01, 0x02, // group_addr (BE: 224.0.1.2)
            0x0A, // rsrv_supp_qrv
            0x7D, // qqic
            0x00, 0x03, // num_srcs (BE: 3)
        ];

        let header_ptr = header_bytes.as_ptr() as *const IgmpV3Hdr;
        let header: IgmpV3Hdr = unsafe { ptr::read_unaligned(header_ptr) };

        assert_eq!(header.type_, 0x22);
        assert_eq!(header.max_res_time, 0x50);
        assert_eq!(u16::from_be_bytes(header.check), 0xFEDC);

        let expected_group_addr_val_be: u32 = Ipv4Addr::new(224, 0, 1, 2).into();
        assert_eq!(
            u32::from_be_bytes(header.group_addr),
            expected_group_addr_val_be
        );

        assert_eq!(header.rsrv_supp_qrv, 0x0A);
        assert_eq!(header.qqic, 0x7D);
        assert_eq!(u16::from_be_bytes(header.num_src), 3);
    }

    #[test]
    fn test_read_sources_valid_two_sources() {
        let mut packet_buffer = [0u8; MAX_TEST_PACKET_BUFFER_SIZE];

        let header_fixed_part: [u8; IGMPV3_HDR_LEN] = [
            0x11, 0x00, 0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00,
            0x02, // num_srcs = 2 (BE)
        ];
        let source1_ip_bytes: [u8; 4] = [0x0A, 0x0B, 0x0C, 0x0D]; // 10.11.12.13 BE
        let source2_ip_bytes: [u8; 4] = [0xC0, 0xA8, 0x00, 0x01]; // 192.168.0.1 BE

        packet_buffer[0..IGMPV3_HDR_LEN].copy_from_slice(&header_fixed_part);
        let mut current_offset = IGMPV3_HDR_LEN;
        packet_buffer[current_offset..current_offset + 4].copy_from_slice(&source1_ip_bytes);
        current_offset += 4;
        packet_buffer[current_offset..current_offset + 4].copy_from_slice(&source2_ip_bytes);

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let header = unsafe { &*header_ptr };
        let mut output_sources_buffer: [u32; 2] = [0; 2];

        let result = unsafe { header.src_addresses_buffer(&mut output_sources_buffer) };

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let count_read = result.unwrap();
        assert_eq!(count_read, 2, "Should have read 2 sources");

        let expected_ip1_val: u32 = Ipv4Addr::new(10, 11, 12, 13).into();
        let expected_ip2_val: u32 = Ipv4Addr::new(192, 168, 0, 1).into();
        assert_eq!(output_sources_buffer[0], expected_ip1_val);
        assert_eq!(output_sources_buffer[1], expected_ip2_val);
    }

    #[test]
    fn test_read_sources_zero_num_sources() {
        let mut packet_buffer = [0u8; MAX_TEST_PACKET_BUFFER_SIZE];
        let header_fixed_part: [u8; IGMPV3_HDR_LEN] = [
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // num_srcs = 0 (BE)
        ];
        packet_buffer[0..IGMPV3_HDR_LEN].copy_from_slice(&header_fixed_part);

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let header = unsafe { &*header_ptr };
        let mut output_buffer: [u32; 1] = [999];

        let result = unsafe { header.src_addresses_buffer(&mut output_buffer) };

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        assert_eq!(result.unwrap(), 0, "Should have read 0 sources");
        assert_eq!(output_buffer[0], 999, "Output buffer should be untouched");
    }

    #[test]
    fn test_read_sources_output_buffer_limits_copy() {
        let mut packet_buffer = [0u8; MAX_TEST_PACKET_BUFFER_SIZE];
        let header_fixed_part: [u8; IGMPV3_HDR_LEN] = [
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, // num_srcs = 3 (BE)
        ];
        let source1_bytes = [1u8, 0, 0, 1]; // BE
        let source2_bytes = [1u8, 0, 0, 2]; // BE
        let source3_bytes = [1u8, 0, 0, 3]; // BE

        packet_buffer[0..IGMPV3_HDR_LEN].copy_from_slice(&header_fixed_part);
        let mut current_offset = IGMPV3_HDR_LEN;
        packet_buffer[current_offset..current_offset + 4].copy_from_slice(&source1_bytes);
        current_offset += 4;
        packet_buffer[current_offset..current_offset + 4].copy_from_slice(&source2_bytes);
        current_offset += 4;
        packet_buffer[current_offset..current_offset + 4].copy_from_slice(&source3_bytes);

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let header = unsafe { &*header_ptr };
        let mut output_buffer: [u32; 2] = [0; 2]; // Output buffer can only hold 2

        let result = unsafe { header.src_addresses_buffer(&mut output_buffer) };

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let count_read = result.unwrap();
        assert_eq!(count_read, 2, "Should have copied only 2 sources");
        assert_eq!(output_buffer[0], u32::from_be_bytes(source1_bytes));
        assert_eq!(output_buffer[1], u32::from_be_bytes(source2_bytes));
    }
}
