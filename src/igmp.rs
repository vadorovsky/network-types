use core::mem;
use core::ptr;

/// Represents an IGMPv2 header according to RFC 2236.
/// This header format applies to all IGMPv2 messages.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IgmpV2Hdr {
    /// The IGMP message type
    pub p_type: u8,
    /// Maximum time allowed before sending a responding report, in 1/10 seconds
    pub max_res_time: u8,
    /// The 16-bit checksum used to detect data corruption
    pub check: [u8; 2],
    /// The multicast group address this message refers to
    pub group_addr: [u8; 4],
}

impl IgmpV2Hdr {
    /// The total size in bytes of an IGMPv2 header
    pub const LEN: usize = mem::size_of::<IgmpV2Hdr>();

    /// Returns the checksum field.
    #[inline]
    pub fn check(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    /// Sets the checksum field
    #[inline]
    pub fn set_check(&mut self, checksum: u16) {
        self.check = checksum.to_be_bytes();
    }

    /// Returns the group_addr field
    #[inline]
    pub fn group_addr(&self) -> u32 {
        u32::from_be_bytes(self.group_addr)
    }

    /// Sets the group_addr field
    #[inline]
    pub fn set_group_addr(&mut self, group_addr: u32) {
        self.group_addr = group_addr.to_be_bytes();
    }
}

/// Represents an IGMPv3 header according to RFC 3376.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IgmpV3Hdr {
    /// The IGMP message type
    pub p_type: u8,
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
    pub num_srcs: [u8; 2],
}

#[derive(Debug)]
pub enum IgmpV3Error {
    /// Indicates an attempt to read data outside the valid packet boundaries.
    OutOfBounds,
    // Maybe add an error about running out of stack memory?
}

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
        //Mask last three bits to ensure value
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
    pub fn check(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    /// Sets the checksum field
    #[inline]
    pub fn set_check(&mut self, checksum: u16) {
        self.check = checksum.to_be_bytes();
    }

    /// Returns the group_addr field
    #[inline]
    pub fn group_addr(&self) -> u32 {
        u32::from_be_bytes(self.group_addr)
    }

    /// Sets the group_addr field
    #[inline]
    pub fn set_group_addr(&mut self, group_addr: u32) {
        self.group_addr = group_addr.to_be_bytes();
    }

    /// Returns the num_srs field.
    #[inline]
    pub fn num_srs(&self) -> u16 {
        u16::from_be_bytes(self.num_srcs)
    }

    /// Sets the num_srs field
    #[inline]
    pub fn set_num_srs(&mut self, num_srs: u16) {
        self.num_srcs = num_srs.to_be_bytes();
    }

    /// Reads IGMPv3 source addresses from packet data into a caller-provided slice.
    /// # Safety
    /// - `header_ptr` must be a potential pointer to the start of an `IgmpV3Hdr`
    ///   within the packet data. This function will validate its accessibility.
    /// - `packet_end_ptr` must point to the byte *after* the last valid byte of the packet data.
    /// - This should point to the end of the last Source Address onf the header.
    ///
    /// # Arguments
    /// - `header_ptr`: Pointer to where the `IgmpV3Hdr` is expected to start in the packet.
    /// - `packet_end_ptr`: Pointer indicating the end of valid packet data.
    /// - `output_sources_slice`: A mutable slice (e.g., from a stack-allocated array)
    ///   where source IPs will be written in host byte order.
    ///
    /// # Returns
    /// - `Ok(count)`: The number of source IPs successfully read and written.
    /// - `Err(IgmpV3Error)`: If an error occurs (e.g., out-of-bounds access).
    ///
    ///  --- Conceptual TC eBPF Program Snippet ---
    /// // Max sources this eBPF program is prepared to handle on its stack for this operation
    /// const MAX_PROGRAM_IGMP_SOURCES: usize = 8;
    ///
    /// // Define the eBPF map, matching the userspace example's HashMap<_, u32, u32>
    /// // Here, we assume the key is an IPv4 address (u32) and value is a placeholder u32.
    /// #[map]
    /// static mut BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    ///
    /// // Logging macro (using aya_log_ebpf::info or printk for simplicity)
    /// #[cfg(feature = "logging")] // Assuming a feature flag for logging
    /// use aya_log_ebpf::{info, warn}; // Using aya-log-ebpf for structured logging
    ///
    /// // Fallback for no logging feature
    /// #[cfg(not(feature = "logging"))]
    /// macro_rules! info { ($($arg:tt)*) => {{ let _ = format_args!($($arg)*); }} }
    /// #[cfg(not(feature = "logging"))]
    /// macro_rules! warn { ($($arg:tt)*) => {{ let _ = format_args!($($arg)*); }} }
    ///
    /// // This function would be the entry point for your TC egress classifier program.
    /// // The userspace code would load and attach this program named "tc_egress".
    /// #[classifier]
    /// pub fn tc_egress(ctx: TcContext) -> i32 {
    ///     // --- Conceptual Part 1: Assume IGMP Header Location is Determined ---
    ///     // In a complete program, this section would involve parsing Ethernet and IPv4
    ///     // headers, performing bounds checks, and validating packet types.
    ///     // For this conceptual example, we assume `igmp_header_ptr` and `packet_data_end_ptr`
    ///     // have been safely obtained.
    ///
    ///     // Placeholder: In a real program, derive these from `ctx` after parsing prior headers.
    ///     // Example: let packet_data_end_ptr = ctx.data_end() as *const u8;
    ///     // Example: let igmp_header_ptr = derive_igmp_header_ptr_from_ctx(&ctx);
    ///     let packet_data_end_ptr: *const u8 = ctx.data_end() as *const u8; // Example: how it might be obtained
    ///     let igmp_header_ptr: *const IgmpV3Hdr = {
    ///         // Simplified: If this were a real function, you'd have complex parsing here.
    ///         // For the sake of focusing on the IgmpV3Hdr helper call, let's assume
    ///         // this part of the code is only reached if it *is* an IGMP packet
    ///         // and igmp_header_ptr is correctly set after prior parsing.
    ///         // For conceptual purposes, we'll simulate it being at a fixed offset if it exists.
    ///         let presumed_offset_to_igmp = 14 + 20; // Simplified Eth + IPv4_min offset
    ///         let start_ptr = ctx.data_start() as *const u8;
    ///         if unsafe { start_ptr.add(presumed_offset_to_igmp) } < packet_data_end_ptr {
    ///              unsafe { start_ptr.add(presumed_offset_to_igmp) as *const IgmpV3Hdr }
    ///         } else {
    ///             ptr::null() // Packet too short even for this simplified offset
    ///         }
    ///     };
    ///
    ///     if igmp_header_ptr.is_null() {
    ///         // This means either it wasn't an IGMP packet based on prior (omitted) parsing,
    ///         // or the packet was too short.
    ///         return TC_ACT_OK; // Pass non-IGMP or too-short packets
    ///     }
    ///
    ///     // --- Conceptual Part 2: Using the IgmpV3Hdr Helper ---
    ///     let mut sources_buffer: [u32; MAX_PROGRAM_IGMP_SOURCES] = [0; MAX_PROGRAM_IGMP_SOURCES];
    ///
    ///     match unsafe {
    ///         IgmpV3Hdr::read_source_addresses_from_packet(
    ///             igmp_header_ptr,
    ///             packet_data_end_ptr,
    ///             &mut sources_buffer,
    ///         )
    ///     } {
    ///         Ok(count_read) => {
    ///             if count_read > 0 {
    ///                 info!(&ctx, "TC Egress: Read {} IGMPv3 source(s). First: {:i}", // Use {:i} for IP
    ///                     count_read,
    ///                     sources_buffer[0] // sources_buffer[0] is u32, network byte order.
    ///                                       // For logging as IP, it might need from_be() if logger expects host order.
    ///                                       // aya_log_ebpf's {:i} handles u32 as IP.
    ///                 );
    ///
    ///                 // Process the source addresses, e.g., check against a blocklist
    ///                 for i in 0..count_read {
    ///                     let source_ip_net_order = sources_buffer[i]; // This is already network byte order (Big Endian)
    ///                     // The BLOCKLIST map stores keys also in network byte order if inserted that way.
    ///                     // The userspace example inserts Ipv4Addr::new(1,1,1,1).into(), which is u32 in BE.
    ///                     match unsafe { BLOCKLIST.get(&source_ip_net_order) } {
    ///                         Some(_) => {
    ///                             info!(&ctx, "TC Egress: IGMP Source IP {:i} is in BLOCKLIST. Dropping.", source_ip_net_order);
    ///                             return TC_ACT_SHOT; // Drop packet
    ///                         }
    ///                         None => {
    ///                             // Source IP not in blocklist, continue processing or pass
    ///                         }
    ///                     }
    ///                 }
    ///             }
    ///             // No sources to block, or all sources checked and okay.
    ///             TC_ACT_OK // Pass the packet
    ///         }
    ///         Err(IgmpV3Error::OutOfBounds) => {
    ///             warn!(&ctx, "TC Egress: Error reading IGMPv3 sources (OutOfBounds).");
    ///             TC_ACT_SHOT // Drop malformed/suspicious packet
    ///         }
    ///     }
    /// }
    ///  --- End Conceptual TC eBPF Program Snippet ---
    pub unsafe fn read_source_addresses_from_packet(
        header_ptr: *const IgmpV3Hdr,
        packet_end_ptr: *const u8,
        output_sources_slice: &mut [u32],
    ) -> Result<usize, IgmpV3Error> {
        //Ensure fixed part of IGMPv3 header is within packet bounds
        let igmpv3_size = core::mem::size_of::<IgmpV3Hdr>();
        if (header_ptr as *const u8).add(igmpv3_size) > packet_end_ptr {
            return Err(IgmpV3Error::OutOfBounds);
        }

        //Extract expected number of sources to read from the header, convert from big endian to a number
        //Get pointer to location first
        let num_sources_ptr = ptr::addr_of!((*header_ptr).num_srcs);
        let num_sources_be = unsafe { ptr::read_unaligned(num_sources_ptr) };
        let num_sources_expected = u16::from_be_bytes(num_sources_be) as usize;

        //Calculate starting location of Source Addresses, directly after IGMPv3 header struct
        let sources_start_ptr = (header_ptr as *const u8).add(igmpv3_size) as *const u32;

        //Check if expected number of sources fits within packet data range
        //saturating_mul multiplies itself by passed value
        let expected_sources_len_bytes =
            num_sources_expected.saturating_mul(core::mem::size_of::<u32>());
        if (sources_start_ptr as *const u8).add(expected_sources_len_bytes) > packet_end_ptr {
            return Err(IgmpV3Error::OutOfBounds);
        }

        //Check how many sources to copy based on size limit of output_sources_slice
        let num_to_copy = if num_sources_expected > output_sources_slice.len() {
            output_sources_slice.len()
        } else {
            num_sources_expected
        };

        //Finally, copy sources into provided array
        for i in 0..num_to_copy {
            let source_ip_be = ptr::read_volatile(sources_start_ptr.add(i));
            output_sources_slice[i] = u32::from_be(source_ip_be);
        }

        Ok(num_to_copy)
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

        assert_eq!(header.p_type, 0x22);
        assert_eq!(header.max_res_time, 0x50);
        assert_eq!(u16::from_be_bytes(header.check), 0xFEDC);

        let expected_group_addr_val_be: u32 = Ipv4Addr::new(224, 0, 1, 2).into();
        assert_eq!(
            u32::from_be_bytes(header.group_addr),
            expected_group_addr_val_be
        );

        assert_eq!(header.rsrv_supp_qrv, 0x0A);
        assert_eq!(header.qqic, 0x7D);
        assert_eq!(u16::from_be_bytes(header.num_srcs), 3);
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
        current_offset += 4;
        let packet_data_len = current_offset; // Actual length of meaningful data

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let packet_end_ptr = unsafe { packet_buffer.as_ptr().add(packet_data_len) };
        let mut output_sources_buffer: [u32; 2] = [0; 2];

        let result = unsafe {
            IgmpV3Hdr::read_source_addresses_from_packet(
                header_ptr,
                packet_end_ptr,
                &mut output_sources_buffer,
            )
        };

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
        let packet_data_len = IGMPV3_HDR_LEN;

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let packet_end_ptr = unsafe { packet_buffer.as_ptr().add(packet_data_len) };
        let mut output_buffer: [u32; 1] = [999];

        let result = unsafe {
            IgmpV3Hdr::read_source_addresses_from_packet(
                header_ptr,
                packet_end_ptr,
                &mut output_buffer,
            )
        };

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
        current_offset += 4;
        let packet_data_len = current_offset;

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let packet_end_ptr = unsafe { packet_buffer.as_ptr().add(packet_data_len) };
        let mut output_buffer: [u32; 2] = [0; 2]; // Output buffer can only hold 2

        let result = unsafe {
            IgmpV3Hdr::read_source_addresses_from_packet(
                header_ptr,
                packet_end_ptr,
                &mut output_buffer,
            )
        };

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let count_read = result.unwrap();
        assert_eq!(count_read, 2, "Should have copied only 2 sources");
        assert_eq!(output_buffer[0], u32::from_be_bytes(source1_bytes));
        assert_eq!(output_buffer[1], u32::from_be_bytes(source2_bytes));
    }

    #[test]
    fn test_read_sources_err_packet_too_short_for_header() {
        let packet_data: [u8; IGMPV3_HDR_LEN - 2] = [0; IGMPV3_HDR_LEN - 2]; // Too short for header

        let header_ptr = packet_data.as_ptr() as *const IgmpV3Hdr;
        let packet_end_ptr = unsafe { packet_data.as_ptr().add(packet_data.len()) };
        let mut output_buffer: [u32; 1] = [0];

        let result = unsafe {
            IgmpV3Hdr::read_source_addresses_from_packet(
                header_ptr,
                packet_end_ptr,
                &mut output_buffer,
            )
        };

        assert!(result.is_err(), "Expected Err, got Ok: {:?}", result);
        assert!(
            matches!(result.unwrap_err(), IgmpV3Error::OutOfBounds),
            "Expected OutOfBounds error"
        );
    }

    #[test]
    fn test_read_sources_err_packet_too_short_for_claimed_sources() {
        let mut packet_buffer = [0u8; MAX_TEST_PACKET_BUFFER_SIZE];
        let header_fixed_part: [u8; IGMPV3_HDR_LEN] = [
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, // num_srcs = 3 (BE)
        ];
        let source1_bytes = [1u8, 0, 0, 1]; // BE

        packet_buffer[0..IGMPV3_HDR_LEN].copy_from_slice(&header_fixed_part);
        let mut current_offset = IGMPV3_HDR_LEN;
        packet_buffer[current_offset..current_offset + 4].copy_from_slice(&source1_bytes);
        current_offset += 4;
        let packet_data_len = current_offset; // Data for only 1 source, header claims 3

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let packet_end_ptr = unsafe { packet_buffer.as_ptr().add(packet_data_len) };
        let mut output_buffer: [u32; 3] = [0; 3];

        let result = unsafe {
            IgmpV3Hdr::read_source_addresses_from_packet(
                header_ptr,
                packet_end_ptr,
                &mut output_buffer,
            )
        };
        assert!(result.is_err(), "Expected Err, got Ok: {:?}", result);
        assert!(
            matches!(result.unwrap_err(), IgmpV3Error::OutOfBounds),
            "Expected OutOfBounds error"
        );
    }

    #[test]
    fn test_read_sources_err_no_space_for_any_sources_when_num_sources_gt_0() {
        let mut packet_buffer = [0u8; MAX_TEST_PACKET_BUFFER_SIZE];
        let header_fixed_part: [u8; IGMPV3_HDR_LEN] = [
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, // num_srcs = 1 (BE)
        ];
        packet_buffer[0..IGMPV3_HDR_LEN].copy_from_slice(&header_fixed_part);
        let packet_data_len = IGMPV3_HDR_LEN; // Packet ends exactly after header

        let header_ptr = packet_buffer.as_ptr() as *const IgmpV3Hdr;
        let packet_end_ptr = unsafe { packet_buffer.as_ptr().add(packet_data_len) };
        let mut output_buffer: [u32; 1] = [0];

        let result = unsafe {
            IgmpV3Hdr::read_source_addresses_from_packet(
                header_ptr,
                packet_end_ptr,
                &mut output_buffer,
            )
        };
        assert!(result.is_err(), "Expected Err, got Ok: {:?}", result);
        assert!(
            matches!(result.unwrap_err(), IgmpV3Error::OutOfBounds),
            "Expected OutOfBounds error"
        );
    }
}
