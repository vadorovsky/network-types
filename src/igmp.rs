use core::mem;
use core::ptr;

/// Internet Group Management Protocol (IGMP) .
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IgmpV2Hdr {
    //
    pub igmp_type: u8,
    pub max_response_time: u8,
    pub checksum: u16,
    pub group_addr: u32,
}

impl IgmpV2Hdr {
    pub const LEN: usize = mem::size_of::<IgmpV2Hdr>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IgmpV3Hdr {
    pub igmp_type: u8,
    pub max_response_time: u8,
    pub checksum: u16,
    pub group_addr: u32,
    pub rsrv_supp_qrv: u8,
    pub qqic: u8,
    pub num_sources: u16,
}

#[derive(Debug)]
pub enum IgmpV3Error {
    /// Indicates an attempt to read data outside the valid packet boundaries.
    OutOfBounds,
    // Maybe add an error about running out of stack memory?
}

impl IgmpV3Hdr {
    pub const LEN: usize = mem::size_of::<IgmpV3Hdr>();

    /// Extracts the 4-bit value for Reserved
    #[inline]
    pub fn rsrv(&self) -> u8 {
        self.rsrv_supp_qrv >>4
    }

    /// Extracts the 1-bit value for Suppress Router-side Processing
    #[inline]
    pub fn supp(&self) -> u8 {
        //Mask last bit after shifting to ensure 1 bit value back
        (self.rsrv_supp_qrv << 3) & 0x01
    }

    /// Extracts the 3-bit value for QRV
    #[inline]
    pub fn qrv(&self) -> u8 {
        //Mask last three bits to ensure value
        self.rsrv_supp_qrv & 0x07
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
    ///  --- Conceptual TC eBPF Program Snippet ---
    /// // Placeholder for max sources buffer size
    /// const MAX_PROGRAM_IGMP_SOURCES: usize = 8; // Or your desired limit
    ///
    /// // Placeholders for eBPF context and action types
    /// struct SomeEbpfContext { /* ... fields to get packet pointers ... */ }
    /// impl SomeEbpfContext {
    ///     fn data_start(&self) -> *const u8 { /* ... implementation ... */ core::ptr::null() }
    ///     fn data_end(&self) -> *const u8 { /* ... implementation ... */ core::ptr::null() }
    ///     // In a real scenario, these would provide actual packet data pointers
    /// }
    ///
    /// type TcActionResult = i32; // e.g., TC_ACT_OK or TC_ACT_SHOT
    /// const TC_OK_ACTION: TcActionResult = 0; // Replace with actual values
    /// const TC_SHOT_ACTION: TcActionResult = 1;
    ///
    /// // Logging macro (same as before)
    /// #[cfg(feature = "log_printk")]
    /// use aya_bpf::macros::printk;
    /// #[cfg(feature = "log_printk")]
    /// macro_rules! log {
    ///     ($($arg:tt)*) => {{
    ///         printk!($($arg)*);
    ///     }}
    /// }
    /// #[cfg(not(feature = "log_printk"))]
    /// macro_rules! log {
    ///     ($($arg:tt)*) => {{
    ///         let _ = format_args!($($arg)*);
    ///     }}
    /// }
    /// fn conceptual_tc_igmp_processor(ctx: &SomeEbpfContext) -> TcActionResult {
    ///     // Assume these are obtained after parsing preceding headers (Ethernet, IP)
    ///     // and performing necessary bounds checks for those headers.
    ///     let packet_data_end_ptr = ctx.data_end();
    /// 
    ///     // Validate IGMP type is V3 before parsing
    ///     let igmp_header_ptr: *const IgmpV3Hdr = {
    ///         // Conceptual: obtain pointer to IGMP header after Eth/IP parsing
    ///         // let packet_data_start_ptr = ctx.data_start();
    ///         // let offset_to_igmp = calculate_offset_to_igmp_payload(packet_data_start_ptr, packet_data_end_ptr);
    ///         // if offset_to_igmp is invalid, return TC_OK_ACTION or TC_SHOT_ACTION
    ///         // (packet_data_start_ptr as *const u8).add(offset_to_igmp) as *const IgmpV3Hdr
    ///         core::ptr::null() // Placeholder: replace with actual pointer derivation
    ///     };
    ///
    ///     // If igmp_header_ptr could not be safely determined
    ///     if igmp_header_ptr.is_null() {
    ///         log!("TC: Could not locate IGMP header.");
    ///         return TC_OK_ACTION; // Or appropriate action
    ///     }
    ///
    ///     let mut my_igmp_sources_buffer: [u32; MAX_PROGRAM_IGMP_SOURCES] = [0; MAX_PROGRAM_IGMP_SOURCES];
    ///
    ///     match unsafe {
    ///         IgmpV3Hdr::read_source_addresses_from_packet(
    ///             igmp_header_ptr,
    ///             packet_data_end_ptr,
    ///             &mut my_igmp_sources_buffer,
    ///         )
    ///     } {
    ///         Ok(count_read) => {
    ///             if count_read > 0 {
    ///                 log!("TC: Conceptually read {} IGMP source(s). First: 0x{:08X}",
    ///                     count_read,
    ///                     my_igmp_sources_buffer[0]
    ///                 );
    ///                 // Process the `count_read` sources in `my_igmp_sources_buffer`.
    ///             }
    ///             // Successfully processed or no sources to process.
    ///             // Decide TC action based on policy.
    ///             return TC_OK_ACTION;
    ///         }
    ///         Err(IgmpV3Error::OutOfBounds) => {
    ///             log!("TC: Error reading IGMP sources (OutOfBounds).");
    ///             // Policy decision: Drop (TC_SHOT) or allow (TC_OK).
    ///             return TC_SHOT_ACTION; // Example: drop on error
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
        let num_sources_ptr = ptr::addr_of!((*header_ptr).num_sources);
        let num_sources_be = unsafe {ptr::read_unaligned(num_sources_ptr)};
        let num_sources_expected = u16::from_be(num_sources_be) as usize;

        //Calculate starting location of Source Addresses, directly after IGMPv3 header struct
        let sources_start_ptr = (header_ptr as *const u8).add(igmpv3_size) as *const u32;

        //Check if expected number of sources fits within packet data range
        //saturating_mul multiplies itself by passed value
        let expected_sources_len_bytes = num_sources_expected.saturating_mul(core::mem::size_of::<u32>());
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

    } // End of read sources helper function


}


