use core::mem;
use std::io::{Read, Result as IoResult, Error as IoError, ErrorKind};

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
        let num_sources_be = ptr::read_volatile(&((*header_ptr).num_sources));
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

    } // End of read sources helper function


}


