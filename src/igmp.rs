use core::mem;

use crate::{getter_be, setter_be};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IGMPv2Hdr {
    /// Message type
    pub message_type: u8,

    /// Maximum Response Time
    pub max_response_time: u8,

    /// Checksum
    pub checksum: [u8; 2],

    /// Group Address
    pub group_address: [u8; 4],
}

impl IGMPv2Hdr {
    /// The size of the IGMPv2 header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<IGMPv2Hdr>();

    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, checksum, u16) }
    }

    #[inline]
    pub fn group_address(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, group_address, u32) }
    }

    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, checksum, checksum) }
    }

    #[inline]
    pub fn set_group_address(&mut self, group_address: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, group_address, group_address) }
    }
}

#[cfg(test)]
mod test {
    use super::IGMPv2Hdr;
    use core::mem;

    #[test]
    fn test_igmpv2_hdr_size() {
        assert_eq!(8, mem::size_of::<IGMPv2Hdr>());
    }
}
