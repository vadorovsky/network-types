use core::mem;

use crate::{getter_be, setter_be};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IGMPv1Hdr {
    /// Version/Type
    pub vt: u8,

    /// Unused field
    pub _unused: u8,

    /// Checksum
    pub checksum: [u8; 2],

    /// Group Address
    pub group_address: [u8; 4],
}

impl IGMPv1Hdr {
    /// The size of the IGMPv1 header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<IGMPv1Hdr>();

    #[inline]
    pub fn version(&self) -> u8 {
        (self.vt >> 4) & 0xF
    }

    #[inline]
    pub fn type_(&self) -> u8 {
        self.vt & 0xF
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, checksum, u16) }
    }

    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, checksum, checksum) }
    }

    #[inline]
    pub fn group_address(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, group_address, u32) }
    }

    #[inline]
    pub fn set_group_address(&mut self, group_address: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, group_address, group_address) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, checksum, checksum) }
    }

    #[inline]
    pub fn group_address(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, group_address, u32) }
    }

    #[inline]
    pub fn set_group_address(&mut self, group_address: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, group_address, group_address) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IGMPv3MembershipQueryHdr {
    /// Message type
    pub message_type: u8,

    /// Maximum Response Time
    pub max_response_time: u8,

    /// Checksum
    pub checksum: [u8; 2],

    /// Group Address
    pub group_address: [u8; 4],

    pub rsq: u8,

    /// Querier's Query Interval Code
    pub qqic: u8,

    /// Number of Sources
    pub nb_sources: [u8; 2],
}

impl IGMPv3MembershipQueryHdr {
    pub const LEN: usize = mem::size_of::<IGMPv3MembershipQueryHdr>();

    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, checksum, u16) }
    }

    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, checksum, checksum) }
    }

    #[inline]
    pub fn group_address(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, group_address, u32) }
    }

    #[inline]
    pub fn set_group_address(&mut self, group_address: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, group_address, group_address) }
    }

    #[inline]
    pub fn s(&self) -> u8 {
        (self.rsq >> 3) & 1
    }

    #[inline]
    pub fn qrv(&self) -> u8 {
        self.rsq & 0b111
    }

    #[inline]
    pub fn nb_sources(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, nb_sources, u32) }
    }

    #[inline]
    pub fn set_nb_sources(&mut self, nb_sources: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, nb_sources, nb_sources) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IGMPv3MembershipReportHdr {
    /// Message type
    pub message_type: u8,

    _unused_1: u8,

    /// Checksum
    pub checksum: [u8; 2],

    _unused_2: [u8; 2],

    /// Number of Sources
    pub nb_group_records: [u8; 2],
}

impl IGMPv3MembershipReportHdr {
    pub const LEN: usize = mem::size_of::<IGMPv3MembershipReportHdr>();

    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, checksum, u16) }
    }

    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, checksum, checksum) }
    }

    #[inline]
    pub fn nb_group_records(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, nb_group_records, u16) }
    }

    #[inline]
    pub fn set_nb_group_records(&mut self, nb_group_records: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, nb_group_records, nb_group_records) }
    }
}
