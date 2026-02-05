use crate::{
    eth::{EthError, EtherType},
    getter_be,
};
use core::mem;

/// VLAN tag header structure
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VlanHdr {
    /// First 2 bytes containing PCP (3 bits), DEI (1 bit), and VLAN ID (12 bits)
    pub tci: [u8; 2],
    /// EtherType field indicating the protocol encapsulated in the payload
    pub ether_type: u16,
}

impl VlanHdr {
    pub const LEN: usize = mem::size_of::<VlanHdr>();

    #[inline]
    fn tci(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, tci, u16) }
    }

    /// Extract the Priority Code Point (PCP) from the VLAN header
    #[inline]
    pub fn pcp(&self) -> u8 {
        (self.tci() >> 13) as u8
    }

    /// Extract the Drop Eligible Indicator (DEI) from the VLAN header
    #[inline]
    pub fn dei(&self) -> u8 {
        ((self.tci() >> 12) & 1) as u8
    }

    /// Extract the VLAN ID from the VLAN header
    #[inline]
    pub fn vid(&self) -> u16 {
        self.tci() & 0xFFF
    }

    /// Get the EtherType value
    #[inline]
    pub fn ether_type(&self) -> Result<EtherType, EthError> {
        EtherType::try_from(self.ether_type)
    }
}
