use core::mem;
use crate::eth::EtherType;

/// VLAN tag header structure
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VlanHdr {
    /// First 2 bytes containing PCP (3 bits), DEI (1 bit), and VLAN ID (12 bits)
    pub tci: u16,
    /// EtherType field indicating the protocol encapsulated in the payload
    pub eth_type: EtherType,
}

impl VlanHdr {
    pub const LEN: usize = mem::size_of::<VlanHdr>();

    /// Extract the Priority Code Point (PCP) from the VLAN header
    #[inline]
    pub fn pcp(&self) -> u8 {
        (u16::from_be(self.tci) >> 13) as u8
    }

    /// Extract the Drop Eligible Indicator (DEI) from the VLAN header
    #[inline]
    pub fn dei(&self) -> u8 {
        ((u16::from_be(self.tci) >> 12) & 1) as u8
    }

    /// Extract the VLAN ID from the VLAN header
    #[inline]
    pub fn vid(&self) -> u16 {
        u16::from_be(self.tci) & 0xFFF
    }
    
    /// Get the EtherType value
    #[inline]
    pub fn eth_type(&self) -> EtherType {
        self.eth_type
    }
}
