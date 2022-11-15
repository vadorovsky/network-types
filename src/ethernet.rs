use core::mem;

use crate::macros::impl_enum_try_from_be;

pub const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>();

/// Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthHdr {
    /// Destination MAC address.
    pub h_dest: [u8; 6],
    /// Source MAC address.
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

impl EthHdr {
    /// Returns layer 3 (network layer) protocol.
    pub fn protocol(&self) -> Result<L3Protocol, ()> {
        self.h_proto.try_into()
    }
}

impl_enum_try_from_be!(
    /// Layer 3 (network layer) protocol.
    #[repr(u16)]
    #[derive(PartialEq, Eq, Debug, Copy, Clone)]
    pub enum L3Protocol {
        Loop = 0x0060,
        Ipv4 = 0x0800,
        Arp = 0x0806,
        Ipv6 = 0x86DD,
        FibreChannel = 0x8906,
        Infiniband = 0x8915,
        LoopbackIeee8023 = 0x9000,
    },
    u16
);
