use core::mem;

use crate::l3::L3Protocol;

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
