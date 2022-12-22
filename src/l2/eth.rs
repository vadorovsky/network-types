use core::mem;

pub const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>();

/// Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthHdr {
    /// Destination MAC address.
    pub dest: [u8; 6],
    /// Source MAC address.
    pub source: [u8; 6],
    /// Protocol which is encapsulated in the payload of the frame.
    pub proto: EthProto,
}

/// Protocol which is encapsulated in the payload of the Ethernet frame.
#[repr(u16)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum EthProto {
    Loop = 0x0060_u16.to_be(),
    Ipv4 = 0x0800_u16.to_be(),
    Arp = 0x0806_u16.to_be(),
    Ipv6 = 0x86DD_u16.to_be(),
    FibreChannel = 0x8906_u16.to_be(),
    Infiniband = 0x8915_u16.to_be(),
    LoopbackIeee8023 = 0x9000_u16.to_be(),
}
