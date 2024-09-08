use core::mem;

/// ARP header, which is present after the Ethernet header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ArpHdr {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: u16,
    pub sha: [u16; 3],
    pub spa: u32,
    pub tha: [u16; 3],
    pub tpa: u32,
}

impl ArpHdr {
    pub const LEN: usize = mem::size_of::<ArpHdr>();
}
