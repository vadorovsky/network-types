use core::mem;

pub const ICMP_HDR_LEN: usize = mem::size_of::<IcmpHdr>();

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdr {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub un: IcmpHdrUn,
}

impl IcmpHdr {
    pub const LEN: usize = mem::size_of::<IcmpHdr>();
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub union IcmpHdrUn {
    pub echo: IcmpHdrEcho,
    pub gateway: u32,
    pub frag: IcmpHdrFrag,
    pub reserved: [u8; 4usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdrEcho {
    pub id: u16,
    pub sequence: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdrFrag {
    pub __unused: u16,
    pub mtu: u16,
}
