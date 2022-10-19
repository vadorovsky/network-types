#[repr(C)]
#[derive(Copy, Clone)]
pub struct IcmpHdr {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub un: IcmpHdrUn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IcmpHdrUn {
    pub echo: IcmpHdrEcho,
    pub gateway: u32,
    pub frag: IcmpHdrFrag,
    pub reserved: [u8; 4usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IcmpHdrEcho {
    pub id: u16,
    pub sequence: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IcmpHdrFrag {
    pub __unused: u16,
    pub mtu: u16,
}
