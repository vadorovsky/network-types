use core::mem;

pub const UDP_HDR_LEN: usize = mem::size_of::<UdpHdr>();

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}
