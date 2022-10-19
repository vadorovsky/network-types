#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}
