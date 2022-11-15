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

impl UdpHdr {
    /// Returns the source port as an unsigned integer of the target's
    /// endianness.
    pub fn source_from_be(&self) -> u16 {
        u16::from_be(self.source)
    }

    /// Returns the destination port as an unsigned integer of the target's
    /// endianness.
    pub fn dest_from_be(&self) -> u16 {
        u16::from_be(self.dest)
    }
}
