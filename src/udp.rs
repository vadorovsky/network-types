use core::mem;

/// UDP header, which is present after the IP header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct UdpHdr {
    pub source: [u8; 2],
    pub dest: [u8; 2],
    pub len: [u8; 2],
    pub check: [u8; 2],
}

impl UdpHdr {
    pub const LEN: usize = mem::size_of::<UdpHdr>();

    pub fn source(&self) -> u16 {
        u16::from_be_bytes(self.source)
    }

    pub fn set_source(&mut self, source: u16) {
        self.source = source.to_be_bytes();
    }

    pub fn dest(&self) -> u16 {
        u16::from_be_bytes(self.dest)
    }

    pub fn set_dest(&mut self, dest: u16) {
        self.dest = dest.to_be_bytes();
    }

    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }

    pub fn set_len(&mut self, len: u16) {
        self.len = len.to_be_bytes();
    }

    pub fn check(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    pub fn set_check(&mut self, check: u16) {
        self.check = check.to_be_bytes();
    }
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serialize() {
        use super::UdpHdr;
        use bincode::{config::standard, serde::encode_to_vec};

        let udp = UdpHdr {
            source: 4242_u16.to_be_bytes(),
            dest: 4789_u16.to_be_bytes(),
            len: 42_u16.to_be_bytes(),
            check: 0_u16.to_be_bytes(),
        };

        let options = standard().with_fixed_int_encoding().with_big_endian();

        encode_to_vec(udp, options).unwrap();
    }
}
