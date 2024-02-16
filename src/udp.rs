use core::mem;

/// UDP header, which is present after the IP header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

impl UdpHdr {
    pub const LEN: usize = mem::size_of::<UdpHdr>();
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "bincode")]
fn serialize() {
    use bincode::config::standard;
    use bincode::serde::encode_to_vec;

    let udp = UdpHdr {
        source: 4242,
        dest: 4789,
        len: 42,
        check: 0,
    };

    let options = standard().with_fixed_int_encoding().with_big_endian();

    encode_to_vec(&udp, options).unwrap();
}
