use core::mem;

use crate::{bitfield::BitfieldUnit, macros::impl_enum_try_from};

pub const IPV4_HDR_LEN: usize = mem::size_of::<Ipv4Hdr>();
pub const IPV6_HDR_LEN: usize = mem::size_of::<Ipv6Hdr>();

#[repr(usize)]
pub enum IpHdrLen {
    V4 = IPV4_HDR_LEN,
    V6 = IPV6_HDR_LEN,
}

pub enum IpHdr {
    V4(Ipv4Hdr),
    V6(Ipv6Hdr),
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv4Hdr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl Ipv4Hdr {
    pub fn protocol(&self) -> Result<Ipv4Protocol, ()> {
        self.protocol.try_into()
    }

    /// Returns the source IP address as an unsigned integer of the target's
    /// endianness.
    pub fn saddr(&self) -> u32 {
        u32::from_be(self.saddr)
    }

    /// Returns the destination IP address as an unsigned integer of the
    /// target's endianness.
    pub fn daddr(&self) -> u32 {
        u32::from_be(self.daddr)
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_ihl(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn version(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_version(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn new_bitfield_1(ihl: u8, version: u8) -> BitfieldUnit<[u8; 1usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 1usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, {
            let ihl: u8 = unsafe { mem::transmute(ihl) };
            ihl as u64
        });
        bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { mem::transmute(version) };
            version as u64
        });
        bitfield_unit
    }
}

impl_enum_try_from!(
    /// IPv4 protocol
    #[repr(u8)]
    #[derive(PartialEq, Eq, Debug, Copy, Clone)]
    pub enum Ipv4Protocol {
        Icmp = 1,
        Igmp = 2,
        IpIp = 4,
        Tcp = 6,
        Egp = 8,
        Pup = 12,
        Udp = 17,
        Idp = 22,
        Tp = 29,
        Dccp = 33,
        Ipv6InIpv4Tunnel = 41,
        Rsvp = 46,
        Gre = 47,
        Esp = 50,
        Ah = 51,
        Mtp = 92,
        Beet = 94,
        Encap = 98,
        Pim = 103,
        Comp = 108,
        Sctp = 132,
        UdpLite = 136,
        Mpls = 137,
        EthernetInIpv4 = 143,
        Raw = 255,
    },
    u8
);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub in6_u: in6_u,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union in6_u {
    pub u6_addr8: [u8; 16usize],
    pub u6_addr16: [u16; 8usize],
    pub u6_addr32: [u32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv6Hdr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
    pub flow_lbl: [u8; 3usize],
    pub payload_len: u16,
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: in6_addr,
    pub daddr: in6_addr,
}

impl Ipv6Hdr {
    /// Returns the source IP address as array of bytes.
    pub fn saddr(&self) -> [u8; 16usize] {
        unsafe { self.saddr.in6_u.u6_addr8 }
    }

    /// Returns the destination IP address as array of bytes.
    pub fn daddr(&self) -> [u8; 16usize] {
        unsafe { self.daddr.in6_u.u6_addr8 }
    }

    #[inline]
    pub fn priority(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_priority(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn version(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_version(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn new_bitfield_1(priority: u8, version: u8) -> BitfieldUnit<[u8; 1usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 1usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, {
            let priority: u8 = unsafe { mem::transmute(priority) };
            priority as u64
        });
        bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { mem::transmute(version) };
            version as u64
        });
        bitfield_unit
    }
}
