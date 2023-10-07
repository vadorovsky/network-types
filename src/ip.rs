use core::mem;

use crate::bitfield::BitfieldUnit;

/// IP headers, which are present after the Ethernet header.
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum IpHdr {
    V4(Ipv4Hdr),
    V6(Ipv6Hdr),
}

//// IPv4 header, which is present after the Ethernet header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv4Hdr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: IpProto,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

impl Ipv4Hdr {
    pub const LEN: usize = mem::size_of::<Ipv4Hdr>();

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

#[cfg(feature = "std")]
impl Ipv4Hdr {
    /// Returns the source address field. As network endianness is big endian, we convert it to host endianness.
    pub fn src_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from_be(self.src_addr))
    }

    /// Returns the destination address field. As network endianness is big endian, we convert it to host endianness.
    pub fn dst_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from_be(self.dst_addr))
    }

    /// Sets the source address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_src_addr(&mut self, src: std::net::Ipv4Addr) {
        self.src_addr = u32::from(src).to_be();
    }

    /// Sets the destination address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_dst_addr(&mut self, dst: std::net::Ipv4Addr) {
        self.dst_addr = u32::from(dst).to_be();
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct in6_addr {
    pub in6_u: in6_u,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub union in6_u {
    pub u6_addr8: [u8; 16usize],
    pub u6_addr16: [u16; 8usize],
    pub u6_addr32: [u32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv6Hdr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
    pub flow_label: [u8; 3usize],
    pub payload_len: u16,
    pub next_hdr: IpProto,
    pub hop_limit: u8,
    pub src_addr: in6_addr,
    pub dst_addr: in6_addr,
}

impl Ipv6Hdr {
    pub const LEN: usize = mem::size_of::<Ipv6Hdr>();

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

#[cfg(feature = "std")]
impl Ipv6Hdr {
    /// Returns the source address field. As network endianness is big endian, we convert it to host endianness.
    pub fn src_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(u128::from_be_bytes(unsafe { self.src_addr.in6_u.u6_addr8 }))
    }

    /// Returns the destination address field. As network endianness is big endian, we convert it to host endianness.
    pub fn dst_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(u128::from_be_bytes(unsafe { self.dst_addr.in6_u.u6_addr8 }))
    }

    /// Sets the source address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_src_addr(&mut self, src: std::net::Ipv6Addr) {
        self.src_addr = in6_addr {
            in6_u: in6_u {
                u6_addr8: u128::from(src).to_be_bytes(),
            },
        };
    }

    /// Sets the destination address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_dst_addr(&mut self, dst: std::net::Ipv6Addr) {
        self.dst_addr = in6_addr {
            in6_u: in6_u {
                u6_addr8: u128::from(dst).to_be_bytes(),
            },
        };
    }
}

/// Protocol which is encapsulated in the IPv4 packet.
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum IpProto {
    /// IPv6 Hop-by-Hop Option
    HopOpt = 0,
    /// Internet Control Message
    Icmp = 1,
    /// Internet Group Management
    Igmp = 2,
    /// Gateway-to-Gateway
    Ggp = 3,
    /// IPv4 encapsulation
    Ipv4 = 4,
    /// Stream
    Stream = 5,
    /// Transmission Control
    Tcp = 6,
    /// CBT
    Cbt = 7,
    /// Exterior Gateway Protocol
    Egp = 8,
    /// Any private interior gateway (used by Cisco for their IGRP)
    Igp = 9,
    /// BBN RCC Monitoring
    BbnRccMon = 10,
    /// Network Voice Protocol
    NvpII = 11,
    /// PUP
    Pup = 12,
    /// ARGUS
    Argus = 13,
    /// EMCON
    Emcon = 14,
    /// Cross Net Debugger
    Xnet = 15,
    /// Chaos
    Chaos = 16,
    /// User Datagram
    Udp = 17,
    /// Multiplexing
    Mux = 18,
    /// DCN Measurement Subsystems
    DcnMeas = 19,
    /// Host Monitoring
    Hmp = 20,
    /// Packet Radio Measurement
    Prm = 21,
    /// XEROX NS IDP
    Idp = 22,
    /// Trunk-1
    Trunk1 = 23,
    /// Trunk-2
    Trunk2 = 24,
    /// Leaf-1
    Leaf1 = 25,
    /// Leaf-2
    Leaf2 = 26,
    /// Reliable Data Protocol
    Rdp = 27,
    /// Internet Reliable Transaction
    Irtp = 28,
    /// ISO Transport Protocol Class 4
    Tp4 = 29,
    /// Bulk Data Transfer Protocol
    Netblt = 30,
    /// MFE Network Services Protocol
    MfeNsp = 31,
    /// MERIT Internodal Protocol
    MeritInp = 32,
    /// Datagram Congestion Control Protocol
    Dccp = 33,
    /// Third Party Connect Protocol
    ThirdPartyConnect = 34,
    /// Inter-Domain Policy Routing Protocol
    Idpr = 35,
    /// XTP
    Xtp = 36,
    /// Datagram Delivery Protocol
    Ddp = 37,
    /// IDPR Control Message Transport Proto
    IdprCmtp = 38,
    /// TP++ Transport Protocol
    TpPlusPlus = 39,
    /// IL Transport Protocol
    Il = 40,
    /// IPv6 encapsulation
    Ipv6 = 41,
    /// Source Demand Routing Protocol
    Sdrp = 42,
    /// Routing Header for IPv6
    Ipv6Route = 43,
    /// Fragment Header for IPv6
    Ipv6Frag = 44,
    /// Inter-Domain Routing Protocol
    Idrp = 45,
    /// Reservation Protocol
    Rsvp = 46,
    /// General Routing Encapsulation
    Gre = 47,
    /// Dynamic Source Routing Protocol
    Dsr = 48,
    /// BNA
    Bna = 49,
    /// Encap Security Payload
    Esp = 50,
    /// Authentication Header
    Ah = 51,
    /// Integrated Net Layer Security TUBA
    Inlsp = 52,
    /// IP with Encryption
    Swipe = 53,
    /// NBMA Address Resolution Protocol
    Narp = 54,
    /// IP Mobility
    Mobile = 55,
    /// Transport Layer Security Protocol using Kryptonet key management
    Tlsp = 56,
    /// SKIP
    Skip = 57,
    /// Internet Control Message Protocol for IPv6
    Ipv6Icmp = 58,
    /// No Next Header for IPv6
    Ipv6NoNxt = 59,
    /// Destination Options for IPv6
    Ipv6Opts = 60,
    /// Any host internal protocol
    AnyHostInternal = 61,
    /// CFTP
    Cftp = 62,
    /// Any local network
    AnyLocalNetwork = 63,
    /// SATNET and Backroom EXPAK
    SatExpak = 64,
    /// Kryptolan
    Kryptolan = 65,
    /// MIT Remote Virtual Disk Protocol
    Rvd = 66,
    /// Internet Pluribus Packet Core
    Ippc = 67,
    /// Any distributed file system
    AnyDistributedFileSystem = 68,
    /// SATNET Monitoring
    SatMon = 69,
    /// VISA Protocol
    Visa = 70,
    /// Internet Packet Core Utility
    Ipcv = 71,
    /// Computer Protocol Network Executive
    Cpnx = 72,
    /// Computer Protocol Heart Beat
    Cphb = 73,
    /// Wang Span Network
    Wsn = 74,
    /// Packet Video Protocol
    Pvp = 75,
    /// Backroom SATNET Monitoring
    BrSatMon = 76,
    /// SUN ND PROTOCOL-Temporary
    SunNd = 77,
    /// WIDEBAND Monitoring
    WbMon = 78,
    /// WIDEBAND EXPAK
    WbExpak = 79,
    /// ISO Internet Protocol
    IsoIp = 80,
    /// VMTP
    Vmtp = 81,
    /// SECURE-VMTP
    SecureVmtp = 82,
    /// VINES
    Vines = 83,
    /// Transaction Transport Protocol
    Ttp = 84,
    /// NSFNET-IGP
    NsfnetIgp = 85,
    /// Dissimilar Gateway Protocol
    Dgp = 86,
    /// TCF
    Tcf = 87,
    /// EIGRP
    Eigrp = 88,
    /// OSPFIGP
    Ospfigp = 89,
    /// Sprite RPC Protocol
    SpriteRpc = 90,
    /// Locus Address Resolution Protocol
    Larp = 91,
    /// Multicast Transport Protocol
    Mtp = 92,
    /// AX.25 Frames
    Ax25 = 93,
    /// IP-within-IP Encapsulation Protocol
    Ipip = 94,
    /// Mobile Internetworking Control Pro.
    Micp = 95,
    /// Semaphore Communications Sec. Pro.
    SccSp = 96,
    /// Ethernet-within-IP Encapsulation
    Etherip = 97,
    /// Encapsulation Header
    Encap = 98,
    /// Any private encryption scheme
    AnyPrivateEncryptionScheme = 99,
    /// GMTP
    Gmtp = 100,
    /// Ipsilon Flow Management Protocol
    Ifmp = 101,
    /// PNNI over IP
    Pnni = 102,
    /// Protocol Independent Multicast
    Pim = 103,
    /// ARIS
    Aris = 104,
    /// SCPS
    Scps = 105,
    /// QNX
    Qnx = 106,
    /// Active Networks
    ActiveNetworks = 107,
    /// IP Payload Compression Protocol
    IpComp = 108,
    /// Sitara Networks Protocol
    Snp = 109,
    /// Compaq Peer Protocol
    CompaqPeer = 110,
    /// IPX in IP
    IpxInIp = 111,
    /// Virtual Router Redundancy Protocol
    Vrrp = 112,
    /// PGM Reliable Transport Protocol
    Pgm = 113,
    /// Any 0-hop protocol
    AnyZeroHopProtocol = 114,
    /// Layer Two Tunneling Protocol
    L2tp = 115,
    /// D-II Data Exchange (DDX)
    Ddx = 116,
    /// Interactive Agent Transfer Protocol
    Iatp = 117,
    /// Schedule Transfer Protocol
    Stp = 118,
    /// SpectraLink Radio Protocol
    Srp = 119,
    /// UTI
    Uti = 120,
    /// Simple Message Protocol
    Smp = 121,
    /// Simple Multicast Protocol
    Sm = 122,
    /// Performance Transparency Protocol
    Ptp = 123,
    /// ISIS over IPv4
    IsisOverIpv4 = 124,
    /// FIRE
    Fire = 125,
    /// Combat Radio Transport Protocol
    Crtp = 126,
    /// Combat Radio User Datagram
    Crudp = 127,
    /// SSCOPMCE
    Sscopmce = 128,
    /// IPLT
    Iplt = 129,
    /// Secure Packet Shield
    Sps = 130,
    /// Private IP Encapsulation within IP
    Pipe = 131,
    /// Stream Control Transmission Protocol
    Sctp = 132,
    /// Fibre Channel
    Fc = 133,
    /// RSVP-E2E-IGNORE
    RsvpE2eIgnore = 134,
    /// Mobility Header
    MobilityHeader = 135,
    /// Lightweight User Datagram Protocol
    UdpLite = 136,
    /// MPLS-in-IP
    Mpls = 137,
    /// MANET Protocols
    Manet = 138,
    /// Host Identity Protocol
    Hip = 139,
    /// Shim6 Protocol
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload
    Wesp = 141,
    /// Robust Header Compression
    Rohc = 142,
    /// Ethernet in IPv4
    EthernetInIpv4 = 143,
    /// AGGFRAG encapsulation payload for ESP
    Aggfrag = 144,
    /// Use for experimentation and testing
    Test1 = 253,
    /// Use for experimentation and testing
    Test2 = 254,
    /// Reserved
    Reserved = 255,
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "std")]
    #[test]
    fn test_v4() {
        use core::mem;
        use std::net::Ipv4Addr;

        use crate::ip::Ipv4Hdr;

        let expected_header_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2,
        ];

        let ipv4_header: Ipv4Hdr = unsafe {
            mem::transmute::<[u8; Ipv4Hdr::LEN], _>(expected_header_bytes.try_into().unwrap())
        };
        assert_eq!(ipv4_header.src_addr(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4_header.dst_addr(), Ipv4Addr::new(127, 0, 0, 2));

        let mut header_bytes = [0u8; 20];
        let ipv4_header: *mut Ipv4Hdr = &mut header_bytes as *mut _ as *mut _;
        unsafe {
            (*ipv4_header).set_src_addr(Ipv4Addr::new(127, 0, 0, 1));
            (*ipv4_header).set_dst_addr(Ipv4Addr::new(127, 0, 0, 2));
        }

        let ipv4_header: Ipv4Hdr =
            unsafe { mem::transmute::<[u8; Ipv4Hdr::LEN], _>(header_bytes.try_into().unwrap()) };
        assert_eq!(ipv4_header.src_addr(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4_header.dst_addr(), Ipv4Addr::new(127, 0, 0, 2));

        assert_eq!(expected_header_bytes, header_bytes);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_v6() {
        use core::mem;
        use std::net::Ipv6Addr;

        use crate::ip::Ipv6Hdr;

        let expected_header_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        let ipv6_header: Ipv6Hdr = unsafe {
            mem::transmute::<[u8; Ipv6Hdr::LEN], _>(expected_header_bytes.try_into().unwrap())
        };
        assert_eq!(
            ipv6_header.src_addr(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            ipv6_header.dst_addr(),
            Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1)
        );

        let mut header_bytes = [0u8; 40];
        let ipv6_header: *mut Ipv6Hdr = &mut header_bytes as *mut _ as *mut _;
        unsafe {
            (*ipv6_header).set_src_addr(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
            (*ipv6_header).set_dst_addr(Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1));
        }

        let ipv6_header: Ipv6Hdr =
            unsafe { mem::transmute::<[u8; Ipv6Hdr::LEN], _>(header_bytes.try_into().unwrap()) };
        assert_eq!(
            ipv6_header.src_addr(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            ipv6_header.dst_addr(),
            Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1)
        );

        assert_eq!(expected_header_bytes, header_bytes);
    }
}
