use core::mem;

use crate::{getter_be, setter_be};

/// Represents errors that can occur while processing ICMP headers.
#[derive(Debug)]
pub enum IpError {
    /// Invalid ID of an encapsulated protocol.
    InvalidProto(u8),
}

/// IP headers, which are present after the Ethernet header.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpHdr {
    V4(Ipv4Hdr),
    V6(Ipv6Hdr),
}

/// IPv4 header, which is present after the Ethernet header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv4Hdr {
    pub vihl: u8,
    pub tos: u8,
    pub tot_len: [u8; 2],
    pub id: [u8; 2],
    pub frags: [u8; 2],
    pub ttl: u8,
    pub proto: u8,
    pub check: [u8; 2],
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

impl Ipv4Hdr {
    pub const LEN: usize = mem::size_of::<Ipv4Hdr>();

    /// Returns the IP version field (should be 4).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.vihl >> 4) & 0xF
    }

    /// Returns the IP header length in bytes.
    #[inline]
    pub fn ihl(&self) -> u8 {
        (self.vihl & 0xF) << 2
    }

    /// Returns the length of the IP options in bytes.
    #[inline]
    pub fn options_len(&self) -> u8 {
        self.ihl() - Self::LEN as u8
    }

    /// Sets both the version and IHL fields.
    #[inline]
    pub fn set_vihl(&mut self, version: u8, ihl_in_bytes: u8) {
        let ihl_in_words = ihl_in_bytes / 4;
        self.vihl = ((version & 0xF) << 4) | (ihl_in_words & 0xF);
    }

    /// Returns the DSCP (Differentiated Services Code Point) field.
    #[inline]
    pub fn dscp(&self) -> u8 {
        (self.tos >> 2) & 0x3F
    }

    /// Returns the ECN (Explicit Congestion Notification) field.
    #[inline]
    pub fn ecn(&self) -> u8 {
        self.tos & 0x3
    }

    /// Sets the TOS field with separate DSCP and ECN values.
    #[inline]
    pub fn set_tos(&mut self, dscp: u8, ecn: u8) {
        self.tos = ((dscp & 0x3F) << 2) | (ecn & 0x3);
    }

    /// Returns the total length of the IP packet.
    #[inline]
    pub fn tot_len(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, tot_len, u16) }
    }

    /// Sets the total length of the IP packet.
    #[inline]
    pub fn set_tot_len(&mut self, len: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, tot_len, len) }
    }

    /// Returns the identification field.
    #[inline]
    pub fn id(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, id, u16) }
    }

    /// Sets the identification field.
    #[inline]
    pub fn set_id(&mut self, id: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, id, id) }
    }

    #[inline]
    fn frags(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, frags, u16) }
    }

    /// Returns the fragmentation flags (3 bits).
    #[inline]
    pub fn frag_flags(&self) -> u8 {
        (self.frags() >> 13) as u8
    }

    /// Returns the fragmentation offset (13 bits).
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        self.frags() & 0x1FFF
    }

    /// Sets both the fragmentation flags and offset.
    #[inline]
    pub fn set_frags(&mut self, flags: u8, offset: u16) {
        let value = ((flags as u16 & 0x7) << 13) | (offset & 0x1FFF);
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, frags, value) }
    }

    /// Returns the encapsulated protocol.
    #[inline]
    pub fn proto(&self) -> Result<IpProto, IpError> {
        IpProto::try_from(self.proto)
    }

    /// Sets the encapsulated protocol.
    #[inline]
    pub fn set_proto(&mut self, proto: IpProto) {
        self.proto = proto.into();
    }

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, check, u16) }
    }

    /// Sets the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, check, checksum) }
    }

    /// Returns the source address field.
    #[inline]
    pub fn src_addr(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.src_addr)
    }

    /// Returns the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.dst_addr)
    }

    /// Sets the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, src: core::net::Ipv4Addr) {
        self.src_addr = src.octets();
    }

    /// Sets the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, dst: core::net::Ipv4Addr) {
        self.dst_addr = dst.octets();
    }
}

/// IPv6 header, which is present after the Ethernet header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv6Hdr {
    /// First 4 bytes containing Version (4 bits), Traffic Class (8 bits), and Flow Label (20 bits)
    pub vcf: [u8; 4],
    /// Payload length (excluding the IPv6 header)
    pub payload_len: [u8; 2],
    /// Next header protocol
    pub next_hdr: u8,
    /// Hop limit (similar to TTL in IPv4)
    pub hop_limit: u8,
    /// Source IPv6 address (16 bytes)
    pub src_addr: [u8; 16],
    /// Destination IPv6 address (16 bytes)
    pub dst_addr: [u8; 16],
}

impl Ipv6Hdr {
    pub const LEN: usize = mem::size_of::<Ipv6Hdr>();

    /// Returns the IP version field (should be 6).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.vcf[0] >> 4) & 0xF
    }

    /// Sets the version field.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.vcf[0] = (self.vcf[0] & 0x0F) | ((version & 0xF) << 4);
    }

    /// Returns the DSCP (Differentiated Services Code Point) field.
    #[inline]
    pub fn dscp(&self) -> u8 {
        ((self.vcf[0] & 0x0F) << 2) | ((self.vcf[1] >> 6) & 0x03)
    }

    /// Returns the ECN (Explicit Congestion Notification) field.
    #[inline]
    pub fn ecn(&self) -> u8 {
        (self.vcf[1] >> 4) & 0x03
    }

    /// Returns the flow label field (20 bits).
    #[inline]
    pub fn flow_label(&self) -> u32 {
        ((self.vcf[1] as u32 & 0x0F) << 16) | ((self.vcf[2] as u32) << 8) | (self.vcf[3] as u32)
    }

    /// Sets the DSCP and ECN fields.
    #[inline]
    pub fn set_dscp_ecn(&mut self, dscp: u8, ecn: u8) {
        // Set the lower 4 bits of the first byte (upper 4 bits of DSCP)
        self.vcf[0] = (self.vcf[0] & 0xF0) | ((dscp >> 2) & 0x0F);

        // Set the upper 2 bits of the second byte (lower 2 bits of DSCP) and the next 2 bits (ECN)
        self.vcf[1] = (self.vcf[1] & 0x0F) | (((dscp & 0x03) << 6) | ((ecn & 0x03) << 4));
    }

    /// Sets the flow label field (20 bits).
    #[inline]
    pub fn set_flow_label(&mut self, flow_label: u32) {
        self.vcf[1] = (self.vcf[1] & 0xF0) | ((flow_label >> 16) as u8 & 0x0F);
        self.vcf[2] = ((flow_label >> 8) & 0xFF) as u8;
        self.vcf[3] = (flow_label & 0xFF) as u8;
    }

    /// Sets the version, DSCP, ECN, and flow label in one operation.
    #[inline]
    pub fn set_vcf(&mut self, version: u8, dscp: u8, ecn: u8, flow_label: u32) {
        self.vcf[0] = ((version & 0x0F) << 4) | ((dscp >> 2) & 0x0F);
        self.vcf[1] =
            ((dscp & 0x03) << 6) | ((ecn & 0x03) << 4) | ((flow_label >> 16) as u8 & 0x0F);
        self.vcf[2] = ((flow_label >> 8) & 0xFF) as u8;
        self.vcf[3] = (flow_label & 0xFF) as u8;
    }

    /// Returns the payload length.
    #[inline]
    pub fn payload_len(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, payload_len, u16) }
    }

    /// Sets the payload length.
    #[inline]
    pub fn set_payload_len(&mut self, len: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, payload_len, len) }
    }

    /// Returns the encapsulated protocol.
    #[inline]
    pub fn next_hdr(&self) -> Result<IpProto, IpError> {
        IpProto::try_from(self.next_hdr)
    }

    #[inline]
    pub fn set_next_hdr(&mut self, proto: IpProto) {
        self.next_hdr = proto.into();
    }

    /// Returns the source address field.
    #[inline]
    pub fn src_addr(&self) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(self.src_addr)
    }

    /// Returns the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(self.dst_addr)
    }

    /// Sets the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, src: core::net::Ipv6Addr) {
        self.src_addr = src.octets();
    }

    /// Sets the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, dst: core::net::Ipv6Addr) {
        self.dst_addr = dst.octets();
    }
}

/// Protocol which is encapsulated in the IPv4 packet.
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

// This allows converting a u8 value into an IpProto enum variant.
// This is useful when parsing headers.
impl TryFrom<u8> for IpProto {
    type Error = IpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=144 | 253..=255 => {
                // SAFETY: IpProto uses #[repr(u8)] and we only transmute known discriminants.
                Ok(unsafe { core::mem::transmute::<u8, IpProto>(value) })
            }
            other => Err(IpError::InvalidProto(other)),
        }
    }
}

// This allows converting an IpProto enum variant back to its u8 representation.
// This is useful when constructing headers.
impl From<IpProto> for u8 {
    fn from(value: IpProto) -> Self {
        value as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    // Helper to create a default Ipv4Hdr for tests
    fn default_ipv4_hdr() -> Ipv4Hdr {
        Ipv4Hdr {
            vihl: 0,
            tos: 0,
            tot_len: [0; 2],
            id: [0; 2],
            frags: [0; 2],
            ttl: 0,
            proto: IpProto::Tcp.into(),
            check: [0; 2],
            src_addr: [0; 4],
            dst_addr: [0; 4],
        }
    }

    // Helper to create a default Ipv6Hdr for tests
    fn default_ipv6_hdr() -> Ipv6Hdr {
        Ipv6Hdr {
            vcf: [0; 4],
            payload_len: [0; 2],
            next_hdr: IpProto::Tcp.into(),
            hop_limit: 0,
            src_addr: [0; 16],
            dst_addr: [0; 16],
        }
    }

    #[test]
    fn test_ipv4_vihl() {
        let mut hdr = default_ipv4_hdr();
        hdr.set_vihl(4, 20); // Version 4, IHL 20 bytes (5 words)
        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 20);
        assert_eq!(hdr.options_len(), 0);

        hdr.set_vihl(4, 24); // Version 4, IHL 24 bytes (6 words)
        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 24);
        assert_eq!(hdr.options_len(), 4);

        hdr.set_vihl(4, 60); // Version 4, IHL 60 bytes (15 words)
        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 60);
        assert_eq!(hdr.options_len(), 40);
    }

    #[test]
    fn test_ipv4_tos() {
        let mut hdr = default_ipv4_hdr();
        hdr.set_tos(0b001010, 0b01); // DSCP 10, ECN 1
        assert_eq!(hdr.dscp(), 0b001010);
        assert_eq!(hdr.ecn(), 0b01);

        hdr.set_tos(0b110011, 0b10); // DSCP 51, ECN 2
        assert_eq!(hdr.dscp(), 0b110011);
        assert_eq!(hdr.ecn(), 0b10);
    }

    #[test]
    fn test_ipv4_tot_len() {
        let mut hdr = default_ipv4_hdr();
        hdr.set_tot_len(1500);
        assert_eq!(hdr.tot_len(), 1500);
    }

    #[test]
    fn test_ipv4_id() {
        let mut hdr = default_ipv4_hdr();
        hdr.set_id(0xABCD);
        assert_eq!(hdr.id(), 0xABCD);
    }

    #[test]
    fn test_ipv4_frags() {
        let mut hdr = default_ipv4_hdr();
        // Flags: 0b010 (DF set), Offset: 100
        hdr.set_frags(0b010, 100);
        assert_eq!(hdr.frag_flags(), 0b010);
        assert_eq!(hdr.frag_offset(), 100);

        // Flags: 0b001 (MF set), Offset: 0x1ABC
        hdr.set_frags(0b001, 0x1ABC);
        assert_eq!(hdr.frag_flags(), 0b001);
        assert_eq!(hdr.frag_offset(), 0x1ABC);
    }

    #[test]
    fn test_ipv4_checksum() {
        let mut hdr = default_ipv4_hdr();
        hdr.set_checksum(0x1234);
        assert_eq!(hdr.checksum(), 0x1234);
    }

    #[test]
    fn test_ipv4_addrs() {
        let mut hdr = default_ipv4_hdr();
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        hdr.set_src_addr(src);
        hdr.set_dst_addr(dst);
        assert_eq!(hdr.src_addr(), src);
        assert_eq!(hdr.dst_addr(), dst);
    }

    #[test]
    fn test_ipv6_version() {
        let mut hdr = default_ipv6_hdr();
        hdr.set_version(6);
        assert_eq!(hdr.version(), 6);
    }

    #[test]
    fn test_ipv6_dscp_ecn() {
        let mut hdr = default_ipv6_hdr();
        // DSCP: 0b001010 (10), ECN: 0b01 (1)
        hdr.set_dscp_ecn(0b001010, 0b01);
        assert_eq!(hdr.dscp(), 0b001010);
        assert_eq!(hdr.ecn(), 0b01);

        // DSCP: 0b110011 (51), ECN: 0b10 (2)
        // Ensure other parts of vcf[0] and vcf[1] are not clobbered unnecessarily
        // by setting version and flow label first
        hdr.set_version(6);
        hdr.set_flow_label(0xFFFFF); // Max flow label
        hdr.set_dscp_ecn(0b110011, 0b10);
        assert_eq!(hdr.version(), 6); // Check version is maintained
        assert_eq!(hdr.dscp(), 0b110011);
        assert_eq!(hdr.ecn(), 0b10);
        assert_eq!(hdr.flow_label(), 0xFFFFF); // Check flow label is maintained
    }

    #[test]
    fn test_ipv6_flow_label() {
        let mut hdr = default_ipv6_hdr();
        hdr.set_flow_label(0x12345); // 20-bit value
        assert_eq!(hdr.flow_label(), 0x12345);

        // Ensure other parts of vcf[1] are not clobbered
        // by setting dscp and ecn first
        hdr.set_version(6);
        hdr.set_dscp_ecn(0b001010, 0b01);
        hdr.set_flow_label(0xABCDE);
        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.dscp(), 0b001010);
        assert_eq!(hdr.ecn(), 0b01);
        assert_eq!(hdr.flow_label(), 0xABCDE);
    }

    #[test]
    fn test_ipv6_set_vcf() {
        let mut hdr = default_ipv6_hdr();
        let version = 6;
        let dscp = 0b001111; // 15
        let ecn = 0b11; // 3
        let flow_label = 0xFEDCB; // 20-bit

        hdr.set_vcf(version, dscp, ecn, flow_label);
        assert_eq!(hdr.version(), version);
        assert_eq!(hdr.dscp(), dscp);
        assert_eq!(hdr.ecn(), ecn);
        assert_eq!(hdr.flow_label(), flow_label);
    }

    #[test]
    fn test_ipv6_payload_len() {
        let mut hdr = default_ipv6_hdr();
        hdr.set_payload_len(3000);
        assert_eq!(hdr.payload_len(), 3000);
    }

    #[test]
    fn test_ipv6_addrs() {
        let mut hdr = default_ipv6_hdr();
        let src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001);
        let dst = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0002);
        hdr.set_src_addr(src);
        hdr.set_dst_addr(dst);
        assert_eq!(hdr.src_addr(), src);
        assert_eq!(hdr.dst_addr(), dst);
    }

    #[test]
    fn test_ip_proto_variants() {
        assert_eq!(IpProto::Tcp as u8, 6);
        assert_eq!(IpProto::Udp as u8, 17);
        assert_eq!(IpProto::Icmp as u8, 1);
        assert_eq!(IpProto::Ipv6Icmp as u8, 58);
    }

    #[test]
    fn test_iphdr_enum() {
        let ipv4_hdr = default_ipv4_hdr();
        let ip_hdr_v4 = IpHdr::V4(ipv4_hdr);
        if let IpHdr::V4(hdr) = ip_hdr_v4 {
            assert_eq!(hdr.vihl, ipv4_hdr.vihl); // Check a field to ensure it's the same
        } else {
            panic!("Expected IpHdr::V4");
        }

        let ipv6_hdr = default_ipv6_hdr();
        let ip_hdr_v6 = IpHdr::V6(ipv6_hdr);
        if let IpHdr::V6(hdr) = ip_hdr_v6 {
            assert_eq!(hdr.vcf, ipv6_hdr.vcf); // Check a field
        } else {
            panic!("Expected IpHdr::V6");
        }
    }
}
