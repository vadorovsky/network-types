use crate::macros::impl_enum_try_from;

pub mod icmp;
pub mod tcp;
pub mod udp;

impl_enum_try_from!(
    /// Layer 4 (transport layer) protocol.
    /// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    #[repr(u8)]
    #[derive(PartialEq, Eq, Debug, Copy, Clone)]
    pub enum L4Protocol {
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
        IPv6ICMP = 58,
        Mtp = 92,
        Beet = 94,
        Encap = 98,
        Pim = 103,
        Comp = 108,
        Vrrp = 112,
        Sctp = 132,
        UdpLite = 136,
        Mpls = 137,
        EthernetInIpv4 = 143,
        Raw = 255,
    },
    u8
);
