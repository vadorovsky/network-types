use enum_try_from::impl_enum_try_from_be;

pub mod ip;

impl_enum_try_from_be!(
    /// Layer 3 (network layer) protocol.
    #[repr(u16)]
    #[derive(PartialEq, Eq, Debug, Copy, Clone)]
    pub enum L3Protocol {
        Loop = 0x0060,
        Ipv4 = 0x0800,
        Arp = 0x0806,
        Ipv6 = 0x86DD,
        FibreChannel = 0x8906,
        Infiniband = 0x8915,
        LoopbackIeee8023 = 0x9000,
    },
    u16,
    (),
    ()
);
