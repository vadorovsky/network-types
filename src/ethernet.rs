#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

impl EthHdr {
    pub fn protocol(&self) -> Result<EthProtocol, ()> {
        self.h_proto.try_into()
    }
}

#[repr(u16)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum EthProtocol {
    Loop = 0x0060,
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
    FibreChannel = 0x8906,
    Infiniband = 0x8915,
    LoopbackIeee8023 = 0x9000,
}

impl TryFrom<u16> for EthProtocol {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        let v = u16::from_be(v);
        match v {
            x if x == EthProtocol::Loop as u16 => Ok(EthProtocol::Loop),
            x if x == EthProtocol::Ipv4 as u16 => Ok(EthProtocol::Ipv4),
            x if x == EthProtocol::Arp as u16 => Ok(EthProtocol::Arp),
            x if x == EthProtocol::Ipv6 as u16 => Ok(EthProtocol::Ipv6),
            x if x == EthProtocol::FibreChannel as u16 => Ok(EthProtocol::FibreChannel),
            x if x == EthProtocol::Infiniband as u16 => Ok(EthProtocol::Infiniband),
            x if x == EthProtocol::LoopbackIeee8023 as u16 => Ok(EthProtocol::LoopbackIeee8023),
            _ => Err(()),
        }
    }
}
