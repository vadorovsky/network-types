use core::mem;

/// Represents errors that occur while processing Ethernet headers.
#[derive(Debug, Eq, PartialEq)]
pub enum EthError {
    /// Invalid tag of an encapsulated protocol.
    InvalidEtherType(u16),
}

/// Ethernet header structure that appears at the beginning of every Ethernet frame.
/// This structure represents the standard IEEE 802.3 Ethernet header format.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct EthHdr {
    /// Destination MAC address.
    pub dst_addr: [u8; 6],
    /// Source MAC address.
    pub src_addr: [u8; 6],
    /// Protocol which is encapsulated in the payload of the frame.
    /// Indicates what type of data follows the Ethernet header (e.g., IPv4, IPv6, ARP)
    pub ether_type: u16,
}

impl EthHdr {
    pub const LEN: usize = mem::size_of::<EthHdr>();

    /// Attempts to convert the raw ether_type field into an EtherType enum.
    /// Returns either the corresponding EtherType variant or the raw value if unknown.
    ///
    /// # Returns
    /// - `Ok(EtherType)` if a known protocol type
    /// - `Err(u16)` if an unknown protocol type (returns the raw value)
    pub fn ether_type(&self) -> Result<EtherType, EthError> {
        EtherType::try_from(self.ether_type)
    }

    /// Creates a new Ethernet header with the specified addresses and protocol type
    ///
    /// # Parameters
    /// - `dst_addr`: The destination MAC address
    /// - `src_addr`: The source MAC address
    /// - `ether_type_enum`: The protocol type encapsulated in the payload
    ///
    /// # Returns
    /// A new EthHdr structure initialized with the given values
    pub fn new(dst_addr: [u8; 6], src_addr: [u8; 6], eth_type: EtherType) -> Self {
        EthHdr {
            dst_addr,
            src_addr,
            ether_type: eth_type.into(),
        }
    }
}

/// Protocol which is encapsulated in the payload of the Ethernet frame.
/// These values represent the standard IEEE assigned protocol numbers
#[repr(u16)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum EtherType {
    Loop = 0x0060_u16.to_be(),
    Ipv4 = 0x0800_u16.to_be(),
    Arp = 0x0806_u16.to_be(),
    Ieee8021q = 0x8100_u16.to_be(),
    Ipv6 = 0x86DD_u16.to_be(),
    Ieee8021ad = 0x88A8_u16.to_be(),
    Ieee8021MacSec = 0x88E5_u16.to_be(),
    Ieee8021ah = 0x88E7_u16.to_be(),
    Ieee8021mvrp = 0x88F5_u16.to_be(),
    FibreChannel = 0x8906_u16.to_be(),
    Infiniband = 0x8915_u16.to_be(),
    LoopbackIeee8023 = 0x9000_u16.to_be(),
    Ieee8021QinQ1 = 0x9100_u16.to_be(),
    Ieee8021QinQ2 = 0x9200_u16.to_be(),
    Ieee8021QinQ3 = 0x9300_u16.to_be(),
}

// This allows converting a u16 value into an EtherType enum variant.
// This is useful when parsing headers.
impl TryFrom<u16> for EtherType {
    type Error = EthError; // Return the unknown value itself as the error

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value.to_be() {
            0x0060_u16 => Ok(EtherType::Loop),
            0x0800_u16 => Ok(EtherType::Ipv4),
            0x0806_u16 => Ok(EtherType::Arp),
            0x8100_u16 => Ok(EtherType::Ieee8021q),
            0x86DD_u16 => Ok(EtherType::Ipv6),
            0x88A8_u16 => Ok(EtherType::Ieee8021ad),
            0x88E5_u16 => Ok(EtherType::Ieee8021MacSec),
            0x88E7_u16 => Ok(EtherType::Ieee8021ah),
            0x88F5_u16 => Ok(EtherType::Ieee8021mvrp),
            0x8906_u16 => Ok(EtherType::FibreChannel),
            0x8915_u16 => Ok(EtherType::Infiniband),
            0x9000_u16 => Ok(EtherType::LoopbackIeee8023),
            0x9100_u16 => Ok(EtherType::Ieee8021QinQ1),
            0x9200_u16 => Ok(EtherType::Ieee8021QinQ2),
            0x9300_u16 => Ok(EtherType::Ieee8021QinQ3),
            other => Err(EthError::InvalidEtherType(other)),
        }
    }
}

// This allows converting an EtherType enum variant back to its u16 representation.
// This is useful when constructing headers.
impl From<EtherType> for u16 {
    fn from(ether_type: EtherType) -> Self {
        ether_type as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use core::mem;

    // Test constants for MAC addresses
    const TEST_DST_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const TEST_SRC_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    #[test]
    fn test_ethhdr_len() {
        assert_eq!(EthHdr::LEN, 14);
        assert_eq!(mem::size_of::<EthHdr>(), 14);
    }

    #[test]
    fn test_ethhdr_new() {
        let eth_hdr = EthHdr::new(TEST_DST_MAC, TEST_SRC_MAC, EtherType::Ipv4);
        assert_eq!(eth_hdr.dst_addr, TEST_DST_MAC);
        assert_eq!(eth_hdr.src_addr, TEST_SRC_MAC);
        let ether_type_value = eth_hdr.ether_type;
        assert_eq!(ether_type_value, EtherType::Ipv4 as u16);
        assert_eq!(ether_type_value, 0x0800_u16.to_be());
    }

    #[test]
    fn test_ethhdr_ether_type_method_known() {
        let eth_hdr = EthHdr {
            dst_addr: TEST_DST_MAC,
            src_addr: TEST_SRC_MAC,
            ether_type: EtherType::Ipv6 as u16,
        };
        assert_eq!(eth_hdr.ether_type().unwrap(), EtherType::Ipv6);
    }

    #[test]
    fn test_ethhdr_ether_type_method_unknown() {
        let unknown_type_val = 0x1234_u16;
        let eth_hdr = EthHdr {
            dst_addr: TEST_DST_MAC,
            src_addr: TEST_SRC_MAC,
            ether_type: unknown_type_val.to_be(),
        };
        assert_matches!(eth_hdr.ether_type(), Err(EthError::InvalidEtherType(val)) if val == unknown_type_val);
    }

    #[test]
    fn test_ethertype_try_from_u16_known() {
        let ipv4_val = 0x0800_u16.to_be();
        assert_eq!(EtherType::try_from(ipv4_val), Ok(EtherType::Ipv4));

        let ipv6_val = 0x86DD_u16.to_be();
        assert_eq!(EtherType::try_from(ipv6_val), Ok(EtherType::Ipv6));

        let arp_val = 0x0806_u16.to_be();
        assert_eq!(EtherType::try_from(arp_val), Ok(EtherType::Arp));
    }

    #[test]
    fn test_ethertype_try_from_u16_unknown() {
        let unknown_val = 0x1234_u16;
        assert_matches!(EtherType::try_from(unknown_val.to_be()), Err(EthError::InvalidEtherType(val)) if val == unknown_val);
    }

    #[test]
    fn test_u16_from_ethertype() {
        assert_eq!(u16::from(EtherType::Ipv4), 0x0800_u16.to_be());
        assert_eq!(u16::from(EtherType::Arp), 0x0806_u16.to_be());
        assert_eq!(u16::from(EtherType::Ipv6), 0x86DD_u16.to_be());
        assert_eq!(u16::from(EtherType::Loop), 0x0060_u16.to_be());
    }

    #[test]
    fn test_ethertype_variants_unique_values() {
        let all_types = [
            EtherType::Loop,
            EtherType::Ipv4,
            EtherType::Arp,
            EtherType::Ieee8021q,
            EtherType::Ipv6,
            EtherType::Ieee8021ad,
            EtherType::Ieee8021MacSec,
            EtherType::Ieee8021ah,
            EtherType::Ieee8021mvrp,
            EtherType::FibreChannel,
            EtherType::Infiniband,
            EtherType::LoopbackIeee8023,
            EtherType::Ieee8021QinQ1,
            EtherType::Ieee8021QinQ2,
            EtherType::Ieee8021QinQ3,
        ];

        for i in 0..all_types.len() {
            for j in (i + 1)..all_types.len() {
                // Compare the u16 representation of each EtherType
                let val_i = all_types[i] as u16;
                let val_j = all_types[j] as u16;
                assert_ne!(
                    val_i, val_j,
                    "Duplicate EtherType value found: {:?} and {:?} both have value {:#06x}",
                    all_types[i], all_types[j], val_i
                );
            }
        }
    }
}
