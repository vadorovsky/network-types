use core::mem;
use core::net;

pub const ICMP_HDR_LEN: usize = mem::size_of::<IcmpHdr>();

#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdr {
    pub type_: u8,
    pub code: u8,
    pub check: [u8; 2],
    pub data: IcmpHdrUn,
}

impl IcmpHdr {
    pub const LEN: usize = mem::size_of::<IcmpHdr>();

    /// # Safety
    /// These functions are unsafe because they access union fields without verifying the ICMP type.
    /// Callers must ensure they check the ICMP type before calling these accessors.
    /// For example, only call echo_fields() when type is 0, 8, 13, 14, 15, 16, 17, 18, 37, or 38.

    /// Returns the ICMP header checksum value in host byte order.
    /// This field is used to detect data corruption in the ICMP header and payload.
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    /// Sets the ICMP header checksum field to the given value.
    /// The checksum value should be calculated over the entire ICMP message (header and payload)
    /// according to RFC 792. The value will be stored in network byte order.
    pub fn set_checksum(&mut self, checksum: u16) {
        self.check = checksum.to_be_bytes();
    }
    
    /// Returns the identification field from ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    #[inline]
    pub fn echo_id(&self) -> u16 {
        u16::from_be_bytes(unsafe { self.data.echo.id })
    }

    /// Sets the identification field for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    #[inline]
    pub fn set_echo_id(&mut self, id: u16) {
        unsafe {
            self.data.echo.id = id.to_be_bytes();
        }
    }

    /// Returns the sequence number from ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    #[inline]
    pub fn echo_sequence(&self) -> u16 {
        u16::from_be_bytes(unsafe { self.data.echo.sequence })
    }

    /// Sets the sequence number for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    #[inline]
    pub fn set_echo_sequence(&mut self, sequence: u16) {
        unsafe {
            self.data.echo.sequence = sequence.to_be_bytes();
        }
    }

    /// Returns the gateway internet address from an ICMP Redirect message (Type 5)
    #[inline]
    pub fn gateway_address(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(unsafe { self.data.redirect })
    }

    /// Sets the gateway internet address for an ICMP Redirect message (Type 5)
    #[inline]
    pub fn set_gateway_address(&mut self, addr: net::Ipv4Addr) {
        unsafe {
            self.data.redirect = addr.octets();
        }
    }

    /// Returns the Next-Hop MTU field from a Destination Unreachable message
    /// in host byte order. Used for Path MTU Discovery (RFC 1191).
    #[inline]
    pub fn next_hop_mtu(&self) -> u16 {
        u16::from_be_bytes(unsafe { self.data.dst_unreachable.mtu })
    }

    /// Sets the Next-Hop MTU field for a Destination Unreachable message.
    /// Used for Path MTU Discovery (RFC 1191).
    #[inline]
    pub fn set_next_hop_mtu(&mut self, mtu: u16) {
        unsafe {
            self.data.dst_unreachable.mtu = mtu.to_be_bytes();
        }
    }

    /// Returns the pointer to the errored byte from a Parameter Problem message (Type 12)
    #[inline]
    pub fn parameter_pointer(&self) -> u8 {
        unsafe { self.data.param_problem.pointer }
    }

    /// Sets the pointer to the errored byte for a Parameter Problem message (Type 12)
    #[inline]
    pub fn set_parameter_pointer(&mut self, pointer: u8) {
        unsafe {
            self.data.param_problem.pointer = pointer;
        }
    }

    /// Returns the ID Number field from a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    /// This is only valid for ICMP Type 30 (Traceroute Request) and Type 31 (Traceroute Reply).
    #[inline]
    pub fn traceroute_id(&self) -> u16 {
        u16::from_be_bytes(unsafe { self.data.traceroute.id })
    }

    /// Sets the ID Number field for a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    #[inline]
    pub fn set_traceroute_id(&mut self, id: u16) {
        unsafe {
            self.data.traceroute.id = id.to_be_bytes();
        }
    }

    /// Returns the Security Parameters Index (SPI) from a PHOTURIS message (Type 40).
    /// The SPI identifies a security association between two peers.
    #[inline]
    pub fn photuris_spi(&self) -> u16 {
        u16::from_be_bytes(unsafe { self.data.photuris.reserved_spi })
    }

    /// Sets the Security Parameters Index (SPI) for a PHOTURIS message (Type 40).
    /// The SPI identifies a security association between two peers.
    #[inline]
    pub fn set_photuris_spi(&mut self, spi: u16) {
        unsafe {
            self.data.photuris.reserved_spi = spi.to_be_bytes();
        }
    }

    /// Returns the pointer to the byte where an error was detected in a PHOTURIS message (Type 40).
    /// Used to identify the location of errors during PHOTURIS protocol processing.
    #[inline]
    pub fn photuris_pointer(&self) -> u16 {
        u16::from_be_bytes(unsafe { self.data.photuris.pointer })
    }

    /// Sets the pointer to the byte where an error was detected in a PHOTURIS message (Type 40).
    /// Used to identify the location of errors during PHOTURIS protocol processing.
    #[inline]
    pub fn set_photuris_pointer(&mut self, pointer: u16) {
        unsafe {
            self.data.photuris.pointer = pointer.to_be_bytes();
        }
    }
}

/// Union holding the variable 4-byte field after the first 4 bytes of an ICMP header.
/// The meaning of this field depends on the ICMP type:
/// - `echo`: Used for Echo Request/Reply and other messages with ID/sequence numbers (Types: 0,8,13,14,15,16,17,18,37,38)
/// - `redirect`: Used for Redirect messages (Type 5) to hold gateway IPv4 address
/// - `dst_unreachable`: Used for Destination Unreachable messages (Type 3) to hold Next-Hop MTU
/// - `param_problem`: Used for Parameter Problem messages (Type 12) to point to error location
/// - `traceroute`: Used for Traceroute messages (Type 30) to hold ID number
/// - `photuris`: Used for PHOTURIS security messages (Type 40) to hold SPI and error pointer
/// - `reserved`: Generic 4-byte field for types not covered by other variants
#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub union IcmpHdrUn {
    pub echo: IcmpHdrEcho,
    pub redirect: [u8; 4],
    pub dst_unreachable: IcmpHdrDstUnreachable,
    pub param_problem: IcmpHdrParamProblem,
    pub traceroute: IcmpHdrTraceroute,
    pub photuris: IcmpHdrPhoturis,
    pub reserved: [u8; 4],  // Generic 4-byte data, also for "Unused" fields
}

/// Represents Echo Request/Reply messages and other message types that share the same header format.
/// Used for ICMP Types:
/// - 0: Echo Reply
/// - 8: Echo Request
/// - 13: Timestamp Request
/// - 14: Timestamp Reply
/// - 15: Information Request (deprecated)
/// - 16: Information Reply (deprecated)
/// - 17: Address Mask Request (deprecated)
/// - 18: Address Mask Reply (deprecated)
/// - 37: Domain Name Request (deprecated)
/// - 38: Domain Name Reply (deprecated)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdrEcho {
    pub id: [u8; 2],
    pub sequence: [u8; 2],
}

/// For ICMP Type 3 "Destination Unreachable" Message (RFC 792) with support for PMTUD (RFC 1191)
/// Contains 2 unused bytes followed by a Next-Hop MTU field indicating the maximum transmission unit 
/// of the next-hop network on which fragmentation is required.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdrDstUnreachable {
    pub __unused: [u8; 2],
    pub mtu: [u8; 2],
}

/// For ICMP Type 12 "Parameter Problem" Message (RFC 792)
/// Contains a pointer to the byte in the original datagram that caused the error
/// and 3 bytes of unused padding to make the field a total of 4 bytes.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdrParamProblem {
    pub pointer: u8,
    pub __unused: [u8; 3], // To make up 4 bytes
}

/// For ICMP Type 40 (PHOTURIS) Message (RFC 2521)
/// Contains 2 "Reserved" bytes followed by the Security Parameters Index used 
/// for a security association between two peers. Also includes a 2-byte pointer 
/// field indicating where in the message the error was detected.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdrPhoturis {
    pub reserved_spi: [u8; 2],
    pub pointer: [u8; 2],
}

/// For ICMP Type 30 "Traceroute" Message (RFC 1393)
/// Contains a 16-bit ID Number field used by the source to match responses to outgoing requests
/// followed by 2 unused bytes to make a total of 4 bytes. The ID Number helps match Reply messages
/// (type 31) to their corresponding Requests.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdrTraceroute {
    pub id: [u8; 2],
    pub __unused: [u8; 2],
}

/// Represents the variable length portion of a Timestamp Request/Reply message (RFC 792)
/// that follows the ICMP header. 
///
/// Timestamps are milliseconds since midnight UT and are stored in network byte order.
///
/// # Example
/// ```
/// use core::mem;
/// use aya_ebpf::programs::TcContext;
/// use network_types::eth::EthHdr;
/// use network_types::icmp::{IcmpHdr, IcmpTimestampMsgPart};
/// use network_types::ip::Ipv4Hdr;
///
/// fn handle_icmp_timestamp(ctx: &TcContext) -> Result<u32, ()> {
///     // Parse the ICMP header from start of payload
///     let icmp_start = ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN;
///     let icmp: *const IcmpHdr = icmp_start as *const IcmpHdr;
///     
///     // Check if it's a Timestamp message (type 13 or 14)
///     if unsafe { (*icmp).type_ } == 13 || unsafe { (*icmp).type_ } == 14 {
///         // Access the timestamp part that follows the header
///         let timestamps: *const IcmpTimestampMsgPart = unsafe {
///             (icmp_start as *const u8)
///                 .add(IcmpHdr::LEN) as *const IcmpTimestampMsgPart
///         };
///
///         // Now you can read the timestamps in network byte order
///         let orig = timestamps.originate_timestamp();
///         let recv = timestamps.receive_timestamp();
///         let xmit = timestamps.transmit_timestamp();
///     }
///     Ok(0)
/// }
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpTimestampMsgPart {
    pub originate_timestamp: [u8; 4],
    pub receive_timestamp: [u8; 4],
    pub transmit_timestamp: [u8; 4],
}

impl IcmpTimestampMsgPart {
    pub const LEN: usize = mem::size_of::<IcmpTimestampMsgPart>();

    /// Returns the originate timestamp in host byte order (milliseconds since midnight UT)
    pub fn originate_timestamp(&self) -> u32 {
        u32::from_be_bytes(self.originate_timestamp)
    }

    /// Sets the originate timestamp field (milliseconds since midnight UT).
    /// The value will be stored in network byte order.
    pub fn set_originate_timestamp(&mut self, timestamp: u32) {
        self.originate_timestamp = timestamp.to_be_bytes();
    }

    /// Returns the receive timestamp in host byte order (milliseconds since midnight UT)
    pub fn receive_timestamp(&self) -> u32 {
        u32::from_be_bytes(self.receive_timestamp)
    }

    /// Sets the receive timestamp field (milliseconds since midnight UT).
    /// The value will be stored in network byte order.
    pub fn set_receive_timestamp(&mut self, timestamp: u32) {
        self.receive_timestamp = timestamp.to_be_bytes();
    }

    /// Returns the transmit timestamp in host byte order (milliseconds since midnight UT)
    pub fn transmit_timestamp(&self) -> u32 {
        u32::from_be_bytes(self.transmit_timestamp)
    }

    /// Sets the transmit timestamp field (milliseconds since midnight UT).
    /// The value will be stored in network byte order. 
    pub fn set_transmit_timestamp(&mut self, timestamp: u32) {
        self.transmit_timestamp = timestamp.to_be_bytes();
    }
}

/// Represents the variable length portion of a Traceroute message (RFC 1393)
/// that follows the ICMP header.
///
/// Contains hop counts, bandwidth, and MTU information about the traced route.
/// All fields are stored in network byte order.
///
/// # Example
/// ```
/// use core::mem;
/// use aya_ebpf::programs::TcContext;
/// use network_types::eth::EthHdr;
/// use network_types::icmp::{IcmpHdr, IcmpTracerouteMsgPart};
/// use network_types::ip::Ipv4Hdr;
///
/// fn handle_icmp_traceroute(ctx: &TcContext) -> Result<u32, ()> {
///     // Parse the ICMP header from start of payload 
///     let icmp_start = ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN;
///     let icmp: *const IcmpHdr = icmp_start as *const IcmpHdr;
///     
///     // Check if it's a Traceroute message (type 30)
///     if unsafe { (*icmp).type_ } == 30 {
///         // Access the traceroute part that follows the header
///         let traceroute: *const IcmpTracerouteMsgPart = unsafe {
///             (icmp_start as *const u8)
///                 .add(IcmpHdr::LEN) as *const IcmpTracerouteMsgPart
///         };
///
///         // Now you can read the traceroute fields in network byte order
///         let hops_out = traceroute.hops_out(); 
///         let bandwidth = traceroute.bandwidth_out();
///         let mtu = traceroute.mtu_out();
///     }
///     Ok(0)
/// }
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpTracerouteMsgPart {
    pub hops_out: [u8; 2],
    pub hops_in: [u8; 2],
    pub bandwidth_out: [u8; 4],
    pub mtu_out: [u8; 4],
}

impl IcmpTracerouteMsgPart {
    pub const LEN: usize = mem::size_of::<IcmpTracerouteMsgPart>();

    /// Returns the outbound hop count in host byte order.
    /// This indicates the maximum number of hops that can be traversed to the target.
    pub fn hops_out(&self) -> u16 {
        u16::from_be_bytes(self.hops_out)
    }

    /// Sets the outbound hop count field. The value will be stored in network byte order.
    /// This should be set to the maximum number of hops that can be traversed to the target.
    pub fn set_hops_out(&mut self, hops: u16) {
        self.hops_out = hops.to_be_bytes();
    }

    /// Returns the inbound hop count in host byte order.
    /// This indicates the maximum number of hops that can be traversed in the return path.
    pub fn hops_in(&self) -> u16 {
        u16::from_be_bytes(self.hops_in)
    }

    /// Sets the inbound hop count field. The value will be stored in network byte order.
    /// This should be set to the maximum number of hops that can be traversed in the return path.
    pub fn set_hops_in(&mut self, hops: u16) {
        self.hops_in = hops.to_be_bytes();
    }

    /// Returns the outbound bandwidth estimate in host byte order.
    /// This represents the minimum bandwidth along the forward path in bytes per second.
    pub fn bandwidth_out(&self) -> u32 {
        u32::from_be_bytes(self.bandwidth_out)
    }

    /// Sets the outbound bandwidth field. The value will be stored in network byte order.
    /// This should be set to the minimum bandwidth along the forward path in bytes per second.
    pub fn set_bandwidth_out(&mut self, bandwidth: u32) {
        self.bandwidth_out = bandwidth.to_be_bytes();
    }

    /// Returns the outbound MTU in host byte order.
    /// This represents the minimum MTU along the forward path in bytes.
    pub fn mtu_out(&self) -> u32 {
        u32::from_be_bytes(self.mtu_out)
    }

    /// Sets the outbound MTU field. The value will be stored in network byte order.
    /// This should be set to the minimum MTU along the forward path in bytes.
    pub fn set_mtu_out(&mut self, mtu: u32) {
        self.mtu_out = mtu.to_be_bytes();
    }
}

pub const ICMPV6_HDR_LEN: usize = mem::size_of::<Icmpv6Hdr>();

/// ICMPv6 Header structure (RFC 4443)
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Icmpv6Hdr {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub body: Icmpv6HdrBody, // For many common types, the first 4 bytes are used (e.g. echo, params)
}

impl Icmpv6Hdr {
    pub const LEN: usize = mem::size_of::<Icmpv6Hdr>();
}

/// Represents the body of an ICMPv6 message.
/// For Echo Request/Reply, this typically contains an identifier and sequence number.
/// For other types, it might be different or part of a larger variable-length message.
/// This union covers the first 4 bytes of the message body.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub union Icmpv6HdrBody {
    pub echo: Icmpv6HdrEcho,
    pub bytes: [u8; 4], // Generic access to the first 4 bytes of the body
}

impl core::fmt::Debug for Icmpv6HdrBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Safety: Accessing one variant of the union.
        // For simplicity, we'll print the 'bytes' representation.
        // You might want to make this more sophisticated based on the ICMPv6 type.
        f.debug_struct("Icmpv6HdrBody")
            .field("bytes", unsafe { &self.bytes })
            .finish()
    }
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Icmpv6HdrEcho {
    pub id: u16,
    pub sequence: u16,
}

// ICMPv6 Types (RFC 4443 and others)
// Error Messages
pub const ICMPV6_DEST_UNREACH: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_PARAM_PROB: u8 = 4;

// Informational Messages
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

// Neighbor Discovery Protocol (NDP) Messages (RFC 4861)
pub const ICMPV6_ROUTER_SOLICITATION: u8 = 133;
pub const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub const ICMPV6_REDIRECT_MESSAGE: u8 = 137;

