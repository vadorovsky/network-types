use core::mem;
use core::net;

use crate::getter_be;
use crate::setter_be;

/// An enum representing either an ICMPv4 or ICMPv6 header.
///
/// - `V4` contains an IPv4 ICMP header as defined in RFC 792 (see `Icmpv4Hdr`)
/// - `V6` contains an IPv6 ICMP header as defined in RFC 4443 (see `Icmpv6Hdr`)
///
/// This enum allows working with both ICMP protocol versions through a unified interface.
#[derive(Debug, Copy, Clone)]
pub enum Icmp {
    V4(Icmpv4Hdr),
    V6(Icmpv6Hdr),
}

/// An enum representing errors that can occur while processing ICMP headers.
///
/// # Variants
/// - `InvalidIcmpType`: Indicates an attempt to access a field with an incompatible ICMP message type.
///   For example, trying to access echo fields on a redirect message.
#[derive(Debug)]
pub enum IcmpError {
    InvalidIcmpType,
}

/// Represents an ICMP header as defined in RFC 792.
/// The header consists of a type and code field identifying the message type,
/// a checksum for error detection, and a data field whose format depends on the message type.
///
/// The `type_` field identifies the general category of message, such as:
/// - 0: Echo Reply
/// - 3: Destination Unreachable
/// - 5: Redirect
/// - 8: Echo Request
/// - 30: Traceroute
/// - 40: PHOTURIS
///
/// The `code` field provides additional context for the message type.
///
/// The `check` field contains a checksum calculated over the ICMP header and its payload.
///
/// The `data` field contains type-specific data such as echo identifiers/sequence numbers,
/// redirect gateway addresses, or pointers to errors in received packets.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Icmpv4Hdr {
    pub type_: u8,
    pub code: u8,
    pub check: [u8; 2],
    pub data: [u8; 4],
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Icmpv4Type {
    EchoReply = 0,
    DestinationUnreachable = 3,
    Redirect = 5,
    Echo = 8,
    ParameterProblem = 12,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
    Traceroute = 30,
    DomainNameRequest = 37,
    DomainNameReply = 38,
    Photuris = 40,
}

impl TryFrom<u8> for Icmpv4Type {
    type Error = IcmpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::EchoReply),
            3 => Ok(Self::DestinationUnreachable),
            5 => Ok(Self::Redirect),
            8 => Ok(Self::Echo),
            12 => Ok(Self::ParameterProblem),
            13 => Ok(Self::Timestamp),
            14 => Ok(Self::TimestampReply),
            15 => Ok(Self::InformationRequest),
            16 => Ok(Self::InformationReply),
            17 => Ok(Self::AddressMaskRequest),
            18 => Ok(Self::AddressMaskReply),
            30 => Ok(Self::Traceroute),
            37 => Ok(Self::DomainNameRequest),
            38 => Ok(Self::DomainNameReply),
            40 => Ok(Self::Photuris),
            _ => Err(Self::Error::InvalidIcmpType),
        }
    }
}

/// Strongly typed view of [`Icmpv4Hdr::data`].
#[derive(Debug, Copy, Clone)]
pub enum Icmpv4HdrData<'a> {
    EchoReply(&'a IcmpIdSequence),
    DestinationUnreachable(&'a IcmpDstUnreachable),
    Redirect(&'a Icmpv4Redirect),
    Echo(&'a IcmpIdSequence),
    ParameterProblem(&'a Icmpv4ParamProblem),
    Timestamp(&'a IcmpIdSequence),
    TimestampReply(&'a IcmpIdSequence),
    InformationRequest(&'a IcmpIdSequence),
    InformationReply(&'a IcmpIdSequence),
    AddressMaskRequest(&'a IcmpIdSequence),
    AddressMaskReply(&'a IcmpIdSequence),
    Traceroute(&'a IcmpTraceroute),
    DomainNameRequest(&'a IcmpIdSequence),
    DomainNameReply(&'a IcmpIdSequence),
    Photuris(&'a IcmpHdrPhoturis),
}

/// Mutable strongly typed view of [`Icmpv4Hdr::data`].
#[derive(Debug)]
pub enum Icmpv4HdrDataMut<'a> {
    EchoReply(&'a mut IcmpIdSequence),
    DestinationUnreachable(&'a mut IcmpDstUnreachable),
    Redirect(&'a mut Icmpv4Redirect),
    Echo(&'a mut IcmpIdSequence),
    ParameterProblem(&'a mut Icmpv4ParamProblem),
    Timestamp(&'a mut IcmpIdSequence),
    TimestampReply(&'a mut IcmpIdSequence),
    InformationRequest(&'a mut IcmpIdSequence),
    InformationReply(&'a mut IcmpIdSequence),
    AddressMaskRequest(&'a mut IcmpIdSequence),
    AddressMaskReply(&'a mut IcmpIdSequence),
    Traceroute(&'a mut IcmpTraceroute),
    DomainNameRequest(&'a mut IcmpIdSequence),
    DomainNameReply(&'a mut IcmpIdSequence),
    Photuris(&'a mut IcmpHdrPhoturis),
}

impl Icmpv4Hdr {
    pub const LEN: usize = mem::size_of::<Icmpv4Hdr>();

    #[inline]
    pub fn icmp_type(&self) -> Result<Icmpv4Type, IcmpError> {
        Icmpv4Type::try_from(self.type_)
    }

    /// Returns the ICMP header checksum value in host byte order.
    /// This field is used to detect data corruption in the ICMP header and payload.
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, check, u16) }
    }

    /// Sets the ICMP header checksum field to the given value.
    /// The checksum value should be calculated over the entire ICMP message (header and payload)
    /// according to RFC 792. The value will be stored in network byte order.
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, check, checksum) }
    }

    /// Returns a type-safe view over the `data` bytes based on the ICMPv4 type.
    #[inline]
    pub fn data(&self) -> Result<Icmpv4HdrData<'_>, IcmpError> {
        match self.icmp_type()? {
            Icmpv4Type::EchoReply => Ok(Icmpv4HdrData::EchoReply(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::DestinationUnreachable => {
                Ok(Icmpv4HdrData::DestinationUnreachable(unsafe {
                    self.destination_unreachable_unchecked()
                }))
            }
            Icmpv4Type::Redirect => Ok(Icmpv4HdrData::Redirect(unsafe {
                self.redirect_unchecked()
            })),
            Icmpv4Type::Echo => Ok(Icmpv4HdrData::Echo(unsafe { self.id_sequence_unchecked() })),
            Icmpv4Type::ParameterProblem => Ok(Icmpv4HdrData::ParameterProblem(unsafe {
                self.parameter_problem_unchecked()
            })),
            Icmpv4Type::Timestamp => Ok(Icmpv4HdrData::Timestamp(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::TimestampReply => Ok(Icmpv4HdrData::TimestampReply(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::InformationRequest => Ok(Icmpv4HdrData::InformationRequest(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::InformationReply => Ok(Icmpv4HdrData::InformationReply(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::AddressMaskRequest => Ok(Icmpv4HdrData::AddressMaskRequest(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::AddressMaskReply => Ok(Icmpv4HdrData::AddressMaskReply(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::Traceroute => Ok(Icmpv4HdrData::Traceroute(unsafe {
                self.traceroute_unchecked()
            })),
            Icmpv4Type::DomainNameRequest => Ok(Icmpv4HdrData::DomainNameRequest(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::DomainNameReply => Ok(Icmpv4HdrData::DomainNameReply(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv4Type::Photuris => Ok(Icmpv4HdrData::Photuris(unsafe {
                self.photuris_unchecked()
            })),
        }
    }

    /// Returns a mutable type-safe view over the `data` bytes based on the ICMPv4 type.
    #[inline]
    pub fn data_mut(&mut self) -> Result<Icmpv4HdrDataMut<'_>, IcmpError> {
        match self.icmp_type()? {
            Icmpv4Type::EchoReply => Ok(Icmpv4HdrDataMut::EchoReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::DestinationUnreachable => {
                Ok(Icmpv4HdrDataMut::DestinationUnreachable(unsafe {
                    self.destination_unreachable_mut_unchecked()
                }))
            }
            Icmpv4Type::Redirect => Ok(Icmpv4HdrDataMut::Redirect(unsafe {
                self.redirect_mut_unchecked()
            })),
            Icmpv4Type::Echo => Ok(Icmpv4HdrDataMut::Echo(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::ParameterProblem => Ok(Icmpv4HdrDataMut::ParameterProblem(unsafe {
                self.parameter_problem_mut_unchecked()
            })),
            Icmpv4Type::Timestamp => Ok(Icmpv4HdrDataMut::Timestamp(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::TimestampReply => Ok(Icmpv4HdrDataMut::TimestampReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::InformationRequest => Ok(Icmpv4HdrDataMut::InformationRequest(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::InformationReply => Ok(Icmpv4HdrDataMut::InformationReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::AddressMaskRequest => Ok(Icmpv4HdrDataMut::AddressMaskRequest(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::AddressMaskReply => Ok(Icmpv4HdrDataMut::AddressMaskReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::Traceroute => Ok(Icmpv4HdrDataMut::Traceroute(unsafe {
                self.traceroute_mut_unchecked()
            })),
            Icmpv4Type::DomainNameRequest => Ok(Icmpv4HdrDataMut::DomainNameRequest(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::DomainNameReply => Ok(Icmpv4HdrDataMut::DomainNameReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv4Type::Photuris => Ok(Icmpv4HdrDataMut::Photuris(unsafe {
                self.photuris_mut_unchecked()
            })),
        }
    }
}

/// These are the unsafe alternatives to the safe functions on `IcmpHdr` that do prevent undefined behavior.
impl Icmpv4Hdr {
    /// Returns a reference to the ID and sequence fields.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Calling this method with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    pub unsafe fn id_sequence_unchecked(&self) -> &IcmpIdSequence {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the ID and sequence fields.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Calling this method with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    pub unsafe fn id_sequence_mut_unchecked(&mut self) -> &mut IcmpIdSequence {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference to the Redirect message payload (Type 5).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 5 (Redirect) before calling this function.
    #[inline]
    pub unsafe fn redirect_unchecked(&self) -> &Icmpv4Redirect {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the Redirect message payload (Type 5).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 5 (Redirect) before calling this function.
    #[inline]
    pub unsafe fn redirect_mut_unchecked(&mut self) -> &mut Icmpv4Redirect {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference to the Destination Unreachable message.
    /// Used for Path MTU Discovery (RFC 1191).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 3 (Destination Unreachable) before calling this function.
    /// Accessing the dst_unreachable field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn destination_unreachable_unchecked(&self) -> &IcmpDstUnreachable {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the Destination Unreachable message.
    /// Used for Path MTU Discovery (RFC 1191).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 3 (Destination Unreachable) before calling this function.
    /// Accessing the dst_unreachable field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn destination_unreachable_mut_unchecked(&mut self) -> &mut IcmpDstUnreachable {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference to the Parameter Problem message (Type 12)
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 12 (Parameter Problem) before calling this function.
    /// Accessing the param_problem field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn parameter_problem_unchecked(&self) -> &Icmpv4ParamProblem {
        &*self.data.as_ptr().cast()
    }

    /// Returns a reference to the Parameter Problem message (Type 12)
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 12 (Parameter Problem) before calling this function.
    /// Accessing the param_problem field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn parameter_problem_mut_unchecked(&mut self) -> &mut Icmpv4ParamProblem {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference the Traceroute message (Type 30).
    /// This is only valid for ICMP Type 30 (Traceroute Request).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn traceroute_unchecked(&self) -> &IcmpTraceroute {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference the Traceroute message (Type 30).
    /// This is only valid for ICMP Type 30 (Traceroute Request).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn traceroute_mut_unchecked(&mut self) -> &mut IcmpTraceroute {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference to the PHOTURIS message (Type 40).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 40 (PHOTURIS) before calling this function.
    /// Accessing the photuris field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn photuris_unchecked(&self) -> &IcmpHdrPhoturis {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the PHOTURIS message (Type 40).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 40 (PHOTURIS) before calling this function.
    /// Accessing the photuris field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn photuris_mut_unchecked(&mut self) -> &mut IcmpHdrPhoturis {
        &mut *self.data.as_mut_ptr().cast()
    }
}

/// Represents the ID and sequence fields, used by the following ICMP Types:
///
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
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct IcmpIdSequence {
    pub id: [u8; 2],
    pub sequence: [u8; 2],
}

impl IcmpIdSequence {
    /// Returns the identification field from ICMP Echo/Timestamp/Info/Mask messages.
    #[inline]
    pub fn id(&self) -> u16 {
        unsafe { getter_be!(self, id, u16) }
    }

    /// Sets the identification field for ICMP Echo/Timestamp/Info/Mask messages.
    #[inline]
    pub fn set_id(&mut self, id: u16) {
        unsafe { setter_be!(self, id, id) }
    }

    /// Returns the sequence number from ICMP Echo/Timestamp/Info/Mask messages.
    #[inline]
    pub fn sequence(&self) -> u16 {
        unsafe { getter_be!(self, sequence, u16) }
    }

    /// Sets the sequence number for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    pub fn set_sequence(&mut self, sequence: u16) {
        unsafe { setter_be!(self, sequence, sequence) }
    }
}

/// Represents the payload of an ICMP Redirect message (Type 5).
/// The four bytes encode the gateway internet address in network byte order.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Icmpv4Redirect {
    gateway: [u8; 4],
}

impl Icmpv4Redirect {
    #[inline]
    pub fn gateway_address(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.gateway)
    }

    #[inline]
    pub fn set_gateway_address(&mut self, addr: net::Ipv4Addr) {
        self.gateway = addr.octets();
    }
}

/// For ICMP Type 3 "Destination Unreachable" Message (RFC 792) with support for PMTUD (RFC 1191)
/// Contains 2 unused bytes followed by a Next-Hop MTU field indicating the maximum transmission unit
/// of the next-hop network on which fragmentation is required.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct IcmpDstUnreachable {
    pub _unused: [u8; 2],
    pub mtu: [u8; 2],
}

impl IcmpDstUnreachable {
    /// Returns the Next-Hop MTU field from a Destination Unreachable message
    /// in host byte order. Used for Path MTU Discovery (RFC 1191).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 3 (Destination Unreachable) before calling this function.
    /// Accessing the dst_unreachable field with other ICMP types may result in undefined behavior.
    #[inline]
    pub fn mtu(&self) -> u16 {
        unsafe { getter_be!(self, mtu, u16) }
    }

    #[inline]
    pub fn set_mtu(&mut self, mtu: u16) {
        unsafe { setter_be!(self, mtu, mtu) }
    }
}

/// For ICMP Type 12 "Parameter Problem" Message (RFC 792)
/// Contains a pointer to the byte in the original datagram that caused the error
/// and 3 bytes of unused padding to make the field a total of 4 bytes.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Icmpv4ParamProblem {
    pub pointer: u8,
    pub _unused: [u8; 3], // To make up 4 bytes
}

impl Icmpv4ParamProblem {
    #[inline]
    pub fn pointer(&self) -> u8 {
        self.pointer
    }

    #[inline]
    pub fn set_pointer(&mut self, pointer: u8) {
        self.pointer = pointer;
    }
}

/// For ICMP Type 40 (PHOTURIS) Message (RFC 2521)
/// Contains 2 "Reserved" bytes followed by the Security Parameters Index used
/// for a security association between two peers. Also includes a 2-byte pointer
/// field indicating where in the message the error was detected.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct IcmpHdrPhoturis {
    pub reserved_spi: [u8; 2],
    pub pointer: [u8; 2],
}

impl IcmpHdrPhoturis {
    #[inline]
    pub fn reserved_spi(&self) -> u16 {
        unsafe { getter_be!(self, reserved_spi, u16) }
    }

    #[inline]
    pub fn set_reserved_spi(&mut self, spi: u16) {
        unsafe { setter_be!(self, reserved_spi, spi) }
    }

    #[inline]
    pub fn pointer(&self) -> u16 {
        unsafe { getter_be!(self, pointer, u16) }
    }

    #[inline]
    pub fn set_pointer(&mut self, pointer: u16) {
        unsafe { setter_be!(self, pointer, pointer) }
    }
}

/// For ICMP Type 30 "Traceroute" Message (RFC 1393)
/// Contains a 16-bit ID Number field used by the source to match responses to outgoing requests
/// followed by 2 unused bytes to make a total of 4 bytes.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct IcmpTraceroute {
    pub id: [u8; 2],
    pub _unused: [u8; 2],
}

impl IcmpTraceroute {
    /// Returns the ID Number field from a Traceroute message (Type 30).
    /// This is only valid for ICMP Type 30 (Traceroute Request).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    pub fn id(&self) -> u16 {
        unsafe { getter_be!(self, id, u16) }
    }

    /// Sets the ID Number field for a Traceroute message (Type 30).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    pub fn set_id(&mut self, id: u16) {
        unsafe { setter_be!(self, id, id) }
    }
}

/// Represents the variable length portion of a Timestamp Request/Reply message (RFC 792)
/// that follows the ICMP header.
///
/// Timestamps are milliseconds since midnight UT and are stored in network byte order.
///
/// # Example
/// ```no_run,rust,standalone_crate
/// use aya_ebpf::programs::TcContext;
/// use network_types::eth::EthHdr;
/// use network_types::icmp::{Icmpv4Hdr, IcmpError, Icmpv4HdrData, IcmpTimestampMsgPart};
/// use network_types::ip::Ipv4Hdr;
///
/// fn handle_icmp_timestamp(ctx: &TcContext) -> Result<u32, IcmpError> {
///     // Parse the ICMP header from start of payload
///     let icmp_start = ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN;
///     let icmp_hdr: *mut Icmpv4Hdr = icmp_start as *mut Icmpv4Hdr;
///
///     // Timestamp request/reply share the same echo layout; ensure the type matches
///     match unsafe { (*icmp_hdr).data()? } {
///         Icmpv4HdrData::Timestamp(id_seq)
///             | Icmpv4HdrData::TimestampReply(id_seq) => {
///             let timestamps_ptr_location = icmp_start + Icmpv4Hdr::LEN;
///             let timestamps: *const IcmpTimestampMsgPart =
///                 timestamps_ptr_location as *const IcmpTimestampMsgPart;
///
///             let _id = id_seq.id();
///             let _sequence = id_seq.sequence();
///             unsafe {
///                 let _orig = (*timestamps).originate_timestamp();
///                 let _recv = (*timestamps).receive_timestamp();
///                 let _xmit = (*timestamps).transmit_timestamp();
///                 // Use the timestamp fields as needed.
///             }
///         },
///         _ => {},
///     }
///     Ok(0)
/// }
/// ```
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct IcmpTimestampMsgPart {
    pub originate_timestamp: [u8; 4],
    pub receive_timestamp: [u8; 4],
    pub transmit_timestamp: [u8; 4],
}

impl IcmpTimestampMsgPart {
    pub const LEN: usize = mem::size_of::<IcmpTimestampMsgPart>();

    /// Returns the originate timestamp in host byte order (milliseconds since midnight UT)
    pub fn originate_timestamp(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, originate_timestamp, u32) }
    }

    /// Sets the originate timestamp field (milliseconds since midnight UT).
    /// The value will be stored in network byte order.
    pub fn set_originate_timestamp(&mut self, timestamp: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, originate_timestamp, timestamp) }
    }

    /// Returns the receive timestamp in host byte order (milliseconds since midnight UT)
    pub fn receive_timestamp(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, receive_timestamp, u32) }
    }

    /// Sets the receive timestamp field (milliseconds since midnight UT).
    /// The value will be stored in network byte order.
    pub fn set_receive_timestamp(&mut self, timestamp: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, receive_timestamp, timestamp) }
    }

    /// Returns the transmit timestamp in host byte order (milliseconds since midnight UT)
    pub fn transmit_timestamp(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, transmit_timestamp, u32) }
    }

    /// Sets the transmit timestamp field (milliseconds since midnight UT).
    /// The value will be stored in network byte order.
    pub fn set_transmit_timestamp(&mut self, timestamp: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, transmit_timestamp, timestamp) }
    }
}

/// Represents the variable length portion of a Traceroute message (RFC 1393)
/// that follows the ICMP header.
///
/// Contains hop counts, bandwidth, and MTU information about the traced route.
/// All fields are stored in network byte order.
///
/// # Example
/// ```no_run,rust,standalone_crate
/// use core::mem;
/// use aya_ebpf::programs::TcContext;
/// use network_types::eth::EthHdr;
/// use network_types::icmp::{Icmpv4Hdr, Icmpv4HdrData, IcmpTracerouteMsgPart};
/// use network_types::ip::Ipv4Hdr;
///
/// fn handle_icmp_traceroute(ctx: &TcContext) -> Result<u32, ()> {
///     // Parse the ICMP header from start of payload
///     let icmp_start = ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN;
///     let icmp_hdr: *mut Icmpv4Hdr = icmp_start as *mut Icmpv4Hdr;
///
///     // Check if it's a Traceroute Request/Reply message by matching on the safe enum.
///     if let Ok(Icmpv4HdrData::Traceroute(traceroute_hdr)) = unsafe { (*icmp_hdr).data() } {
///         // Access the traceroute-specific fields without repeating the type checks.
///         let traceroute_msg: *const IcmpTracerouteMsgPart = unsafe {
///             (icmp_start as *const u8)
///                 .add(Icmpv4Hdr::LEN) as *const IcmpTracerouteMsgPart
///         };
///
///         // Consume the traceroute fields in network byte order
///         let _id = traceroute_hdr.id();
///         unsafe {
///             let _hops_out = (*traceroute_msg).hops_out();
///             let _bandwidth = (*traceroute_msg).bandwidth_out();
///             let _mtu = (*traceroute_msg).mtu_out();
///             // Do something meaningful with these values here.
///         }
///     }
///     Ok(0)
/// }
/// ```
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
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
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, hops_out, u16) }
    }

    /// Sets the outbound hop count field. The value will be stored in network byte order.
    /// This should be set to the maximum number of hops that can be traversed to the target.
    pub fn set_hops_out(&mut self, hops: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, hops_out, hops) }
    }

    /// Returns the inbound hop count in host byte order.
    /// This indicates the maximum number of hops that can be traversed in the return path.
    pub fn hops_in(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, hops_in, u16) }
    }

    /// Sets the inbound hop count field. The value will be stored in network byte order.
    /// This should be set to the maximum number of hops that can be traversed in the return path.
    pub fn set_hops_in(&mut self, hops: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, hops_in, hops) }
    }

    /// Returns the outbound bandwidth estimate in host byte order.
    /// This represents the minimum bandwidth along the forward path in bytes per second.
    pub fn bandwidth_out(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, bandwidth_out, u32) }
    }

    /// Sets the outbound bandwidth field. The value will be stored in network byte order.
    /// This should be set to the minimum bandwidth along the forward path in bytes per second.
    pub fn set_bandwidth_out(&mut self, bandwidth: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, bandwidth_out, bandwidth) }
    }

    /// Returns the outbound MTU in host byte order.
    /// This represents the minimum MTU along the forward path in bytes.
    pub fn mtu_out(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, mtu_out, u32) }
    }

    /// Sets the outbound MTU field. The value will be stored in network byte order.
    /// This should be set to the minimum MTU along the forward path in bytes.
    pub fn set_mtu_out(&mut self, mtu: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, mtu_out, mtu) }
    }
}

/// Represents an ICMPv6 header as defined in RFC 4443.
/// The header consists of a type and code field identifying the message type,
/// a checksum for error detection, and a data field whose format depends on the message type.
///
/// The `type_` field identifies the general category of message, such as:
/// - 1: Destination Unreachable
/// - 2: Packet Too Big
/// - 3: Time Exceeded
/// - 4: Parameter Problem
/// - 128: Echo Request
/// - 129: Echo Reply
///
/// The `code` field provides additional context for the message type.
///
/// The `check` field contains a checksum calculated over an IPv6 pseudo-header,
/// the ICMPv6 header, and its payload.
///
/// The `data` field contains type-specific data such as echo identifiers/sequence numbers,
/// MTU values, or pointers to errors in received packets.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Icmpv6Hdr {
    pub type_: u8,
    pub code: u8,
    pub check: [u8; 2],
    pub data: [u8; 4],
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Icmpv6Type {
    PacketTooBig = 2,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RedirectMessage = 137,
}

impl TryFrom<u8> for Icmpv6Type {
    type Error = IcmpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::PacketTooBig),
            4 => Ok(Self::ParameterProblem),
            128 => Ok(Self::EchoRequest),
            129 => Ok(Self::EchoReply),
            137 => Ok(Self::RedirectMessage),
            _ => Err(Self::Error::InvalidIcmpType),
        }
    }
}

/// Strongly typed view of [`Icmpv6Hdr::data`].
#[derive(Debug)]
pub enum Icmpv6HdrData<'a> {
    PacketTooBig(&'a IcmpPacketTooBig),
    ParameterProblem(&'a Icmpv6ParamProblem),
    EchoRequest(&'a IcmpIdSequence),
    EchoReply(&'a IcmpIdSequence),
    RedirectMessage(&'a Icmpv6Redirect),
}

/// Mutable strongly typed view of [`Icmpv6Hdr::data`].
#[derive(Debug)]
pub enum Icmpv6HdrDataMut<'a> {
    PacketTooBig(&'a mut IcmpPacketTooBig),
    ParameterProblem(&'a mut Icmpv6ParamProblem),
    EchoRequest(&'a mut IcmpIdSequence),
    EchoReply(&'a mut IcmpIdSequence),
    RedirectMessage(&'a mut Icmpv6Redirect),
}

impl Icmpv6Hdr {
    pub const LEN: usize = mem::size_of::<Icmpv6Hdr>();

    #[inline]
    pub fn icmp_type(&self) -> Result<Icmpv6Type, IcmpError> {
        Icmpv6Type::try_from(self.type_)
    }

    /// Returns the ICMPv6 header checksum value in host byte order.
    /// This field is used to detect corruption in the ICMPv6 header and payload.
    pub fn checksum(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, check, u16) }
    }

    /// Sets the ICMPv6 header checksum field to the given value.
    /// The checksum value should be calculated over the pseudo-header, ICMPv6 header, and payload
    /// according to RFC 4443. The value will be stored in network byte order.
    pub fn set_checksum(&mut self, checksum: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, check, checksum) }
    }

    /// Returns a type-safe view over the `data` bytes based on the ICMPv6 type.
    #[inline]
    pub fn data(&self) -> Result<Icmpv6HdrData<'_>, IcmpError> {
        match self.icmp_type()? {
            Icmpv6Type::PacketTooBig => Ok(Icmpv6HdrData::PacketTooBig(unsafe {
                self.packet_too_big_unchecked()
            })),
            Icmpv6Type::ParameterProblem => Ok(Icmpv6HdrData::ParameterProblem(unsafe {
                self.parameter_problem_unchecked()
            })),
            Icmpv6Type::EchoRequest => Ok(Icmpv6HdrData::EchoRequest(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv6Type::EchoReply => Ok(Icmpv6HdrData::EchoReply(unsafe {
                self.id_sequence_unchecked()
            })),
            Icmpv6Type::RedirectMessage => Ok(Icmpv6HdrData::RedirectMessage(unsafe {
                self.redirect_unchecked()
            })),
        }
    }

    /// Returns a mutable type-safe view over the `data` bytes based on the ICMPv6 type.
    #[inline]
    pub fn data_mut(&mut self) -> Result<Icmpv6HdrDataMut<'_>, IcmpError> {
        match self.icmp_type()? {
            Icmpv6Type::PacketTooBig => Ok(Icmpv6HdrDataMut::PacketTooBig(unsafe {
                self.packet_too_big_mut_unchecked()
            })),
            Icmpv6Type::ParameterProblem => Ok(Icmpv6HdrDataMut::ParameterProblem(unsafe {
                self.parameter_problem_mut_unchecked()
            })),
            Icmpv6Type::EchoRequest => Ok(Icmpv6HdrDataMut::EchoRequest(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv6Type::EchoReply => Ok(Icmpv6HdrDataMut::EchoReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            Icmpv6Type::RedirectMessage => Ok(Icmpv6HdrDataMut::RedirectMessage(unsafe {
                self.redirect_mut_unchecked()
            })),
        }
    }
}

/// These are the unsafe alternatives to the safe functions on `Icmpv6Hdr` that do prevent undefined behavior.
impl Icmpv6Hdr {
    /// Returns a reference to the ID and sequence fields.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling
    /// this function. Accessing the fields with other ICMPv6 types may result in undefined
    /// behavior.
    #[inline]
    pub unsafe fn id_sequence_unchecked(&self) -> &IcmpIdSequence {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the ID and sequence fields.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling
    /// this function. Accessing the fields with other ICMPv6 types may result in undefined
    /// behavior.
    #[inline]
    pub unsafe fn id_sequence_mut_unchecked(&mut self) -> &mut IcmpIdSequence {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference to the Packet Too Big message (Type 2).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 2 (Packet Too Big) before calling.
    /// Accessing the fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn packet_too_big_unchecked(&self) -> &IcmpPacketTooBig {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the Packet Too Big message (Type 2).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 2 (Packet Too Big) before calling.
    /// Accessing the fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn packet_too_big_mut_unchecked(&mut self) -> &mut IcmpPacketTooBig {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference to the Parameter Problem message (Type 4).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 4 (Parameter Problem) before calling.
    /// Accessing the fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn parameter_problem_unchecked(&self) -> &Icmpv6ParamProblem {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the Parameter Problem message (Type 4).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 4 (Parameter Problem) before calling.
    /// Accessing the fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn parameter_problem_mut_unchecked(&mut self) -> &mut Icmpv6ParamProblem {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns a reference to the ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be initialized to zeros by the sender.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn redirect_unchecked(&self) -> &Icmpv6Redirect {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be initialized to zeros by the sender.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn redirect_mut_unchecked(&mut self) -> &mut Icmpv6Redirect {
        &mut *self.data.as_mut_ptr().cast()
    }
}

/// Represents the Packet Too Big message.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct IcmpPacketTooBig {
    mtu: [u8; 4],
}

impl IcmpPacketTooBig {
    #[inline]
    pub fn mtu(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, mtu, u32) }
    }

    #[inline]
    pub fn set_mtu(&mut self, mtu: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, mtu, mtu) }
    }
}

/// Represents the [Parameter Problem message for ICMPv6][parameter-problem-v6].
///
/// [parameter-problem-v6]: https://datatracker.ietf.org/doc/html/rfc4443#section-3.4
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Icmpv6ParamProblem {
    pub pointer: [u8; 4],
}

impl Icmpv6ParamProblem {
    #[inline]
    pub fn pointer(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { getter_be!(self, pointer, u32) }
    }

    #[inline]
    pub fn set_pointer(&mut self, pointer: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct.
        unsafe { setter_be!(self, pointer, pointer) }
    }
}

/// Represents the [Redirect message][redirect-v6].
///
/// [redirect-v6]: https://datatracker.ietf.org/doc/html/rfc4861#section-4.5
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Icmpv6Redirect {
    pub reserved: [u8; 4],
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    macro_rules! expect_data {
        ($hdr:expr, $enum:ident, $variant:ident) => {{
            match $hdr.data().expect("invalid ICMP message") {
                $enum::$variant(value) => value,
                _ => panic!("expected {} message", stringify!($variant)),
            }
        }};
    }

    macro_rules! expect_data_mut {
        ($hdr:expr, $enum:ident, $variant:ident) => {{
            match $hdr.data_mut().expect("invalid ICMP message") {
                $enum::$variant(value) => value,
                _ => panic!("expected {} message", stringify!($variant)),
            }
        }};
    }

    #[test]
    fn test_icmp_hdr_size() {
        // Icmpv4Hdr should be exactly 8 bytes: type(1) + code(1) + check(2) + data(4)
        assert_eq!(Icmpv4Hdr::LEN, 8);
        assert_eq!(Icmpv4Hdr::LEN, mem::size_of::<Icmpv4Hdr>());
    }

    // Helper function to create a default Icmpv4Hdr for testing
    fn create_test_icmp_hdr() -> Icmpv4Hdr {
        Icmpv4Hdr {
            type_: 0,
            code: 0,
            check: [0, 0],
            data: [0, 0, 0, 0],
        }
    }

    #[test]
    fn test_checksum() {
        let mut hdr = create_test_icmp_hdr();
        let test_checksum: u16 = 0x1234;

        // Convert test value to network byte order
        let bytes = test_checksum.to_be_bytes();
        hdr.check = bytes;

        // Check that getter properly converts from network to host byte order
        assert_eq!(hdr.checksum(), test_checksum);

        // Test setter
        hdr.set_checksum(0xABCD);
        assert_eq!(hdr.check, [0xAB, 0xCD]);
        assert_eq!(hdr.checksum(), 0xABCD);
    }

    #[test]
    fn test_echo_fields() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Echo Reply (0) which is valid for echo fields
        hdr.type_ = 0;

        // Test echo ID
        let test_id: u16 = 0x4321;
        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, EchoReply).set_id(test_id);
        assert_eq!(expect_data!(&hdr, Icmpv4HdrData, EchoReply).id(), test_id);

        // Verify byte order in raw storage
        assert_eq!(hdr.data[..2], test_id.to_be_bytes());

        // Test echo sequence
        let test_seq: u16 = 0x8765;
        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, EchoReply).set_sequence(test_seq);
        assert_eq!(
            expect_data!(&hdr, Icmpv4HdrData, EchoReply).sequence(),
            test_seq
        );

        // Verify byte order in raw storage
        assert_eq!(hdr.data[2..], test_seq.to_be_bytes());
    }

    #[test]
    fn test_gateway_address() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Redirect (5) which is valid for gateway address
        hdr.type_ = 5;
        let test_addr = Ipv4Addr::new(192, 168, 1, 1);

        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, Redirect).set_gateway_address(test_addr);
        assert_eq!(
            expect_data!(&hdr, Icmpv4HdrData, Redirect).gateway_address(),
            test_addr
        );

        // Verify the raw bytes
        assert_eq!(hdr.data, [192, 168, 1, 1]);
    }

    #[test]
    fn test_message_enum_echo() {
        let mut hdr = create_test_icmp_hdr();
        hdr.type_ = 8;

        match hdr.data_mut().expect("echo view") {
            Icmpv4HdrDataMut::Echo(echo) => {
                echo.set_id(0xABCD);
                echo.set_sequence(0x1234);
            }
            _ => panic!("unexpected variant"),
        }

        match hdr.data().expect("echo view") {
            Icmpv4HdrData::Echo(echo) => {
                assert_eq!(echo.id(), 0xABCD);
                assert_eq!(echo.sequence(), 0x1234);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_message_enum_invalid_type() {
        let hdr = Icmpv4Hdr {
            type_: 9,
            code: 0,
            check: [0, 0],
            data: [0, 0, 0, 0],
        };

        assert!(hdr.data().is_err());
    }

    #[test]
    fn test_next_hop_mtu() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Destination Unreachable (3) which is valid for next_hop_mtu
        hdr.type_ = 3;
        let test_mtu: u16 = 1500;

        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, DestinationUnreachable).set_mtu(test_mtu);
        assert_eq!(
            expect_data!(&hdr, Icmpv4HdrData, DestinationUnreachable).mtu(),
            test_mtu
        );

        // Verify byte order in raw storage
        assert_eq!(hdr.data[2..], test_mtu.to_be_bytes());
    }

    #[test]
    fn test_parameter_pointer() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Parameter Problem (12) which is valid for parameter_pointer
        hdr.type_ = 12;
        let test_pointer: u8 = 42;

        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, ParameterProblem).set_pointer(test_pointer);
        assert_eq!(
            expect_data!(&hdr, Icmpv4HdrData, ParameterProblem).pointer(),
            test_pointer
        );

        // Verify the raw byte
        assert_eq!(hdr.data[0], test_pointer);
    }

    #[test]
    fn test_traceroute_id() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Traceroute (30) which is valid for traceroute_id
        hdr.type_ = 30;
        let test_id: u16 = 0x9876;

        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, Traceroute).set_id(test_id);
        assert_eq!(expect_data!(&hdr, Icmpv4HdrData, Traceroute).id(), test_id);

        // Verify byte order in raw storage
        assert_eq!(hdr.data[..2], test_id.to_be_bytes());
    }

    #[test]
    fn test_photuris_spi() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to PHOTURIS (40) which is valid for photuris_spi
        hdr.type_ = 40;
        let test_spi: u16 = 0xFEDC;

        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, Photuris).set_reserved_spi(test_spi);
        assert_eq!(
            expect_data!(&hdr, Icmpv4HdrData, Photuris).reserved_spi(),
            test_spi
        );

        // Verify byte order in raw storage
        assert_eq!(hdr.data[..2], test_spi.to_be_bytes());
    }

    #[test]
    fn test_photuris_pointer() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to PHOTURIS (40) which is valid for photuris_pointer
        hdr.type_ = 40;
        let test_pointer: u16 = 0x1A2B;

        expect_data_mut!(&mut hdr, Icmpv4HdrDataMut, Photuris).set_pointer(test_pointer);
        assert_eq!(
            expect_data!(&hdr, Icmpv4HdrData, Photuris).pointer(),
            test_pointer
        );

        // Verify byte order in raw storage
        assert_eq!(hdr.data[2..], test_pointer.to_be_bytes());
    }

    #[test]
    fn test_type_and_code_fields() {
        let mut hdr = create_test_icmp_hdr();

        // Test common ICMP types and codes
        // Echo Request
        hdr.type_ = 8;
        hdr.code = 0;
        assert_eq!(hdr.type_, 8);
        assert_eq!(hdr.code, 0);

        // Destination Unreachable - Host Unreachable
        hdr.type_ = 3;
        hdr.code = 1;
        assert_eq!(hdr.type_, 3);
        assert_eq!(hdr.code, 1);
    }

    #[test]
    fn test_icmp_hdr_bitwise_operations() {
        // This test covers operations that might be common in packet processing
        let mut hdr = create_test_icmp_hdr();

        // Set a sample checksum
        hdr.set_checksum(0x1234);

        // Modify the checksum using bit operations
        let modified_checksum = hdr.checksum() ^ 0xFFFF; // Bitwise NOT
        hdr.set_checksum(modified_checksum);

        assert_eq!(hdr.checksum(), 0xEDCB); // 0x1234 XOR 0xFFFF = 0xEDCB
    }

    #[test]
    fn test_icmp_common_type_constants() {
        // This test verifies common ICMP type handling
        let mut hdr = create_test_icmp_hdr();

        // Echo Request
        hdr.type_ = 8;
        assert_eq!(hdr.type_, 8);

        // Echo Reply
        hdr.type_ = 0;
        assert_eq!(hdr.type_, 0);

        // Destination Unreachable
        hdr.type_ = 3;
        assert_eq!(hdr.type_, 3);

        // Redirect
        hdr.type_ = 5;
        assert_eq!(hdr.type_, 5);
    }

    #[test]
    fn test_icmp_timestamp_msg_part_size() {
        // IcmpTimestampMsgPart should be exactly 12 bytes: 3 timestamps of 4 bytes each
        assert_eq!(IcmpTimestampMsgPart::LEN, 12);
        assert_eq!(
            IcmpTimestampMsgPart::LEN,
            mem::size_of::<IcmpTimestampMsgPart>()
        );
    }

    #[test]
    fn test_timestamp_originate() {
        let mut timestamp_part = IcmpTimestampMsgPart {
            originate_timestamp: [0, 0, 0, 0],
            receive_timestamp: [0, 0, 0, 0],
            transmit_timestamp: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_timestamp: u32 = 0x12345678;
        timestamp_part.set_originate_timestamp(test_timestamp);
        assert_eq!(timestamp_part.originate_timestamp(), test_timestamp);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(timestamp_part.originate_timestamp, [0x12, 0x34, 0x56, 0x78]);

        // Test with zero
        timestamp_part.set_originate_timestamp(0);
        assert_eq!(timestamp_part.originate_timestamp(), 0);
        assert_eq!(timestamp_part.originate_timestamp, [0, 0, 0, 0]);

        // Test with max value
        timestamp_part.set_originate_timestamp(u32::MAX);
        assert_eq!(timestamp_part.originate_timestamp(), u32::MAX);
        assert_eq!(timestamp_part.originate_timestamp, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_timestamp_receive() {
        let mut timestamp_part = IcmpTimestampMsgPart {
            originate_timestamp: [0, 0, 0, 0],
            receive_timestamp: [0, 0, 0, 0],
            transmit_timestamp: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_timestamp: u32 = 0x87654321;
        timestamp_part.set_receive_timestamp(test_timestamp);
        assert_eq!(timestamp_part.receive_timestamp(), test_timestamp);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(timestamp_part.receive_timestamp, [0x87, 0x65, 0x43, 0x21]);

        // Test with zero
        timestamp_part.set_receive_timestamp(0);
        assert_eq!(timestamp_part.receive_timestamp(), 0);
        assert_eq!(timestamp_part.receive_timestamp, [0, 0, 0, 0]);

        // Test with max value
        timestamp_part.set_receive_timestamp(u32::MAX);
        assert_eq!(timestamp_part.receive_timestamp(), u32::MAX);
        assert_eq!(timestamp_part.receive_timestamp, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_timestamp_transmit() {
        let mut timestamp_part = IcmpTimestampMsgPart {
            originate_timestamp: [0, 0, 0, 0],
            receive_timestamp: [0, 0, 0, 0],
            transmit_timestamp: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_timestamp: u32 = 0xABCDEF01;
        timestamp_part.set_transmit_timestamp(test_timestamp);
        assert_eq!(timestamp_part.transmit_timestamp(), test_timestamp);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(timestamp_part.transmit_timestamp, [0xAB, 0xCD, 0xEF, 0x01]);

        // Test with zero
        timestamp_part.set_transmit_timestamp(0);
        assert_eq!(timestamp_part.transmit_timestamp(), 0);
        assert_eq!(timestamp_part.transmit_timestamp, [0, 0, 0, 0]);

        // Test with max value
        timestamp_part.set_transmit_timestamp(u32::MAX);
        assert_eq!(timestamp_part.transmit_timestamp(), u32::MAX);
        assert_eq!(timestamp_part.transmit_timestamp, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_timestamp_msg_part_construction() {
        // Test creating a complete timestamp message part
        let mut timestamp_part = IcmpTimestampMsgPart {
            originate_timestamp: [0, 0, 0, 0],
            receive_timestamp: [0, 0, 0, 0],
            transmit_timestamp: [0, 0, 0, 0],
        };

        // Set all three timestamps
        timestamp_part.set_originate_timestamp(0x11223344);
        timestamp_part.set_receive_timestamp(0x55667788);
        timestamp_part.set_transmit_timestamp(0x99AABBCC);

        // Verify all values are correctly set and retrieved
        assert_eq!(timestamp_part.originate_timestamp(), 0x11223344);
        assert_eq!(timestamp_part.receive_timestamp(), 0x55667788);
        assert_eq!(timestamp_part.transmit_timestamp(), 0x99AABBCC);

        // Verify raw byte storage
        assert_eq!(timestamp_part.originate_timestamp, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(timestamp_part.receive_timestamp, [0x55, 0x66, 0x77, 0x88]);
        assert_eq!(timestamp_part.transmit_timestamp, [0x99, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_icmp_traceroute_msg_part_size() {
        // IcmpTracerouteMsgPart should be exactly 12 bytes: hops_out(2) + hops_in(2) + bandwidth_out(4) + mtu_out(4)
        assert_eq!(IcmpTracerouteMsgPart::LEN, 12);
        assert_eq!(
            IcmpTracerouteMsgPart::LEN,
            mem::size_of::<IcmpTracerouteMsgPart>()
        );
    }

    #[test]
    fn test_traceroute_hops_out() {
        let mut traceroute_part = IcmpTracerouteMsgPart {
            hops_out: [0, 0],
            hops_in: [0, 0],
            bandwidth_out: [0, 0, 0, 0],
            mtu_out: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_hops: u16 = 0x1234;
        traceroute_part.set_hops_out(test_hops);
        assert_eq!(traceroute_part.hops_out(), test_hops);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(traceroute_part.hops_out, [0x12, 0x34]);

        // Test with zero
        traceroute_part.set_hops_out(0);
        assert_eq!(traceroute_part.hops_out(), 0);
        assert_eq!(traceroute_part.hops_out, [0, 0]);

        // Test with max value
        traceroute_part.set_hops_out(u16::MAX);
        assert_eq!(traceroute_part.hops_out(), u16::MAX);
        assert_eq!(traceroute_part.hops_out, [0xFF, 0xFF]);
    }

    #[test]
    fn test_traceroute_hops_in() {
        let mut traceroute_part = IcmpTracerouteMsgPart {
            hops_out: [0, 0],
            hops_in: [0, 0],
            bandwidth_out: [0, 0, 0, 0],
            mtu_out: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_hops: u16 = 0x5678;
        traceroute_part.set_hops_in(test_hops);
        assert_eq!(traceroute_part.hops_in(), test_hops);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(traceroute_part.hops_in, [0x56, 0x78]);

        // Test with zero
        traceroute_part.set_hops_in(0);
        assert_eq!(traceroute_part.hops_in(), 0);
        assert_eq!(traceroute_part.hops_in, [0, 0]);

        // Test with max value
        traceroute_part.set_hops_in(u16::MAX);
        assert_eq!(traceroute_part.hops_in(), u16::MAX);
        assert_eq!(traceroute_part.hops_in, [0xFF, 0xFF]);
    }

    #[test]
    fn test_traceroute_bandwidth_out() {
        let mut traceroute_part = IcmpTracerouteMsgPart {
            hops_out: [0, 0],
            hops_in: [0, 0],
            bandwidth_out: [0, 0, 0, 0],
            mtu_out: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_bandwidth: u32 = 0x12345678;
        traceroute_part.set_bandwidth_out(test_bandwidth);
        assert_eq!(traceroute_part.bandwidth_out(), test_bandwidth);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(traceroute_part.bandwidth_out, [0x12, 0x34, 0x56, 0x78]);

        // Test with zero
        traceroute_part.set_bandwidth_out(0);
        assert_eq!(traceroute_part.bandwidth_out(), 0);
        assert_eq!(traceroute_part.bandwidth_out, [0, 0, 0, 0]);

        // Test with max value
        traceroute_part.set_bandwidth_out(u32::MAX);
        assert_eq!(traceroute_part.bandwidth_out(), u32::MAX);
        assert_eq!(traceroute_part.bandwidth_out, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_traceroute_mtu_out() {
        let mut traceroute_part = IcmpTracerouteMsgPart {
            hops_out: [0, 0],
            hops_in: [0, 0],
            bandwidth_out: [0, 0, 0, 0],
            mtu_out: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_mtu: u32 = 0x87654321;
        traceroute_part.set_mtu_out(test_mtu);
        assert_eq!(traceroute_part.mtu_out(), test_mtu);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(traceroute_part.mtu_out, [0x87, 0x65, 0x43, 0x21]);

        // Test with zero
        traceroute_part.set_mtu_out(0);
        assert_eq!(traceroute_part.mtu_out(), 0);
        assert_eq!(traceroute_part.mtu_out, [0, 0, 0, 0]);

        // Test with max value
        traceroute_part.set_mtu_out(u32::MAX);
        assert_eq!(traceroute_part.mtu_out(), u32::MAX);
        assert_eq!(traceroute_part.mtu_out, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_traceroute_msg_part_construction() {
        // Test creating a complete traceroute message part
        let mut traceroute_part = IcmpTracerouteMsgPart {
            hops_out: [0, 0],
            hops_in: [0, 0],
            bandwidth_out: [0, 0, 0, 0],
            mtu_out: [0, 0, 0, 0],
        };

        // Set all fields
        traceroute_part.set_hops_out(30);
        traceroute_part.set_hops_in(25);
        traceroute_part.set_bandwidth_out(100000000); // 100 Mbps
        traceroute_part.set_mtu_out(1500);

        // Verify all values are correctly set and retrieved
        assert_eq!(traceroute_part.hops_out(), 30);
        assert_eq!(traceroute_part.hops_in(), 25);
        assert_eq!(traceroute_part.bandwidth_out(), 100000000);
        assert_eq!(traceroute_part.mtu_out(), 1500);

        // Verify raw byte storage
        assert_eq!(traceroute_part.hops_out, [0, 30]);
        assert_eq!(traceroute_part.hops_in, [0, 25]);
        assert_eq!(traceroute_part.bandwidth_out, [0x05, 0xF5, 0xE1, 0x00]); // 100000000 in hex
        assert_eq!(traceroute_part.mtu_out, [0, 0, 0x05, 0xDC]); // 1500 in hex
    }

    #[test]
    fn test_icmpv6_hdr_size() {
        // IcmpV6Hdr is the base header: type(1) + code(1) + check(2) + data(4)
        assert_eq!(Icmpv6Hdr::LEN, 8);
        assert_eq!(Icmpv6Hdr::LEN, mem::size_of::<Icmpv6Hdr>());
    }

    // Helper function to create a default IcmpV6Hdr for testing
    fn create_test_icmpv6_hdr() -> Icmpv6Hdr {
        Icmpv6Hdr {
            type_: 0,
            code: 0,
            check: [0, 0],
            data: [0, 0, 0, 0],
        }
    }

    #[test]
    fn test_icmpv6_checksum() {
        let mut hdr = create_test_icmpv6_hdr();
        let test_checksum: u16 = 0x1234;

        // Convert test value to network byte order
        let bytes = test_checksum.to_be_bytes();
        hdr.check = bytes;

        // Check that getter properly converts from network to host byte order
        assert_eq!(hdr.checksum(), test_checksum);

        // Test setter
        hdr.set_checksum(0xABCD);
        assert_eq!(hdr.check, [0xAB, 0xCD]);
        assert_eq!(hdr.checksum(), 0xABCD);
    }

    #[test]
    fn test_icmpv6_echo_fields() {
        let mut hdr = create_test_icmpv6_hdr();
        // Set type to Echo Request (128) which is valid for echo fields
        hdr.type_ = 128;

        // Test echo ID
        let test_id: u16 = 0x4321;
        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, EchoRequest).set_id(test_id);
        assert_eq!(expect_data!(&hdr, Icmpv6HdrData, EchoRequest).id(), test_id);

        // Verify byte order in raw storage
        let test_id_bytes = test_id.to_be_bytes();
        assert_eq!(&hdr.data[..2], &test_id_bytes);

        // Test echo sequence
        let test_seq: u16 = 0x8765;
        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, EchoRequest).set_sequence(test_seq);
        assert_eq!(
            expect_data!(&hdr, Icmpv6HdrData, EchoRequest).sequence(),
            test_seq
        );

        // Verify byte order in raw storage
        let test_seq_bytes = test_seq.to_be_bytes();
        assert_eq!(&hdr.data[2..], &test_seq_bytes);
    }

    #[test]
    fn test_icmpv6_mtu() {
        let mut hdr = create_test_icmpv6_hdr();
        // Set type to Packet Too Big (2) which is valid for mtu
        hdr.type_ = 2;
        let test_mtu: u32 = 0x12345678;

        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, PacketTooBig).set_mtu(test_mtu);
        assert_eq!(
            expect_data!(&hdr, Icmpv6HdrData, PacketTooBig).mtu(),
            test_mtu
        );

        // Verify byte order in raw storage
        assert_eq!(hdr.data, test_mtu.to_be_bytes());

        // Test with zero
        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, PacketTooBig).set_mtu(0);
        assert_eq!(expect_data!(&hdr, Icmpv6HdrData, PacketTooBig).mtu(), 0);
        assert_eq!(hdr.data, [0, 0, 0, 0]);

        // Test with max value
        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, PacketTooBig).set_mtu(u32::MAX);
        assert_eq!(
            expect_data!(&hdr, Icmpv6HdrData, PacketTooBig).mtu(),
            u32::MAX
        );
        assert_eq!(hdr.data, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_icmpv6_pointer() {
        let mut hdr = create_test_icmpv6_hdr();
        // Set type to Parameter Problem (4) which is valid for pointer
        hdr.type_ = 4;
        let test_pointer: u32 = 0x87654321;

        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, ParameterProblem).set_pointer(test_pointer);
        assert_eq!(
            expect_data!(&hdr, Icmpv6HdrData, ParameterProblem).pointer(),
            test_pointer
        );

        // Verify byte order in raw storage
        assert_eq!(hdr.data, test_pointer.to_be_bytes());

        // Test with zero
        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, ParameterProblem).set_pointer(0);
        assert_eq!(
            expect_data!(&hdr, Icmpv6HdrData, ParameterProblem).pointer(),
            0
        );
        assert_eq!(hdr.data, [0, 0, 0, 0]);

        // Test with max value
        expect_data_mut!(&mut hdr, Icmpv6HdrDataMut, ParameterProblem).set_pointer(u32::MAX);
        assert_eq!(
            expect_data!(&hdr, Icmpv6HdrData, ParameterProblem).pointer(),
            u32::MAX
        );
        assert_eq!(hdr.data, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_icmpv6_type_and_code_fields() {
        let mut hdr = create_test_icmpv6_hdr();

        // Test common ICMPv6 types and codes
        // Echo Request
        hdr.type_ = 128;
        hdr.code = 0;
        assert_eq!(hdr.type_, 128);
        assert_eq!(hdr.code, 0);

        // Echo Reply
        hdr.type_ = 129;
        hdr.code = 0;
        assert_eq!(hdr.type_, 129);
        assert_eq!(hdr.code, 0);

        // Destination Unreachable - No route to destination
        hdr.type_ = 1;
        hdr.code = 0;
        assert_eq!(hdr.type_, 1);
        assert_eq!(hdr.code, 0);

        // Packet Too Big
        hdr.type_ = 2;
        hdr.code = 0;
        assert_eq!(hdr.type_, 2);
        assert_eq!(hdr.code, 0);

        // Time Exceeded - Hop limit exceeded in transit
        hdr.type_ = 3;
        hdr.code = 0;
        assert_eq!(hdr.type_, 3);
        assert_eq!(hdr.code, 0);

        // Parameter Problem - Erroneous header field encountered
        hdr.type_ = 4;
        hdr.code = 0;
        assert_eq!(hdr.type_, 4);
        assert_eq!(hdr.code, 0);
    }
}

#[cfg(all(test, feature = "wincode"))]
mod wincode_prop_tests {
    use super::*;
    use proptest::array::{uniform2, uniform4};
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;
    use wincode::{SchemaRead, SchemaWrite, config::DefaultConfig};

    const MAX_PACKET_SIZE: usize = Icmpv6Hdr::LEN;

    trait FixedPacket {
        const SERIALIZED_LEN: usize;
    }

    impl FixedPacket for Icmpv4Hdr {
        const SERIALIZED_LEN: usize = Icmpv4Hdr::LEN;
    }

    impl FixedPacket for Icmpv6Hdr {
        const SERIALIZED_LEN: usize = Icmpv6Hdr::LEN;
    }

    fn round_trip<T>(value: &T) -> T
    where
        T: SchemaWrite<DefaultConfig, Src = T>,
        for<'de> T: SchemaRead<'de, DefaultConfig, Dst = T>,
        T: FixedPacket,
    {
        let mut bytes = [0u8; MAX_PACKET_SIZE];
        let len = T::SERIALIZED_LEN;
        assert!(len <= bytes.len());
        wincode::serialize_into(&mut bytes.as_mut_slice(), value).unwrap();
        wincode::deserialize(&bytes).unwrap()
    }

    fn icmp_hdr_strategy() -> impl Strategy<Value = Icmpv4Hdr> {
        (
            any::<u8>(),
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform4(any::<u8>()),
        )
            .prop_map(|(type_, code, check, data)| Icmpv4Hdr {
                type_,
                code,
                check,
                data,
            })
    }

    fn echo_bytes(id: [u8; 2], seq: [u8; 2]) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[..2].copy_from_slice(&id);
        bytes[2..].copy_from_slice(&seq);
        bytes
    }

    fn icmpv6_hdr_strategy() -> impl Strategy<Value = Icmpv6Hdr> {
        let echo = (
            Just(128u8),
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform2(any::<u8>()),
            uniform2(any::<u8>()),
        )
            .prop_map(|(type_, code, check, id, seq)| Icmpv6Hdr {
                type_,
                code,
                check,
                data: echo_bytes(id, seq),
            });

        let echo_reply = (
            Just(129u8),
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform2(any::<u8>()),
            uniform2(any::<u8>()),
        )
            .prop_map(|(type_, code, check, id, seq)| Icmpv6Hdr {
                type_,
                code,
                check,
                data: echo_bytes(id, seq),
            });

        let packet_too_big = (
            Just(2u8),
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform4(any::<u8>()),
        )
            .prop_map(|(type_, code, check, bytes)| Icmpv6Hdr {
                type_,
                code,
                check,
                data: bytes,
            });

        let param_problem = (
            Just(4u8),
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform4(any::<u8>()),
        )
            .prop_map(|(type_, code, check, bytes)| Icmpv6Hdr {
                type_,
                code,
                check,
                data: bytes,
            });

        let redirect = (
            Just(137u8),
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform4(any::<u8>()),
        )
            .prop_map(|(type_, code, check, reserved)| Icmpv6Hdr {
                type_,
                code,
                check,
                data: reserved,
            });

        let fallback = (
            any::<u8>().prop_filter("use reserved field", |ty| {
                !matches!(ty, 128 | 129 | 2 | 4 | 137)
            }),
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform4(any::<u8>()),
        )
            .prop_map(|(type_, code, check, bytes)| Icmpv6Hdr {
                type_,
                code,
                check,
                data: bytes,
            });

        prop_oneof![
            echo,
            echo_reply,
            packet_too_big,
            param_problem,
            redirect,
            fallback
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn icmp_hdr_round_trips(hdr in icmp_hdr_strategy()) {
            let decoded = round_trip(&hdr);
            prop_assert_eq!(decoded.type_, hdr.type_);
            prop_assert_eq!(decoded.code, hdr.code);
            prop_assert_eq!(decoded.check, hdr.check);
            prop_assert_eq!(decoded.data, hdr.data);
        }

        #[test]
        fn icmpv6_hdr_round_trips(hdr in icmpv6_hdr_strategy()) {
            let decoded = round_trip(&hdr);
            prop_assert_eq!(decoded.type_, hdr.type_);
            prop_assert_eq!(decoded.code, hdr.code);
            prop_assert_eq!(decoded.check, hdr.check);
            prop_assert_eq!(decoded.data, hdr.data);
        }
    }
}
