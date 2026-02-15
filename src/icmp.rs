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

/// Strongly typed view of [`Icmpv4Hdr::data`] and [`Icmpv6Hdr::data`].
#[derive(Debug, Copy, Clone)]
pub enum IcmpHdrMessage<'a> {
    EchoReply(&'a IcmpIdSequence),
    DestinationUnreachable(&'a IcmpDstUnreachable),
    Redirect(&'a IcmpRedirect),
    Echo(&'a IcmpIdSequence),
    ParameterProblem(&'a IcmpParamProblem),
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

/// Mutable strongly typed view of [`Icmpv4Hdr::data`] and [`Icmpv6Hdr::Data`].
#[derive(Debug)]
pub enum IcmpHdrMessageMut<'a> {
    EchoReply(&'a mut IcmpIdSequence),
    DestinationUnreachable(&'a mut IcmpDstUnreachable),
    Redirect(&'a mut IcmpRedirect),
    Echo(&'a mut IcmpIdSequence),
    ParameterProblem(&'a mut IcmpParamProblem),
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

#[derive(Clone, Copy)]
enum IcmpMessageKind {
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

impl Icmpv4Hdr {
    pub const LEN: usize = mem::size_of::<Icmpv4Hdr>();

    #[inline]
    fn message_kind(&self) -> Result<IcmpMessageKind, IcmpError> {
        match self.type_ {
            0 => Ok(IcmpMessageKind::EchoReply),
            3 => Ok(IcmpMessageKind::DestinationUnreachable),
            5 => Ok(IcmpMessageKind::Redirect),
            8 => Ok(IcmpMessageKind::Echo),
            12 => Ok(IcmpMessageKind::ParameterProblem),
            13 => Ok(IcmpMessageKind::Timestamp),
            14 => Ok(IcmpMessageKind::TimestampReply),
            15 => Ok(IcmpMessageKind::InformationRequest),
            16 => Ok(IcmpMessageKind::InformationReply),
            17 => Ok(IcmpMessageKind::AddressMaskRequest),
            18 => Ok(IcmpMessageKind::AddressMaskReply),
            30 => Ok(IcmpMessageKind::Traceroute),
            37 => Ok(IcmpMessageKind::DomainNameRequest),
            38 => Ok(IcmpMessageKind::DomainNameReply),
            40 => Ok(IcmpMessageKind::Photuris),
            _ => Err(IcmpError::InvalidIcmpType),
        }
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

    /// Returns a type-safe view over the `data` bytes based on the message type.
    /// Consumers can match on the returned enum once and reuse the borrowed view.
    #[inline]
    pub fn message(&self) -> Result<IcmpHdrMessage<'_>, IcmpError> {
        match self.message_kind()? {
            IcmpMessageKind::EchoReply => Ok(IcmpHdrMessage::EchoReply(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::DestinationUnreachable => {
                Ok(IcmpHdrMessage::DestinationUnreachable(unsafe {
                    self.destination_unreachable_unchecked()
                }))
            }
            IcmpMessageKind::Redirect => Ok(IcmpHdrMessage::Redirect(unsafe {
                self.redirect_unchecked()
            })),
            IcmpMessageKind::Echo => Ok(IcmpHdrMessage::Echo(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::ParameterProblem => Ok(IcmpHdrMessage::ParameterProblem(unsafe {
                self.parameter_problem_unchecked()
            })),
            IcmpMessageKind::Timestamp => Ok(IcmpHdrMessage::Timestamp(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::TimestampReply => Ok(IcmpHdrMessage::TimestampReply(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::InformationRequest => Ok(IcmpHdrMessage::InformationRequest(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::InformationReply => Ok(IcmpHdrMessage::InformationReply(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::AddressMaskRequest => Ok(IcmpHdrMessage::AddressMaskRequest(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::AddressMaskReply => Ok(IcmpHdrMessage::AddressMaskReply(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::Traceroute => Ok(IcmpHdrMessage::Traceroute(unsafe {
                self.traceroute_unchecked()
            })),
            IcmpMessageKind::DomainNameRequest => Ok(IcmpHdrMessage::DomainNameRequest(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::DomainNameReply => Ok(IcmpHdrMessage::DomainNameReply(unsafe {
                self.id_sequence_unchecked()
            })),
            IcmpMessageKind::Photuris => Ok(IcmpHdrMessage::Photuris(unsafe {
                self.photuris_unchecked()
            })),
        }
    }

    /// Returns a mutable type-safe view over the `data` bytes based on the message type.
    /// Only the specific variant matching the header's type will be returned.
    #[inline]
    pub fn message_mut(&mut self) -> Result<IcmpHdrMessageMut<'_>, IcmpError> {
        match self.message_kind()? {
            IcmpMessageKind::EchoReply => Ok(IcmpHdrMessageMut::EchoReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            IcmpMessageKind::DestinationUnreachable => {
                Ok(IcmpHdrMessageMut::DestinationUnreachable(unsafe {
                    self.destination_unreachable_mut_unchecked()
                }))
            }
            IcmpMessageKind::Redirect => Ok(IcmpHdrMessageMut::Redirect(unsafe {
                self.redirect_mut_unchecked()
            })),
            IcmpMessageKind::Echo => Ok(IcmpHdrMessageMut::Echo(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            IcmpMessageKind::ParameterProblem => Ok(IcmpHdrMessageMut::ParameterProblem(unsafe {
                self.parameter_problem_mut_unchecked()
            })),
            IcmpMessageKind::Timestamp => Ok(IcmpHdrMessageMut::Timestamp(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            IcmpMessageKind::TimestampReply => Ok(IcmpHdrMessageMut::TimestampReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            IcmpMessageKind::InformationRequest => {
                Ok(IcmpHdrMessageMut::InformationRequest(unsafe {
                    self.id_sequence_mut_unchecked()
                }))
            }
            IcmpMessageKind::InformationReply => Ok(IcmpHdrMessageMut::InformationReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            IcmpMessageKind::AddressMaskRequest => {
                Ok(IcmpHdrMessageMut::AddressMaskRequest(unsafe {
                    self.id_sequence_mut_unchecked()
                }))
            }
            IcmpMessageKind::AddressMaskReply => Ok(IcmpHdrMessageMut::AddressMaskReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            IcmpMessageKind::Traceroute => Ok(IcmpHdrMessageMut::Traceroute(unsafe {
                self.traceroute_mut_unchecked()
            })),
            IcmpMessageKind::DomainNameRequest => {
                Ok(IcmpHdrMessageMut::DomainNameRequest(unsafe {
                    self.id_sequence_mut_unchecked()
                }))
            }
            IcmpMessageKind::DomainNameReply => Ok(IcmpHdrMessageMut::DomainNameReply(unsafe {
                self.id_sequence_mut_unchecked()
            })),
            IcmpMessageKind::Photuris => Ok(IcmpHdrMessageMut::Photuris(unsafe {
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
    pub unsafe fn redirect_unchecked(&self) -> &IcmpRedirect {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the Redirect message payload (Type 5).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 5 (Redirect) before calling this function.
    #[inline]
    pub unsafe fn redirect_mut_unchecked(&mut self) -> &mut IcmpRedirect {
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
    pub unsafe fn parameter_problem_unchecked(&self) -> &IcmpParamProblem {
        &*self.data.as_ptr().cast()
    }

    /// Returns a reference to the Parameter Problem message (Type 12)
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 12 (Parameter Problem) before calling this function.
    /// Accessing the param_problem field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn parameter_problem_mut_unchecked(&mut self) -> &mut IcmpParamProblem {
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
pub struct IcmpRedirect {
    gateway: [u8; 4],
}

impl IcmpRedirect {
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
pub struct IcmpParamProblem {
    pub pointer: u8,
    pub _unused: [u8; 3], // To make up 4 bytes
}

impl IcmpParamProblem {
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
/// use network_types::icmp::{Icmpv4Hdr, IcmpError, IcmpHdrMessage, IcmpTimestampMsgPart};
/// use network_types::ip::Ipv4Hdr;
///
/// fn handle_icmp_timestamp(ctx: &TcContext) -> Result<u32, IcmpError> {
///     // Parse the ICMP header from start of payload
///     let icmp_start = ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN;
///     let icmp: *mut Icmpv4Hdr = icmp_start as *mut Icmpv4Hdr;
///
///     if let Some(icmp_hdr) = unsafe { icmp.as_mut() } {
///         // Timestamp request/reply share the same echo layout; ensure the type matches
///         match icmp_hdr.message()? {
///             IcmpHdrMessage::Timestamp(id_seq)
///                 | IcmpHdrMessage::TimestampReply(id_seq) => {
///                 let timestamps_ptr_location = icmp_start + Icmpv4Hdr::LEN;
///                 let timestamps_ptr: *const IcmpTimestampMsgPart =
///                     timestamps_ptr_location as *const IcmpTimestampMsgPart;
///
///                 if let Some(timestamps_ref) = unsafe { timestamps_ptr.as_ref() } {
///                     let _id = id_seq.id();
///                     let _sequence = id_seq.sequence();
///                     let _orig = timestamps_ref.originate_timestamp();
///                     let _recv = timestamps_ref.receive_timestamp();
///                     let _xmit = timestamps_ref.transmit_timestamp();
///                     // Use the timestamp fields as needed.
///                 }
///             },
///             _ => {},
///         }
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
/// use network_types::icmp::{Icmpv4Hdr, IcmpHdrMessage, IcmpTracerouteMsgPart};
/// use network_types::ip::Ipv4Hdr;
///
/// fn handle_icmp_traceroute(ctx: &TcContext) -> Result<u32, ()> {
///     // Parse the ICMP header from start of payload
///     let icmp_start = ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN;
///     let icmp: *mut Icmpv4Hdr = icmp_start as *mut Icmpv4Hdr;
///
///     // Check if it's a Traceroute Request/Reply message by matching on the safe enum.
///     if let Some(icmp_hdr) = unsafe { icmp.as_mut() } {
///         if let Ok(IcmpHdrMessage::Traceroute(traceroute_hdr)) = icmp_hdr.message() {
///             // Access the traceroute-specific fields without repeating the type checks.
///             let traceroute_ptr: *const IcmpTracerouteMsgPart = unsafe {
///                 (icmp_start as *const u8)
///                     .add(Icmpv4Hdr::LEN) as *const IcmpTracerouteMsgPart
///             };
///
///             if let Some(traceroute_ref) = unsafe { traceroute_ptr.as_ref() } {
///                 // Consume the traceroute fields in network byte order
///                 let _id = traceroute_hdr.id();
///                 let _hops_out = traceroute_ref.hops_out();
///                 let _bandwidth = traceroute_ref.bandwidth_out();
///                 let _mtu = traceroute_ref.mtu_out();
///                 // Do something meaningful with these values here.
///             } else {
///                 return Err(()); // Malformed packet or insufficient bounds
///             }
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

/// Full ICMPv6 Redirect message as defined in RFC 4443 section 4.5.
/// Combines the base ICMPv6 header with the target and destination addresses.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct IcmpV6RedirectMsg {
    pub hdr: Icmpv6Hdr,
    target_address: [u8; 16],
    destination_address: [u8; 16],
}

impl IcmpV6RedirectMsg {
    pub const LEN: usize = mem::size_of::<IcmpV6RedirectMsg>();

    /// Returns the 4-byte reserved field from the embedded redirect header.
    /// This field is currently unused and MUST be initialized to zeros by the sender.
    #[inline]
    pub fn reserved(&self) -> [u8; 4] {
        unsafe { self.hdr.redirect_reserved_unchecked() }
    }

    /// Sets the 4-byte reserved field in the embedded redirect header.
    /// This field is currently unused and MUST be set to zeros.
    #[inline]
    pub fn set_reserved(&mut self, reserved: [u8; 4]) {
        unsafe {
            self.hdr.set_redirect_reserved_unchecked(reserved);
        }
    }

    /// Returns the Target Address from an ICMPv6 Redirect message (Type 137).
    /// This field contains the address that is a better first hop to use for the destination.
    #[inline]
    pub fn target_address(&self) -> net::Ipv6Addr {
        net::Ipv6Addr::from(self.target_address)
    }

    /// Sets the Target Address for an ICMPv6 Redirect message (Type 137).
    /// This should be set to the address that is a better first hop to use for the destination.
    #[inline]
    pub fn set_target_address(&mut self, addr: net::Ipv6Addr) {
        self.target_address = addr.octets();
    }

    /// Returns the Destination Address from an ICMPv6 Redirect message (Type 137).
    /// This field contains the IP address of the destination that is redirected to the target.
    #[inline]
    pub fn destination_address(&self) -> net::Ipv6Addr {
        net::Ipv6Addr::from(self.destination_address)
    }

    /// Sets the Destination Address for an ICMPv6 Redirect message (Type 137).
    /// This should be set to the IP address of the destination that is redirected to the target.
    #[inline]
    pub fn set_destination_address(&mut self, addr: net::Ipv6Addr) {
        self.destination_address = addr.octets();
    }
}

impl Icmpv6Hdr {
    pub const LEN: usize = mem::size_of::<Icmpv6Hdr>();

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

    #[inline]
    fn check_echo(&self) -> Result<(), IcmpError> {
        if matches!(self.type_, 128 | 129) {
            Ok(())
        } else {
            Err(IcmpError::InvalidIcmpType)
        }
    }

    #[inline]
    pub fn echo(&self) -> Result<&IcmpIdSequence, IcmpError> {
        self.check_echo().map(|_| {
            // SAFETY: We verified the ICMPv6 type before reinterpreting the bytes.
            unsafe { self.echo_unchecked() }
        })
    }

    #[inline]
    pub fn echo_mut(&mut self) -> Result<&mut IcmpIdSequence, IcmpError> {
        self.check_echo().map(|_| {
            // SAFETY: We verified the ICMPv6 type before reinterpreting the bytes.
            unsafe { self.echo_mut_unchecked() }
        })
    }

    /// Returns the identification field from ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn echo_id(&self) -> Result<u16, IcmpError> {
        self.echo().map(|echo| echo.id())
    }

    /// Sets the identification field for ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn set_echo_id(&mut self, id: u16) -> Result<(), IcmpError> {
        self.echo_mut().map(|echo| echo.set_id(id))
    }

    /// Returns the sequence number from ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn echo_sequence(&self) -> Result<u16, IcmpError> {
        self.echo().map(|echo| echo.sequence())
    }

    /// Sets the sequence number for ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn set_echo_sequence(&mut self, sequence: u16) -> Result<(), IcmpError> {
        self.echo_mut().map(|echo| echo.set_sequence(sequence))
    }

    #[inline]
    fn check_packet_too_big(&self) -> Result<(), IcmpError> {
        if self.type_ == 2 {
            Ok(())
        } else {
            Err(IcmpError::InvalidIcmpType)
        }
    }

    /// Returns the MTU field from an ICMPv6 Packet Too Big message (Type 2).
    /// This value indicates the maximum packet size that can be handled by the next hop.
    #[inline]
    pub fn mtu(&self) -> Result<u32, IcmpError> {
        self.check_packet_too_big()
            .map(|_| unsafe { self.mtu_unchecked() })
    }

    /// Sets the MTU field for an ICMPv6 Packet Too Big message (Type 2).
    /// This should be set to the maximum packet size that can be handled by the next hop.
    #[inline]
    pub fn set_mtu(&mut self, mtu: u32) -> Result<(), IcmpError> {
        self.check_packet_too_big()
            .map(|_| unsafe { self.set_mtu_unchecked(mtu) })
    }

    #[inline]
    fn check_parameter_problem(&self) -> Result<(), IcmpError> {
        if self.type_ == 4 {
            Ok(())
        } else {
            Err(IcmpError::InvalidIcmpType)
        }
    }

    /// Returns the pointer field from an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer indicates the offset within the invoking packet where the error was detected.
    #[inline]
    pub fn pointer(&self) -> Result<u32, IcmpError> {
        self.check_parameter_problem()
            .map(|_| unsafe { self.pointer_unchecked() })
    }

    /// Sets the pointer field for an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer should indicate the offset within the invoking packet where the error was detected.
    #[inline]
    pub fn set_pointer(&mut self, pointer: u32) -> Result<(), IcmpError> {
        self.check_parameter_problem()
            .map(|_| unsafe { self.set_pointer_unchecked(pointer) })
    }

    #[inline]
    fn check_redirect(&self) -> Result<(), IcmpError> {
        if self.type_ == 137 {
            Ok(())
        } else {
            Err(IcmpError::InvalidIcmpType)
        }
    }

    /// Returns the 4-byte reserved field from an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be initialized to zeros by the sender.
    #[inline]
    pub fn redirect_reserved(&self) -> Result<[u8; 4], IcmpError> {
        self.check_redirect()
            .map(|_| unsafe { self.redirect_reserved_unchecked() })
    }

    /// Sets the 4-byte reserved field for an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be set to zeros.
    #[inline]
    pub fn set_redirect_reserved(&mut self, reserved: [u8; 4]) -> Result<(), IcmpError> {
        self.check_redirect()
            .map(|_| unsafe { self.set_redirect_reserved_unchecked(reserved) })
    }
}

impl Icmpv6Hdr {
    /// Returns a reference to the ICMPv6 Echo Request/Reply data.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling
    /// this function. Accessing the echo fields with other ICMPv6 types may result in undefined
    /// behavior.
    #[inline]
    pub unsafe fn echo_unchecked(&self) -> &IcmpIdSequence {
        &*self.data.as_ptr().cast()
    }

    /// Returns a mutable reference to the ICMPv6 Echo Request/Reply data.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling
    /// this function. Accessing the echo fields with other ICMPv6 types may result in undefined
    /// behavior.
    #[inline]
    pub unsafe fn echo_mut_unchecked(&mut self) -> &mut IcmpIdSequence {
        &mut *self.data.as_mut_ptr().cast()
    }

    /// Returns the MTU field from an ICMPv6 Packet Too Big message (Type 2).
    /// This value indicates the maximum packet size that can be handled by the next hop.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 2 (Packet Too Big) before calling.
    /// Accessing MTU field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn mtu_unchecked(&self) -> u32 {
        u32::from_be_bytes(self.data)
    }

    /// Sets the MTU field for an ICMPv6 Packet Too Big message (Type 2).
    /// This should be set to the maximum packet size that can be handled by the next hop.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 2 (Packet Too Big) before calling.
    /// Accessing MTU field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_mtu_unchecked(&mut self, mtu: u32) {
        self.data = mtu.to_be_bytes();
    }

    /// Returns the pointer field from an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer indicates the offset within the invoking packet where the error was detected.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 4 (Parameter Problem) before calling.
    /// Accessing pointer field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn pointer_unchecked(&self) -> u32 {
        u32::from_be_bytes(self.data)
    }

    /// Sets the pointer field for an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer should indicate the offset within the invoking packet where the error was detected.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 4 (Parameter Problem) before calling.
    /// Accessing pointer field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_pointer_unchecked(&mut self, pointer: u32) {
        self.data = pointer.to_be_bytes();
    }

    /// Returns the 4-byte reserved field from an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be initialized to zeros by the sender.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn redirect_reserved_unchecked(&self) -> [u8; 4] {
        self.data
    }

    /// Sets the 4-byte reserved field for an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be set to zeros.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_redirect_reserved_unchecked(&mut self, reserved: [u8; 4]) {
        self.data = reserved;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    macro_rules! expect_message {
        ($hdr:expr, $variant:ident) => {{
            match $hdr.message().expect("invalid ICMP message") {
                IcmpHdrMessage::$variant(value) => value,
                _ => panic!("expected {} message", stringify!($variant)),
            }
        }};
    }

    macro_rules! expect_message_mut {
        ($hdr:expr, $variant:ident) => {{
            match $hdr.message_mut().expect("invalid ICMP message") {
                IcmpHdrMessageMut::$variant(value) => value,
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
        expect_message_mut!(&mut hdr, EchoReply).set_id(test_id);
        assert_eq!(expect_message!(&hdr, EchoReply).id(), test_id);

        // Verify byte order in raw storage
        assert_eq!(hdr.data[..2], test_id.to_be_bytes());

        // Test echo sequence
        let test_seq: u16 = 0x8765;
        expect_message_mut!(&mut hdr, EchoReply).set_sequence(test_seq);
        assert_eq!(expect_message!(&hdr, EchoReply).sequence(), test_seq);

        // Verify byte order in raw storage
        assert_eq!(hdr.data[2..], test_seq.to_be_bytes());
    }

    #[test]
    fn test_gateway_address() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Redirect (5) which is valid for gateway address
        hdr.type_ = 5;
        let test_addr = Ipv4Addr::new(192, 168, 1, 1);

        expect_message_mut!(&mut hdr, Redirect).set_gateway_address(test_addr);
        assert_eq!(expect_message!(&hdr, Redirect).gateway_address(), test_addr);

        // Verify the raw bytes
        assert_eq!(hdr.data, [192, 168, 1, 1]);
    }

    #[test]
    fn test_message_enum_echo() {
        let mut hdr = create_test_icmp_hdr();
        hdr.type_ = 8;

        match hdr.message_mut().expect("echo view") {
            IcmpHdrMessageMut::Echo(echo) => {
                echo.set_id(0xABCD);
                echo.set_sequence(0x1234);
            }
            _ => panic!("unexpected variant"),
        }

        match hdr.message().expect("echo view") {
            IcmpHdrMessage::Echo(echo) => {
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

        assert!(hdr.message().is_err());
    }

    #[test]
    fn test_next_hop_mtu() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Destination Unreachable (3) which is valid for next_hop_mtu
        hdr.type_ = 3;
        let test_mtu: u16 = 1500;

        expect_message_mut!(&mut hdr, DestinationUnreachable).set_mtu(test_mtu);
        assert_eq!(
            expect_message!(&hdr, DestinationUnreachable).mtu(),
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

        expect_message_mut!(&mut hdr, ParameterProblem).set_pointer(test_pointer);
        assert_eq!(
            expect_message!(&hdr, ParameterProblem).pointer(),
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

        expect_message_mut!(&mut hdr, Traceroute).set_id(test_id);
        assert_eq!(expect_message!(&hdr, Traceroute).id(), test_id);

        // Verify byte order in raw storage
        assert_eq!(hdr.data[..2], test_id.to_be_bytes());
    }

    #[test]
    fn test_photuris_spi() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to PHOTURIS (40) which is valid for photuris_spi
        hdr.type_ = 40;
        let test_spi: u16 = 0xFEDC;

        expect_message_mut!(&mut hdr, Photuris).set_reserved_spi(test_spi);
        assert_eq!(expect_message!(&hdr, Photuris).reserved_spi(), test_spi);

        // Verify byte order in raw storage
        assert_eq!(hdr.data[..2], test_spi.to_be_bytes());
    }

    #[test]
    fn test_photuris_pointer() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to PHOTURIS (40) which is valid for photuris_pointer
        hdr.type_ = 40;
        let test_pointer: u16 = 0x1A2B;

        expect_message_mut!(&mut hdr, Photuris).set_pointer(test_pointer);
        assert_eq!(expect_message!(&hdr, Photuris).pointer(), test_pointer);

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
    fn test_icmp_echo_message_construction() {
        // Test creating a typical ICMP Echo Request
        let mut hdr = create_test_icmp_hdr();

        hdr.type_ = 8; // Echo Request
        hdr.code = 0;
        hdr.set_checksum(0); // Would be calculated later based on the entire message

        // Echo Request (type 8) is valid for echo_id and echo_sequence
        let echo = expect_message_mut!(&mut hdr, Echo);
        echo.set_id(0x1234);
        echo.set_sequence(0x5678);

        assert_eq!(hdr.type_, 8);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum(), 0);
        let echo = expect_message!(&hdr, Echo);
        assert_eq!(echo.id(), 0x1234);
        assert_eq!(echo.sequence(), 0x5678);
    }

    #[test]
    fn test_icmp_destination_unreachable_construction() {
        // Test creating a Destination Unreachable message
        let mut hdr = create_test_icmp_hdr();

        hdr.type_ = 3; // Destination Unreachable
        hdr.code = 4; // Fragmentation needed but DF bit set
        hdr.set_checksum(0); // Would be calculated later

        // Destination Unreachable (type 3) is valid for next_hop_mtu
        expect_message_mut!(&mut hdr, DestinationUnreachable).set_mtu(1400); // Example MTU value

        assert_eq!(hdr.type_, 3);
        assert_eq!(hdr.code, 4);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(expect_message!(&hdr, DestinationUnreachable).mtu(), 1400);
    }

    #[test]
    fn test_icmp_parameter_problem_construction() {
        // Test creating a Parameter Problem message
        let mut hdr = create_test_icmp_hdr();

        hdr.type_ = 12; // Parameter Problem
        hdr.code = 0; // Pointer indicates the error
        hdr.set_checksum(0); // Would be calculated later

        // Parameter Problem (type 12) is valid for parameter_pointer
        expect_message_mut!(&mut hdr, ParameterProblem).set_pointer(20); // Error at byte offset 20

        assert_eq!(hdr.type_, 12);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(expect_message!(&hdr, ParameterProblem).pointer(), 20);
    }

    #[test]
    fn test_icmp_redirect_construction() {
        // Test creating a Redirect message
        let mut hdr = create_test_icmp_hdr();

        hdr.type_ = 5; // Redirect
        hdr.code = 1; // Redirect for host
        hdr.set_checksum(0); // Would be calculated later

        expect_message_mut!(&mut hdr, Redirect).set_gateway_address(Ipv4Addr::new(10, 0, 0, 1));

        assert_eq!(hdr.type_, 5);
        assert_eq!(hdr.code, 1);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(
            expect_message!(&hdr, Redirect).gateway_address(),
            Ipv4Addr::new(10, 0, 0, 1)
        );
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

    #[test]
    fn test_icmpv6_redirect_msg_size() {
        assert_eq!(IcmpV6RedirectMsg::LEN, mem::size_of::<IcmpV6RedirectMsg>());
        // Header (8 bytes) + target address (16) + destination address (16)
        assert_eq!(IcmpV6RedirectMsg::LEN, 40);
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
        hdr.set_echo_id(test_id).unwrap();
        assert_eq!(hdr.echo_id().unwrap(), test_id);

        // Verify byte order in raw storage
        let test_id_bytes = test_id.to_be_bytes();
        assert_eq!(&hdr.data[..2], &test_id_bytes);

        // Test echo sequence
        let test_seq: u16 = 0x8765;
        hdr.set_echo_sequence(test_seq).unwrap();
        assert_eq!(hdr.echo_sequence().unwrap(), test_seq);

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

        hdr.set_mtu(test_mtu).unwrap();
        assert_eq!(hdr.mtu().unwrap(), test_mtu);

        // Verify byte order in raw storage
        assert_eq!(hdr.data, test_mtu.to_be_bytes());

        // Test with zero
        hdr.set_mtu(0).unwrap();
        assert_eq!(hdr.mtu().unwrap(), 0);
        assert_eq!(hdr.data, [0, 0, 0, 0]);

        // Test with max value
        hdr.set_mtu(u32::MAX).unwrap();
        assert_eq!(hdr.mtu().unwrap(), u32::MAX);
        assert_eq!(hdr.data, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_icmpv6_pointer() {
        let mut hdr = create_test_icmpv6_hdr();
        // Set type to Parameter Problem (4) which is valid for pointer
        hdr.type_ = 4;
        let test_pointer: u32 = 0x87654321;

        hdr.set_pointer(test_pointer).unwrap();
        assert_eq!(hdr.pointer().unwrap(), test_pointer);

        // Verify byte order in raw storage
        assert_eq!(hdr.data, test_pointer.to_be_bytes());

        // Test with zero
        hdr.set_pointer(0).unwrap();
        assert_eq!(hdr.pointer().unwrap(), 0);
        assert_eq!(hdr.data, [0, 0, 0, 0]);

        // Test with max value
        hdr.set_pointer(u32::MAX).unwrap();
        assert_eq!(hdr.pointer().unwrap(), u32::MAX);
        assert_eq!(hdr.data, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_icmpv6_redirect_fields() {
        use core::net::Ipv6Addr;

        let mut msg = IcmpV6RedirectMsg {
            hdr: Icmpv6Hdr {
                type_: 137,
                code: 0,
                check: [0, 0],
                data: [0, 0, 0, 0],
            },
            target_address: [0; 16],
            destination_address: [0; 16],
        };

        // Test reserved field
        let test_reserved: [u8; 4] = [0, 0, 0, 0]; // Should be zeros per RFC
        msg.set_reserved(test_reserved);
        assert_eq!(msg.reserved(), test_reserved);

        // Test target address
        let test_target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        msg.set_target_address(test_target);
        assert_eq!(msg.target_address(), test_target);

        // Test destination address
        let test_dest = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        msg.set_destination_address(test_dest);
        assert_eq!(msg.destination_address(), test_dest);
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

    #[test]
    fn test_icmpv6_echo_request_construction() {
        // Test creating a typical ICMPv6 Echo Request
        let mut hdr = create_test_icmpv6_hdr();

        hdr.type_ = 128; // Echo Request
        hdr.code = 0;
        hdr.set_checksum(0); // Would be calculated later based on the entire message
        hdr.set_echo_id(0x1234).unwrap();
        hdr.set_echo_sequence(0x5678).unwrap();

        assert_eq!(hdr.type_, 128);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.echo_id().unwrap(), 0x1234);
        assert_eq!(hdr.echo_sequence().unwrap(), 0x5678);
    }

    #[test]
    fn test_icmpv6_packet_too_big_construction() {
        // Test creating a Packet Too Big message
        let mut hdr = create_test_icmpv6_hdr();

        hdr.type_ = 2; // Packet Too Big
        hdr.code = 0;
        hdr.set_checksum(0); // Would be calculated later
        hdr.set_mtu(1500).unwrap(); // Example MTU value

        assert_eq!(hdr.type_, 2);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.mtu().unwrap(), 1500);
    }

    #[test]
    fn test_icmpv6_parameter_problem_construction() {
        // Test creating a Parameter Problem message
        let mut hdr = create_test_icmpv6_hdr();

        hdr.type_ = 4; // Parameter Problem
        hdr.code = 0; // Erroneous header field encountered
        hdr.set_checksum(0); // Would be calculated later
        hdr.set_pointer(40).unwrap(); // Error at byte offset 40

        assert_eq!(hdr.type_, 4);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.pointer().unwrap(), 40);
    }
}

#[cfg(all(test, feature = "wincode"))]
mod wincode_prop_tests {
    use super::*;
    use proptest::array::{uniform2, uniform4, uniform16};
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;
    use wincode::{SchemaRead, SchemaWrite, config::DefaultConfig};

    const MAX_PACKET_SIZE: usize = IcmpV6RedirectMsg::LEN;

    trait FixedPacket {
        const SERIALIZED_LEN: usize;
    }

    impl FixedPacket for Icmpv4Hdr {
        const SERIALIZED_LEN: usize = Icmpv4Hdr::LEN;
    }

    impl FixedPacket for Icmpv6Hdr {
        const SERIALIZED_LEN: usize = Icmpv6Hdr::LEN;
    }

    impl FixedPacket for IcmpV6RedirectMsg {
        const SERIALIZED_LEN: usize = IcmpV6RedirectMsg::LEN;
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

    fn icmpv6_redirect_msg_strategy() -> impl Strategy<Value = IcmpV6RedirectMsg> {
        (
            any::<u8>(),
            uniform2(any::<u8>()),
            uniform4(any::<u8>()),
            uniform16(any::<u8>()),
            uniform16(any::<u8>()),
        )
            .prop_map(|(code, check, reserved, target, dest)| IcmpV6RedirectMsg {
                hdr: Icmpv6Hdr {
                    type_: 137,
                    code,
                    check,
                    data: reserved,
                },
                target_address: target,
                destination_address: dest,
            })
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

        #[test]
        fn icmpv6_redirect_msg_round_trips(msg in icmpv6_redirect_msg_strategy()) {
            let decoded = round_trip(&msg);
            prop_assert_eq!(decoded.hdr.type_, msg.hdr.type_);
            prop_assert_eq!(decoded.hdr.code, msg.hdr.code);
            prop_assert_eq!(decoded.hdr.check, msg.hdr.check);
            prop_assert_eq!(decoded.hdr.data, msg.hdr.data);
            prop_assert_eq!(decoded.target_address, msg.target_address);
            prop_assert_eq!(decoded.destination_address, msg.destination_address);
        }
    }
}
