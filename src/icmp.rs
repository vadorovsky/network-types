use core::mem;
use core::net;

use crate::getter_be;
use crate::setter_be;

/// An enum representing either an ICMPv4 or ICMPv6 header.
///
/// - `V4` contains an IPv4 ICMP header as defined in RFC 792 (see `IcmpHdr`)
/// - `V6` contains an IPv6 ICMP header as defined in RFC 4443 (see `IcmpV6Hdr`)
///
/// This enum allows working with both ICMP protocol versions through a unified interface.
#[derive(Debug, Copy, Clone)]
pub enum Icmp {
    V4(IcmpHdr),
    V6(IcmpV6Hdr),
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
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpHdr {
    pub type_: u8,
    pub code: u8,
    pub check: [u8; 2],
    pub data: IcmpHdrUn,
}

impl IcmpHdr {
    pub const LEN: usize = mem::size_of::<IcmpHdr>();

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

    /// Returns the identification field from ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    #[inline]
    pub fn echo_id(&self) -> Result<u16, IcmpError> {
        if !matches!(self.type_, 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18 | 37 | 38) {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.echo_id_unchecked() })
    }

    /// Sets the identification field for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    #[inline]
    pub fn set_echo_id(&mut self, id: u16) -> Result<(), IcmpError> {
        if !matches!(self.type_, 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18 | 37 | 38) {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_echo_id_unchecked(id);
        }
        Ok(())
    }

    /// Returns the sequence number from ICMP Echo/Timestamp/Info/Mask messages.
    #[inline]
    pub fn echo_sequence(&self) -> Result<u16, IcmpError> {
        if !matches!(self.type_, 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18 | 37 | 38) {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.echo_sequence_unchecked() })
    }

    /// Sets the sequence number for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    #[inline]
    pub fn set_echo_sequence(&mut self, sequence: u16) -> Result<(), IcmpError> {
        if !matches!(self.type_, 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18 | 37 | 38) {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_echo_sequence_unchecked(sequence);
        }
        Ok(())
    }

    /// Returns the gateway internet address from an ICMP Redirect message (Type 5)
    #[inline]
    pub fn gateway_address(&self) -> Result<net::Ipv4Addr, IcmpError> {
        if self.type_ != 5 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.gateway_address_unchecked() })
    }

    /// Sets the gateway internet address for an ICMP Redirect message (Type 5)
    #[inline]
    pub fn set_gateway_address(&mut self, addr: net::Ipv4Addr) -> Result<(), IcmpError> {
        if self.type_ != 5 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_gateway_address_unchecked(addr);
        }
        Ok(())
    }

    /// Returns the Next-Hop MTU field from a Destination Unreachable message
    /// in host byte order. Used for Path MTU Discovery (RFC 1191).
    #[inline]
    pub fn next_hop_mtu(&self) -> Result<u16, IcmpError> {
        if self.type_ != 3 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.next_hop_mtu_unchecked() })
    }

    /// Sets the Next-Hop MTU field for a Destination Unreachable message.
    /// Used for Path MTU Discovery (RFC 1191).
    #[inline]
    pub fn set_next_hop_mtu(&mut self, mtu: u16) -> Result<(), IcmpError> {
        if self.type_ != 3 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_next_hop_mtu_unchecked(mtu);
        }
        Ok(())
    }

    /// Returns the pointer to the errored byte from a Parameter Problem message (Type 12)
    #[inline]
    pub fn parameter_pointer(&self) -> Result<u8, IcmpError> {
        if self.type_ != 12 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.parameter_pointer_unchecked() })
    }

    /// Sets the pointer to the errored byte for a Parameter Problem message (Type 12)
    #[inline]
    pub fn set_parameter_pointer(&mut self, pointer: u8) -> Result<(), IcmpError> {
        if self.type_ != 12 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_parameter_pointer_unchecked(pointer);
        }
        Ok(())
    }

    /// Returns the ID Number field from a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    /// This is only valid for ICMP Type 30 (Traceroute Request) and Type 31 (Traceroute Reply).
    #[inline]
    pub fn traceroute_id(&self) -> Result<u16, IcmpError> {
        if !matches!(self.type_, 30 | 31) {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.traceroute_id_unchecked() })
    }

    /// Sets the ID Number field for a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    #[inline]
    pub fn set_traceroute_id(&mut self, id: u16) -> Result<(), IcmpError> {
        if !matches!(self.type_, 30 | 31) {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_traceroute_id_unchecked(id);
        }
        Ok(())
    }

    /// Returns the Security Parameters Index (SPI) from a PHOTURIS message (Type 40).
    /// The SPI identifies a security association between two peers.
    #[inline]
    pub fn photuris_spi(&self) -> Result<u16, IcmpError> {
        if self.type_ != 40 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.photuris_spi_unchecked() })
    }

    /// Sets the Security Parameters Index (SPI) for a PHOTURIS message (Type 40).
    /// The SPI identifies a security association between two peers.
    #[inline]
    pub fn set_photuris_spi(&mut self, spi: u16) -> Result<(), IcmpError> {
        if self.type_ != 40 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_photuris_spi_unchecked(spi);
        }
        Ok(())
    }

    /// Returns the pointer to the byte where an error was detected in a PHOTURIS message (Type 40).
    /// Used to identify the location of errors during PHOTURIS protocol processing.
    #[inline]
    pub fn photuris_pointer(&self) -> Result<u16, IcmpError> {
        if self.type_ != 40 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.photuris_pointer_unchecked() })
    }

    /// Sets the pointer to the byte where an error was detected in a PHOTURIS message (Type 40).
    /// Used to identify the location of errors during PHOTURIS protocol processing.
    #[inline]
    pub fn set_photuris_pointer(&mut self, pointer: u16) -> Result<(), IcmpError> {
        if self.type_ != 40 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_photuris_pointer_unchecked(pointer);
        }
        Ok(())
    }
}

/// These are the unsafe alternatives to the safe functions on `IcmpHdr` that do prevent undefined behavior.
impl IcmpHdr {
    /// Returns the identification field from ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    pub unsafe fn echo_id_unchecked(&self) -> u16 {
        self.data.echo.id_unchecked()
    }

    /// Sets the identification field for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    pub unsafe fn set_echo_id_unchecked(&mut self, id: u16) {
        self.data.echo.set_id_unchecked(id);
    }

    /// Returns the sequence number from ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    pub unsafe fn echo_sequence_unchecked(&self) -> u16 {
        self.data.echo.sequence_unchecked()
    }

    /// Sets the sequence number for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    pub unsafe fn set_echo_sequence_unchecked(&mut self, sequence: u16) {
        self.data.echo.set_sequence_unchecked(sequence);
    }

    /// Returns the gateway internet address from an ICMP Redirect message (Type 5)
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 5 (Redirect) before calling this function.
    /// Accessing the redirect field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn gateway_address_unchecked(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.data.redirect)
    }

    /// Sets the gateway internet address for an ICMP Redirect message (Type 5)
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 5 (Redirect) before calling this function.
    /// Accessing the redirect field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_gateway_address_unchecked(&mut self, addr: net::Ipv4Addr) {
        self.data.redirect = addr.octets();
    }

    /// Returns the Next-Hop MTU field from a Destination Unreachable message
    /// in host byte order. Used for Path MTU Discovery (RFC 1191).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 3 (Destination Unreachable) before calling this function.
    /// Accessing the dst_unreachable field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn next_hop_mtu_unchecked(&self) -> u16 {
        self.data.dst_unreachable.mtu_unchecked()
    }

    /// Sets the Next-Hop MTU field for a Destination Unreachable message.
    /// Used for Path MTU Discovery (RFC 1191).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 3 (Destination Unreachable) before calling this function.
    /// Accessing the dst_unreachable field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_next_hop_mtu_unchecked(&mut self, mtu: u16) {
        self.data.dst_unreachable.set_mtu_unchecked(mtu)
    }

    /// Returns the pointer to the errored byte from a Parameter Problem message (Type 12)
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 12 (Parameter Problem) before calling this function.
    /// Accessing the param_problem field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn parameter_pointer_unchecked(&self) -> u8 {
        self.data.param_problem.pointer
    }

    /// Sets the pointer to the errored byte for a Parameter Problem message (Type 12)
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 12 (Parameter Problem) before calling this function.
    /// Accessing the param_problem field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_parameter_pointer_unchecked(&mut self, pointer: u8) {
        self.data.param_problem.pointer = pointer;
    }

    /// Returns the ID Number field from a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    /// This is only valid for ICMP Type 30 (Traceroute Request) and Type 31 (Traceroute Reply).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) or 31 (Traceroute Reply) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn traceroute_id_unchecked(&self) -> u16 {
        self.data.traceroute.id_unchecked()
    }

    /// Sets the ID Number field for a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) or 31 (Traceroute Reply) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_traceroute_id_unchecked(&mut self, id: u16) {
        self.data.traceroute.set_id_unchecked(id);
    }

    /// Returns the Security Parameters Index (SPI) from a PHOTURIS message (Type 40).
    /// The SPI identifies a security association between two peers.
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 40 (PHOTURIS) before calling this function.
    /// Accessing the photuris field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn photuris_spi_unchecked(&self) -> u16 {
        self.data.photuris.reserved_spi_unchecked()
    }

    /// Sets the Security Parameters Index (SPI) for a PHOTURIS message (Type 40).
    /// The SPI identifies a security association between two peers.
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 40 (PHOTURIS) before calling this function.
    /// Accessing the photuris field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_photuris_spi_unchecked(&mut self, spi: u16) {
        self.data.photuris.set_reserved_spi_unckecked(spi);
    }

    /// Returns the pointer to the byte where an error was detected in a PHOTURIS message (Type 40).
    /// Used to identify the location of errors during PHOTURIS protocol processing.
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 40 (PHOTURIS) before calling this function.
    /// Accessing the photuris field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn photuris_pointer_unchecked(&self) -> u16 {
        self.data.photuris.pointer_unchecked()
    }

    /// Sets the pointer to the byte where an error was detected in a PHOTURIS message (Type 40).
    /// Used to identify the location of errors during PHOTURIS protocol processing.
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 40 (PHOTURIS) before calling this function.
    /// Accessing the photuris field with other ICMP types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_photuris_pointer_unchecked(&mut self, pointer: u16) {
        self.data.photuris.set_pointer_unchecked(pointer);
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
    pub echo: IcmpEcho,
    pub redirect: [u8; 4],
    pub dst_unreachable: IcmpDstUnreachable,
    pub param_problem: IcmpParamProblem,
    pub traceroute: IcmpTraceroute,
    pub photuris: IcmpHdrPhoturis,
    pub reserved: [u8; 4], // Generic 4-byte data, also for "Unused" fields
}

impl core::fmt::Debug for IcmpHdrUn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Safe approach: just show the raw 4 bytes
        let bytes = unsafe { self.reserved };
        write!(
            f,
            "IcmpHdrUn([{:#04x}, {:#04x}, {:#04x}, {:#04x}])",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
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
pub struct IcmpEcho {
    pub id: [u8; 2],
    pub sequence: [u8; 2],
}

impl IcmpEcho {
    /// Returns the identification field from ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    unsafe fn id_unchecked(&self) -> u16 {
        getter_be!(self, id, u16)
    }

    /// Sets the identification field for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    unsafe fn set_id_unchecked(&mut self, id: u16) {
        setter_be!(self, id, id)
    }

    /// Returns the sequence number from ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    unsafe fn sequence_unchecked(&self) -> u16 {
        getter_be!(self, sequence, u16)
    }

    /// Sets the sequence number for ICMP Echo/Timestamp/Info/Mask messages.
    /// Only valid for ICMP Types: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38.
    ///
    /// # Safety
    /// Caller must ensure that the ICMP type is one of: 0, 8, 13, 14, 15, 16, 17, 18, 37, 38
    /// before calling this function. Accessing the echo fields with other ICMP types may result
    /// in undefined behavior.
    #[inline]
    unsafe fn set_sequence_unchecked(&mut self, sequence: u16) {
        setter_be!(self, sequence, sequence)
    }
}

/// For ICMP Type 3 "Destination Unreachable" Message (RFC 792) with support for PMTUD (RFC 1191)
/// Contains 2 unused bytes followed by a Next-Hop MTU field indicating the maximum transmission unit
/// of the next-hop network on which fragmentation is required.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
    unsafe fn mtu_unchecked(&self) -> u16 {
        getter_be!(self, mtu, u16)
    }

    #[inline]
    unsafe fn set_mtu_unchecked(&mut self, mtu: u16) {
        setter_be!(self, mtu, mtu)
    }
}

/// For ICMP Type 12 "Parameter Problem" Message (RFC 792)
/// Contains a pointer to the byte in the original datagram that caused the error
/// and 3 bytes of unused padding to make the field a total of 4 bytes.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpParamProblem {
    pub pointer: u8,
    pub _unused: [u8; 3], // To make up 4 bytes
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

impl IcmpHdrPhoturis {
    #[inline]
    unsafe fn reserved_spi_unchecked(&self) -> u16 {
        getter_be!(self, reserved_spi, u16)
    }

    #[inline]
    unsafe fn set_reserved_spi_unckecked(&mut self, spi: u16) {
        setter_be!(self, reserved_spi, spi)
    }

    #[inline]
    unsafe fn pointer_unchecked(&self) -> u16 {
        getter_be!(self, pointer, u16)
    }

    #[inline]
    unsafe fn set_pointer_unchecked(&mut self, pointer: u16) {
        setter_be!(self, pointer, pointer)
    }
}

/// For ICMP Type 30 "Traceroute" Message (RFC 1393)
/// Contains a 16-bit ID Number field used by the source to match responses to outgoing requests
/// followed by 2 unused bytes to make a total of 4 bytes. The ID Number helps match Reply messages
/// (type 31) to their corresponding Requests.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpTraceroute {
    pub id: [u8; 2],
    pub _unused: [u8; 2],
}

impl IcmpTraceroute {
    /// Returns the ID Number field from a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    /// This is only valid for ICMP Type 30 (Traceroute Request) and Type 31 (Traceroute Reply).
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) or 31 (Traceroute Reply) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    unsafe fn id_unchecked(&self) -> u16 {
        getter_be!(self, id, u16)
    }

    /// Sets the ID Number field for a Traceroute message (Type 30).
    /// The ID Number is used to match Reply messages (Type 31) to their corresponding Request messages.
    ///
    /// # Safety
    /// Caller must ensure ICMP type is 30 (Traceroute Request) or 31 (Traceroute Reply) before calling
    /// this function. Accessing the traceroute field with other ICMP types may result in undefined behavior.
    #[inline]
    unsafe fn set_id_unchecked(&mut self, id: u16) {
        setter_be!(self, id, id)
    }
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
/// // Assuming aya_log_ebpf is available for logging, as per project dependencies.
/// // If not, remove or adapt the log lines.
/// // use aya_log_ebpf::{info, warn};
///
///
/// // This is an adaptation of the example code provided in the doc comment
/// // for IcmpTimestampMsgPart, corrected to resolve the E0599 error.
/// // The actual code at src/icmp.rs:355 likely follows this pattern.
/// fn handle_icmp_timestamp(ctx: &TcContext) -> Result<u32, ()> {
///     // Parse the ICMP header from start of payload
///     let icmp_start = ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN;
///
///     // Boundary check: Ensure icmp_start is within packet bounds
///     // This check is simplified; a real check would involve ctx.data_end().
///     if icmp_start + IcmpHdr::LEN > ctx.data_end() {
///         // warn!(ctx, "ICMP header out of bounds");
///         return Err(());
///     }
///     let icmp: *const IcmpHdr = icmp_start as *const IcmpHdr;
///
///     // Check if it's a Timestamp message (type 13 or 14)
///     // Reading from a raw pointer is unsafe.
///     if unsafe { (*icmp).type_ } == 13 || unsafe { (*icmp).type_ } == 14 {
///         // Calculate pointer to the timestamp part
///         let timestamps_ptr_location = icmp_start + IcmpHdr::LEN;
///
///         // Boundary check: Ensure IcmpTimestampMsgPart is within packet bounds
///         if timestamps_ptr_location + IcmpTimestampMsgPart::LEN > ctx.data_end() {
///             // warn!(ctx, "ICMP timestamp message part out of bounds");
///             return Err(());
///         }
///
///         let timestamps_ptr: *const IcmpTimestampMsgPart = timestamps_ptr_location as *const IcmpTimestampMsgPart;
///
///         // Safely dereference the pointer to get a reference
///         match unsafe { timestamps_ptr.as_ref() } {
///             Some(timestamps_ref) => {
///                 // Now you can read the timestamps in network byte order
///                 let orig = timestamps_ref.originate_timestamp();
///                 let recv = timestamps_ref.receive_timestamp();
///                 let xmit = timestamps_ref.transmit_timestamp();
///
///                 // You can now use orig, recv, and xmit. For example, log them:
///                 // info!(ctx, "ICMP Timestamps: O={}, R={}, T={}", orig, recv, xmit);
///
///                 // Placeholder for further processing:
///                 // For example, return one of the timestamps or 0 for success.
///             }
///             None => {
///                 // This case implies timestamps_ptr was null.
///                 // While less common if pointer arithmetic is correct and data_end checks pass,
///                 // it's good practice to handle it.
///                 // warn!(ctx, "Failed to get reference to ICMP timestamps: pointer was null");
///                 return Err(());
///             }
///         }
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
///     // Ensure 'icmp' is within bounds before dereferencing.
///     // if (icmp as *const u8).add(IcmpHdr::LEN) > ctx.data_end() { return Err(()); }
///     if unsafe { (*icmp).type_ } == 30 {
///         // Access the traceroute part that follows the header
///         let traceroute_ptr: *const IcmpTracerouteMsgPart = unsafe {
///             (icmp_start as *const u8)
///                 .add(IcmpHdr::LEN) as *const IcmpTracerouteMsgPart
///         };
///
///         // Before dereferencing traceroute_ptr, ensure it's within packet bounds.
///         // For example:
///         // if (traceroute_ptr as *const u8).add(IcmpTracerouteMsgPart::LEN) > ctx.data_end() {
///         //     aya_log_ebpf::error!(ctx, "Traceroute part out of bounds");
///         //     return Err(());
///         // }
///
///         // Safely get a reference to IcmpTracerouteMsgPart
///         if let Some(traceroute_ref) = unsafe { traceroute_ptr.as_ref() } {
///             // Now you can read the traceroute fields in network byte order
///             let hops_out = traceroute_ref.hops_out();
///             let bandwidth = traceroute_ref.bandwidth_out();
///             let mtu = traceroute_ref.mtu_out();
///
///             // You can now use hops_out, bandwidth, mtu
///             // For example, in a real eBPF program, you might log them or store them in a map.
///             // aya_log_ebpf::info!(ctx, "Hops: {}, BW: {}, MTU: {}", hops_out, bandwidth, mtu);
///         } else {
///             // Handle the case where traceroute_ptr is null or misaligned.
///             // This indicates an issue, possibly a malformed packet.
///             // aya_log_ebpf::error!(ctx, "Failed to get reference to IcmpTracerouteMsgPart: pointer invalid");
///             return Err(()); // Or other appropriate error handling
///         }
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
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpV6Hdr {
    pub type_: u8,
    pub code: u8,
    pub check: [u8; 2],
    pub data: IcmpV6HdrUn,
}

/// Union holding the variable 4-byte field after the first 4 bytes of an ICMPv6 header.
/// The meaning of this field depends on the ICMPv6 type:
/// - `echo`: Used for Echo Request/Reply messages (Types: 128, 129)
/// - `packet_too_big_mtu`: Used in Packet Too Big messages (Type 2) to indicate next-hop MTU
/// - `param_problem_pointer`: Used in Parameter Problem messages (Type 4) to point to error location
/// - `reserved`: Generic 4-byte field for unused/reserved data in other message types
#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub union IcmpV6HdrUn {
    pub echo: IcmpEcho,
    pub packet_too_big_mtu: [u8; 4],
    pub param_problem_pointer: [u8; 4],
    pub redirect: IcmpV6Redirect,
    pub reserved: [u8; 4],
}

impl IcmpV6HdrUn {
    #[inline]
    unsafe fn mtu_unchecked(&self) -> u32 {
        getter_be!(self, packet_too_big_mtu, u32)
    }

    #[inline]
    unsafe fn set_mtu_unchecked(&mut self, mtu: u32) {
        setter_be!(self, packet_too_big_mtu, mtu)
    }

    #[inline]
    unsafe fn pointer_unchecked(&self) -> u32 {
        getter_be!(self, param_problem_pointer, u32)
    }

    #[inline]
    unsafe fn set_pointer_unchecked(&mut self, pointer: u32) {
        setter_be!(self, param_problem_pointer, pointer)
    }
}

impl core::fmt::Debug for IcmpV6HdrUn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Safe approach: just show the raw 4 bytes
        let bytes = unsafe { self.reserved };
        write!(
            f,
            "IcmpV6HdrUn([{:#04x}, {:#04x}, {:#04x}, {:#04x}])",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IcmpV6Redirect {
    reserved: [u8; 4],
    target_address: [u8; 16],
    destination_address: [u8; 16],
}

impl IcmpV6Hdr {
    pub const LEN: usize = mem::size_of::<IcmpV6Hdr>();

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

    /// Returns the identification field from ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn echo_id(&self) -> Result<u16, IcmpError> {
        if !matches!(self.type_, 128 | 129) {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.echo_id_unchecked() })
    }

    /// Sets the identification field for ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn set_echo_id(&mut self, id: u16) -> Result<(), IcmpError> {
        if !matches!(self.type_, 128 | 129) {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_echo_id_unchecked(id);
        }
        Ok(())
    }

    /// Returns the sequence number from ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn echo_sequence(&self) -> Result<u16, IcmpError> {
        if !matches!(self.type_, 128 | 129) {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.echo_sequence_unchecked() })
    }

    /// Sets the sequence number for ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    #[inline]
    pub fn set_echo_sequence(&mut self, sequence: u16) -> Result<(), IcmpError> {
        if !matches!(self.type_, 128 | 129) {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_echo_sequence_unchecked(sequence);
        }
        Ok(())
    }

    /// Returns the MTU field from an ICMPv6 Packet Too Big message (Type 2).
    /// This value indicates the maximum packet size that can be handled by the next hop.
    #[inline]
    pub fn mtu(&self) -> Result<u32, IcmpError> {
        if self.type_ != 2 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.mtu_unchecked() })
    }

    /// Sets the MTU field for an ICMPv6 Packet Too Big message (Type 2).
    /// This should be set to the maximum packet size that can be handled by the next hop.
    #[inline]
    pub fn set_mtu(&mut self, mtu: u32) -> Result<(), IcmpError> {
        if self.type_ != 2 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_mtu_unchecked(mtu);
        }
        Ok(())
    }

    /// Returns the pointer field from an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer indicates the offset within the invoking packet where the error was detected.
    #[inline]
    pub fn pointer(&self) -> Result<u32, IcmpError> {
        if self.type_ != 4 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.pointer_unchecked() })
    }

    /// Sets the pointer field for an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer should indicate the offset within the invoking packet where the error was detected.
    #[inline]
    pub fn set_pointer(&mut self, pointer: u32) -> Result<(), IcmpError> {
        if self.type_ != 4 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_pointer_unchecked(pointer);
        }
        Ok(())
    }

    /// Returns the 4-byte reserved field from an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be initialized to zeros by the sender.
    #[inline]
    pub fn redirect_reserved(&self) -> Result<[u8; 4], IcmpError> {
        if self.type_ != 137 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.redirect_reserved_unchecked() })
    }

    /// Sets the 4-byte reserved field for an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be set to zeros.
    #[inline]
    pub fn set_redirect_reserved(&mut self, reserved: [u8; 4]) -> Result<(), IcmpError> {
        if self.type_ != 137 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_redirect_reserved_unchecked(reserved);
        }
        Ok(())
    }

    /// Returns the Target Address from an ICMPv6 Redirect message (Type 137).
    /// This field contains the address that is a better first hop to use for the destination.
    #[inline]
    pub fn redirect_target_address(&self) -> Result<net::Ipv6Addr, IcmpError> {
        if self.type_ != 137 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.redirect_target_address_unchecked() })
    }

    /// Sets the Target Address for an ICMPv6 Redirect message (Type 137).
    /// This should be set to the address that is a better first hop to use for the destination.
    #[inline]
    pub fn set_redirect_target_address(&mut self, addr: net::Ipv6Addr) -> Result<(), IcmpError> {
        if self.type_ != 137 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_redirect_target_address_unchecked(addr);
        }
        Ok(())
    }

    /// Returns the Destination Address from an ICMPv6 Redirect message (Type 137).
    /// This field contains the IP address of the destination that is redirected to the target.
    #[inline]
    pub fn redirect_destination_address(&self) -> Result<net::Ipv6Addr, IcmpError> {
        if self.type_ != 137 {
            return Err(IcmpError::InvalidIcmpType);
        }
        Ok(unsafe { self.redirect_destination_address_unchecked() })
    }

    /// Sets the Destination Address for an ICMPv6 Redirect message (Type 137).
    /// This should be set to the IP address of the destination that is redirected to the target.
    #[inline]
    pub fn set_redirect_destination_address(
        &mut self,
        addr: net::Ipv6Addr,
    ) -> Result<(), IcmpError> {
        if self.type_ != 137 {
            return Err(IcmpError::InvalidIcmpType);
        }
        unsafe {
            self.set_redirect_destination_address_unchecked(addr);
        }
        Ok(())
    }
}

impl IcmpV6Hdr {
    /// Returns the identification field from ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling.
    /// Accessing echo fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn echo_id_unchecked(&self) -> u16 {
        self.data.echo.id_unchecked()
    }

    /// Sets the identification field for ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling.
    /// Accessing echo fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_echo_id_unchecked(&mut self, id: u16) {
        self.data.echo.set_id_unchecked(id);
    }

    /// Returns the sequence number from ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling.
    /// Accessing echo fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn echo_sequence_unchecked(&self) -> u16 {
        self.data.echo.sequence_unchecked()
    }

    /// Sets the sequence number for ICMPv6 Echo Request/Reply messages.
    /// Only valid for ICMPv6 Types: 128 (Echo Request), 129 (Echo Reply).
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 128 (Echo Request) or 129 (Echo Reply) before calling.
    /// Accessing echo fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_echo_sequence_unchecked(&mut self, sequence: u16) {
        self.data.echo.set_sequence_unchecked(sequence);
    }

    /// Returns the MTU field from an ICMPv6 Packet Too Big message (Type 2).
    /// This value indicates the maximum packet size that can be handled by the next hop.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 2 (Packet Too Big) before calling.
    /// Accessing MTU field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn mtu_unchecked(&self) -> u32 {
        self.data.mtu_unchecked()
    }

    /// Sets the MTU field for an ICMPv6 Packet Too Big message (Type 2).
    /// This should be set to the maximum packet size that can be handled by the next hop.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 2 (Packet Too Big) before calling.
    /// Accessing MTU field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_mtu_unchecked(&mut self, mtu: u32) {
        self.data.set_mtu_unchecked(mtu);
    }

    /// Returns the pointer field from an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer indicates the offset within the invoking packet where the error was detected.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 4 (Parameter Problem) before calling.
    /// Accessing pointer field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn pointer_unchecked(&self) -> u32 {
        self.data.pointer_unchecked()
    }

    /// Sets the pointer field for an ICMPv6 Parameter Problem message (Type 4).
    /// The pointer should indicate the offset within the invoking packet where the error was detected.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 4 (Parameter Problem) before calling.
    /// Accessing pointer field with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_pointer_unchecked(&mut self, pointer: u32) {
        self.data.set_pointer_unchecked(pointer);
    }

    /// Returns the 4-byte reserved field from an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be initialized to zeros by the sender.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn redirect_reserved_unchecked(&self) -> [u8; 4] {
        self.data.redirect.reserved
    }

    /// Sets the 4-byte reserved field for an ICMPv6 Redirect message (Type 137).
    /// This field is currently unused and MUST be set to zeros.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_redirect_reserved_unchecked(&mut self, reserved: [u8; 4]) {
        self.data.redirect.reserved = reserved;
    }

    /// Returns the Target Address from an ICMPv6 Redirect message (Type 137).
    /// This field contains the address that is a better first hop to use for the destination.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn redirect_target_address_unchecked(&self) -> net::Ipv6Addr {
        net::Ipv6Addr::from(unsafe { self.data.redirect.target_address })
    }

    /// Sets the Target Address for an ICMPv6 Redirect message (Type 137).
    /// This should be set to the address that is a better first hop to use for the destination.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_redirect_target_address_unchecked(&mut self, addr: net::Ipv6Addr) {
        self.data.redirect.target_address = addr.octets();
    }

    /// Returns the Destination Address from an ICMPv6 Redirect message (Type 137).
    /// This field contains the IP address of the destination that is redirected to the target.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn redirect_destination_address_unchecked(&self) -> net::Ipv6Addr {
        net::Ipv6Addr::from(unsafe { self.data.redirect.destination_address })
    }

    /// Sets the Destination Address for an ICMPv6 Redirect message (Type 137).
    /// This should be set to the IP address of the destination that is redirected to the target.
    ///
    /// # Safety
    /// Caller must ensure ICMPv6 type is 137 (Redirect) before calling.
    /// Accessing redirect fields with other types may result in undefined behavior.
    #[inline]
    pub unsafe fn set_redirect_destination_address_unchecked(&mut self, addr: net::Ipv6Addr) {
        self.data.redirect.destination_address = addr.octets();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;
    use core::net::Ipv4Addr;

    #[test]
    fn test_icmp_hdr_size() {
        // IcmpHdr should be exactly 8 bytes: type(1) + code(1) + check(2) + data(4)
        assert_eq!(IcmpHdr::LEN, 8);
        assert_eq!(IcmpHdr::LEN, mem::size_of::<IcmpHdr>());
    }

    // Helper function to create a default IcmpHdr for testing
    fn create_test_icmp_hdr() -> IcmpHdr {
        IcmpHdr {
            type_: 0,
            code: 0,
            check: [0, 0],
            data: IcmpHdrUn {
                reserved: [0, 0, 0, 0],
            },
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
        hdr.set_echo_id(test_id).unwrap();
        assert_eq!(hdr.echo_id().unwrap(), test_id);

        // Verify byte order in raw storage
        unsafe {
            assert_eq!(hdr.data.echo.id, test_id.to_be_bytes());
        }

        // Test echo sequence
        let test_seq: u16 = 0x8765;
        hdr.set_echo_sequence(test_seq).unwrap();
        assert_eq!(hdr.echo_sequence().unwrap(), test_seq);

        // Verify byte order in raw storage
        unsafe {
            assert_eq!(hdr.data.echo.sequence, test_seq.to_be_bytes());
        }
    }

    #[test]
    fn test_gateway_address() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Redirect (5) which is valid for gateway address
        hdr.type_ = 5;
        let test_addr = Ipv4Addr::new(192, 168, 1, 1);

        hdr.set_gateway_address(test_addr).unwrap();
        assert_eq!(hdr.gateway_address().unwrap(), test_addr);

        // Verify the raw bytes
        unsafe {
            assert_eq!(hdr.data.redirect, [192, 168, 1, 1]);
        }
    }

    #[test]
    fn test_next_hop_mtu() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Destination Unreachable (3) which is valid for next_hop_mtu
        hdr.type_ = 3;
        let test_mtu: u16 = 1500;

        hdr.set_next_hop_mtu(test_mtu).unwrap();
        assert_eq!(hdr.next_hop_mtu().unwrap(), test_mtu);

        // Verify byte order in raw storage
        unsafe {
            assert_eq!(hdr.data.dst_unreachable.mtu, test_mtu.to_be_bytes());
        }
    }

    #[test]
    fn test_parameter_pointer() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Parameter Problem (12) which is valid for parameter_pointer
        hdr.type_ = 12;
        let test_pointer: u8 = 42;

        hdr.set_parameter_pointer(test_pointer).unwrap();
        assert_eq!(hdr.parameter_pointer().unwrap(), test_pointer);

        // Verify the raw byte
        unsafe {
            assert_eq!(hdr.data.param_problem.pointer, test_pointer);
        }
    }

    #[test]
    fn test_traceroute_id() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to Traceroute (30) which is valid for traceroute_id
        hdr.type_ = 30;
        let test_id: u16 = 0x9876;

        hdr.set_traceroute_id(test_id).unwrap();
        assert_eq!(hdr.traceroute_id().unwrap(), test_id);

        // Verify byte order in raw storage
        unsafe {
            assert_eq!(hdr.data.traceroute.id, test_id.to_be_bytes());
        }
    }

    #[test]
    fn test_photuris_spi() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to PHOTURIS (40) which is valid for photuris_spi
        hdr.type_ = 40;
        let test_spi: u16 = 0xFEDC;

        hdr.set_photuris_spi(test_spi).unwrap();
        assert_eq!(hdr.photuris_spi().unwrap(), test_spi);

        // Verify byte order in raw storage
        unsafe {
            assert_eq!(hdr.data.photuris.reserved_spi, test_spi.to_be_bytes());
        }
    }

    #[test]
    fn test_photuris_pointer() {
        let mut hdr = create_test_icmp_hdr();
        // Set type to PHOTURIS (40) which is valid for photuris_pointer
        hdr.type_ = 40;
        let test_pointer: u16 = 0x1A2B;

        hdr.set_photuris_pointer(test_pointer).unwrap();
        assert_eq!(hdr.photuris_pointer().unwrap(), test_pointer);

        // Verify byte order in raw storage
        unsafe {
            assert_eq!(hdr.data.photuris.pointer, test_pointer.to_be_bytes());
        }
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
    fn test_union_field_access_safety() {
        // This test demonstrates that different union field accesses
        // manipulate the same memory
        let mut hdr = create_test_icmp_hdr();

        // Set type to Echo Reply (0) which is valid for echo_id
        hdr.type_ = 0;

        // Set echo ID and verify the memory is shared with redirect
        hdr.set_echo_id(0xABCD).unwrap();

        unsafe {
            assert_eq!(hdr.data.redirect[0], 0xAB);
            assert_eq!(hdr.data.redirect[1], 0xCD);
        }

        // Set type to Redirect (5) which is valid for gateway_address
        hdr.type_ = 5;

        // Set gateway address and verify it affects the echo ID
        hdr.set_gateway_address(Ipv4Addr::new(1, 2, 3, 4)).unwrap();

        // Set type back to Echo Reply (0) to check echo_id
        hdr.type_ = 0;
        assert_eq!(hdr.echo_id().unwrap(), 0x0102); // First two bytes of the IP address
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
        hdr.set_echo_id(0x1234).unwrap();
        hdr.set_echo_sequence(0x5678).unwrap();

        assert_eq!(hdr.type_, 8);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.echo_id().unwrap(), 0x1234);
        assert_eq!(hdr.echo_sequence().unwrap(), 0x5678);
    }

    #[test]
    fn test_icmp_destination_unreachable_construction() {
        // Test creating a Destination Unreachable message
        let mut hdr = create_test_icmp_hdr();

        hdr.type_ = 3; // Destination Unreachable
        hdr.code = 4; // Fragmentation needed but DF bit set
        hdr.set_checksum(0); // Would be calculated later

        // Destination Unreachable (type 3) is valid for next_hop_mtu
        hdr.set_next_hop_mtu(1400).unwrap(); // Example MTU value

        assert_eq!(hdr.type_, 3);
        assert_eq!(hdr.code, 4);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.next_hop_mtu().unwrap(), 1400);
    }

    #[test]
    fn test_icmp_parameter_problem_construction() {
        // Test creating a Parameter Problem message
        let mut hdr = create_test_icmp_hdr();

        hdr.type_ = 12; // Parameter Problem
        hdr.code = 0; // Pointer indicates the error
        hdr.set_checksum(0); // Would be calculated later

        // Parameter Problem (type 12) is valid for parameter_pointer
        hdr.set_parameter_pointer(20).unwrap(); // Error at byte offset 20

        assert_eq!(hdr.type_, 12);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.parameter_pointer().unwrap(), 20);
    }

    #[test]
    fn test_icmp_redirect_construction() {
        // Test creating a Redirect message
        let mut hdr = create_test_icmp_hdr();

        hdr.type_ = 5; // Redirect
        hdr.code = 1; // Redirect for host
        hdr.set_checksum(0); // Would be calculated later

        // Redirect (type 5) is valid for gateway_address
        hdr.set_gateway_address(Ipv4Addr::new(10, 0, 0, 1)).unwrap(); // Gateway address

        assert_eq!(hdr.type_, 5);
        assert_eq!(hdr.code, 1);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.gateway_address().unwrap(), Ipv4Addr::new(10, 0, 0, 1));
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
        // IcmpV6Hdr size includes the union which contains IcmpV6Redirect (largest variant)
        // type(1) + code(1) + check(2) + data(union with IcmpV6Redirect which is 36 bytes)
        assert_eq!(IcmpV6Hdr::LEN, 40);
        assert_eq!(IcmpV6Hdr::LEN, mem::size_of::<IcmpV6Hdr>());
    }

    // Helper function to create a default IcmpV6Hdr for testing
    fn create_test_icmpv6_hdr() -> IcmpV6Hdr {
        IcmpV6Hdr {
            type_: 0,
            code: 0,
            check: [0, 0],
            data: IcmpV6HdrUn {
                reserved: [0, 0, 0, 0],
            },
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
        unsafe {
            assert_eq!(hdr.data.echo.id, test_id.to_be_bytes());
        }

        // Test echo sequence
        let test_seq: u16 = 0x8765;
        hdr.set_echo_sequence(test_seq).unwrap();
        assert_eq!(hdr.echo_sequence().unwrap(), test_seq);

        // Verify byte order in raw storage
        unsafe {
            assert_eq!(hdr.data.echo.sequence, test_seq.to_be_bytes());
        }
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
        unsafe {
            assert_eq!(hdr.data.packet_too_big_mtu, test_mtu.to_be_bytes());
        }

        // Test with zero
        hdr.set_mtu(0).unwrap();
        assert_eq!(hdr.mtu().unwrap(), 0);
        unsafe {
            assert_eq!(hdr.data.packet_too_big_mtu, [0, 0, 0, 0]);
        }

        // Test with max value
        hdr.set_mtu(u32::MAX).unwrap();
        assert_eq!(hdr.mtu().unwrap(), u32::MAX);
        unsafe {
            assert_eq!(hdr.data.packet_too_big_mtu, [0xFF, 0xFF, 0xFF, 0xFF]);
        }
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
        unsafe {
            assert_eq!(hdr.data.param_problem_pointer, test_pointer.to_be_bytes());
        }

        // Test with zero
        hdr.set_pointer(0).unwrap();
        assert_eq!(hdr.pointer().unwrap(), 0);
        unsafe {
            assert_eq!(hdr.data.param_problem_pointer, [0, 0, 0, 0]);
        }

        // Test with max value
        hdr.set_pointer(u32::MAX).unwrap();
        assert_eq!(hdr.pointer().unwrap(), u32::MAX);
        unsafe {
            assert_eq!(hdr.data.param_problem_pointer, [0xFF, 0xFF, 0xFF, 0xFF]);
        }
    }

    #[test]
    fn test_icmpv6_redirect_fields() {
        use core::net::Ipv6Addr;
        let mut hdr = create_test_icmpv6_hdr();
        // Set type to Redirect (137) which is valid for redirect fields
        hdr.type_ = 137;

        // Test reserved field
        let test_reserved: [u8; 4] = [0, 0, 0, 0]; // Should be zeros per RFC
        hdr.set_redirect_reserved(test_reserved).unwrap();
        assert_eq!(hdr.redirect_reserved().unwrap(), test_reserved);

        // Test target address
        let test_target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        hdr.set_redirect_target_address(test_target).unwrap();
        assert_eq!(hdr.redirect_target_address().unwrap(), test_target);

        // Test destination address
        let test_dest = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        hdr.set_redirect_destination_address(test_dest).unwrap();
        assert_eq!(hdr.redirect_destination_address().unwrap(), test_dest);

        // Verify raw byte storage for target address
        unsafe {
            assert_eq!(hdr.data.redirect.target_address, test_target.octets());
        }

        // Verify raw byte storage for destination address
        unsafe {
            assert_eq!(hdr.data.redirect.destination_address, test_dest.octets());
        }
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
