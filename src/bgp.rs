//! BGP (Border Gateway Protocol) packet parsing and manipulation.
//!
//! This module provides types for creating, parsing, and modifying
//! BGP packets, designed for efficiency and use in `no_std` environments
//! like eBPF. It supports standard BGP message types: OPEN, UPDATE,
//! NOTIFICATION, KEEPALIVE, and ROUTE_REFRESH.
//!
//! The main entry point is [`BgpHdr`], which represents the BGP common
//! header and provides access to the message-specific payloads through
//! a union. For variable-length messages like UPDATE, additional
//! "view" and "iterator" types are provided for safe and efficient
//! access to dynamic content (e.g., withdrawn routes, path attributes).
//!
//! # Example: Creating a KEEPALIVE message
//! ```
//! # use network_types::bgp::{BgpHdr, BgpMsgType};
//! // Create a new BGP header for a KEEPALIVE message
//! let mut hdr = BgpHdr::new(BgpMsgType::KeepAlive);
//!
//! // The length is automatically set to the minimum for a KEEPALIVE (19 bytes)
//! assert_eq!(hdr.length(), 19);
//! assert_eq!(hdr.msg_type(), Ok(BgpMsgType::KeepAlive));
//!
//! // The marker is initialized to all 0xFFs by default
//! assert_eq!(hdr.marker, [0xff; 16]);
//! ```
//!
//! # Example: Parsing an OPEN message
//! ```
//! # use network_types::bgp::{BgpHdr, BgpMsgType, OpenMsgLayout};
//! # use core::mem;
//! // A buffer containing a raw BGP OPEN message
//! let mut buf = [0u8; mem::size_of::<BgpHdr>()];
//!
//! // Construct a header for an OPEN message
//! let mut open_hdr = BgpHdr::new(BgpMsgType::Open);
//! open_hdr.as_open_mut().unwrap().set_my_as(64512);
//! open_hdr.as_open_mut().unwrap().set_bgp_id(0xc0a80101); // 192.168.1.1
//!
//! // Pretend we received these bytes from the network
//! let hdr_bytes: &[u8] = unsafe {
//!     core::slice::from_raw_parts(
//!         &open_hdr as *const _ as *const u8,
//!         mem::size_of::<BgpHdr>(),
//!     )
//! };
//! buf.copy_from_slice(hdr_bytes);
//!
//! // Get a pointer to the header from the buffer
//! let hdr: *const BgpHdr = buf.as_ptr() as *const _;
//!
//! // Safely access the payload
//! unsafe {
//!     assert_eq!((*hdr).msg_type(), Ok(BgpMsgType::Open));
//!     let open_msg = (*hdr).as_open().unwrap();
//!     assert_eq!(open_msg.my_as(), 64512);
//!     assert_eq!(open_msg.bgp_id(), 0xc0a80101);
//! }
//! ```

#![allow(clippy::len_without_is_empty)]

use core::{convert::TryFrom, iter::FusedIterator, mem, mem::size_of, ptr};

/// The length of the BGP common header in bytes (16-byte marker + 2-byte length + 1-byte type).
pub const COMMON_HDR_LEN: usize = 19;

/// Returns the compile‑time payload length for a given message type.
#[inline(always)]
const fn payload_len(mt: BgpMsgType) -> usize {
    match mt {
        BgpMsgType::Open => OpenMsgLayout::LEN,
        BgpMsgType::Update => UpdateInitialMsgLayout::LEN,
        BgpMsgType::Notification => NotificationMsgLayout::LEN,
        BgpMsgType::KeepAlive => KeepAliveMsgLayout::LEN,
        BgpMsgType::RouteRefresh => RouteRefreshMsgLayout::LEN,
    }
}

/// Reads a big‑endian `u16` from a slice without creating a temporary array.
#[inline(always)]
const fn read_u16_be(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | (b[1] as u16)
}

/// Reads a big‑endian `u32` from a slice without creating a temporary array.
#[inline(always)]
const fn read_u32_be(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | (b[3] as u32)
}

/// Error types that can occur during BGP message parsing or manipulation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BgpError {
    /// A method requiring a specific BGP message type was invoked on another
    /// type. The enclosed `u8` is the actual type encountered.
    IncorrectMessageType(u8),
    /// The supplied slice is too small for the requested operation.
    BufferTooShort,
}

impl core::fmt::Display for BgpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BgpError::IncorrectMessageType(t) => {
                write!(f, "incorrect BGP message type for operation: {}", t)
            }
            BgpError::BufferTooShort => write!(f, "buffer too short for operation"),
        }
    }
}

/// The type of BGP message, as specified in the common header.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum BgpMsgType {
    /// OPEN message, used to establish a BGP session.
    Open = 1,
    /// UPDATE message, used to transfer routing information.
    Update = 2,
    /// NOTIFICATION message, used to report errors.
    Notification = 3,
    /// KEEPALIVE message, used to maintain the BGP session.
    KeepAlive = 4,
    /// ROUTE_REFRESH message, used to request dynamic route updates.
    RouteRefresh = 5,
}

impl TryFrom<u8> for BgpMsgType {
    type Error = BgpError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Open),
            2 => Ok(Self::Update),
            3 => Ok(Self::Notification),
            4 => Ok(Self::KeepAlive),
            5 => Ok(Self::RouteRefresh),
            _ => Err(BgpError::IncorrectMessageType(v)),
        }
    }
}

/// Represents the fixed-size layout of a BGP OPEN message payload.
///
/// This structure provides methods for safely accessing and modifying the fields
/// of an OPEN message, handling byte order conversions automatically.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct OpenMsgLayout {
    /// BGP protocol version number. The current version is 4.
    pub version: u8,
    /// The Autonomous System (AS) number of the sender. Stored in big-endian format.
    pub my_as: [u8; 2],
    /// The proposed time in seconds between KEEPALIVE messages. Stored in big-endian format.
    pub hold_time: [u8; 2],
    /// A BGP Identifier of the sender, typically the router's IP address. Stored in big-endian format.
    pub bgp_id: [u8; 4],
    /// The total length of the Optional Parameters field in octets.
    pub opt_parm_len: u8,
}

impl OpenMsgLayout {
    /// The size of the `OpenMsgLayout` struct in bytes.
    pub const LEN: usize = size_of::<Self>();

    /// Gets the BGP version.
    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the BGP version.
    #[inline(always)]
    pub fn set_version(&mut self, v: u8) {
        self.version = v;
    }

    /// Gets the Autonomous System (AS) number.
    #[inline(always)]
    pub fn my_as(&self) -> u16 {
        read_u16_be(&self.my_as)
    }

    /// Sets the Autonomous System (AS) number.
    #[inline(always)]
    pub fn set_my_as(&mut self, asn: u16) {
        self.my_as = asn.to_be_bytes();
    }

    /// Gets the hold time in seconds.
    #[inline(always)]
    pub fn hold_time(&self) -> u16 {
        read_u16_be(&self.hold_time)
    }

    /// Sets the hold time in seconds.
    #[inline(always)]
    pub fn set_hold_time(&mut self, ht: u16) {
        self.hold_time = ht.to_be_bytes();
    }

    /// Gets the BGP identifier.
    #[inline(always)]
    pub fn bgp_id(&self) -> u32 {
        read_u32_be(&self.bgp_id)
    }

    /// Sets the BGP identifier.
    #[inline(always)]
    pub fn set_bgp_id(&mut self, id: u32) {
        self.bgp_id = id.to_be_bytes();
    }

    /// Gets the length of the optional parameters field.
    #[inline(always)]
    pub fn opt_parm_len(&self) -> u8 {
        self.opt_parm_len
    }

    /// Sets the length of the optional parameters field.
    #[inline(always)]
    pub fn set_opt_parm_len(&mut self, l: u8) {
        self.opt_parm_len = l;
    }
}

/// Represents the initial, fixed-size part of a BGP UPDATE message payload.
///
/// An UPDATE message is composed of several variable-length fields. This struct
/// represents the first field, which specifies the length of the withdrawn routes list.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct UpdateInitialMsgLayout {
    /// The total length of the Withdrawn Routes field in octets. Stored in big-endian format.
    pub withdrawn_routes_length: [u8; 2],
}

impl UpdateInitialMsgLayout {
    /// The size of the `UpdateInitialMsgLayout` struct in bytes.
    pub const LEN: usize = size_of::<Self>();

    /// Gets the length of the withdrawn routes field.
    #[inline(always)]
    pub fn get_withdrawn_routes_length(&self) -> u16 {
        read_u16_be(&self.withdrawn_routes_length)
    }

    /// Sets the length of the withdrawn routes field.
    #[inline(always)]
    pub fn set_withdrawn_routes_length(&mut self, len: u16) {
        self.withdrawn_routes_length = len.to_be_bytes();
    }
}

impl Default for UpdateInitialMsgLayout {
    fn default() -> Self {
        Self {
            withdrawn_routes_length: [0; 2],
        }
    }
}

/// A view into a withdrawn route entry in a BGP UPDATE message.
///
/// This represents a single IP prefix being withdrawn from service.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct WithdrawnRoute<'a> {
    /// The length of the IP prefix in bits.
    pub length_bits: u8,
    /// A slice containing the IP prefix itself.
    pub prefix: &'a [u8],
}

/// An iterator over withdrawn routes in a BGP UPDATE message.
///
/// This iterator parses the Withdrawn Routes field of an UPDATE message on-the-fly.
#[derive(Debug, Clone)]
pub struct WithdrawnRoutesIterator<'a> {
    buffer: &'a [u8],
}

impl<'a> WithdrawnRoutesIterator<'a> {
    /// Creates a new iterator over the given buffer.
    ///
    /// # Parameters
    /// * `buffer`: A slice containing the raw bytes of the Withdrawn Routes field.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }
}

impl<'a> Iterator for WithdrawnRoutesIterator<'a> {
    type Item = WithdrawnRoute<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }
        let length_bits = self.buffer[0];
        let prefix_len_bytes = ((length_bits as usize) + 7) >> 3;
        let total = 1 + prefix_len_bytes;
        if self.buffer.len() < total {
            self.buffer = &[]; // Exhaust the iterator on malformed data
            return None;
        }
        let prefix = &self.buffer[1..total];
        self.buffer = &self.buffer[total..];
        Some(WithdrawnRoute {
            length_bits,
            prefix,
        })
    }
}

impl<'a> FusedIterator for WithdrawnRoutesIterator<'a> {}

/// A view into a BGP Path Attribute.
///
/// Path Attributes are used in UPDATE messages to convey information about network paths.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PathAttributeView<'a> {
    /// Attribute flags (Optional, Transitive, Partial, Extended Length).
    pub flags: u8,
    /// The type code of the attribute (e.g., ORIGIN, AS_PATH, NEXT_HOP).
    pub type_code: u8,
    /// A slice containing the value of the attribute.
    pub value: &'a [u8],
}

impl<'a> PathAttributeView<'a> {
    /// Checks if the Optional bit is set. Optional attributes do not need to be
    /// recognized by all BGP implementations.
    #[inline(always)]
    pub fn is_optional(&self) -> bool {
        (self.flags & 0x80) != 0
    }

    /// Checks if the Transitive bit is set. Transitive attributes should be passed
    /// along to other BGP neighbors, even if not recognized.
    #[inline(always)]
    pub fn is_transitive(&self) -> bool {
        (self.flags & 0x40) != 0
    }

    /// Checks if the Partial bit is set. This is set by a BGP speaker that recognizes
    /// a transitive attribute but has modified it.
    #[inline(always)]
    pub fn is_partial(&self) -> bool {
        (self.flags & 0x20) != 0
    }

    /// Checks if the Extended Length bit is set. If set, the attribute length field
    /// is 2 octets; otherwise, it is 1 octet.
    #[inline(always)]
    pub fn is_extended_length(&self) -> bool {
        (self.flags & 0x10) != 0
    }
}

/// An iterator over path attributes in a BGP UPDATE message.
///
/// This iterator parses the Path Attributes field of an UPDATE message on-the-fly.
#[derive(Debug, Clone)]
pub struct PathAttributeIterator<'a> {
    buffer: &'a [u8],
}

impl<'a> PathAttributeIterator<'a> {
    /// Creates a new path attribute iterator over the given buffer.
    ///
    /// # Parameters
    /// * `buffer`: A slice containing the raw bytes of the Total Path Attributes field.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }
}

impl<'a> Iterator for PathAttributeIterator<'a> {
    type Item = PathAttributeView<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() < 2 {
            return None;
        }
        let flags = self.buffer[0];
        let type_code = self.buffer[1];
        let is_ext = (flags & 0x10) != 0;
        let (len, hdr_len) = if is_ext {
            if self.buffer.len() < 4 {
                return None;
            }
            (read_u16_be(&self.buffer[2..]) as usize, 4)
        } else {
            if self.buffer.len() < 3 {
                return None;
            }
            (self.buffer[2] as usize, 3)
        };
        let end = hdr_len + len;
        if self.buffer.len() < end {
            self.buffer = &[]; // Exhaust iterator on malformed data
            return None;
        }
        let val = &self.buffer[hdr_len..end];
        self.buffer = &self.buffer[end..];
        Some(PathAttributeView {
            flags,
            type_code,
            value: val,
        })
    }
}

impl<'a> FusedIterator for PathAttributeIterator<'a> {}

/// A read-only view over a BGP UPDATE message's variable-length payload.
///
/// This view provides safe access to the different sections of an UPDATE message
/// that follow the initial fixed-size layout.
#[derive(Debug, Copy, Clone)]
pub struct UpdateMessageView<'a> {
    buffer: &'a [u8],
}

impl<'a> UpdateMessageView<'a> {
    /// Creates a new `UpdateMessageView` from a buffer.
    ///
    /// # Parameters
    /// * `buffer`: A slice containing the BGP UPDATE message payload, starting *after*
    ///   the common BGP header.
    ///
    /// # Returns
    /// `Some(UpdateMessageView)` if the buffer is large enough for the initial layout,
    /// `None` otherwise.
    pub fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() < UpdateInitialMsgLayout::LEN {
            return None;
        }
        Some(Self { buffer })
    }

    /// Reads the initially fixed layout (unaligned-safe).
    #[inline(always)]
    fn initial_layout(&self) -> UpdateInitialMsgLayout {
        // Safety: The `new` method ensures the buffer is long enough to read `UpdateInitialMsgLayout`.
        unsafe { ptr::read_unaligned(self.buffer.as_ptr() as *const _) }
    }

    /// Returns an iterator over the withdrawn routes.
    ///
    /// The iterator will be empty if the withdrawn routes length is zero. It may
    /// also stop early if the buffer is shorter than indicated by the length field.
    pub fn withdrawn_routes_iter(&self) -> WithdrawnRoutesIterator<'a> {
        let len = self.initial_layout().get_withdrawn_routes_length() as usize;
        let start = UpdateInitialMsgLayout::LEN;
        let end = start.saturating_add(len);
        let buf = if end > self.buffer.len() {
            // Provide a potentially truncated buffer; the iterator will handle it.
            &self.buffer[start..]
        } else {
            &self.buffer[start..end]
        };
        WithdrawnRoutesIterator::new(buf)
    }

    /// Returns an iterator over the path attributes.
    ///
    /// # Returns
    /// `Some(PathAttributeIterator)` if path attributes are present and the buffer
    /// is large enough to contain their length field. `None` otherwise.
    pub fn path_attributes_iter(&self) -> Option<PathAttributeIterator<'a>> {
        let withdrawn_len = self.initial_layout().get_withdrawn_routes_length() as usize;
        let offset = UpdateInitialMsgLayout::LEN + withdrawn_len;
        if self.buffer.len() < offset + 2 {
            return None;
        }
        let block_len = read_u16_be(&self.buffer[offset..]) as usize;
        if block_len == 0 {
            // No path attributes are present.
            return None;
        }
        let start = offset + 2;
        let end = start + block_len;
        if end > self.buffer.len() {
            // Buffer is too short to contain the advertised path attributes.
            return None;
        }
        Some(PathAttributeIterator::new(&self.buffer[start..end]))
    }

    /// Returns a slice containing the Network Layer Reachability Information (NLRI).
    ///
    /// The NLRI field contains the list of new routes being advertised.
    ///
    /// # Returns
    /// `Some(&[u8])` containing the NLRI data, or `None` if the message is too short
    /// to contain the path attributes and NLRI fields.
    pub fn nlri(&self) -> Option<&'a [u8]> {
        let withdrawn_len = self.initial_layout().get_withdrawn_routes_length() as usize;
        let offset = UpdateInitialMsgLayout::LEN + withdrawn_len;
        if self.buffer.len() < offset + 2 {
            return None;
        }
        let pa_len = read_u16_be(&self.buffer[offset..]) as usize;
        if pa_len == 0 {
            // This case might be ambiguous, but if pa_len is 0, start is where NLRI begins.
            let start = offset + 2;
            if start > self.buffer.len() {
                return None;
            }
            return Some(&self.buffer[start..]);
        }
        let start = offset + 2 + pa_len;
        if start > self.buffer.len() {
            return None;
        }
        Some(&self.buffer[start..])
    }
}

/// A helper for writing BGP prefixes into a buffer.
///
/// This is used for constructing the Withdrawn Routes and NLRI fields of an UPDATE message.
pub struct PrefixWriter<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> PrefixWriter<'a> {
    /// Creates a new `PrefixWriter` for the given buffer.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Appends a prefix to the buffer.
    ///
    /// A prefix is encoded as `(length_in_bits, prefix_bytes)`.
    ///
    /// # Parameters
    /// * `length_bits`: The length of the prefix in bits.
    /// * `prefix`: A slice containing the prefix bytes. Its length must match the
    ///   byte-length calculated from `length_bits`.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error message if the buffer is too small or the
    /// prefix length is incorrect.
    pub fn push(&mut self, length_bits: u8, prefix: &[u8]) -> Result<(), &'static str> {
        let prefix_bytes = ((length_bits as usize) + 7) >> 3;
        if prefix.len() != prefix_bytes {
            return Err("prefix byte length does not match bit-length");
        }
        let record_len = 1 + prefix_bytes;
        if self.cursor + record_len > self.buffer.len() {
            return Err("buffer too small for new prefix");
        }
        let dst = &mut self.buffer[self.cursor..self.cursor + record_len];
        dst[0] = length_bits;
        dst[1..].copy_from_slice(prefix);
        self.cursor += record_len;
        Ok(())
    }
}

/// A helper for writing BGP path attributes into a buffer.
pub struct PathAttributeWriter<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> PathAttributeWriter<'a> {
    /// Creates a new `PathAttributeWriter` for the given buffer.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Appends a path attribute to the buffer.
    ///
    /// This method automatically handles setting the "Extended Length" flag if the
    /// attribute value is longer than 255 bytes.
    ///
    /// # Parameters
    /// * `flags`: The attribute flags (Optional, Transitive, Partial). The Extended Length
    ///   bit will be set automatically if needed.
    /// * `type_code`: The attribute type code.
    /// * `value`: The attribute value.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error message if the buffer is too small.
    pub fn push(&mut self, flags: u8, type_code: u8, value: &[u8]) -> Result<(), &'static str> {
        let is_ext = value.len() > 255;
        let flags = if is_ext { flags | 0x10 } else { flags };
        let len_field = if is_ext { 2 } else { 1 };
        let header = 2 + len_field;
        let total = header + value.len();
        if self.cursor + total > self.buffer.len() {
            return Err("buffer too small for new path attribute");
        }
        let dst = &mut self.buffer[self.cursor..self.cursor + total];
        dst[0] = flags;
        dst[1] = type_code;
        if is_ext {
            dst[2..4].copy_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            dst[2] = value.len() as u8;
        }
        dst[header..].copy_from_slice(value);

        self.cursor += total;
        Ok(())
    }
}

/// A helper for constructing the body of a BGP UPDATE message.
///
/// This writer helps structure the complex, variable-length payload of an UPDATE message.
pub struct UpdateMessageWriter<'a> {
    buffer: &'a mut [u8],
}

impl<'a> UpdateMessageWriter<'a> {
    /// Creates a new `UpdateMessageWriter` from a buffer.
    ///
    /// The buffer must be large enough to hold at least the two length fields
    /// (Withdrawn Routes Length and Total Path Attributes Length), which is 4 bytes.
    ///
    /// # Parameters
    /// * `buffer`: The mutable slice where the UPDATE message payload will be written.
    ///
    /// # Returns
    /// `Some(UpdateMessageWriter)` on success, `None` if the buffer is too small.
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < 4 {
            None
        } else {
            Some(Self { buffer })
        }
    }

    /// Prepares the UPDATE message structure and returns writers for its sections.
    ///
    /// This method writes the `Withdrawn Routes Length` and `Total Path Attribute Length`
    /// fields into the buffer and then provides three section-specific writers.
    ///
    /// # Parameters
    /// * `withdrawn_len`: The total length in bytes of the withdrawn routes section.
    /// * `path_attr_len`: The total length in bytes of the path attributes section.
    ///
    /// # Returns
    /// A `Result` containing a tuple of writers for:
    /// 1. Withdrawn Routes (`PrefixWriter`)
    /// 2. Path Attributes (`PathAttributeWriter`)
    /// 3. NLRI (`PrefixWriter`)
    ///
    /// Returns an error if the provided lengths exceed the buffer's capacity.
    pub fn structure(
        &mut self,
        withdrawn_len: u16,
        path_attr_len: u16,
    ) -> Result<(PrefixWriter<'_>, PathAttributeWriter<'_>, PrefixWriter<'_>), &'static str> {
        let w = withdrawn_len as usize;
        let p = path_attr_len as usize;
        // 2 bytes for withdrawn_len, 2 for path_attr_len
        let need = 2 + w + 2 + p;
        if self.buffer.len() < need {
            return Err("provided lengths exceed buffer");
        }
        // write lengths
        self.buffer[0..2].copy_from_slice(&withdrawn_len.to_be_bytes());
        let pa_off = 2 + w;
        self.buffer[pa_off..pa_off + 2].copy_from_slice(&path_attr_len.to_be_bytes());
        // create writers for sections
        let (wr_buf, rest) = self.buffer[2..].split_at_mut(w);
        let (pa_buf, nlri_buf) = rest[2..].split_at_mut(p);
        Ok((
            PrefixWriter::new(wr_buf),
            PathAttributeWriter::new(pa_buf),
            PrefixWriter::new(nlri_buf),
        ))
    }
}

/// Represents the layout of a BGP NOTIFICATION message payload.
///
/// This message is sent to report errors.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotificationMsgLayout {
    /// Indicates the type of error.
    pub error_code: u8,
    /// Provides more specific information about the reported error.
    pub error_subcode: u8,
}
impl NotificationMsgLayout {
    /// The size of the `NotificationMsgLayout` struct in bytes.
    pub const LEN: usize = size_of::<Self>();

    /// Gets the error code.
    #[inline(always)]
    pub fn error_code(&self) -> u8 {
        self.error_code
    }
    /// Sets the error code.
    #[inline(always)]
    pub fn set_error_code(&mut self, c: u8) {
        self.error_code = c;
    }
    /// Gets the error subcode.
    #[inline(always)]
    pub fn error_subcode(&self) -> u8 {
        self.error_subcode
    }
    /// Sets the error subcode.
    #[inline(always)]
    pub fn set_error_subcode(&mut self, s: u8) {
        self.error_subcode = s;
    }
}

/// Represents the layout of a BGP KEEPALIVE message payload.
///
/// A KEEPALIVE message has no payload, so this is a zero-sized struct.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct KeepAliveMsgLayout {}
impl KeepAliveMsgLayout {
    /// The size of the `KeepAliveMsgLayout` struct in bytes (which is 0).
    pub const LEN: usize = size_of::<Self>();
}

/// Represents the layout of a BGP ROUTE-REFRESH message payload.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct RouteRefreshMsgLayout {
    /// Address Family Identifier (e.g., IPv4, IPv6). Stored in big-endian format.
    pub afi: [u8; 2],
    /// This field is reserved and should be set to 0.
    pub _reserved: u8,
    /// Subsequent Address Family Identifier (e.g., Unicast, Multicast).
    pub safi: u8,
}
impl RouteRefreshMsgLayout {
    /// The size of the `RouteRefreshMsgLayout` struct in bytes.
    pub const LEN: usize = mem::size_of::<Self>();

    /// Gets the Address Family Identifier (AFI).
    #[inline(always)]
    pub fn afi(&self) -> u16 {
        read_u16_be(&self.afi)
    }
    /// Sets the Address Family Identifier (AFI).
    #[inline(always)]
    pub fn set_afi(&mut self, afi: u16) {
        self.afi = afi.to_be_bytes();
    }

    /// Gets the reserved field.
    #[inline(always)]
    pub fn res(&self) -> u8 {
        self._reserved
    }
    /// Sets the reserved field.
    #[inline(always)]
    pub fn set_res(&mut self, r: u8) {
        self._reserved = r;
    }

    /// Gets the Subsequent Address Family Identifier (SAFI).
    #[inline(always)]
    pub fn safi(&self) -> u8 {
        self.safi
    }
    /// Sets the Subsequent Address Family Identifier (SAFI).
    #[inline(always)]
    pub fn set_safi(&mut self, s: u8) {
        self.safi = s;
    }
}

/// A union holding the payload for any BGP message type.
///
/// This allows `BgpHdr` to store the fixed-size portion of any BGP message
/// payload in a memory-efficient way. Access to the variants should be
/// guarded by a check of the message type.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union BgpMsgUn {
    /// Payload for an OPEN message.
    pub open: OpenMsgLayout,
    /// Initial payload for an UPDATE message.
    pub update: UpdateInitialMsgLayout,
    /// Payload for a NOTIFICATION message.
    pub notification: NotificationMsgLayout,
    /// Payload for a KEEPALIVE message (zero-sized).
    pub keep_alive: KeepAliveMsgLayout,
    /// Payload for a ROUTE-REFRESH message.
    pub route_refresh: RouteRefreshMsgLayout,
}

impl Default for BgpMsgUn {
    fn default() -> Self {
        Self {
            open: OpenMsgLayout::default(),
        }
    }
}

/// Represents a BGP message header and its fixed-size payload part.
///
/// This struct provides a unified interface for working with different BGP messages.
/// It contains the common header fields (marker, length, type) and a union (`BgpMsgUn`)
/// for the initial, fixed-size part of the message payload.
///
/// For messages with variable-length data (like UPDATE), you must use other "view"
/// types (e.g., `UpdateMessageView`) to parse the data that follows this header.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct BgpHdr {
    /// 16-byte field to detect mis-synchronization; must be all ones.
    pub marker: [u8; 16],
    /// Total length of the BGP message in octets, including the header. Stored in big-endian format.
    pub length: [u8; 2],
    /// The type of BGP message. See `BgpMsgType`.
    pub msg_type: u8,
    /// A union containing the fixed-size portion of the message-specific data.
    pub data: BgpMsgUn,
}

impl BgpHdr {
    /// The size of the `BgpHdr` struct in bytes. This is the minimum possible
    /// BGP message length (for a KEEPALIVE).
    pub const LEN: usize = mem::size_of::<Self>();

    /// Creates a new `BgpHdr` for the specified message type.
    ///
    /// It initializes the marker to all `0xFF`, sets the message type, calculates
    /// the initial total length based on the message type's fixed payload size,
    /// and zero-initializes the payload data.
    ///
    /// # Parameters
    /// * `msg_type`: The `BgpMsgType` for the new header.
    pub fn new(msg_type: BgpMsgType) -> Self {
        let total_len = (COMMON_HDR_LEN + payload_len(msg_type)) as u16;
        let data = match msg_type {
            BgpMsgType::Open => BgpMsgUn {
                open: OpenMsgLayout::default(),
            },
            BgpMsgType::Update => BgpMsgUn {
                update: UpdateInitialMsgLayout::default(),
            },
            BgpMsgType::Notification => BgpMsgUn {
                notification: NotificationMsgLayout::default(),
            },
            BgpMsgType::KeepAlive => BgpMsgUn {
                keep_alive: KeepAliveMsgLayout::default(),
            },
            BgpMsgType::RouteRefresh => BgpMsgUn {
                route_refresh: RouteRefreshMsgLayout::default(),
            },
        };

        Self {
            marker: [0xff; 16],
            length: total_len.to_be_bytes(),
            msg_type: msg_type as u8,
            data,
        }
    }

    /// Sets the 16-byte marker field to all ones, as required by the BGP specification.
    #[inline(always)]
    pub fn set_marker_to_ones(&mut self) {
        self.marker = [0xff; 16];
    }

    /// Gets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn length(&self) -> u16 {
        read_u16_be(&self.length)
    }

    /// Sets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn set_length(&mut self, l: u16) {
        self.length = l.to_be_bytes();
    }

    /// Gets the raw message type as a `u8`.
    #[inline(always)]
    pub fn msg_type_raw(&self) -> u8 {
        self.msg_type
    }

    /// Gets the message type as a `BgpMsgType` enum.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the type is valid, or `Err(BgpError::IncorrectMessageType)`
    /// if the raw type byte is not a known BGP message type.
    #[inline(always)]
    pub fn msg_type(&self) -> Result<BgpMsgType, BgpError> {
        BgpMsgType::try_from(self.msg_type)
    }

    /// Sets the message type from a `BgpMsgType` enum.
    #[inline(always)]
    pub fn set_msg_type(&mut self, t: BgpMsgType) {
        self.msg_type = t as u8;
    }

    /// Sets the raw message type from a `u8`.
    #[inline(always)]
    pub fn set_msg_type_raw(&mut self, t: u8) {
        self.msg_type = t;
    }

    /// Returns an immutable reference to the `OpenMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a reference to `OpenMsgLayout` if the message type is `Open`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_open(&self) -> Result<&OpenMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Open as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &self.data.open })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the `OpenMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a mutable reference to `OpenMsgLayout` if the message type is `Open`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_open_mut(&mut self) -> Result<&mut OpenMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Open as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &mut self.data.open })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns an immutable reference to the `UpdateInitialMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a reference to `UpdateInitialMsgLayout` if the message type is `Update`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_update(&self) -> Result<&UpdateInitialMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Update as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &self.data.update })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the `UpdateInitialMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a mutable reference to `UpdateInitialMsgLayout` if the message type is `Update`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_update_mut(&mut self) -> Result<&mut UpdateInitialMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Update as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &mut self.data.update })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns an immutable reference to the `NotificationMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a reference to `NotificationMsgLayout` if the message type is `Notification`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_notification(&self) -> Result<&NotificationMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Notification as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &self.data.notification })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the `NotificationMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a mutable reference to `NotificationMsgLayout` if the message type is `Notification`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_notification_mut(&mut self) -> Result<&mut NotificationMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Notification as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &mut self.data.notification })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns an immutable reference to the `KeepAliveMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a reference to `KeepAliveMsgLayout` if the message type is `KeepAlive`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_keep_alive(&self) -> Result<&KeepAliveMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::KeepAlive as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &self.data.keep_alive })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the `KeepAliveMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a mutable reference to `KeepAliveMsgLayout` if the message type is `KeepAlive`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_keep_alive_mut(&mut self) -> Result<&mut KeepAliveMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::KeepAlive as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &mut self.data.keep_alive })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns an immutable reference to the `RouteRefreshMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a reference to `RouteRefreshMsgLayout` if the message type is `RouteRefresh`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_route_refresh(&self) -> Result<&RouteRefreshMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::RouteRefresh as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &self.data.route_refresh })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the `RouteRefreshMsgLayout` payload.
    ///
    /// # Returns
    /// A `Result` containing a mutable reference to `RouteRefreshMsgLayout` if the message type is `RouteRefresh`,
    /// or `BgpError::IncorrectMessageType` otherwise.
    #[inline(always)]
    pub fn as_route_refresh_mut(&mut self) -> Result<&mut RouteRefreshMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::RouteRefresh as u8 {
            // Safety: The message type has been checked to match the accessed union field.
            Ok(unsafe { &mut self.data.route_refresh })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Reads the Total Path Attribute Length field from an UPDATE message.
    ///
    /// This requires access to the full message buffer, as this field is located
    /// after the withdrawn routes list, which is variable in length.
    ///
    /// # Parameters
    /// * `msg`: A slice representing the entire BGP message.
    ///
    /// # Returns
    /// `Some(u16)` with the length if successful, `None` if the message is not an UPDATE
    /// or the buffer is too short.
    #[inline(always)]
    pub fn update_total_path_attr_len(&self, msg: &[u8]) -> Option<u16> {
        if self.msg_type != BgpMsgType::Update as u8 {
            return None;
        }
        // Safety: The message type has been checked to be Update, so accessing the `update` union field is safe.
        let wrl = read_u16_be(unsafe { &self.data.update.withdrawn_routes_length });
        let off = COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN + wrl as usize;
        if msg.len() < off + 2 {
            return None;
        }
        Some(read_u16_be(&msg[off..]))
    }

    /// Sets the Total Path Attribute Length field in an UPDATE message.
    ///
    /// This requires access to the full message buffer, as this field is located
    /// after the withdrawn routes list, which is variable in length.
    ///
    /// # Parameters
    /// * `msg`: A mutable slice representing the entire BGP message.
    /// * `tpal`: The total path attribute length to write.
    ///
    /// # Returns
    /// `Ok(())` on success, or a `BgpError` if the message is not an UPDATE or the buffer is too short.
    #[inline(always)]
    pub fn set_update_total_path_attr_len(
        &mut self,
        msg: &mut [u8],
        tpal: u16,
    ) -> Result<(), BgpError> {
        if self.msg_type != BgpMsgType::Update as u8 {
            return Err(BgpError::IncorrectMessageType(self.msg_type));
        }
        // Safety: The message type has been checked to be Update, so accessing the `update` union field is safe.
        let wrl = read_u16_be(unsafe { &self.data.update.withdrawn_routes_length });
        let off = COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN + wrl as usize;
        if msg.len() < off + 2 {
            return Err(BgpError::BufferTooShort);
        }
        msg[off..off + 2].copy_from_slice(&tpal.to_be_bytes());
        Ok(())
    }

    /// Returns an immutable reference to the `OpenMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Open` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_open_unchecked(&self) -> &OpenMsgLayout {
        &self.data.open
    }

    /// Returns a mutable reference to the `OpenMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Open` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_open_mut_unchecked(&mut self) -> &mut OpenMsgLayout {
        &mut self.data.open
    }

    /// Returns an immutable reference to the `UpdateInitialMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Update` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_update_unchecked(&self) -> &UpdateInitialMsgLayout {
        &self.data.update
    }

    /// Returns a mutable reference to the `UpdateInitialMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Update` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_update_mut_unchecked(&mut self) -> &mut UpdateInitialMsgLayout {
        &mut self.data.update
    }

    /// Reads the Total Path Attribute Length field from an UPDATE message without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Update` before calling this method.
    ///
    /// # Parameters
    /// * `msg`: A slice representing the entire BGP message.
    ///
    /// # Returns
    /// `Some(u16)` with the length if successful, `None` if the buffer is too short.
    #[inline(always)]
    pub unsafe fn update_total_path_attr_len_unchecked(&self, msg: &[u8]) -> Option<u16> {
        let wrl = read_u16_be(&self.data.update.withdrawn_routes_length);
        let off = COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN + wrl as usize;
        if msg.len() < off + 2 {
            return None;
        }
        Some(read_u16_be(&msg[off..]))
    }

    /// Sets the Total Path Attribute Length field in an UPDATE message without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Update` and that the `msg` buffer
    /// is large enough to contain the field at the calculated offset.
    ///
    /// # Parameters
    /// * `msg`: A mutable slice representing the entire BGP message.
    /// * `tpal`: The total path attribute length to write.
    #[inline(always)]
    pub unsafe fn set_update_total_path_attr_len_unchecked(&mut self, msg: &mut [u8], tpal: u16) {
        let wrl = read_u16_be(&self.data.update.withdrawn_routes_length);
        let off = COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN + wrl as usize;
        msg[off..off + 2].copy_from_slice(&tpal.to_be_bytes());
    }

    /// Returns an immutable reference to the `NotificationMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Notification` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_notification_unchecked(&self) -> &NotificationMsgLayout {
        &self.data.notification
    }

    /// Returns a mutable reference to the `NotificationMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::Notification` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_notification_mut_unchecked(&mut self) -> &mut NotificationMsgLayout {
        &mut self.data.notification
    }

    /// Returns an immutable reference to the `KeepAliveMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::KeepAlive` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_keep_alive_unchecked(&self) -> &KeepAliveMsgLayout {
        &self.data.keep_alive
    }

    /// Returns a mutable reference to the `KeepAliveMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::KeepAlive` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_keep_alive_mut_unchecked(&mut self) -> &mut KeepAliveMsgLayout {
        &mut self.data.keep_alive
    }

    /// Returns an immutable reference to the `RouteRefreshMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::RouteRefresh` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_route_refresh_unchecked(&self) -> &RouteRefreshMsgLayout {
        &self.data.route_refresh
    }

    /// Returns a mutable reference to the `RouteRefreshMsgLayout` payload without checking the message type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the message type is `BgpMsgType::RouteRefresh` before calling this method.
    /// Accessing the wrong union field is undefined behavior.
    #[inline(always)]
    pub unsafe fn as_route_refresh_mut_unchecked(&mut self) -> &mut RouteRefreshMsgLayout {
        &mut self.data.route_refresh
    }
}

impl Default for BgpHdr {
    /// Creates a default `BgpHdr`, which is a KEEPALIVE message.
    fn default() -> Self {
        Self::new(BgpMsgType::KeepAlive)
    }
}

impl core::fmt::Debug for BgpHdr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut s = f.debug_struct("BgpHdr");
        s.field("marker", &self.marker)
            .field("length", &self.length());
        match self.msg_type() {
            Ok(mt) => {
                s.field("msg_type", &mt);
                // Safety: The message type is checked before accessing the corresponding union field.
                unsafe {
                    match mt {
                        BgpMsgType::Open => s.field("payload", &self.data.open),
                        BgpMsgType::Update => {
                            s.field("payload_initial", &self.data.update);
                            s.field(
                                "total_path_attribute_len_info",
                                &"<requires full message bytes>",
                            )
                        }
                        BgpMsgType::Notification => s.field("payload", &self.data.notification),
                        BgpMsgType::KeepAlive => s.field("payload", &self.data.keep_alive),
                        BgpMsgType::RouteRefresh => s.field("payload", &self.data.route_refresh),
                    };
                }
            }
            Err(BgpError::IncorrectMessageType(raw)) => {
                s.field("msg_type_raw", &raw).field("data", &"<unknown>");
            }
            Err(BgpError::BufferTooShort) => {
                s.field("msg_type_error", &"BufferTooShort (unexpected)");
            }
        };
        s.finish()
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::{convert::TryFrom, mem, ptr};

    use serde::{
        de::{self, Deserializer, Visitor},
        ser::{Error as SerError, Serializer},
        Serialize,
    };

    use super::{payload_len, BgpError, BgpHdr, BgpMsgType, COMMON_HDR_LEN};

    impl Serialize for BgpHdr {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mt = BgpMsgType::try_from(self.msg_type).map_err(S::Error::custom)?;
            let payload_len = payload_len(mt);
            let total = COMMON_HDR_LEN + payload_len;
            let mut out: Vec<u8> = Vec::with_capacity(total);
            out.extend_from_slice(&self.marker);
            out.extend_from_slice(&self.length);
            out.push(self.msg_type);
            // Safety: The payload length is determined by the message type, ensuring we don't
            // read past the end of the union's allocated space for that specific message type.
            unsafe {
                let p = &self.data as *const _ as *const u8;
                out.extend_from_slice(core::slice::from_raw_parts(p, payload_len));
            }
            serializer.serialize_bytes(&out)
        }
    }

    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = BgpHdr;
        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "byte slice with BGP header")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<BgpHdr, E>
        where
            E: de::Error,
        {
            if v.len() < COMMON_HDR_LEN {
                return Err(E::custom(BgpError::BufferTooShort));
            }
            let mut hdr: BgpHdr = unsafe { mem::zeroed() };
            hdr.marker.copy_from_slice(&v[..16]);
            hdr.length.copy_from_slice(&v[16..18]);
            hdr.msg_type = v[18];
            let mt = BgpMsgType::try_from(hdr.msg_type).map_err(E::custom)?;
            let payload_len = payload_len(mt);
            if v.len() < COMMON_HDR_LEN + payload_len {
                return Err(E::custom(BgpError::BufferTooShort));
            }
            // Safety: The length of the source slice `v` has been checked against the
            // required length (`COMMON_HDR_LEN + payload_len`), so `add` and
            // `copy_nonoverlapping` will not read out of bounds. The destination is a
            // mutable pointer to the union field, which has sufficient space for `payload_len`.
            unsafe {
                let dst = &mut hdr.data as *mut _ as *mut u8;
                ptr::copy_nonoverlapping(v.as_ptr().add(COMMON_HDR_LEN), dst, payload_len);
            }
            Ok(hdr)
        }
    }

    impl<'de> de::Deserialize<'de> for BgpHdr {
        fn deserialize<D>(d: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            d.deserialize_bytes(V)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_struct_sizes() {
        assert_eq!(OpenMsgLayout::LEN, size_of::<OpenMsgLayout>());
        assert_eq!(
            UpdateInitialMsgLayout::LEN,
            size_of::<UpdateInitialMsgLayout>()
        );
        assert_eq!(
            NotificationMsgLayout::LEN,
            size_of::<NotificationMsgLayout>()
        );
        assert_eq!(KeepAliveMsgLayout::LEN, size_of::<KeepAliveMsgLayout>());
        assert_eq!(
            RouteRefreshMsgLayout::LEN,
            size_of::<RouteRefreshMsgLayout>()
        );
    }

    #[test]
    fn test_bgphdr_len_constant() {
        assert_eq!(BgpHdr::LEN, 19 + OpenMsgLayout::LEN);
        assert_eq!(size_of::<BgpHdr>(), BgpHdr::LEN);
    }

    #[test]
    fn test_bgphdr_new_and_default() {
        let hdr_new = BgpHdr::new(BgpMsgType::Open);
        let hdr_default = BgpHdr::default();
        let expected_marker = [0xff; 16];
        assert_eq!(hdr_new.marker, expected_marker);
        assert_eq!(hdr_new.length(), (19 + OpenMsgLayout::LEN) as u16);
        assert_eq!(hdr_new.msg_type_raw(), BgpMsgType::Open as u8);
        unsafe {
            assert_eq!(hdr_new.as_open_unchecked().version, 0);
        }
        assert_eq!(hdr_default.marker, expected_marker);
        assert_eq!(hdr_default.length(), (19 + KeepAliveMsgLayout::LEN) as u16);
        assert_eq!(hdr_default.msg_type_raw(), BgpMsgType::KeepAlive as u8);
        assert!(hdr_default.as_keep_alive().is_ok());
    }

    #[test]
    fn test_bgphdr_common_fields_methods() {
        let mut hdr = BgpHdr::new(BgpMsgType::KeepAlive);
        hdr.set_marker_to_ones();
        hdr.set_length(123);
        assert_eq!(hdr.length(), 123);
        hdr.set_msg_type(BgpMsgType::KeepAlive);
        assert_eq!(hdr.msg_type(), Ok(BgpMsgType::KeepAlive));
        assert_eq!(hdr.msg_type_raw(), BgpMsgType::KeepAlive as u8);
        hdr.set_msg_type_raw(BgpMsgType::Open as u8);
        assert_eq!(hdr.msg_type(), Ok(BgpMsgType::Open));
    }

    #[test]
    fn test_open_msg_fields() {
        let mut hdr = BgpHdr::new(BgpMsgType::Open);
        {
            let open_payload = hdr.as_open_mut().unwrap();
            open_payload.set_version(4);
            open_payload.set_my_as(65000);
            assert_eq!(open_payload.version(), 4);
            assert_eq!(open_payload.my_as(), 65000);
        }
        assert_eq!(hdr.as_open().unwrap().version(), 4);
        assert_eq!(unsafe { hdr.as_open_unchecked() }.version(), 4);
        {
            let open_payload = unsafe { hdr.as_open_mut_unchecked() };
            open_payload.set_my_as(65000);
            assert_eq!(open_payload.my_as(), 65000);
        }
        assert_eq!(hdr.as_open().unwrap().my_as(), 65000);
        assert_eq!(hdr.as_open().unwrap().version(), 4);
        hdr.set_msg_type(BgpMsgType::Update);
        assert!(hdr.as_open().is_err());
        assert!(hdr.as_open_mut().is_err());
        let open_payload_unchecked = unsafe { hdr.as_open_unchecked() };
        assert_eq!(open_payload_unchecked.version(), 4);
        let update_payload = hdr.as_update().unwrap();
        assert_eq!(
            update_payload.get_withdrawn_routes_length(),
            u16::from_be_bytes([4, 253])
        );
    }

    #[test]
    fn test_update_msg_fields() {
        let mut hdr = BgpHdr::new(BgpMsgType::Update);
        let wrl_val: u16 = 4;
        {
            let update_payload = hdr.as_update_mut().unwrap();
            update_payload.set_withdrawn_routes_length(wrl_val);
        }
        assert_eq!(
            hdr.as_update().unwrap().get_withdrawn_routes_length(),
            wrl_val
        );
        assert_eq!(
            unsafe { hdr.as_update_unchecked().get_withdrawn_routes_length() },
            wrl_val
        );
        const BUFFER_SIZE: usize = 64;
        let mut msg_bytes_buffer = [0u8; BUFFER_SIZE];
        let mut current_offset = 0;
        msg_bytes_buffer[current_offset..current_offset + 16].copy_from_slice(&hdr.marker);
        current_offset += 16;
        let temp_len = (19 + UpdateInitialMsgLayout::LEN + wrl_val as usize + 2) as u16;
        msg_bytes_buffer[current_offset..current_offset + 2]
            .copy_from_slice(&temp_len.to_be_bytes());
        current_offset += 2;
        msg_bytes_buffer[current_offset] = hdr.msg_type_raw();
        current_offset += 1;
        msg_bytes_buffer[current_offset..current_offset + UpdateInitialMsgLayout::LEN]
            .copy_from_slice(&unsafe { &hdr.data.update }.withdrawn_routes_length);
        current_offset += UpdateInitialMsgLayout::LEN;
        let withdrawn_data = [0xAAu8; 4];
        msg_bytes_buffer[current_offset..current_offset + withdrawn_data.len()]
            .copy_from_slice(&withdrawn_data);
        current_offset += withdrawn_data.len();
        let tpal_val: u16 = 20;
        msg_bytes_buffer[current_offset..current_offset + 2]
            .copy_from_slice(&tpal_val.to_be_bytes());
        current_offset += 2;
        let final_msg_len = current_offset;
        hdr.set_length(final_msg_len as u16);
        msg_bytes_buffer[16..18].copy_from_slice(&hdr.length);
        assert_eq!(
            hdr.update_total_path_attr_len(&msg_bytes_buffer[..final_msg_len]),
            Some(tpal_val)
        );
        assert_eq!(
            unsafe { hdr.update_total_path_attr_len_unchecked(&msg_bytes_buffer[..final_msg_len]) },
            Some(tpal_val)
        );
        let new_tpal_val: u16 = 30;
        assert!(hdr
            .set_update_total_path_attr_len(&mut msg_bytes_buffer[..final_msg_len], new_tpal_val)
            .is_ok());
        let tpal_read_offset = 19 + UpdateInitialMsgLayout::LEN + (wrl_val as usize);
        assert_eq!(
            &msg_bytes_buffer[tpal_read_offset..tpal_read_offset + 2],
            &(new_tpal_val).to_be_bytes()
        );
        unsafe {
            hdr.set_update_total_path_attr_len_unchecked(
                &mut msg_bytes_buffer[..final_msg_len],
                new_tpal_val + 1,
            );
        }
        assert_eq!(
            &msg_bytes_buffer[tpal_read_offset..tpal_read_offset + 2],
            &(new_tpal_val + 1).to_be_bytes()
        );
        let tpal_calc_offset = 19 + UpdateInitialMsgLayout::LEN + (wrl_val as usize);
        let short_msg_for_get = &msg_bytes_buffer[0..tpal_calc_offset + 1];
        assert_eq!(hdr.update_total_path_attr_len(short_msg_for_get), None);
        assert_eq!(
            unsafe { hdr.update_total_path_attr_len_unchecked(short_msg_for_get) },
            None
        );
        let mut short_msg_for_set_arr = [0u8; BUFFER_SIZE];
        short_msg_for_set_arr[..(tpal_calc_offset + 1)]
            .copy_from_slice(&msg_bytes_buffer[..(tpal_calc_offset + 1)]);
        assert_eq!(
            hdr.set_update_total_path_attr_len(
                &mut short_msg_for_set_arr[..(tpal_calc_offset + 1)],
                50
            ),
            Err(BgpError::BufferTooShort)
        );
        let current_type_val = BgpMsgType::Open as u8;
        hdr.set_msg_type(BgpMsgType::Open);
        assert!(hdr.as_update().is_err());
        assert_eq!(
            hdr.update_total_path_attr_len(&msg_bytes_buffer[..final_msg_len]),
            None
        );
        assert_eq!(
            hdr.set_update_total_path_attr_len(&mut msg_bytes_buffer[..final_msg_len], 10),
            Err(BgpError::IncorrectMessageType(current_type_val))
        );
    }

    #[test]
    fn test_notification_msg_fields() {
        let mut hdr = BgpHdr::new(BgpMsgType::Notification);
        {
            let notif_payload = hdr.as_notification_mut().unwrap();
            notif_payload.set_error_code(1);
        }
        assert_eq!(hdr.as_notification().unwrap().error_code(), 1);
        assert_eq!(unsafe { hdr.as_notification_unchecked() }.error_code(), 1);
        {
            let notif_payload = unsafe { hdr.as_notification_mut_unchecked() };
            notif_payload.set_error_subcode(2);
        }
        assert_eq!(hdr.as_notification().unwrap().error_subcode(), 2);
        hdr.set_msg_type(BgpMsgType::Open);
        assert!(hdr.as_notification().is_err());
    }

    #[test]
    fn test_route_refresh_msg_fields() {
        let mut hdr = BgpHdr::new(BgpMsgType::RouteRefresh);
        {
            let rr_payload = hdr.as_route_refresh_mut().unwrap();
            rr_payload.set_afi(1);
        }
        assert_eq!(hdr.as_route_refresh().unwrap().afi(), 1);
        assert_eq!(unsafe { hdr.as_route_refresh_unchecked() }.afi(), 1);
        {
            let rr_payload = unsafe { hdr.as_route_refresh_mut_unchecked() };
            rr_payload.set_res(0);
        }
        assert_eq!(hdr.as_route_refresh().unwrap().res(), 0);
        {
            let rr_payload = hdr.as_route_refresh_mut().unwrap();
            rr_payload.set_safi(1);
        }
        assert_eq!(hdr.as_route_refresh().unwrap().safi(), 1);
        hdr.set_msg_type(BgpMsgType::Open);
        assert!(hdr.as_route_refresh().is_err());
    }

    #[test]
    fn test_keepalive_msg_no_specific_fields() {
        let mut hdr = BgpHdr::new(BgpMsgType::KeepAlive);
        assert_eq!(hdr.length(), 19);
        assert!(hdr.as_open().is_err());
        assert!(hdr.as_update().is_err());
        assert!(hdr.as_keep_alive().is_ok());
        assert!(hdr.as_keep_alive_mut().is_ok());
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use bincode;

        use super::*;

        fn roundtrip_test(hdr: &BgpHdr, expected_on_wire_len: usize) {
            let config = bincode::config::standard().with_fixed_int_encoding();
            let bytes = bincode::serde::encode_to_vec(hdr, config).expect("Serialization failed");
            let bincode_prefix_len = 8;
            assert_eq!(bytes.len(), bincode_prefix_len + expected_on_wire_len);
            let header_bytes = &bytes[bincode_prefix_len..];
            assert_eq!(&header_bytes[0..16], &hdr.marker);
            assert_eq!(&header_bytes[16..18], &hdr.length);
            assert_eq!(header_bytes[18], hdr.msg_type);
            let (de_hdr, len): (BgpHdr, usize) =
                bincode::serde::decode_from_slice(&bytes, config).expect("Deserialization failed");
            assert_eq!(len, bytes.len());
            assert_eq!(de_hdr.marker, hdr.marker);
            assert_eq!(de_hdr.length(), hdr.length());
            assert_eq!(de_hdr.msg_type(), hdr.msg_type());
            let payload_len = expected_on_wire_len - 19;
            unsafe {
                let original_payload_ptr = &hdr.data as *const _ as *const u8;
                let original_payload =
                    core::slice::from_raw_parts(original_payload_ptr, payload_len);
                let deserialized_payload_ptr = &de_hdr.data as *const _ as *const u8;
                let deserialized_payload =
                    core::slice::from_raw_parts(deserialized_payload_ptr, payload_len);
                assert_eq!(original_payload, deserialized_payload);
            }
        }

        #[test]
        fn test_open_msg_serde_roundtrip() {
            let mut hdr = BgpHdr::new(BgpMsgType::Open);
            hdr.as_open_mut().unwrap().set_version(4);
            hdr.as_open_mut().unwrap().set_my_as(65001);
            hdr.as_open_mut().unwrap().set_hold_time(180);
            hdr.as_open_mut().unwrap().set_bgp_id(0xc0a80101);
            hdr.as_open_mut().unwrap().set_opt_parm_len(0);
            let expected_len = 19 + OpenMsgLayout::LEN;
            hdr.set_length(expected_len as u16);
            roundtrip_test(&hdr, expected_len);
        }

        #[test]
        fn test_update_msg_serde_roundtrip() {
            let mut hdr = BgpHdr::new(BgpMsgType::Update);
            hdr.as_update_mut().unwrap().set_withdrawn_routes_length(23);
            let expected_len = 19 + UpdateInitialMsgLayout::LEN;
            // The full length of an UPDATE message is variable. Our serialization
            // only handles the fixed part of the header.
            hdr.set_length(expected_len as u16);
            roundtrip_test(&hdr, expected_len);
        }

        #[test]
        fn test_notification_msg_serde_roundtrip() {
            let mut hdr = BgpHdr::new(BgpMsgType::Notification);
            hdr.as_notification_mut().unwrap().set_error_code(6); // Cease
            hdr.as_notification_mut().unwrap().set_error_subcode(1); // Max Prefixes
            let expected_len = 19 + NotificationMsgLayout::LEN;
            hdr.set_length(expected_len as u16);
            roundtrip_test(&hdr, expected_len);
        }

        #[test]
        fn test_keepalive_msg_serde_roundtrip() {
            let hdr = BgpHdr::new(BgpMsgType::KeepAlive);
            let expected_len = 19 + KeepAliveMsgLayout::LEN;
            assert_eq!(hdr.length(), expected_len as u16);
            roundtrip_test(&hdr, expected_len);
        }

        #[test]
        fn test_route_refresh_msg_serde_roundtrip() {
            let mut hdr = BgpHdr::new(BgpMsgType::RouteRefresh);
            hdr.as_route_refresh_mut().unwrap().set_afi(1); // IPv4
            hdr.as_route_refresh_mut().unwrap().set_safi(1); // Unicast

            let expected_len = 19 + RouteRefreshMsgLayout::LEN;
            hdr.set_length(expected_len as u16);

            roundtrip_test(&hdr, expected_len);
        }

        #[test]
        fn test_deserialization_failures() {
            let config = bincode::config::standard().with_fixed_int_encoding();
            let run_test = |bytes: &[u8]| -> Result<(BgpHdr, usize), _> {
                let encoded = bincode::serde::encode_to_vec(bytes, config).unwrap();
                bincode::serde::decode_from_slice(&encoded, config)
            };
            assert!(
                run_test(&[]).is_err(),
                "Deserializing empty bytes should fail"
            );
            assert!(
                run_test(&[0xff; 18]).is_err(),
                "Deserializing truncated common header should fail"
            );
            let mut invalid_type_bytes = [0xff; 19];
            invalid_type_bytes[16..18].copy_from_slice(&(19u16).to_be_bytes());
            invalid_type_bytes[18] = 99; // Invalid type
            assert!(
                run_test(&invalid_type_bytes).is_err(),
                "Deserializing invalid message type should fail"
            );
            let mut truncated_open = [0xff; 19 + OpenMsgLayout::LEN - 1];
            let len_bytes = (truncated_open.len() as u16).to_be_bytes();
            truncated_open[16..18].copy_from_slice(&len_bytes);
            truncated_open[18] = BgpMsgType::Open as u8;
            assert!(
                run_test(&truncated_open).is_err(),
                "Deserializing truncated Open payload should fail"
            );
        }
    }
}
