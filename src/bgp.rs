use core::convert::TryInto;
use core::mem;

/// Error types that can occur during BGP message parsing or manipulation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BgpError {
    /// Indicates an operation was attempted on a BGP message with a
    /// message type incompatible with that operation.
    /// The enclosed `u8` is the actual message type encountered.
    IncorrectMessageType(u8),
    /// Indicates that a provided buffer or slice was too short to complete
    /// the requested operation, potentially leading to out-of-bounds access.
    BufferTooShort,
}

impl core::fmt::Display for BgpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BgpError::IncorrectMessageType(msg_type) => {
                write!(f, "Incorrect BGP message type for operation: {}", msg_type)
            }
            BgpError::BufferTooShort => write!(f, "Buffer too short for operation"),
        }
    }
}

/// Defines the standard BGP message types as per RFC 4271 (Section 4.1)
/// and RFC 2918 (for ROUTE-REFRESH).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum BgpMsgType {
    /// OPEN message type (1).
    Open = 1,
    /// UPDATE message type (2).
    Update = 2,
    /// NOTIFICATION message type (3).
    Notification = 3,
    /// KEEPALIVE message type (4).
    KeepAlive = 4,
    /// ROUTE-REFRESH message type (5).
    RouteRefresh = 5,
}

impl TryFrom<u8> for BgpMsgType {
    type Error = BgpError;

    /// Attempts to convert a raw `u8` value into a `BgpMsgType`.
    ///
    /// # Parameters
    /// * `value`: The `u8` value representing the BGP message type.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the value corresponds to a known BGP message type,
    /// otherwise `Err(BgpError::IncorrectMessageType)` with the invalid value.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(BgpMsgType::Open),
            2 => Ok(BgpMsgType::Update),
            3 => Ok(BgpMsgType::Notification),
            4 => Ok(BgpMsgType::KeepAlive),
            5 => Ok(BgpMsgType::RouteRefresh),
            _ => Err(BgpError::IncorrectMessageType(value)),
        }
    }
}

/// Represents the fixed-size layout of a BGP OPEN message payload.
/// (RFC 4271, Section 4.2).
///
/// This structure is `#[repr(C, packed)]` to ensure it matches the on-wire format.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct OpenMsgLayout {
    /// BGP protocol version number. For BGP-4, this is 4.
    pub version: u8,
    /// The Autonomous System (AS) number of the sender, in network byte order.
    pub my_as: [u8; 2],
    /// The proposed Hold Time in seconds, in network byte order.
    pub hold_time: [u8; 2],
    /// The BGP Identifier of the sender, in network byte order. Typically, an IP address.
    pub bgp_id: [u8; 4],
    /// The length of the Optional Parameters field in octets.
    pub opt_parm_len: u8,
}

impl OpenMsgLayout {
    /// The length of the fixed part of a BGP OPEN message in bytes.
    pub const LEN: usize = mem::size_of::<Self>();

    /// Gets the BGP protocol version.
    ///
    /// # Returns
    /// The `u8` BGP version number.
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the BGP protocol version.
    ///
    /// # Parameters
    /// * `version`: The `u8` BGP version number to set.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    /// Gets the sender's Autonomous System (AS) number.
    ///
    /// # Returns
    /// The `u16` AS number, converted from network byte order.
    #[inline]
    pub fn my_as(&self) -> u16 {
        u16::from_be_bytes(self.my_as)
    }

    /// Sets the sender's Autonomous System (AS) number.
    ///
    /// # Parameters
    /// * `my_as`: The `u16` AS number to set (will be converted to network byte order).
    #[inline]
    pub fn set_my_as(&mut self, my_as: u16) {
        self.my_as = my_as.to_be_bytes();
    }

    /// Gets the proposed Hold Time in seconds.
    ///
    /// # Returns
    /// The `u16` Hold Time, converted from network byte order.
    #[inline]
    pub fn hold_time(&self) -> u16 {
        u16::from_be_bytes(self.hold_time)
    }

    /// Sets the proposed Hold Time in seconds.
    ///
    /// # Parameters
    /// * `hold_time`: The `u16` Hold Time to set (will be converted to network byte order).
    #[inline]
    pub fn set_hold_time(&mut self, hold_time: u16) {
        self.hold_time = hold_time.to_be_bytes();
    }

    /// Gets the BGP Identifier of the sender.
    ///
    /// # Returns
    /// The `u32` BGP Identifier, converted from network byte order.
    #[inline]
    pub fn bgp_id(&self) -> u32 {
        u32::from_be_bytes(self.bgp_id)
    }

    /// Sets the BGP Identifier of the sender.
    ///
    /// # Parameters
    /// * `bgp_id`: The `u32` BGP Identifier to set (will be converted to network byte order).
    #[inline]
    pub fn set_bgp_id(&mut self, bgp_id: u32) {
        self.bgp_id = bgp_id.to_be_bytes();
    }

    /// Gets the length of the Optional Parameters field in octets.
    ///
    /// # Returns
    /// The `u8` length of optional parameters.
    #[inline]
    pub fn opt_parm_len(&self) -> u8 {
        self.opt_parm_len
    }

    /// Sets the length of the Optional Parameters field in octets.
    ///
    /// # Parameters
    /// * `len`: The `u8` length of optional parameters to set.
    #[inline]
    pub fn set_opt_parm_len(&mut self, len: u8) {
        self.opt_parm_len = len;
    }
}

/// Represents the fixed-size layout at the beginning of a BGP UPDATE message.
/// (RFC 4271, Section 4.3).
///
/// This structure is `#[repr(C, packed)]` to ensure it matches the on-wire format.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct UpdateInitialMsgLayout {
    /// The length of the Withdrawn Routes field in octets, in network byte order.
    pub withdrawn_routes_length: [u8; 2],
}

impl UpdateInitialMsgLayout {
    /// The length of the fixed part of a BGP UPDATE message in bytes.
    pub const LEN: usize = mem::size_of::<Self>();

    /// Gets the length of the Withdrawn Routes field.
    ///
    /// # Returns
    /// The `u16` length of the Withdrawn Routes field, converted from network byte order.
    pub fn get_withdrawn_routes_length(&self) -> u16 {
        u16::from_be_bytes(self.withdrawn_routes_length)
    }

    /// Sets the length of the Withdrawn Routes field.
    ///
    /// # Parameters
    /// * `len`: The `u16` length to set (will be converted to network byte order).
    pub fn set_withdrawn_routes_length(&mut self, len: u16) {
        self.withdrawn_routes_length = len.to_be_bytes();
    }
}

/// Creates a new `UpdateInitialMsgLayout` with a `withdrawn_routes_length` of zero.
impl Default for UpdateInitialMsgLayout {
    fn default() -> Self {
        Self {
            withdrawn_routes_length: [0, 0],
        }
    }
}

/// Represents a single BGP Withdrawn Route, consisting of a prefix length and the prefix itself.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct WithdrawnRoute<'a> {
    /// The length of the IP address prefix in bits.
    pub length_bits: u8,
    /// A slice pointing to the raw bytes of the IP address prefix.
    pub prefix: &'a [u8],
}

/// A view over a single Path Attribute's data (header + value).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PathAttributeView<'a> {
    pub flags: u8,
    pub type_code: u8,
    pub value: &'a [u8],
}

impl<'a> PathAttributeView<'a> {
    /// Checks if the "Optional" bit is set.
    pub fn is_optional(&self) -> bool { (self.flags & 0x80) != 0 }
    /// Checks if the "Transitive" bit is set.
    pub fn is_transitive(&self) -> bool { (self.flags & 0x40) != 0 }
    /// Checks if the "Partial" bit is set.
    pub fn is_partial(&self) -> bool { (self.flags & 0x20) != 0 }
    /// Checks if the "Extended Length" bit is set, indicating the length field is 2 bytes.
    pub fn is_extended_length(&self) -> bool { (self.flags & 0x10) != 0 }
}

/// A view providing safe, zero-copy access to the components of a BGP UPDATE message.
#[derive(Debug, Copy, Clone)]
pub struct UpdateMessageView<'a> {
    buffer: &'a [u8],
}

impl<'a> UpdateMessageView<'a> {
    /// Creates a new view from the full BGP UPDATE message payload.
    ///
    /// # Parameters
    /// * `buffer`: A slice representing the UPDATE message payload (excluding the common BGP header).
    ///
    /// # Returns
    /// `Some(Self)` if the buffer is large enough for the initial fixed-size layout, `None` otherwise.
    pub fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() < UpdateInitialMsgLayout::LEN {
            return None;
        }
        Some(Self { buffer })
    }

    /// Provides safe access to the initial fixed-layout portion of the header.
    fn initial_layout(&self) -> &UpdateInitialMsgLayout {
        unsafe { &*(self.buffer.as_ptr() as *const UpdateInitialMsgLayout) }
    }

    /// Returns an iterator over the Withdrawn Routes in the message.
    ///
    /// The iterator will parse the Withdrawn Routes field based on the length specified
    /// in the UPDATE message header. It handles cases where the specified length
    /// exceeds the buffer by iterating only over the available bytes.
    ///
    /// # Returns
    /// A `WithdrawnRoutesIterator` to traverse the withdrawn routes.
    pub fn withdrawn_routes_iter(&self) -> WithdrawnRoutesIterator<'a> {
        let len = self.initial_layout().get_withdrawn_routes_length() as usize;
        let start = UpdateInitialMsgLayout::LEN;
        let end = start.saturating_add(len);
        let buffer = if end > self.buffer.len() {
            &self.buffer[start..self.buffer.len()]
        } else {
            &self.buffer[start..end]
        };
        WithdrawnRoutesIterator::new(buffer)
    }

    /// Returns an iterator over the Path Attributes in the message.
    ///
    /// # Returns
    /// `Some(PathAttributeIterator)` if the message contains a valid Path Attributes field.
    /// Returns `None` if the message is too short to contain the path attribute length,
    /// or if the path attributes block is malformed or has a length of zero.
    pub fn path_attributes_iter(&self) -> Option<PathAttributeIterator<'a>> {
        let withdrawn_len = self.initial_layout().get_withdrawn_routes_length() as usize;
        let path_attr_len_offset = UpdateInitialMsgLayout::LEN.saturating_add(withdrawn_len);

        if self.buffer.len() < path_attr_len_offset.saturating_add(2) { return None; }

        let len_bytes = [self.buffer[path_attr_len_offset], self.buffer[path_attr_len_offset + 1]];
        let path_attr_block_len = u16::from_be_bytes(len_bytes) as usize;

        if path_attr_block_len == 0 { return None; }

        let path_attr_start = path_attr_len_offset + 2;
        let path_attr_end = path_attr_start.saturating_add(path_attr_block_len);

        if path_attr_end > self.buffer.len() { return None; }

        Some(PathAttributeIterator::new(&self.buffer[path_attr_start..path_attr_end]))
    }

    /// Returns a slice containing the Network Layer Reachability Information (NLRI).
    ///
    /// # Returns
    /// `Some(&'a [u8])` containing the NLRI data if present.
    /// Returns `None` if the message is malformed, or if Total Path Attribute Length is 0,
    /// as the NLRI field follows the Path Attributes.
    pub fn nlri(&self) -> Option<&'a [u8]> {
        let withdrawn_len = self.initial_layout().get_withdrawn_routes_length() as usize;
        let path_attr_len_offset = UpdateInitialMsgLayout::LEN.saturating_add(withdrawn_len);

        if self.buffer.len() < path_attr_len_offset.saturating_add(2) { return None; }

        let len_bytes = [self.buffer[path_attr_len_offset], self.buffer[path_attr_len_offset + 1]];
        let path_attr_block_len = u16::from_be_bytes(len_bytes) as usize;

        if path_attr_block_len == 0 { return None; }

        let nlri_start = path_attr_len_offset + 2 + path_attr_block_len;
        if nlri_start > self.buffer.len() { return None; }

        Some(&self.buffer[nlri_start..])
    }
}

/// An iterator that parses a block of Withdrawn Route `(Length, Prefix)` tuples.
#[derive(Debug, Clone)]
pub struct WithdrawnRoutesIterator<'a> {
    buffer: &'a [u8],
}

impl<'a> WithdrawnRoutesIterator<'a> {
    /// Creates a new iterator for a Withdrawn Routes data block.
    ///
    /// # Parameters
    /// * `buffer`: A slice containing the raw bytes of the Withdrawn Routes field.
    pub fn new(buffer: &'a [u8]) -> Self { Self { buffer } }
}

impl<'a> Iterator for WithdrawnRoutesIterator<'a> {
    type Item = WithdrawnRoute<'a>;

    /// Parses and returns the next withdrawn route from the buffer.
    ///
    /// Each call to `next` attempts to read a length byte, calculate the
    /// corresponding prefix byte length, and extract the route.
    ///
    /// # Returns
    /// `Some(WithdrawnRoute)` if a complete route is parsed successfully.
    /// `None` if the remaining buffer is empty or too small to contain a valid route.
    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() < 1 { return None; }
        let length_bits = self.buffer[0];
        let prefix_len_bytes = ((length_bits + 7) / 8) as usize;
        let total_record_len = 1 + prefix_len_bytes;
        if self.buffer.len() < total_record_len {
            self.buffer = &[];
            return None;
        }
        let prefix = &self.buffer[1..total_record_len];
        self.buffer = &self.buffer[total_record_len..];
        Some(WithdrawnRoute { length_bits, prefix })
    }
}

/// An iterator that parses a sequence of BGP Path Attributes.
#[derive(Debug, Clone)]
pub struct PathAttributeIterator<'a> {
    buffer: &'a [u8],
}

impl<'a> PathAttributeIterator<'a> {
    /// Creates a new iterator for a Path Attributes data block.
    ///
    /// # Parameters
    /// * `buffer`: A slice containing the raw bytes of the Total Path Attributes field.
    pub fn new(buffer: &'a [u8]) -> Self { Self { buffer } }
}

impl<'a> Iterator for PathAttributeIterator<'a> {
    type Item = PathAttributeView<'a>;

    /// Parses and returns the next path attribute from the buffer.
    ///
    /// Handles both standard and extended-length attributes based on the attribute flags.
    ///
    /// # Returns
    /// `Some(PathAttributeView)` if a complete attribute is parsed successfully.
    /// `None` if the remaining buffer is empty or too small for the next attribute's header or value.
    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() < 2 { return None; }

        let flags = self.buffer[0];
        let type_code = self.buffer[1];
        let is_extended = (flags & 0x10) != 0;

        let (len, data_offset) = if is_extended {
            if self.buffer.len() < 4 { return None; }
            (u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize, 4)
        } else {
            if self.buffer.len() < 3 { return None; }
            (self.buffer[2] as usize, 3)
        };

        let total_attr_len = data_offset + len;
        if self.buffer.len() < total_attr_len {
            self.buffer = &[];
            return None;
        }

        let value = &self.buffer[data_offset..total_attr_len];
        self.buffer = &self.buffer[total_attr_len..];

        Some(PathAttributeView { flags, type_code, value })
    }
}

/// A generic writer for serializing a sequence of (Length, Prefix) tuples.
///
/// This is used for writing both Withdrawn Routes and NLRI data, which share the same format.
pub struct PrefixWriter<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> PrefixWriter<'a> {
    /// Creates a new writer for a prefix data block.
    ///
    /// # Parameters
    /// * `buffer`: The mutable slice where prefix data will be written.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Appends a new prefix to the buffer.
    ///
    /// # Parameters
    /// * `length_bits`: The length of the prefix in bits.
    /// * `prefix`: A slice containing the raw bytes of the prefix.
    ///
    /// # Returns
    /// `Ok(())` on success.
    /// `Err(&'static str)` if the provided prefix byte length doesn't match its
    /// bit-length, or if the buffer is too small.
    pub fn push(&mut self, length_bits: u8, prefix: &[u8]) -> Result<(), &'static str> {
        let prefix_len_bytes = ((length_bits + 7) / 8) as usize;
        if prefix.len() != prefix_len_bytes {
            return Err("Prefix byte length does not match its bit-length");
        }

        let record_len = 1 + prefix_len_bytes;
        if self.cursor + record_len > self.buffer.len() {
            return Err("Buffer too small for new prefix");
        }

        self.buffer[self.cursor] = length_bits;
        self.buffer[self.cursor + 1..self.cursor + record_len].copy_from_slice(prefix);
        self.cursor += record_len;
        Ok(())
    }
}

/// A writer for serializing a sequence of BGP Path Attributes.
pub struct PathAttributeWriter<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> PathAttributeWriter<'a> {
    /// Creates a new writer for a path attribute data block.
    ///
    /// # Parameters
    /// * `buffer`: The mutable slice where path attribute data will be written.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Appends a new path attribute to the buffer.
    ///
    /// Automatically handles setting the "Extended Length" flag if the `value`
    /// is longer than 255 bytes.
    ///
    /// # Parameters
    /// * `flags`: The attribute flags (e.g., Optional, Transitive).
    /// * `type_code`: The attribute type code.
    /// * `value`: A slice containing the attribute's value.
    ///
    /// # Returns
    /// `Ok(())` on success.
    /// `Err(&'static str)` if the buffer is too small for the new attribute.
    pub fn push(&mut self, flags: u8, type_code: u8, value: &[u8]) -> Result<(), &'static str> {
        let is_extended = value.len() > 255;
        let flags = if is_extended { flags | 0x10 } else { flags };

        let len_field_size = if is_extended { 2 } else { 1 };
        let header_size = 2 + len_field_size;
        let total_attr_len = header_size + value.len();

        if self.cursor + total_attr_len > self.buffer.len() {
            return Err("Buffer too small for new path attribute");
        }

        let current = &mut self.buffer[self.cursor..];
        current[0] = flags;
        current[1] = type_code;

        if is_extended {
            current[2..4].copy_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            current[2] = value.len() as u8;
        }

        current[header_size..total_attr_len].copy_from_slice(value);
        self.cursor += total_attr_len;
        Ok(())
    }
}

/// A writer that structures a mutable buffer to be filled with BGP UPDATE message data.
pub struct UpdateMessageWriter<'a> {
    buffer: &'a mut [u8],
}

impl<'a> UpdateMessageWriter<'a> {
    /// Creates a new writer for a BGP UPDATE message from a mutable byte slice.
    ///
    /// The buffer should represent the entire UPDATE message payload (excluding the common BGP header).
    ///
    /// # Parameters
    /// * `buffer`: A mutable slice that will contain the UPDATE message payload.
    ///
    /// # Returns
    /// `Some(Self)` if the buffer is at least 4 bytes long (the minimum for length fields),
    /// otherwise `None`.
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < 4 { // Minimal length for withdrawn_len (2) + path_attr_len (2)
            return None;
        }
        Some(Self { buffer })
    }

    /// Writes the length fields to structure the buffer and returns sub-writers for each section.
    ///
    /// This method partitions the underlying buffer into three distinct sections for
    /// writing Withdrawn Routes, Path Attributes, and NLRI. It writes the length
    /// fields for the first two sections into the buffer before returning the writers.
    ///
    /// # Parameters
    /// * `withdrawn_len`: The total length in bytes of the Withdrawn Routes section.
    /// * `path_attr_len`: The total length in bytes of the Path Attributes section.
    ///
    /// # Returns
    /// On success, a tuple `(PrefixWriter, PathAttributeWriter, PrefixWriter)` for the
    /// Withdrawn Routes, Path Attributes, and NLRI sections, respectively.
    ///
    /// # Errors
    /// Returns `Err(&'static str)` if the sum of the specified lengths exceeds the buffer's capacity.
    pub fn structure(
        &mut self,
        withdrawn_len: u16,
        path_attr_len: u16,
    ) -> Result<
        (
            PrefixWriter,
            PathAttributeWriter,
            PrefixWriter,
        ),
        &'static str,
    > {
        let withdrawn_len_usize = withdrawn_len as usize;
        let path_attr_len_usize = path_attr_len as usize;

        // Required length: 2 bytes for withdrawn_len, the withdrawn data,
        // 2 bytes for path_attr_len, and the path_attr data.
        let required_len = 2 + withdrawn_len_usize + 2 + path_attr_len_usize;
        if self.buffer.len() < required_len {
            return Err("Provided lengths exceed buffer capacity");
        }

        // Write Withdrawn Routes Length
        self.buffer[0..2].copy_from_slice(&withdrawn_len.to_be_bytes());
        // Calculate and write Total Path Attributes Length
        let pa_len_offset = 2 + withdrawn_len_usize;
        self.buffer[pa_len_offset..pa_len_offset + 2].copy_from_slice(&path_attr_len.to_be_bytes());

        // Split the buffer to create writers for each section
        let (wr_buf, rest) = self.buffer[2..].split_at_mut(withdrawn_len_usize);
        let (pa_buf, nlri_buf) = rest[2..].split_at_mut(path_attr_len_usize);

        Ok((
            PrefixWriter::new(wr_buf),
            PathAttributeWriter::new(pa_buf),
            PrefixWriter::new(nlri_buf),
        ))
    }
}

/// Represents the fixed-size layout of a BGP NOTIFICATION message payload.
/// (RFC 4271, Section 4.5).
///
/// This structure is `#[repr(C, packed)]` to ensure it matches the on-wire format.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotificationMsgLayout {
    /// The error code indicating the type of BGP error.
    pub error_code: u8,
    /// The error subcode providing more specific information about the error.
    pub error_subcode: u8,
}

impl NotificationMsgLayout {
    /// The length of the BGP NOTIFICATION message payload in bytes.
    pub const LEN: usize = mem::size_of::<Self>();

    /// Gets the error code.
    ///
    /// # Returns
    /// The `u8` error code.
    #[inline]
    pub fn error_code(&self) -> u8 {
        self.error_code
    }

    /// Sets the error code.
    ///
    /// # Parameters
    /// * `code`: The `u8` error code to set.
    #[inline]
    pub fn set_error_code(&mut self, code: u8) {
        self.error_code = code;
    }

    /// Gets the error subcode.
    ///
    /// # Returns
    /// The `u8` error subcode.
    #[inline]
    pub fn error_subcode(&self) -> u8 {
        self.error_subcode
    }

    /// Sets the error subcode.
    ///
    /// # Parameters
    /// * `subcode`: The `u8` error subcode to set.
    #[inline]
    pub fn set_error_subcode(&mut self, subcode: u8) {
        self.error_subcode = subcode;
    }
}

/// Represents the fixed-size layout of a BGP KEEPALIVE message payload.
/// (RFC 4271, Section 4.4).
///
/// KEEPALIVE messages only consist of the BGP header; they have no additional payload.
/// This structure is `#[repr(C, packed)]`.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct KeepAliveMsgLayout {}

impl KeepAliveMsgLayout {
    /// The length of the BGP KEEPALIVE message payload in bytes (always 0).
    pub const LEN: usize = mem::size_of::<Self>();
}

/// Represents the fixed-size layout of a BGP ROUTE-REFRESH message payload.
/// (RFC 2918, Section 3).
///
/// This structure is `#[repr(C, packed)]` to ensure it matches the on-wire format.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct RouteRefreshMsgLayout {
    /// Address Family Identifier (AFI), in network byte order.
    pub afi: [u8; 2],
    /// Reserved field should be set to 0.
    pub _reserved: u8,
    /// Subsequent Address Family Identifier (SAFI), in network byte order.
    pub safi: u8,
}

impl RouteRefreshMsgLayout {
    /// The length of the BGP ROUTE-REFRESH message payload in bytes.
    pub const LEN: usize = mem::size_of::<Self>();

    /// Gets the Address Family Identifier (AFI).
    ///
    /// # Returns
    /// The `u16` AFI, converted from network byte order.
    #[inline]
    pub fn afi(&self) -> u16 {
        u16::from_be_bytes(self.afi)
    }

    /// Sets the Address Family Identifier (AFI).
    ///
    /// # Parameters
    /// * `afi`: The `u16` AFI to set (will be converted to network byte order).
    #[inline]
    pub fn set_afi(&mut self, afi: u16) {
        self.afi = afi.to_be_bytes();
    }

    /// Gets the reserved field value.
    ///
    /// # Returns
    /// The `u8` value of the reserved field.
    #[inline]
    pub fn res(&self) -> u8 {
        self._reserved
    }

    /// Sets the reserved field value. This should typically be 0.
    ///
    /// # Parameters
    /// * `res`: The `u8` value for the reserved field.
    #[inline]
    pub fn set_res(&mut self, res: u8) {
        self._reserved = res;
    }

    /// Gets the Subsequent Address Family Identifier (SAFI).
    ///
    /// # Returns
    /// The `u8` SAFI.
    #[inline]
    pub fn safi(&self) -> u8 {
        self.safi
    }

    /// Sets the Subsequent Address Family Identifier (SAFI).
    ///
    /// # Parameters
    /// * `safi`: The `u8` SAFI to set.
    #[inline]
    pub fn set_safi(&mut self, safi: u8) {
        self.safi = safi;
    }
}

/// A union to hold the specific payload structure for different BGP message types.
///
/// This union is part of `BgpHdr` and allows interpreting the `data` field
/// based on the `msg_type`.
/// It is `#[repr(C, packed)]` as it's embedded in `BgpHdr`.
#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub union BgpMsgUn {
    /// Payload for an OPEN message.
    pub open: OpenMsgLayout,
    /// Initial payload for an UPDATE message.
    pub update: UpdateInitialMsgLayout,
    /// Payload for a NOTIFICATION message.
    pub notification: NotificationMsgLayout,
    /// Payload for a KEEPALIVE message (empty).
    pub keep_alive: KeepAliveMsgLayout,
    /// Payload for a ROUTE-REFRESH message.
    pub route_refresh: RouteRefreshMsgLayout,
}

impl Default for BgpMsgUn {
    /// Provides a default value for `BgpMsgUn`.
    /// Initializes with a default `OpenMsgLayout`.
    fn default() -> Self {
        BgpMsgUn {
            open: OpenMsgLayout::default(),
        }
    }
}

/// Represents a BGP message header and its associated fixed-payload data.
/// (RFC 4271, Section 4.1).
///
/// This structure is `#[repr(C, packed)]` to ensure it matches the on-wire format
/// for the BGP header and the start of its payload. The `data` field is a union
/// that can be interpreted based on the `msg_type`.
#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpHdr {
    /// The 16-octet marker field. For messages other than early BGP versions,
    /// this field is typically all ones (0xFF).
    pub marker: [u8; 16],
    /// The total length of the BGP message in octets, including the header,
    /// in network byte order.
    pub length: [u8; 2],
    /// The BGP message type code (e.g., OPEN, UPDATE).
    pub msg_type: u8,
    /// A union holding the fixed part of the message payload, specific to the `msg_type`.
    /// Access to this field should be guarded by checking `msg_type` or using
    /// the appropriate `as_...()` or `as_..._unchecked()` methods.
    pub data: BgpMsgUn,
}

impl BgpHdr {
    /// The minimum length of a BGP header if it were to encapsulate the largest
    /// fixed-size payload defined in `BgpMsgUn` (which is `OpenMsgLayout`).
    /// This is `19 (common header) + size_of(OpenMsgLayout)`.
    /// Note: The actual on-wire length is stored in the `length` field of the header.
    pub const LEN: usize = mem::size_of::<Self>();

    /// Creates a new `BgpHdr` initialized for a specific `BgpMsgType`.
    /// The marker is set to all ones, and the length is calculated based on the
    /// common header size (19 bytes) plus the size of the fixed payload for the given message type.
    /// The specific payload part within `data` is default-initialized.
    ///
    /// # Parameters
    /// * `msg_type`: The `BgpMsgType` for the new header.
    ///
    /// # Returns
    /// A new `BgpHdr` instance.
    pub fn new(msg_type: BgpMsgType) -> Self {
        let common_header_len = 19;
        let specific_payload_len = match msg_type {
            BgpMsgType::Open => OpenMsgLayout::LEN,
            BgpMsgType::Update => UpdateInitialMsgLayout::LEN,
            BgpMsgType::Notification => NotificationMsgLayout::LEN,
            BgpMsgType::KeepAlive => KeepAliveMsgLayout::LEN,
            BgpMsgType::RouteRefresh => RouteRefreshMsgLayout::LEN,
        };
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
        BgpHdr {
            marker: [0xff; 16],
            length: ((common_header_len + specific_payload_len) as u16).to_be_bytes(),
            msg_type: msg_type as u8,
            data,
        }
    }

    /// Sets the marker field to all ones (0xFF).
    /// This is the standard marker value for BGP-4.
    #[inline]
    pub fn set_marker_to_ones(&mut self) {
        self.marker = [0xff; 16];
    }

    /// Gets the total length of the BGP message (header and payload) in octets.
    ///
    /// # Returns
    /// The `u16` length, converted from network byte order.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    /// Sets the total length of the BGP message.
    ///
    /// # Parameters
    /// * `length`: The `u16` total length to set (will be converted to network byte order).
    #[inline]
    pub fn set_length(&mut self, length: u16) {
        self.length = length.to_be_bytes();
    }

    /// Gets the raw `u8` value of the BGP message type.
    ///
    /// # Returns
    /// The `u8` message type code.
    #[inline]
    pub fn msg_type_raw(&self) -> u8 {
        self.msg_type
    }

    /// Gets the BGP message type as an enum.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the raw type is valid, otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn msg_type(&self) -> Result<BgpMsgType, BgpError> {
        BgpMsgType::try_from(self.msg_type)
    }

    /// Sets the BGP message type using the `BgpMsgType` enum.
    ///
    /// # Parameters
    /// * `type_val`: The `BgpMsgType` to set.
    #[inline]
    pub fn set_msg_type(&mut self, type_val: BgpMsgType) {
        self.msg_type = type_val as u8;
    }

    /// Sets the BGP message type using a raw `u8` value.
    ///
    /// # Parameters
    /// * `type_val`: The raw `u8` message type code to set.
    #[inline]
    pub fn set_msg_type_raw(&mut self, type_val: u8) {
        self.msg_type = type_val;
    }

    /// Returns a reference to the OPEN message payload if the message type is `Open`.
    ///
    /// # Returns
    /// `Ok(&OpenMsgLayout)` if the message type is `Open`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_open(&self) -> Result<&OpenMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Open as u8 {
            // Safety: msg_type is checked, so accessing self.data.open is valid.
            Ok(unsafe { &self.data.open })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the OPEN message payload if the message type is `Open`.
    ///
    /// # Returns
    /// `Ok(&mut OpenMsgLayout)` if the message type is `Open`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_open_mut(&mut self) -> Result<&mut OpenMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Open as u8 {
            // Safety: msg_type is checked, so accessing self.data.open is valid.
            Ok(unsafe { &mut self.data.open })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a reference to the initial part of the UPDATE message payload if the message type is `Update`.
    ///
    /// # Returns
    /// `Ok(&UpdateInitialMsgLayout)` if the message type is `Update`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_update(&self) -> Result<&UpdateInitialMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Update as u8 {
            // Safety: msg_type is checked, so accessing self.data.update is valid.
            Ok(unsafe { &self.data.update })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the initial part of the UPDATE message payload if the message type is `Update`.
    ///
    /// # Returns
    /// `Ok(&mut UpdateInitialMsgLayout)` if the message type is `Update`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_update_mut(&mut self) -> Result<&mut UpdateInitialMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Update as u8 {
            // Safety: msg_type is checked, so accessing self.data.update is valid.
            Ok(unsafe { &mut self.data.update })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Gets the Total Path Attributes Length from an UPDATE message byte slice.
    /// This field follows the Withdrawn Routes data in an UPDATE message.
    ///
    /// # Parameters
    /// * `message_bytes`: A slice representing the complete BGP message, starting from the marker.
    ///                    This is required to read beyond the fixed header part.
    ///
    /// # Returns
    /// `Some(u16)` containing the Total Path Attributes Length if the message type is `Update`
    /// and the slice is long enough. `None` otherwise (e.g., incorrect type, slice too short).
    #[inline]
    pub fn update_total_path_attr_len(&self, message_bytes: &[u8]) -> Option<u16> {
        if self.msg_type != BgpMsgType::Update as u8 {
            return None;
        }
        // Safety: msg_type is checked to be Update, so accessing self.data.update is valid.
        let wrl_val = u16::from_be_bytes(unsafe { self.data.update.withdrawn_routes_length });
        let common_hdr_size = 19;
        let tpal_offset = common_hdr_size + UpdateInitialMsgLayout::LEN + (wrl_val as usize);
        if message_bytes.len() < tpal_offset + 2 {
            return None;
        }
        let tpal_bytes: [u8; 2] = message_bytes[tpal_offset..tpal_offset + 2]
            .try_into()
            .ok()?;
        Some(u16::from_be_bytes(tpal_bytes))
    }

    /// Sets the Total Path Attributes Length in an UPDATE message byte slice.
    /// This field follows the Withdrawn Routes data in an UPDATE message.
    ///
    /// # Parameters
    /// * `message_bytes`: A mutable slice representing the complete BGP message, starting from the marker.
    ///                    This is required to write beyond the fixed header part.
    /// * `tpal_val`: The `u16` Total Path Attributes Length to write (will be converted to network byte order).
    ///
    /// # Returns
    /// `Ok(())` if the message type is `Update` and the slice is long enough to write the value.
    /// `Err(BgpError::IncorrectMessageType)` if the message is not an UPDATE.
    /// `Err(BgpError::BufferTooShort)` if `message_bytes` is too short.
    #[inline]
    pub fn set_update_total_path_attr_len(
        &mut self,
        message_bytes: &mut [u8],
        tpal_val: u16,
    ) -> Result<(), BgpError> {
        if self.msg_type != BgpMsgType::Update as u8 {
            return Err(BgpError::IncorrectMessageType(self.msg_type));
        }
        // Safety: msg_type is checked to be Update, so accessing self.data.update to read
        // withdrawn_routes_length is valid within the context of this BgpHdr struct.
        // The safety of message_bytes slice access is handled by length checks.
        let wrl_val = u16::from_be_bytes(unsafe { self.data.update.withdrawn_routes_length });
        let common_hdr_size = 19;
        let tpal_offset = common_hdr_size + UpdateInitialMsgLayout::LEN + (wrl_val as usize);
        if message_bytes.len() < tpal_offset + 2 {
            return Err(BgpError::BufferTooShort);
        }
        let bytes_to_write = tpal_val.to_be_bytes();
        message_bytes[tpal_offset..tpal_offset + 2].copy_from_slice(&bytes_to_write);
        Ok(())
    }

    /// Returns a reference to the NOTIFICATION message payload if the message type is `Notification`.
    ///
    /// # Returns
    /// `Ok(&NotificationMsgLayout)` if the message type is `Notification`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_notification(&self) -> Result<&NotificationMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Notification as u8 {
            // Safety: msg_type is checked, so accessing self.data.notification is valid.
            Ok(unsafe { &self.data.notification })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the NOTIFICATION message payload if the message type is `Notification`.
    ///
    /// # Returns
    /// `Ok(&mut NotificationMsgLayout)` if the message type is `Notification`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_notification_mut(&mut self) -> Result<&mut NotificationMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::Notification as u8 {
            // Safety: msg_type is checked, so accessing self.data.notification is valid.
            Ok(unsafe { &mut self.data.notification })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a reference to the KEEPALIVE message payload if the message type is `KeepAlive`.
    /// Since KEEPALIVE messages have no specific payload, this refers to an empty struct.
    ///
    /// # Returns
    /// `Ok(&KeepAliveMsgLayout)` if the message type is `KeepAlive`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_keep_alive(&self) -> Result<&KeepAliveMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::KeepAlive as u8 {
            // Safety: msg_type is checked, so accessing self.data.keep_alive is valid.
            Ok(unsafe { &self.data.keep_alive })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the KEEPALIVE message payload if the message type is `KeepAlive`.
    /// Since KEEPALIVE messages have no specific payload, this refers to an empty struct.
    ///
    /// # Returns
    /// `Ok(&mut KeepAliveMsgLayout)` if the message type is `KeepAlive`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_keep_alive_mut(&mut self) -> Result<&mut KeepAliveMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::KeepAlive as u8 {
            // Safety: msg_type is checked, so accessing self.data.keep_alive is valid.
            Ok(unsafe { &mut self.data.keep_alive })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a reference to the ROUTE-REFRESH message payload if the message type is `RouteRefresh`.
    ///
    /// # Returns
    /// `Ok(&RouteRefreshMsgLayout)` if the message type is `RouteRefresh`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_route_refresh(&self) -> Result<&RouteRefreshMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::RouteRefresh as u8 {
            // Safety: msg_type is checked, so accessing self.data.route_refresh is valid.
            Ok(unsafe { &self.data.route_refresh })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }

    /// Returns a mutable reference to the ROUTE-REFRESH message payload if the message type is `RouteRefresh`.
    ///
    /// # Returns
    /// `Ok(&mut RouteRefreshMsgLayout)` if the message type is `RouteRefresh`,
    /// otherwise `Err(BgpError::IncorrectMessageType)`.
    #[inline]
    pub fn as_route_refresh_mut(&mut self) -> Result<&mut RouteRefreshMsgLayout, BgpError> {
        if self.msg_type == BgpMsgType::RouteRefresh as u8 {
            // Safety: msg_type is checked, so accessing self.data.route_refresh is valid.
            Ok(unsafe { &mut self.data.route_refresh })
        } else {
            Err(BgpError::IncorrectMessageType(self.msg_type))
        }
    }
}

impl BgpHdr {
    /// Returns a reference to the OPEN message payload without checking the message type.
    ///
    /// # Returns
    /// A reference to an `OpenMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `Open`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_open_unchecked(&self) -> &OpenMsgLayout {
        &self.data.open
    }

    /// Returns a mutable reference to the OPEN message payload without checking the message type.
    ///
    /// # Returns
    /// A mutable reference to an `OpenMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `Open`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_open_mut_unchecked(&mut self) -> &mut OpenMsgLayout {
        &mut self.data.open
    }

    /// Returns a reference to the initial part of the UPDATE message payload without checking the message type.
    ///
    /// # Returns
    /// A reference to an `UpdateInitialMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `Update`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_update_unchecked(&self) -> &UpdateInitialMsgLayout {
        &self.data.update
    }

    /// Returns a mutable reference to the initial part of the UPDATE message payload without checking the message type.
    ///
    /// # Returns
    /// A mutable reference to an `UpdateInitialMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `Update`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_update_mut_unchecked(&mut self) -> &mut UpdateInitialMsgLayout {
        &mut self.data.update
    }

    /// Gets the Total Path Attributes Length from an UPDATE message byte slice, without checking `msg_type`.
    ///
    /// # Parameters
    /// * `message_bytes`: A slice representing the complete BGP message, starting from the marker.
    ///
    /// # Returns
    /// `Some(u16)` containing the Total Path Attributes Length if the slice is long enough
    /// based on the `withdrawn_routes_len` field. `None` if the slice is too short.
    ///
    /// # Safety
    /// Caller must ensure that:
    /// 1. The BGP message type is `Update`. Accessing `self.data.update` when the
    ///    message is not an UPDATE is undefined behavior.
    /// 2. The `message_bytes` slice accurately represents the BGP message corresponding to this header.
    #[inline]
    pub unsafe fn update_total_path_attr_len_unchecked(&self, message_bytes: &[u8]) -> Option<u16> {
        // Safety: Caller ensures msg_type is Update, so accessing self.data.update is permissible.
        let wrl_val = u16::from_be_bytes(self.data.update.withdrawn_routes_length);
        let common_hdr_size = 19;
        let tpal_offset = common_hdr_size + UpdateInitialMsgLayout::LEN + (wrl_val as usize);
        if message_bytes.len() < tpal_offset + 2 {
            return None;
        }
        // Safety: Length check above ensures this slice access is within bounds of message_bytes.
        let tpal_bytes: [u8; 2] = message_bytes[tpal_offset..tpal_offset + 2]
            .try_into()
            .ok()?;
        Some(u16::from_be_bytes(tpal_bytes))
    }

    /// Sets the Total Path Attributes Length in an UPDATE message byte slice, without checking `msg_type`.
    ///
    /// # Parameters
    /// * `message_bytes`: A mutable slice representing the complete BGP message, starting from the marker.
    /// * `tpal_val`: The `u16` Total Path Attributes Length to write.
    ///
    /// # Safety
    /// Caller must ensure that:
    /// 1. The BGP message type is `Update`. Accessing `self.data.update` when the
    ///    message is not an UPDATE is undefined behavior.
    /// 2. The `message_bytes` slice is long enough to accommodate the write operation
    ///    based on the current `withdrawn_routes_len` stored in `self.data.update`.
    ///    Failure to do so will result in a panic due to out-of-bounds slice access.
    /// 3. The `message_bytes` slice accurately represents the BGP message corresponding to this header.
    #[inline]
    pub unsafe fn set_update_total_path_attr_len_unchecked(
        &mut self,
        message_bytes: &mut [u8],
        tpal_val: u16,
    ) {
        // Safety: Caller ensures msg_type is Update.
        let wrl_val = u16::from_be_bytes(self.data.update.withdrawn_routes_length);
        let common_hdr_size = 19;
        let tpal_offset = common_hdr_size + UpdateInitialMsgLayout::LEN + (wrl_val as usize);
        let bytes_to_write = tpal_val.to_be_bytes();
        // Safety: Caller ensures message_bytes is long enough. Panic if not.
        message_bytes[tpal_offset..tpal_offset + 2].copy_from_slice(&bytes_to_write);
    }

    /// Returns a reference to the NOTIFICATION message payload without checking the message type.
    ///
    /// # Returns
    /// A reference to a `NotificationMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `Notification`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_notification_unchecked(&self) -> &NotificationMsgLayout {
        &self.data.notification
    }

    /// Returns a mutable reference to the NOTIFICATION message payload without checking the message type.
    ///
    /// # Returns
    /// A mutable reference to a `NotificationMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `Notification`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_notification_mut_unchecked(&mut self) -> &mut NotificationMsgLayout {
        &mut self.data.notification
    }

    /// Returns a reference to the KEEPALIVE message payload without checking the message type.
    ///
    /// # Returns
    /// A reference to a `KeepAliveMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `KeepAlive`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_keep_alive_unchecked(&self) -> &KeepAliveMsgLayout {
        &self.data.keep_alive
    }

    /// Returns a mutable reference to the KEEPALIVE message payload without checking the message type.
    ///
    /// # Returns
    /// A mutable reference to a `KeepAliveMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `KeepAlive`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_keep_alive_mut_unchecked(&mut self) -> &mut KeepAliveMsgLayout {
        &mut self.data.keep_alive
    }

    /// Returns a reference to the ROUTE-REFRESH message payload without checking the message type.
    ///
    /// # Returns
    /// A reference to a `RouteRefreshMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `RouteRefresh`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_route_refresh_unchecked(&self) -> &RouteRefreshMsgLayout {
        &self.data.route_refresh
    }

    /// Returns a mutable reference to the ROUTE-REFRESH message payload without checking the message type.
    ///
    /// # Returns
    /// A mutable reference to a `RouteRefreshMsgLayout` interpreted from the `data` field.
    ///
    /// # Safety
    /// Caller must ensure that the BGP message type is `RouteRefresh`. Accessing the wrong
    /// union field is undefined behavior.
    #[inline]
    pub unsafe fn as_route_refresh_mut_unchecked(&mut self) -> &mut RouteRefreshMsgLayout {
        &mut self.data.route_refresh
    }
}

impl Default for BgpHdr {
    /// Provides a default `BgpHdr`.
    /// By default, it creates a `KeepAlive` message header, as this is the simplest
    /// and most common type for an uninitialized or default state.
    ///
    /// # Returns
    /// A new `BgpHdr` initialized as a KEEPALIVE message.
    fn default() -> Self {
        Self::new(BgpMsgType::KeepAlive)
    }
}

impl core::fmt::Debug for BgpHdr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut builder = f.debug_struct("BgpHdr");
        builder.field("marker", &self.marker);
        builder.field("length", &self.length());
        match self.msg_type() {
            Ok(msg_type) => {
                builder.field("msg_type", &msg_type);
                // Safety: We are matching on msg_type, so accessing the corresponding
                // union field is safe here for debug purposes.
                unsafe {
                    match msg_type {
                        BgpMsgType::Open => builder.field("payload", &self.data.open),
                        BgpMsgType::Update => {
                            builder.field("payload_initial", &self.data.update);
                            builder.field(
                                "total_path_attribute_len_info",
                                &"<Requires full message bytes to calculate>",
                            )
                        }
                        BgpMsgType::Notification => {
                            builder.field("payload", &self.data.notification)
                        }
                        BgpMsgType::KeepAlive => builder.field("payload", &self.data.keep_alive),
                        BgpMsgType::RouteRefresh => {
                            builder.field("payload", &self.data.route_refresh)
                        }
                    };
                }
            }
            Err(BgpError::IncorrectMessageType(raw_type)) => {
                builder.field("msg_type_raw", &raw_type);
                // For unknown types, attempt to show a few bytes of the payload data,
                // assuming it might resemble an OpenMsgLayout for size comparison,
                // but this is speculative.
                // Safety: Accessing self.data.open here is to get a pointer and length for
                // a small part of the data region. This doesn't interpret the data as Open,
                // but just provides a view into the raw bytes of the union.
                let data_as_open_layout_ref: &OpenMsgLayout = unsafe { &self.data.open };
                let data_bytes_ptr = data_as_open_layout_ref as *const OpenMsgLayout as *const u8;
                const MAX_BYTES_TO_SHOW: usize = 4;
                let declared_total_len = self.length() as usize;
                let common_hdr_size = 19;
                if declared_total_len >= common_hdr_size {
                    let specific_payload_actual_len = declared_total_len - common_hdr_size;
                    let displayable_len =
                        core::cmp::min(specific_payload_actual_len, OpenMsgLayout::LEN);
                    if displayable_len > 0 {
                        // Safety: data_bytes_ptr is valid, displayable_len is calculated based on message length
                        // and struct constraints, ensuring it doesn't read out of bounds of the union's data area
                        // if specific_payload_actual_len is respected.
                        let data_slice_to_display =
                            unsafe { core::slice::from_raw_parts(data_bytes_ptr, displayable_len) };
                        if displayable_len >= MAX_BYTES_TO_SHOW {
                            builder.field(
                                "data_bytes_truncated",
                                &&data_slice_to_display[..MAX_BYTES_TO_SHOW],
                            );
                        } else {
                            builder.field("data_bytes", &data_slice_to_display);
                        }
                    } else {
                        builder.field("data", &"<No specific payload data>");
                    }
                } else {
                    builder.field("data", &"<Invalid length, less than common header>");
                }
            }
            Err(BgpError::BufferTooShort) => {
                // This case should ideally not be hit from self.msg_type() directly.
                builder.field(
                    "msg_type_error",
                    &"BufferTooShort (unexpected from msg_type())",
                );
            }
        }
        builder.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    #[test]
    fn test_layout_struct_sizes() {
        assert_eq!(OpenMsgLayout::LEN, mem::size_of::<OpenMsgLayout>());
        assert_eq!(
            UpdateInitialMsgLayout::LEN,
            mem::size_of::<UpdateInitialMsgLayout>()
        );
        assert_eq!(
            NotificationMsgLayout::LEN,
            mem::size_of::<NotificationMsgLayout>()
        );
        assert_eq!(
            KeepAliveMsgLayout::LEN,
            mem::size_of::<KeepAliveMsgLayout>()
        );
        assert_eq!(
            RouteRefreshMsgLayout::LEN,
            mem::size_of::<RouteRefreshMsgLayout>()
        );
    }

    #[test]
    fn test_bgphdr_len_constant() {
        assert_eq!(BgpHdr::LEN, 19 + OpenMsgLayout::LEN);
        assert_eq!(core::mem::size_of::<BgpHdr>(), BgpHdr::LEN);
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
        assert_eq!(hdr.as_update().unwrap().get_withdrawn_routes_length(), wrl_val);
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

    struct DebugCapture {
        buf: [u8; 1024],
        len: usize,
    }

    impl DebugCapture {
        fn new() -> Self {
            DebugCapture {
                buf: [0; 1024],
                len: 0,
            }
        }
        fn as_str(&self) -> Option<&str> {
            core::str::from_utf8(&self.buf[..self.len]).ok()
        }
    }

    impl core::fmt::Write for DebugCapture {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let remaining_cap = self.buf.len() - self.len;
            let bytes_to_copy = if bytes.len() > remaining_cap {
                remaining_cap
            } else {
                bytes.len()
            };
            if bytes_to_copy > 0 {
                self.buf[self.len..self.len + bytes_to_copy]
                    .copy_from_slice(&bytes[..bytes_to_copy]);
                self.len += bytes_to_copy;
            }
            if bytes_to_copy < bytes.len() {
                Err(core::fmt::Error)
            } else {
                Ok(())
            }
        }
    }

    fn custom_debug_contains(hdr: &BgpHdr, substring: &str) -> bool {
        let mut capture = DebugCapture::new();
        if write!(&mut capture, "{:?}", hdr).is_ok() {
            if let Some(s) = capture.as_str() {
                return s.contains(substring);
            }
        }
        false
    }

    #[test]
    fn test_debug_output_various_types() {
        let mut hdr_open = BgpHdr::new(BgpMsgType::Open);
        hdr_open.as_open_mut().unwrap().set_version(4);
        hdr_open.as_open_mut().unwrap().set_my_as(65001);
        assert!(custom_debug_contains(&hdr_open, "msg_type: Open"));
        assert!(custom_debug_contains(
            &hdr_open,
            "OpenMsgLayout { version: 4, my_as: [253, 233]"
        ));
        let mut hdr_update = BgpHdr::new(BgpMsgType::Update);
        hdr_update
            .as_update_mut()
            .unwrap()
            .set_withdrawn_routes_length(0);
        assert!(custom_debug_contains(&hdr_update, "msg_type: Update"));
        assert!(custom_debug_contains(
            &hdr_update,
            "UpdateInitialMsgLayout { withdrawn_routes_length: [0, 0] }"
        ));
        assert!(custom_debug_contains(
            &hdr_update,
            "total_path_attribute_len_info: \"<Requires full message bytes to calculate>\""
        ));
        let mut hdr_notif = BgpHdr::new(BgpMsgType::Notification);
        hdr_notif.as_notification_mut().unwrap().set_error_code(6);
        hdr_notif
            .as_notification_mut()
            .unwrap()
            .set_error_subcode(1);
        assert!(custom_debug_contains(&hdr_notif, "msg_type: Notification"));
        assert!(custom_debug_contains(
            &hdr_notif,
            "NotificationMsgLayout { error_code: 6, error_subcode: 1 }"
        ));
        let mut hdr_rr = BgpHdr::new(BgpMsgType::RouteRefresh);
        hdr_rr.as_route_refresh_mut().unwrap().set_afi(2);
        hdr_rr.as_route_refresh_mut().unwrap().set_safi(128);
        assert!(custom_debug_contains(&hdr_rr, "msg_type: RouteRefresh"));
        assert!(custom_debug_contains(
            &hdr_rr,
            "RouteRefreshMsgLayout { afi: [0, 2]"
        ));
        let hdr_ka = BgpHdr::new(BgpMsgType::KeepAlive);
        assert!(custom_debug_contains(&hdr_ka, "msg_type: KeepAlive"));
        assert!(custom_debug_contains(
            &hdr_ka,
            "payload: KeepAliveMsgLayout"
        ));
        let mut hdr_unknown = BgpHdr::new(BgpMsgType::Open);
        hdr_unknown.set_msg_type_raw(99);
        hdr_unknown.set_length((19 + 3) as u16);
        unsafe {
            let open_mut = &mut hdr_unknown.data.open;
            open_mut.version = 0xAA;
            open_mut.my_as[0] = 0xBB;
            open_mut.my_as[1] = 0xCC;
        }
        assert!(custom_debug_contains(&hdr_unknown, "msg_type_raw: 99"));
        assert!(custom_debug_contains(
            &hdr_unknown,
            "data_bytes: [170, 187, 204]"
        ));
        hdr_unknown.set_length((19 + OpenMsgLayout::LEN) as u16);
        assert!(custom_debug_contains(
            &hdr_unknown,
            "data_bytes_truncated: [170, 187, 204"
        ));
        hdr_unknown.set_length(19);
        assert!(custom_debug_contains(
            &hdr_unknown,
            "data: \"<No specific payload data>\""
        ));
        hdr_unknown.set_length(18);
        assert!(custom_debug_contains(
            &hdr_unknown,
            "data: \"<Invalid length, less than common header>\""
        ));
    }
}
