//! BGP (Border Gateway Protocol) packet parsing and manipulation.
//!
//! This module provides types for creating, parsing, and modifying
//! BGP packets, designed for efficiency and use in `no_std` environments
//! like eBPF. It supports standard BGP message types: OPEN, UPDATE,
//! NOTIFICATION, KEEPALIVE, and ROUTE_REFRESH.
//!
//! The main entry point is [`BgpHdr`], which represents different BGP message
//! types. Each variant encapsulates its specific header structure,
//! starting with the common BGP fixed header. Parsing is primarily handled
//! through the `parse_bgp_hdr!` macro, designed to work with contexts that
//! can load data at a given offset.
//!
//! # Example: Creating a KEEPALIVE message
//! ```
//! use crate::network_types::bgp::{BgpHdr, BgpMsgType, BgpFixedHdr, BgpKeepAliveHdr, COMMON_HDR_LEN};
//! use core::mem::size_of;
//!
//! // Create a new common BGP fixed header
//! let fixed_hdr = BgpFixedHdr::new(
//!     (COMMON_HDR_LEN as u16).to_be_bytes(), // KEEPALIVE has only the fixed header's length
//!     BgpMsgType::KeepAlive
//! );
//!
//! // Create the KEEPALIVE header using the fixed header
//! let keep_alive_hdr = BgpKeepAliveHdr::new(fixed_hdr);
//!
//! // Wrap it in the BgpHdr enum
//! let hdr = BgpHdr::KeepAlive(keep_alive_hdr);
//!
//! // Access properties through the enum variant
//! if let BgpHdr::KeepAlive(ka_hdr) = hdr {
//!     assert_eq!(ka_hdr.length(), COMMON_HDR_LEN as u16);
//!     assert_eq!(ka_hdr.msg_type(), Ok(BgpMsgType::KeepAlive));
//!     assert_eq!(ka_hdr.fixed_hdr.marker, [0xff; 16]);
//! } else {
//!     panic!("Not a KeepAlive header!");
//! }
//! ```
//!
//! # Example: Creating an OPEN message
//! ```
//! use crate::network_types::bgp::{BgpFixedHdr, BgpOpenFixedHdr, BgpOpenHdr, BgpHdr, BgpMsgType, COMMON_HDR_LEN};
//! use core::mem::size_of;
//!
//! // Calculate the total length of the OPEN message (fixed header + open fixed header)
//! let open_msg_len = COMMON_HDR_LEN + size_of::<BgpOpenFixedHdr>();
//!
//! // Create a new common BGP fixed header for an OPEN message
//! let fixed_hdr = BgpFixedHdr::new(
//!     (open_msg_len as u16).to_be_bytes(),
//!     BgpMsgType::Open
//! );
//!
//! // Create the fixed part of the OPEN header
//! let open_fixed_hdr = BgpOpenFixedHdr {
//!     version: 4,
//!     my_as: 64512u16.to_be_bytes(), // Example AS number
//!     hold_time: 180u16.to_be_bytes(), // Example hold time
//!     bgp_id: 0xc0a80101u32.to_be_bytes(), // Example BGP Identifier (192.168.1.1)
//!     opt_parm_len: 0, // No optional parameters for this example
//! };
//!
//! // Create the full OPEN header by combining the fixed and open fixed headers
//! let open_hdr = BgpOpenHdr::new(fixed_hdr, open_fixed_hdr);
//!
//! // Wrap it in the BgpHdr enum
//! let hdr = BgpHdr::Open(open_hdr);
//!
//! // Access properties through the enum variant
//! if let BgpHdr::Open(open_msg) = hdr {
//!     assert_eq!(open_msg.msg_type(), Ok(BgpMsgType::Open));
//!     assert_eq!(open_msg.my_as(), 64512);
//!     assert_eq!(open_msg.bgp_id(), 0xc0a80101);
//!     assert_eq!(open_msg.length(), open_msg_len as u16);
//! } else {
//!     panic!("Not an Open header!");
//! }
//! ```

/// The common header length for all BGP messages, which is 19 bytes.
pub const COMMON_HDR_LEN: usize = 19;
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, PartialEq)]
/// An enum representing the different types of BGP message headers.
pub enum BgpHdr {
    /// Represents an OPEN message header.
    Open(BgpOpenHdr),
    /// Represents an UPDATE message header.
    Update(BgpUpdateHdr),
    /// Represents a NOTIFICATION message header.
    Notification(BgpNotificationHdr),
    /// Represents a KEEPALIVE message header.
    KeepAlive(BgpKeepAliveHdr),
    /// Represents a ROUTE_REFRESH message header.
    RouteRefresh(BgpRouteRefreshHdr),
}
#[macro_export]
/// Parses a BGP header from the given context and offset.
///
/// This macro attempts to read a `BgpFixedHdr` first, then
/// dispatches to the correct specific BGP header type based on the
/// `msg_type_raw` field.
///
/// # Arguments
/// * `$ctx`: The context from which to load data (e.g., a buffer reader).
/// * `$off`: A mutable offset indicating the current position in the context.
///
/// # Returns
/// `Ok(BgpHdr)` if a valid BGP header is parsed, otherwise `Err(())`.
macro_rules! parse_bgp_hdr {
    ($ctx:expr, $off:ident) => {
        (|| -> Result<$crate::bgp::BgpHdr, ()> {
          use $crate::bgp::*;
            let bgp_fixed_hdr: BgpFixedHdr = $ctx.load($off).map_err(|_| ())?;
            $off += BgpFixedHdr::LEN;
            match bgp_fixed_hdr.msg_type_raw() {
                1 => {
                    // OPEN TYPE
                    let bgp_open_fixed_hdr: BgpOpenFixedHdr = $ctx.load($off).map_err(|_| ())?;
                    $off += BgpOpenFixedHdr::LEN;
                    Ok(BgpHdr::Open(BgpOpenHdr::new(bgp_fixed_hdr, bgp_open_fixed_hdr)))
                }
                2 => {
                    // UPDATE TYPE
                    let withdrawn_routes_length: [u8; 2] = $ctx.load($off).map_err(|_| ())?;
                    $off += withdrawn_routes_length.len();
                    let path_attr_length: [u8; 2] = $ctx.load($off).map_err(|_| ())?;
                    $off += path_attr_length.len();
                    let bgp_update_fixed_hdr: BgpUpdateFixedHdr = BgpUpdateFixedHdr::new(withdrawn_routes_length, path_attr_length);
                    Ok(BgpHdr::Update(BgpUpdateHdr::new(bgp_fixed_hdr, bgp_update_fixed_hdr)))
                }
                3 => {
                    // NOTIFICATION TYPE
                    let bgp_notification_fixed_hdr: BgpNotificationFixedHdr = $ctx.load($off).map_err(|_| ())?;
                    $off += BgpNotificationFixedHdr::LEN;
                    Ok(BgpHdr::Notification(BgpNotificationHdr::new(bgp_fixed_hdr, bgp_notification_fixed_hdr)))
                }
                4 => {
                    // KEEP ALIVE TYPE
                    Ok(BgpHdr::KeepAlive(BgpKeepAliveHdr::new(bgp_fixed_hdr)))
                }
                5 => {
                    // ROUTE REFRESH TYPE
                    let bgp_route_refresh_fixed_hdr: BgpRouteRefreshFixedHdr = $ctx.load($off).map_err(|_| ())?;
                    $off += BgpRouteRefreshFixedHdr::LEN;
                    Ok(BgpHdr::RouteRefresh(BgpRouteRefreshHdr::new(bgp_fixed_hdr, bgp_route_refresh_fixed_hdr)))
                }
                _ => Err(())
            }
        })()
    };
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

/// Represents the common header of a BGP message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpFixedHdr {
    /// 16-byte field to detect mis-synchronization; must be all ones.
    pub marker: [u8; 16],
    /// Total length of the BGP message in octets, including the header. Stored in big-endian format.
    pub length: [u8; 2],
    /// The type of BGP message. See `BgpMsgType`.
    pub msg_type: u8,
}
impl BgpFixedHdr {
    pub const LEN: usize = size_of::<Self>();
    /// Creates a new `BgpFixedHdr`.
    ///
    /// # Arguments
    /// * `len`: The total length of the BGP message in octets.
    /// * `msg_type`: The `BgpMsgType` for the new header.
    pub fn new(len: [u8; 2], msg_type: BgpMsgType) -> Self {
        Self {
            marker: [0xff; 16],
            length: len,
            msg_type: msg_type as u8,
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
}
/// Represents the fixed portion of the OPEN message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpOpenFixedHdr {
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
impl BgpOpenFixedHdr {
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
/// Represents the full header frame of a BGP OPEN message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpOpenHdr {
    /// The common fixed header for all BGP messages.
    pub fixed_hdr: BgpFixedHdr,
    /// The fixed part specific to the BGP OPEN message.
    pub bgp_open_fixed_hdr: BgpOpenFixedHdr,
}
impl BgpOpenHdr {
    /// Creates a new `BgpOpenHdr`.
    ///
    /// # Arguments
    /// * `fixed_hdr`: The common fixed BGP header.
    /// * `bgp_open_fixed_hdr`: The fixed part of the BGP OPEN header.
    pub fn new(fixed_hdr: BgpFixedHdr, bgp_open_fixed_hdr: BgpOpenFixedHdr) -> Self {
        Self {
            fixed_hdr,
            bgp_open_fixed_hdr,
        }
    }
    /// Sets the 16-byte marker field to all ones, as required by the BGP specification.
    #[inline(always)]
    pub fn set_marker_to_ones(&mut self) {
        self.fixed_hdr.set_marker_to_ones();
    }
    /// Gets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn length(&self) -> u16 {
        self.fixed_hdr.length()
    }
    /// Sets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn set_length(&mut self, l: u16) {
        self.fixed_hdr.set_length(l);
    }
    /// Gets the raw message type as a `u8`.
    #[inline(always)]
    pub fn msg_type_raw(&self) -> u8 {
        self.fixed_hdr.msg_type_raw()
    }
    /// Gets the message type as a `BgpMsgType` enum.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the type is valid, or `Err(BgpError::IncorrectMessageType)`
    /// if the raw type byte is not a known BGP message type.
    #[inline(always)]
    pub fn msg_type(&self) -> Result<BgpMsgType, BgpError> {
        self.fixed_hdr.msg_type()
    }
    /// Sets the message type from a `BgpMsgType` enum.
    #[inline(always)]
    pub fn set_msg_type(&mut self, t: BgpMsgType) {
        self.set_msg_type_raw(t as u8);
    }
    /// Sets the raw message type from a `u8`.
    #[inline(always)]
    pub fn set_msg_type_raw(&mut self, t: u8) {
        self.fixed_hdr.set_msg_type_raw(t);
    }
    /// Gets the BGP version.
    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.bgp_open_fixed_hdr.version()
    }
    /// Sets the BGP version.
    #[inline(always)]
    pub fn set_version(&mut self, v: u8) {
        self.bgp_open_fixed_hdr.set_version(v)
    }
    /// Gets the Autonomous System (AS) number.
    #[inline(always)]
    pub fn my_as(&self) -> u16 {
        self.bgp_open_fixed_hdr.my_as()
    }
    /// Sets the Autonomous System (AS) number.
    #[inline(always)]
    pub fn set_my_as(&mut self, asn: u16) {
        self.bgp_open_fixed_hdr.set_my_as(asn)
    }
    /// Gets the hold time in seconds.
    #[inline(always)]
    pub fn hold_time(&self) -> u16 {
        self.bgp_open_fixed_hdr.hold_time()
    }
    /// Sets the hold time in seconds.
    #[inline(always)]
    pub fn set_hold_time(&mut self, ht: u16) {
        self.bgp_open_fixed_hdr.set_hold_time(ht)
    }
    /// Gets the BGP identifier.
    #[inline(always)]
    pub fn bgp_id(&self) -> u32 {
        self.bgp_open_fixed_hdr.bgp_id()
    }
    /// Sets the BGP identifier.
    #[inline(always)]
    pub fn set_bgp_id(&mut self, id: u32) {
        self.bgp_open_fixed_hdr.set_bgp_id(id)
    }
    /// Gets the length of the optional parameters field.
    #[inline(always)]
    pub fn opt_parm_len(&self) -> u8 {
        self.bgp_open_fixed_hdr.opt_parm_len()
    }
    /// Sets the length of the optional parameters field.
    #[inline(always)]
    pub fn set_opt_parm_len(&mut self, l: u8) {
        self.bgp_open_fixed_hdr.set_opt_parm_len(l)
    }
}
/// Represents the fixed portion of the UPDATE message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct BgpUpdateFixedHdr {
    /// The total length of the "Withdrawn Routes" field in octets. Stored in big-endian format.
    pub withdrawn_routes_length: [u8; 2],
    /// The total length of the "Path Attributes" field in octets. Stored in big-endian format.
    pub path_attr_length: [u8; 2],
}

impl BgpUpdateFixedHdr {
    pub const LEN: usize = size_of::<Self>();

    /// Creates a new `BgpUpdateFixedHdr`.
    ///
    /// # Arguments
    /// * `withdrawn_routes_length`: The length of the withdrawn routes field in bytes.
    /// * `path_attr_length`: The length of the path attributes field in bytes.
    pub fn new(withdrawn_routes_length: [u8; 2], path_attr_length: [u8; 2]) -> Self {
        Self {
            withdrawn_routes_length,
            path_attr_length
        }
    }

    /// Gets the length of the withdrawn routes field.
    pub fn withdrawn_routes_length(&self) -> u16 {
        read_u16_be(&self.withdrawn_routes_length)
    }
    /// Sets the length of the withdrawn routes field.
    pub fn set_withdrawn_routes_length(&mut self, l: u16) {
        self.withdrawn_routes_length = l.to_be_bytes();
    }
    /// Gets the length of the path attributes field.
    pub fn path_attr_length(&self) -> u16 {
        read_u16_be(&self.path_attr_length)
    }
    /// Sets the length of the path attributes field.
    pub fn set_path_attr_length(&mut self, l: u16) {
        self.path_attr_length = l.to_be_bytes();
    }
}

/// Represents the full message of a BGP UPDATE message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpUpdateHdr {
    /// The fixed part of the BGP header, containing the marker, message type, and length.
    pub fixed_hdr: BgpFixedHdr,
    /// The fixed part specific to the BGP UPDATE message.
    pub bgp_update_fixed_hdr: BgpUpdateFixedHdr
}
impl BgpUpdateHdr {
    pub const LEN: usize = size_of::<Self>();
    /// Creates a new `BgpUpdateHdr`.
    ///
    /// # Arguments
    /// * `fixed_hdr`: The common fixed BGP header.
    /// * `bgp_update_fixed_hdr`: The fixed header specific to the UPDATE message.
    pub fn new(fixed_hdr: BgpFixedHdr, bgp_update_fixed_hdr: BgpUpdateFixedHdr) -> Self {
        Self {
            fixed_hdr,
            bgp_update_fixed_hdr,
        }
    }
    /// Sets the 16-byte marker field to all ones, as required by the BGP specification.
    #[inline(always)]
    pub fn set_marker_to_ones(&mut self) {
        self.fixed_hdr.set_marker_to_ones();
    }
    /// Gets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn length(&self) -> u16 {
        self.fixed_hdr.length()
    }
    /// Sets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn set_length(&mut self, l: u16) {
        self.fixed_hdr.set_length(l);
    }
    /// Gets the raw message type as a `u8`.
    #[inline(always)]
    pub fn msg_type_raw(&self) -> u8 {
        self.fixed_hdr.msg_type_raw()
    }
    /// Gets the message type as a `BgpMsgType` enum.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the type is valid, or `Err(BgpError::IncorrectMessageType)`
    /// if the raw type byte is not a known BGP message type.
    #[inline(always)]
    pub fn msg_type(&self) -> Result<BgpMsgType, BgpError> {
        self.fixed_hdr.msg_type()
    }
    /// Sets the message type from a `BgpMsgType` enum.
    #[inline(always)]
    pub fn set_msg_type(&mut self, t: BgpMsgType) {
        self.set_msg_type_raw(t as u8);
    }
    /// Sets the raw message type from a `u8`.
    #[inline(always)]
    pub fn set_msg_type_raw(&mut self, t: u8) {
        self.fixed_hdr.set_msg_type_raw(t);
    }
    /// Gets the length of the withdrawn routes field.
    pub fn withdrawn_routes_length(&self) -> u16 {
        self.bgp_update_fixed_hdr.withdrawn_routes_length()
    }
    /// Sets the length of the withdrawn routes field.
    pub fn set_withdrawn_routes_length(&mut self, l: u16) {
        self.bgp_update_fixed_hdr.set_withdrawn_routes_length(l)
    }
    /// Gets the length of the path attributes field.
    pub fn path_attr_length(&self) -> u16 {
        self.bgp_update_fixed_hdr.path_attr_length()
    }
    /// Sets the length of the path attributes field.
    pub fn set_path_attr_length(&mut self, l: u16) {
        self.bgp_update_fixed_hdr.set_path_attr_length(l)
    }
}
/// Represents the fixed portion of the NOTIFICATION message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpNotificationFixedHdr {
    /// Indicates the type of error.
    pub error_code: u8,
    /// Provides more specific information about the reported error.
    pub error_subcode: u8,
}
impl BgpNotificationFixedHdr {
    pub const LEN: usize = size_of::<Self>();
    /// Creates a new `BgpNotificationFixedHdr`.
    ///
    /// # Arguments
    /// * `error_code`: The error code.
    /// * `error_subcode`: The error subcode.
    pub fn new(error_code: u8, error_subcode: u8) -> Self {
        Self {
            error_code,
            error_subcode,
        }
    }
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
/// Represents the full message of a BGP NOTIFICATION message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpNotificationHdr {
    /// The fixed part of the BGP header, containing the marker, message type, and length.
    pub fixed_hdr: BgpFixedHdr,
    /// The fixed part specific to the BGP NOTIFICATION message.
    pub bgp_notif_fixed_hdr: BgpNotificationFixedHdr
}
impl BgpNotificationHdr {
    pub const LEN: usize = size_of::<Self>();
    /// Creates a new `BgpNotificationHdr`.
    ///
    /// # Arguments
    /// * `fixed_hdr`: The common fixed BGP header.
    /// * `bgp_notif_fixed_hdr`: The fixed part of the BGP NOTIFICATION header.
    pub fn new(fixed_hdr: BgpFixedHdr, bgp_notif_fixed_hdr: BgpNotificationFixedHdr) -> Self {
        Self {
            fixed_hdr,
            bgp_notif_fixed_hdr
        }
    }
    /// Sets the 16-byte marker field to all ones, as required by the BGP specification.
    #[inline(always)]
    pub fn set_marker_to_ones(&mut self) {
        self.fixed_hdr.set_marker_to_ones();
    }
    /// Gets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn length(&self) -> u16 {
        self.fixed_hdr.length()
    }
    /// Sets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn set_length(&mut self, l: u16) {
        self.fixed_hdr.set_length(l);
    }
    /// Gets the raw message type as a `u8`.
    #[inline(always)]
    pub fn msg_type_raw(&self) -> u8 {
        self.fixed_hdr.msg_type_raw()
    }
    /// Gets the message type as a `BgpMsgType` enum.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the type is valid, or `Err(BgpError::IncorrectMessageType)`
    /// if the raw type byte is not a known BGP message type.
    #[inline(always)]
    pub fn msg_type(&self) -> Result<BgpMsgType, BgpError> {
        self.fixed_hdr.msg_type()
    }
    /// Sets the message type from a `BgpMsgType` enum.
    #[inline(always)]
    pub fn set_msg_type(&mut self, t: BgpMsgType) {
        self.set_msg_type_raw(t as u8);
    }
    /// Sets the raw message type from a `u8`.
    #[inline(always)]
    pub fn set_msg_type_raw(&mut self, t: u8) {
        self.fixed_hdr.set_msg_type_raw(t);
    }
    /// Gets the error code.
    pub fn error_code(&self) -> u8 {
        self.bgp_notif_fixed_hdr.error_code
    }
    /// Sets the error code.
    pub fn set_error_code(&mut self, c: u8) {
        self.bgp_notif_fixed_hdr.set_error_code(c)
    }
    /// Gets the error subcode.
    pub fn error_subcode(&self) -> u8 {
        self.bgp_notif_fixed_hdr.error_subcode
    }
    /// Sets the error subcode.
    pub fn set_error_subcode(&mut self, s: u8) {
        self.bgp_notif_fixed_hdr.set_error_subcode(s)
    }
}
/// Represents the full message of a BGP KEEPALIVE message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpKeepAliveHdr {
    /// The fixed part of the BGP header, containing the marker, message type, and length.
    pub fixed_hdr: BgpFixedHdr
}
impl BgpKeepAliveHdr {
    pub const LEN: usize = size_of::<Self>();
    /// Creates a new `BgpKeepAliveHdr`.
    ///
    /// # Arguments
    /// * `fixed_hdr`: The common fixed BGP header.
    pub fn new(fixed_hdr: BgpFixedHdr) -> Self {
        Self {
            fixed_hdr
        }
    }
    /// Sets the 16-byte marker field to all ones, as required by the BGP specification.
    #[inline(always)]
    pub fn set_marker_to_ones(&mut self) {
        self.fixed_hdr.set_marker_to_ones();
    }
    /// Gets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn length(&self) -> u16 {
        self.fixed_hdr.length()
    }
    /// Sets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn set_length(&mut self, l: u16) {
        self.fixed_hdr.set_length(l);
    }
    /// Gets the raw message type as a `u8`.
    #[inline(always)]
    pub fn msg_type_raw(&self) -> u8 {
        self.fixed_hdr.msg_type_raw()
    }
    /// Gets the message type as a `BgpMsgType` enum.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the type is valid, or `Err(BgpError::IncorrectMessageType)`
    /// if the raw type byte is not a known BGP message type.
    #[inline(always)]
    pub fn msg_type(&self) -> Result<BgpMsgType, BgpError> {
        self.fixed_hdr.msg_type()
    }
    /// Sets the message type from a `BgpMsgType` enum.
    #[inline(always)]
    pub fn set_msg_type(&mut self, t: BgpMsgType) {
        self.set_msg_type_raw(t as u8);
    }
    /// Sets the raw message type from a `u8`.
    #[inline(always)]
    pub fn set_msg_type_raw(&mut self, t: u8) {
        self.fixed_hdr.set_msg_type_raw(t);
    }
}
/// Represents the fixed portion of the ROUTE REFRESH message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpRouteRefreshFixedHdr {
    /// Address Family Identifier (e.g., IPv4, IPv6). Stored in big-endian format.
    pub afi: [u8; 2],
    /// This field is reserved and should be set to 0.
    pub _reserved: u8,
    /// Subsequent Address Family Identifier (e.g., Unicast, Multicast).
    pub safi: u8,
}
impl BgpRouteRefreshFixedHdr {
    pub const LEN: usize = size_of::<Self>();
    /// Creates a new `BgpRouteRefreshFixedHdr`.
    ///
    /// # Arguments
    /// * `afi`: The Address Family Identifier (AFI).
    /// * `safi`: The Subsequent Address Family Identifier (SAFI).
    pub fn new(afi: u16, safi: u8) -> Self {
        Self {
            afi: afi.to_be_bytes(),
            _reserved: 0,
            safi,
        }
    }
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
/// Represents the full message of a BGP ROUTE REFRESH message.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature="serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpRouteRefreshHdr {
    /// The fixed part of the BGP header, containing the marker, message type, and length.
    pub fixed_hdr: BgpFixedHdr,
    /// The fixed part specific to the BGP ROUTE REFRESH message.
    pub bgp_route_refresh_fixed_hdr: BgpRouteRefreshFixedHdr
}
impl BgpRouteRefreshHdr {
    pub const LEN: usize = size_of::<Self>();
    /// Creates a new `BgpRouteRefreshHdr`.
    ///
    /// # Arguments
    /// * `fixed_hdr`: The common fixed BGP header.
    /// * `bgp_route_refresh_fixed_hdr`: The fixed part of the BGP ROUTE REFRESH header.
    pub fn new(fixed_hdr: BgpFixedHdr, bgp_route_refresh_fixed_hdr: BgpRouteRefreshFixedHdr) -> Self {
        Self {
            fixed_hdr,
            bgp_route_refresh_fixed_hdr
        }
    }
    /// Sets the 16-byte marker field to all ones, as required by the BGP specification.
    #[inline(always)]
    pub fn set_marker_to_ones(&mut self) {
        self.fixed_hdr.set_marker_to_ones();
    }
    /// Gets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn length(&self) -> u16 {
        self.fixed_hdr.length()
    }
    /// Sets the total length of the BGP message in bytes.
    #[inline(always)]
    pub fn set_length(&mut self, l: u16) {
        self.fixed_hdr.set_length(l);
    }
    /// Gets the raw message type as a `u8`.
    #[inline(always)]
    pub fn msg_type_raw(&self) -> u8 {
        self.fixed_hdr.msg_type_raw()
    }
    /// Gets the message type as a `BgpMsgType` enum.
    ///
    /// # Returns
    /// `Ok(BgpMsgType)` if the type is valid, or `Err(BgpError::IncorrectMessageType)`
    /// if the raw type byte is not a known BGP message type.
    #[inline(always)]
    pub fn msg_type(&self) -> Result<BgpMsgType, BgpError> {
        self.fixed_hdr.msg_type()
    }
    /// Sets the message type from a `BgpMsgType` enum.
    #[inline(always)]
    pub fn set_msg_type(&mut self, t: BgpMsgType) {
        self.set_msg_type_raw(t as u8);
    }
    /// Sets the raw message type from a `u8`.
    #[inline(always)]
    pub fn set_msg_type_raw(&mut self, t: u8) {
        self.fixed_hdr.set_msg_type_raw(t);
    }
    /// Gets the Address Family Identifier (AFI).
    #[inline(always)]
    pub fn afi(&self) -> u16 {
        self.bgp_route_refresh_fixed_hdr.afi()
    }
    /// Sets the Address Family Identifier (AFI).
    #[inline(always)]
    pub fn set_afi(&mut self, a: u16) {
        self.bgp_route_refresh_fixed_hdr.set_afi(a);
    }
    /// Gets the Subsequent Address Family Identifier (SAFI).
    #[inline(always)]
    pub fn safi(&self) -> u8 {
        self.bgp_route_refresh_fixed_hdr.safi()
    }
    /// Sets the Subsequent Address Family Identifier (SAFI).
    #[inline(always)]
    pub fn set_safi(&mut self, s: u8) {
        self.bgp_route_refresh_fixed_hdr.set_safi(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    /// A helper context for testing the `parse_bgp_hdr!` macro.
    /// It mimics the behavior of a buffer reader with a `load` method.
    struct ByteReader<'a> {
        buf: &'a [u8],
    }

    impl<'a> ByteReader<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf }
        }

        /// Loads a `Copy`-able type from a given byte offset.
        /// Returns `Err(())` if the buffer is too short, mirroring the macro's error handling.
        fn load<T: Copy>(&self, offset: usize) -> Result<T, ()> {
            if offset + size_of::<T>() <= self.buf.len() {
                // This is unsafe but sound in our test environment because we control the
                // input slice and know that the BGP structs are `repr(C, packed)`.
                let ptr = self.buf.as_ptr();
                let loaded_val = unsafe { *(ptr.add(offset) as *const T) };
                Ok(loaded_val)
            } else {
                Err(())
            }
        }
    }

    #[test]
    fn test_read_be_utils() {
        assert_eq!(read_u16_be(&[0x12, 0x34]), 0x1234);
        assert_eq!(read_u16_be(&[0xff, 0xfe]), 65534);
        assert_eq!(read_u32_be(&[0x12, 0x34, 0x56, 0x78]), 0x12345678);
        assert_eq!(read_u32_be(&[0xde, 0xad, 0xbe, 0xef]), 0xdeadbeef);
    }

    #[test]
    fn test_bgp_msg_type_try_from() {
        assert_eq!(BgpMsgType::try_from(1), Ok(BgpMsgType::Open));
        assert_eq!(BgpMsgType::try_from(2), Ok(BgpMsgType::Update));
        assert_eq!(BgpMsgType::try_from(3), Ok(BgpMsgType::Notification));
        assert_eq!(BgpMsgType::try_from(4), Ok(BgpMsgType::KeepAlive));
        assert_eq!(BgpMsgType::try_from(5), Ok(BgpMsgType::RouteRefresh));
        assert_eq!(
            BgpMsgType::try_from(0),
            Err(BgpError::IncorrectMessageType(0))
        );
        assert_eq!(
            BgpMsgType::try_from(6),
            Err(BgpError::IncorrectMessageType(6))
        );
    }

    #[test]
    fn test_bgp_fixed_hdr_methods() {
        let mut hdr = BgpFixedHdr::new(19u16.to_be_bytes(), BgpMsgType::KeepAlive);
        assert_eq!(hdr.marker, [0xff; 16]);
        assert_eq!(hdr.length(), 19);
        assert_eq!(hdr.msg_type(), Ok(BgpMsgType::KeepAlive));

        hdr.set_length(100);
        assert_eq!(hdr.length, 100u16.to_be_bytes());
        assert_eq!(hdr.length(), 100);

        hdr.set_msg_type(BgpMsgType::Open);
        assert_eq!(hdr.msg_type, BgpMsgType::Open as u8);
        assert_eq!(hdr.msg_type(), Ok(BgpMsgType::Open));

        hdr.set_msg_type_raw(255);
        assert_eq!(hdr.msg_type_raw(), 255);
        assert_eq!(
            hdr.msg_type(),
            Err(BgpError::IncorrectMessageType(255))
        );

        hdr.marker = [0; 16];
        hdr.set_marker_to_ones();
        assert_eq!(hdr.marker, [0xff; 16]);
    }

    #[test]
    fn test_bgp_open_fixed_hdr_methods() {
        let mut open_hdr = BgpOpenFixedHdr {
            version: 0,
            my_as: [0; 2],
            hold_time: [0; 2],
            bgp_id: [0; 4],
            opt_parm_len: 0,
        };

        open_hdr.set_version(4);
        assert_eq!(open_hdr.version(), 4);

        open_hdr.set_my_as(64512);
        assert_eq!(open_hdr.my_as(), 64512);
        assert_eq!(open_hdr.my_as, 64512u16.to_be_bytes());

        open_hdr.set_hold_time(180);
        assert_eq!(open_hdr.hold_time(), 180);
        assert_eq!(open_hdr.hold_time, 180u16.to_be_bytes());

        open_hdr.set_bgp_id(0xc0a80101); // 192.168.1.1
        assert_eq!(open_hdr.bgp_id(), 0xc0a80101);
        assert_eq!(open_hdr.bgp_id, 0xc0a80101u32.to_be_bytes());

        open_hdr.set_opt_parm_len(10);
        assert_eq!(open_hdr.opt_parm_len(), 10);
    }

    #[test]
    fn test_bgp_update_hdr_methods() {
        let fixed_hdr = BgpFixedHdr::new(47u16.to_be_bytes(), BgpMsgType::Update);
        let update_fixed_hdr = BgpUpdateFixedHdr::new(4u16.to_be_bytes(), 20u16.to_be_bytes());
        let mut update_hdr = BgpUpdateHdr::new(fixed_hdr, update_fixed_hdr);

        // Check delegated methods from BgpFixedHdr
        assert_eq!(update_hdr.length(), 47);
        assert_eq!(update_hdr.msg_type(), Ok(BgpMsgType::Update));

        // Check delegated methods from BgpUpdateFixedHdr
        assert_eq!(update_hdr.withdrawn_routes_length(), 4);
        assert_eq!(update_hdr.path_attr_length(), 20);

        // Check setters
        update_hdr.set_path_attr_length(30);
        assert_eq!(update_hdr.path_attr_length(), 30);
    }

    #[test]
    fn test_bgp_notification_hdr_methods() {
        let notif_fixed = BgpNotificationFixedHdr::new(6, 1); // Cease / Admin Shutdown
        let fixed_hdr = BgpFixedHdr::new(21u16.to_be_bytes(), BgpMsgType::Notification);
        let mut notif_hdr = BgpNotificationHdr::new(fixed_hdr, notif_fixed);

        assert_eq!(notif_hdr.error_code(), 6);
        assert_eq!(notif_hdr.error_subcode(), 1);

        notif_hdr.set_error_code(3); // Update Error
        notif_hdr.set_error_subcode(5); // Attr Length Error
        assert_eq!(notif_hdr.error_code(), 3);
        assert_eq!(notif_hdr.error_subcode(), 5);
        assert_eq!(notif_hdr.msg_type(), Ok(BgpMsgType::Notification)); // Check delegated method
    }

    #[test]
    fn test_bgp_route_refresh_hdr_methods() {
        let refresh_fixed = BgpRouteRefreshFixedHdr::new(1, 1); // AFI=IPv4, SAFI=Unicast
        let fixed_hdr = BgpFixedHdr::new(23u16.to_be_bytes(), BgpMsgType::RouteRefresh);
        let mut refresh_hdr = BgpRouteRefreshHdr::new(fixed_hdr, refresh_fixed);

        assert_eq!(refresh_hdr.afi(), 1);
        assert_eq!(refresh_hdr.safi(), 1);

        refresh_hdr.set_afi(2); // IPv6
        refresh_hdr.set_safi(2); // Multicast
        assert_eq!(refresh_hdr.afi(), 2);
        assert_eq!(refresh_hdr.safi(), 2);
        assert_eq!(refresh_hdr.length(), 23); // Check delegated method
    }
    
    // Test macro

    #[test]
    fn test_parse_open() {
        // Total size: 16 (marker) + 2 (len) + 1 (type) + 10 (open specific) + 2 (trailing) = 31
        let buf: [u8; 31] = [
            // --- Fixed Header ---
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 29, // Length
            1,       // Type: OPEN
            // --- Open Specific Header ---
            4,       // Version
            0xfc, 0x00, // My AS (64512)
            0x00, 0xb4, // Hold Time (180)
            0xc0, 0xa8, 0x01, 0x01, // BGP ID (192.168.1.1)
            0,       // Opt Parm Len
            // --- Trailing data to check offset ---
            0xde, 0xad,
        ];
        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        let expected_fixed = BgpFixedHdr::new(29u16.to_be_bytes(), BgpMsgType::Open);
        let expected_open_fixed = BgpOpenFixedHdr {
            version: 4, my_as: 64512u16.to_be_bytes(), hold_time: 180u16.to_be_bytes(),
            bgp_id: 0xc0a80101u32.to_be_bytes(), opt_parm_len: 0,
        };
        let expected = Ok(BgpHdr::Open(BgpOpenHdr::new(expected_fixed, expected_open_fixed)));

        assert_eq!(result, expected);
        assert_eq!(offset, 29); // Correct offset after parsing
    }

    #[test]
    fn test_parse_update() {
        // Total length = 19 (common) + 4 (update fixed) + 4 (withdrawn) + 20 (attrs) = 47
        let buf: [u8; 25] = [
            // --- Fixed Header ---
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 47, // Length
            2,       // Type: UPDATE
            // --- Update Specific Header ---
            0x00, 4, // Withdrawn Routes Length
            0x00, 20, // Path Attributes Length
            // --- Trailing data ---
            0xde, 0xad,
        ];

        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        let expected_fixed = BgpFixedHdr::new(47u16.to_be_bytes(), BgpMsgType::Update);
        let expected_update_fixed = BgpUpdateFixedHdr::new(4u16.to_be_bytes(), 20u16.to_be_bytes());
        let expected = Ok(BgpHdr::Update(BgpUpdateHdr::new(expected_fixed, expected_update_fixed)));

        assert_eq!(result, expected);
        assert_eq!(offset, BgpFixedHdr::LEN + BgpUpdateFixedHdr::LEN);
        assert_eq!(offset, 23);
    }

    #[test]
    fn test_parse_notification() {
        // Total size: 16 (marker) + 2 (len) + 1 (type) + 2 (notif specific) + 2 (trailing) = 23
        let buf: [u8; 23] = [
            // --- Fixed Header ---
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 21, // Length
            3,       // Type: NOTIFICATION
            // --- Notification Specific Header ---
            6,       // Error Code: Cease
            1,       // Error Subcode: Admin Shutdown
            // --- Trailing data ---
            0xde, 0xad,
        ];

        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        let expected_fixed = BgpFixedHdr::new(21u16.to_be_bytes(), BgpMsgType::Notification);
        let expected_notif_fixed = BgpNotificationFixedHdr::new(6, 1);
        let expected = Ok(BgpHdr::Notification(BgpNotificationHdr::new(expected_fixed, expected_notif_fixed)));

        assert_eq!(result, expected);
        assert_eq!(offset, 21);
    }

    #[test]
    fn test_parse_keepalive() {
        // Total size: 16 (marker) + 2 (len) + 1 (type) + 2 (trailing) = 21
        let buf: [u8; 21] = [
            // --- Fixed Header ---
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 19, // Length
            4,       // Type: KEEPALIVE
            // --- Trailing data ---
            0xde, 0xad,
        ];

        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        let expected_fixed = BgpFixedHdr::new(19u16.to_be_bytes(), BgpMsgType::KeepAlive);
        let expected = Ok(BgpHdr::KeepAlive(BgpKeepAliveHdr::new(expected_fixed)));

        assert_eq!(result, expected);
        assert_eq!(offset, 19);
    }

    #[test]
    fn test_parse_route_refresh() {
        // Total size: 16 (marker) + 2 (len) + 1 (type) + 4 (rr specific) + 2 (trailing) = 25
        let buf: [u8; 25] = [
            // --- Fixed Header ---
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 23, // Length
            5,       // Type: ROUTE_REFRESH
            // --- Route Refresh Specific Header ---
            0x00, 1, // AFI (IPv4)
            0,       // Reserved
            1,       // SAFI (Unicast)
            // --- Trailing data ---
            0xde, 0xad,
        ];

        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        let expected_fixed = BgpFixedHdr::new(23u16.to_be_bytes(), BgpMsgType::RouteRefresh);
        let expected_rr_fixed = BgpRouteRefreshFixedHdr::new(1, 1);
        let expected = Ok(BgpHdr::RouteRefresh(BgpRouteRefreshHdr::new(expected_fixed, expected_rr_fixed)));

        assert_eq!(result, expected);
        assert_eq!(offset, 23);
    }

    #[test]
    fn test_parse_failure_invalid_type() {
        let buf: [u8; 19] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 19, // Length
            100,     // Invalid Message Type
        ];

        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        assert_eq!(result, Err(()));
        // Offset is still advanced for the fixed header part before the match fails
        assert_eq!(offset, BgpFixedHdr::LEN);
    }

    #[test]
    fn test_parse_failure_buffer_too_short_for_fixed_hdr() {
        let buf = [0xff; 18]; // One byte too short for BgpFixedHdr
        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        assert_eq!(result, Err(()));
        assert_eq!(offset, 0); // Offset should not be advanced
    }

    #[test]
    fn test_parse_failure_buffer_too_short_for_specific_hdr() {
        // Open header is 10 bytes, but we only provide 9 bytes after the fixed header.
        let buf: [u8; 28] = [
            // --- Fixed Header ---
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 29, // Length
            1,       // Type: OPEN
            // --- Incomplete Open Header ---
            4, 0xfc, 0, 0, 0xb4, 0xc0, 0xa8, 0x01, 0x01, // 9 bytes instead of 10
        ];

        let ctx = ByteReader::new(&buf);
        let mut offset = 0;
        let result = parse_bgp_hdr!(ctx, offset);

        assert_eq!(result, Err(()));
        // Offset is advanced for the fixed header part, but not for the failed specific part
        assert_eq!(offset, BgpFixedHdr::LEN);
    }
}