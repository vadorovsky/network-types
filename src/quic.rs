//! QUIC header and Connection‑ID types with full support for
//! variable‑length IDs, long/short header forms and zero‑allocation
//! (kernel‑friendly) (de)serialization.
//!
//! Designed for use inside eBPF (`aya`) programs → `#![no_std]`,
//! fixed‑capacity buffers, no heap, packed layouts.

use core::{
    cmp,
    convert::TryFrom,
    fmt,
    hash::{self, Hash},
    ptr,
};

/// The maximum length of a QUIC Connection ID (CID) in bytes, as per RFC 9000.
pub const QUIC_MAX_CID_LEN: usize = 20;
const HEADER_FORM_BIT: u8 = 0x80;
const FIXED_BIT_MASK: u8 = 0x40;
const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const LONG_PACKET_TYPE_SHIFT: u8 = 4;
const RESERVED_BITS_LONG_MASK: u8 = 0x0C;
const RESERVED_BITS_LONG_SHIFT: u8 = 2;
const SHORT_SPIN_BIT_MASK: u8 = 0x20;
const SHORT_RESERVED_BITS_MASK: u8 = 0x18;
const SHORT_RESERVED_BITS_SHIFT: u8 = 3;
const SHORT_KEY_PHASE_BIT_MASK: u8 = 0x04;
const PN_LENGTH_BITS_MASK: u8 = 0x03;

/// Errors that can occur during QUIC header parsing and manipulation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QuicHdrError {
    /// An operation was attempted that is not valid for the current header form (e.g., reading a version from a Short Header).
    InvalidHeaderForm,
    /// A length field (e.g., for a Connection ID) was invalid or exceeded the maximum allowed size.
    InvalidLength,
    /// The packet type bits in a Long Header were not one of the valid, known values.
    InvalidPacketTypeBits,
}

impl fmt::Display for QuicHdrError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderForm => {
                write!(f, "Operation invalid for current QUIC header form")
            }
            Self::InvalidLength => write!(f, "invalid length value for QUIC header"),
            Self::InvalidPacketTypeBits => {
                write!(f, "invalid packet type bits for QUIC long header")
            }
        }
    }
}

/// QUIC Long Header Packet Types, as per RFC 9000 Section 17.2.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum QuicPacketType {
    /// Initial packet.
    Initial = 0x00,
    /// 0-RTT packet.
    ZeroRTT = 0x01,
    /// Handshake packet.
    Handshake = 0x02,
    /// Retry packet.
    Retry = 0x03,
}

/// QUIC Transport Error Codes, as per RFC 9000 Section 20.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum QuicTransportError {
    /// No error. This is used when the connection is closed gracefully.
    NoError = 0x0,
    /// An internal error occurred in the endpoint.
    InternalError = 0x1,
    /// The server refused the connection.
    ConnectionRefused = 0x2,
    /// A flow control limit was violated.
    FlowControlError = 0x3,
    /// The number of streams exceeded the negotiated limit.
    StreamLimitError = 0x4,
    /// An operation was attempted on a stream in an invalid state.
    StreamStateError = 0x5,
    /// The final size of a stream is incorrect.
    FinalSizeError = 0x6,
    /// A frame was malformed.
    FrameFormatError = 0x7,
    /// A transport parameter was invalid.
    TransportParameterError = 0x8,
    /// The number of connection IDs exceeded the negotiated limit.
    ConnectionIdLimitError = 0x9,
    /// A general protocol violation was detected.
    ProtocolViolation = 0xA,
    /// A token (e.g., for retry or new token) was invalid.
    InvalidToken = 0xB,
    /// An application-specific error occurred.
    ApplicationError = 0xC,
    /// The crypto buffer was exceeded.
    CryptoBufferExceeded = 0xD,
    /// An error occurred during a key update.
    KeyUpdateError = 0xE,
    /// The AEAD confidentiality or integrity limit was reached.
    AeadLimitReached = 0xF,
    /// The endpoint has no viable network path.
    NoViablePath = 0x10,
}

/// Serde helper types for custom error messages.
#[cfg(feature = "serde")]
mod cid_serde_helpers {
    use core::fmt;

    use serde::de::Expected;

    /// Helper struct for creating a `serde::de::Error` when a length constraint is violated.
    pub struct LengthExceedsMaxError {
        /// The invalid length that was encountered.
        pub value: usize,
        /// The maximum allowed length.
        pub max: usize,
        /// The name of the field with the invalid length.
        pub field_name: &'static str,
    }
    impl fmt::Display for LengthExceedsMaxError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{} {} exceeds max {}",
                self.field_name, self.value, self.max
            )
        }
    }
    impl Expected for LengthExceedsMaxError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(self, f)
        }
    }
}

/// A raw, fast, unchecked memory copy.
///
/// # Safety
/// Caller must ensure that `src` and `dst` are valid for reads and writes
/// of `n` bytes, respectively, and that they do not overlap.
#[inline(always)]
unsafe fn raw_copy(src: *const u8, dst: *mut u8, n: usize) {
    ptr::copy_nonoverlapping(src, dst, n);
}

/// Generates a struct and associated implementations for a QUIC Connection ID (CID).
///
/// QUIC CIDs are variable-length identifiers. To handle them in a `no_std`,
/// zero-allocation context like eBPF, this macro creates a struct that pairs
/// a `len` field with a fixed-size byte array. This allows for efficient,
/// direct mapping onto packet data.
///
/// # Arguments
///
/// * `$ty:ident`: The name for the new CID struct (e.g., `QuicDstConnLong`).
/// * `$doc:literal`: A string literal describing the CID type, used to generate
///   the struct's documentation (e.g., `"Destination (Long Hdr)"`).
/// * `$with_len_on_wire:tt`: A boolean (`true` or `false`) that controls the
///   `serde` (de)serialization format.
///   - `true`: The serialized format is `[length_byte, ...cid_bytes]`. This is
///     used for CIDs in Long Headers.
///   - `false`: The serialized format is just `[...cid_bytes]`. This is used for
///     the Destination CID in Short Headers, where the length is implicit.
///
/// # Generated Code
///
/// This macro generates the following for the given `$ty`:
/// - A `#[repr(C, packed)]` struct containing `len: u8` and `bytes: [u8; QUIC_MAX_CID_LEN]`.
/// - An `impl` block with methods like `new()`, `len()`, `as_slice()`, and `set()`.
/// - Implementations for `Debug`, `PartialEq`, `Eq`, and `Hash`.
/// - If the `serde` feature is enabled, implementations for `Serialize` and `Deserialize`
///   that respect the `$with_len_on_wire` argument.
macro_rules! impl_cid_common {
    ($ty:ident, $doc:literal, $with_len_on_wire:tt) => {
        #[doc = concat!("Wrapper for a QUIC ", $doc, " Connection‑ID.")]
        /// This struct holds a variable-length Connection ID in a fixed-size buffer,
        /// suitable for use in `no_std` environments like eBPF programs. It is
        /// generated by the `impl_cid_common!` macro.
        #[repr(C, packed)]
        #[derive(Copy, Clone)]
        pub struct $ty {
            len: u8,
            bytes: [u8; QUIC_MAX_CID_LEN],
        }

        impl $ty {
            /// The total size of the struct in memory.
            pub const LEN: usize = size_of::<Self>();

            /// Creates a new, empty Connection ID.
            #[inline(always)]
            pub const fn new() -> Self {
                Self {
                    len: 0,
                    bytes: [0; QUIC_MAX_CID_LEN],
                }
            }

            /// Returns the actual length of the Connection ID in bytes.
            #[inline(always)]
            pub const fn len(&self) -> u8 {
                self.len
            }

            /// Returns `true` if the Connection ID has a length of zero.
            #[inline(always)]
            pub const fn is_empty(&self) -> bool {
                self.len == 0
            }

            /// Returns a slice of the actual Connection ID bytes.
            #[inline(always)]
            pub fn as_slice(&self) -> &[u8] {
                // Safety: `self.len` is guaranteed by the `set` method to be <= `QUIC_MAX_CID_LEN`.
                unsafe { self.bytes.get_unchecked(..self.len as usize) }
            }

            /// Returns a mutable slice of the actual Connection ID bytes.
            #[inline(always)]
            pub fn as_mut_slice(&mut self) -> &mut [u8] {
                // Safety: `self.len` is guaranteed by the `set` method to be <= `QUIC_MAX_CID_LEN`.
                unsafe { self.bytes.get_unchecked_mut(..self.len as usize) }
            }

            /// Sets the Connection ID from a slice.
            ///
            /// The data is truncated if it is longer than `QUIC_MAX_CID_LEN`.
            #[inline(always)]
            pub fn set(&mut self, data: &[u8]) {
                let n = cmp::min(data.len(), QUIC_MAX_CID_LEN);
                // Safety: `n` is bounded by `QUIC_MAX_CID_LEN`, ensuring no buffer overflow.
                unsafe { raw_copy(data.as_ptr(), self.bytes.as_mut_ptr(), n) };
                self.len = n as u8;
            }
        }

        impl fmt::Debug for $ty {
            #[inline(always)]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($ty))?;
                f.write_str("(")?;
                for (i, b) in self.as_slice().iter().enumerate() {
                    if i != 0 {
                        f.write_str(":")?;
                    }
                    write!(f, "{:02x}", b)?;
                }
                f.write_str(")")
            }
        }
        impl PartialEq for $ty {
            #[inline(always)]
            fn eq(&self, other: &Self) -> bool {
                self.as_slice() == other.as_slice()
            }
        }
        impl Eq for $ty {}
        impl Hash for $ty {
            #[inline(always)]
            fn hash<H: hash::Hasher>(&self, h: &mut H) {
                self.len.hash(h);
                h.write(self.as_slice());
            }
        }

        #[cfg(feature = "serde")]
        const _: () = {
            use serde::{
                de::{self, Visitor},
                Deserializer, Serializer,
            };

            use crate::quic::cid_serde_helpers;

            struct CidVisitor;
            impl<'de> Visitor<'de> for CidVisitor {
                type Value = $ty;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a byte slice for a QUIC Connection‑ID")
                }
                fn visit_bytes<E>(self, v: &[u8]) -> Result<$ty, E>
                where
                    E: de::Error,
                {
                    let data = if $with_len_on_wire {
                        if v.is_empty() {
                            return Err(de::Error::invalid_length(0, &"empty CID"));
                        }
                        let l = v[0] as usize;
                        if v.len() != l + 1 {
                            return Err(de::Error::invalid_value(
                                de::Unexpected::Bytes(v),
                                &"malformed length‑prefixed CID",
                            ));
                        }
                        &v[1..]
                    } else {
                        v
                    };

                    if data.len() > QUIC_MAX_CID_LEN {
                        return Err(de::Error::invalid_length(
                            data.len(),
                            &cid_serde_helpers::LengthExceedsMaxError {
                                value: data.len(),
                                max: QUIC_MAX_CID_LEN,
                                field_name: "CID length",
                            },
                        ));
                    }
                    let mut id = $ty::new();
                    id.set(data);
                    Ok(id)
                }
            }

            impl serde::Serialize for $ty {
                fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    if $with_len_on_wire {
                        let mut buf = [0u8; 1 + QUIC_MAX_CID_LEN];
                        buf[0] = self.len();
                        // Safety: `self.len` is always <= `QUIC_MAX_CID_LEN`.
                        unsafe {
                            raw_copy(
                                self.bytes.as_ptr(),
                                buf[1..].as_mut_ptr(),
                                self.len as usize,
                            )
                        };
                        ser.serialize_bytes(&buf[..1 + self.len as usize])
                    } else {
                        ser.serialize_bytes(self.as_slice())
                    }
                }
            }
            impl<'de> serde::Deserialize<'de> for $ty {
                fn deserialize<D>(deser: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    deser.deserialize_bytes(CidVisitor)
                }
            }
        };
    };
}

impl_cid_common!(QuicDstConnLong, "Destination (Long Hdr)", true);
impl_cid_common!(QuicSrcConnLong, "Source (Long Hdr)", true);
impl_cid_common!(QuicDstConnShort, "Destination (Short Hdr)", false);

/// The inner payload of a QUIC Long Header.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct QuicHdrLong {
    /// The QUIC protocol version.
    pub version: [u8; 4],
    /// The Destination Connection ID.
    pub dst: QuicDstConnLong,
    /// The Source Connection ID.
    pub src: QuicSrcConnLong,
}
impl QuicHdrLong {
    /// The size of the struct in memory.
    pub const LEN: usize = size_of::<Self>();
    /// The minimum possible size of a Long Header on the wire.
    /// (1 byte first_byte + 4-byte version + 1 byte dcil + 1 byte scil)
    pub const MIN_LEN_ON_WIRE: usize = 7;

    /// Creates a new, zero-initialized `QuicHdrLong`.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            version: [0; 4],
            dst: QuicDstConnLong::new(),
            src: QuicSrcConnLong::new(),
        }
    }

    /// Gets the version as a `u32`.
    #[inline(always)]
    pub fn version(&self) -> u32 {
        u32::from_be_bytes(self.version)
    }

    /// Sets the version from a `u32`.
    #[inline(always)]
    pub fn set_version(&mut self, v: u32) {
        self.version = v.to_be_bytes();
    }
}

/// The inner payload of a QUIC Short Header.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct QuicHdrShort {
    /// The Destination Connection ID.
    pub dst: QuicDstConnShort,
}

impl QuicHdrShort {
    /// The size of the struct in memory.
    pub const LEN: usize = size_of::<Self>();
    /// The minimum possible size of a Short Header on the wire.
    /// (1 byte first_byte)
    pub const MIN_LEN_ON_WIRE: usize = 1;

    /// Creates a new, zero-initialized `QuicHdrShort`.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            dst: QuicDstConnShort::new(),
        }
    }
}

/// A `union` to hold either a Long or Short QUIC header payload.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union QuicHdrUn {
    /// Long Header variant.
    pub long: QuicHdrLong,
    /// Short Header variant.
    pub short: QuicHdrShort,
}

impl QuicHdrUn {
    /// Creates a new, zero-initialized `QuicHdrUn`.
    ///
    /// The `long` variant is used for initialization, which zeroes the entire union.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            long: QuicHdrLong::new(),
        }
    }
}

impl fmt::Debug for QuicHdrUn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QuicHdrUn { ... }")
    }
}

/// The logical type of QUIC header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QuicHeaderType {
    /// A Long Header. All connection ID lengths are encoded on the wire.
    QuicLong,
    /// A Short Header. The destination connection ID length must be known from context.
    QuicShort { dc_id_len: u8 },
}

/// A raw, on-the-wire representation of a QUIC header.
///
/// This struct is intended to provide access to QUIC header fields.
/// The actual parsing and interpretation of variable-length fields (like CIDs,
/// Packet Number, Token, Length) often require sequential reading and context.
///
/// For Long Headers (RFC 9000, Section 17.2):
///  +-+-+-+-+-+-+-+-+
///  |1|1|T T|X X X X|  Header Form (1), Fixed Bit (1), Long Packet Type (2), Type-Specific (4)
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         Version (32)                          |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | DCID Len (8)  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |               Destination Connection ID (0..160)            ...
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | SCID Len (8)  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                 Source Connection ID (0..160)               ...
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  ... Type-specific fields (e.g., Token Length, Token for Initial; Length for others) ...
///  ... Packet Number (8, 16, 24, or 32 bits) ...
///
/// For Short Headers (RFC 9000, Section 17.3):
///  +-+-+-+-+-+-+-+-+
///  |0|1|S|R R|K K|P P| Header Form (0), Fixed Bit (1), Spin Bit (S), Reserved (R R), Key Phase (K K), Packet Number Length (P P)
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                Destination Connection ID (0..160)           ... -> Optional, length implicit from context
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     Packet Number (8, 16, 24, or 32 bits)   ...
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     Protected Payload (*)                   ...
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// This struct is designed to be safely loaded directly from packet data in
/// `no_std` environments like eBPF. After loading, call [`QuicHdr::parse()`]
/// to get a [`ParsedQuicHdr`], which provides a safe API for accessing header fields.
///
/// # Example (in an `aya_ebpf` kernel-space program)
///
/// This example demonstrates how to parse a QUIC header from a UDP packet
/// within a TC (Traffic Control) eBPF program.
///
/// ```no_run
/// # use aya_ebpf::{programs::TcContext, macros::classifier};
/// # use network_types::{
/// #     eth::EthHdr,
/// #     ip::{IpProto, Ipv4Hdr},
/// #     udp::UdpHdr,
/// #     quic::{QuicHdr, QuicHdrError},
/// # };
/// #
/// #[classifier]
/// pub fn my_quic_parser(ctx: TcContext) -> i32 {
///     match try_my_quic_parser(ctx) {
///         Ok(ret) => ret,
///         Err(_) => 1, // TC_ACT_SHOT
///     }
/// }
///
/// fn try_my_quic_parser(ctx: TcContext) -> Result<i32, ()> {
///     // Assume offsets for Eth, IP, and UDP headers are already calculated.
///     // A real program would need to handle dynamic IP header lengths.
///     let udp_payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
///
///     // Load the raw QUIC header. `ctx.load` will handle bounds checks.
///     let mut quic_hdr: QuicHdr = ctx.load(udp_payload_offset).map_err(|_| ())?;
///
///     // For Short Headers, the DCID length is not on the wire. The eBPF
///     // program must know it from context (e.g., from connection tracking).
///     // Here, we'll assume a length of 8.
///     const EXPECTED_DCID_LEN_FOR_SHORT_HDR: u8 = 8;
///
///     // Parse the raw header into a safe, logical view.
///     let parsed = quic_hdr.parse(EXPECTED_DCID_LEN_FOR_SHORT_HDR).map_err(|_| ())?;
///
///     if parsed.is_long_header() {
///         let version = parsed.version().unwrap_or(0);
///         let dc_id = parsed.dc_id();
///         let sc_id = parsed.sc_id().unwrap_or(&[]);
///         // Do something with the Long Header info...
///         // aya_log_ebpf::info!(&ctx, "QUIC Long: v={} dcid_len={} scid_len={}",
///         //     version, dc_id.len(), sc_id.len());
///     } else {
///         let dc_id = parsed.dc_id();
///         let spin_bit = parsed.short_spin_bit().unwrap_or(false);
///         // Do something with the Short Header info...
///         // aya_log_ebpf::info!(&ctx, "QUIC Short: dcid_len={} spin={}",
///         //     dc_id.len(), spin_bit);
///     }
///
///     Ok(0) // TC_ACT_OK
/// }
/// ```
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct QuicHdr {
    first_byte: u8,
    inner: QuicHdrUn,
}

/// A safe, parsed view of a QUIC header.
///
/// This struct is created by [`QuicHdr::parse()`] and provides methods to
/// safely access and modify the fields of the underlying header.
pub struct ParsedQuicHdr<'a> {
    hdr: &'a mut QuicHdr,
    header_type: QuicHeaderType,
}

impl QuicHdr {
    /// The total size of the struct in memory.
    pub const LEN: usize = size_of::<Self>();
    /// The minimum size of a valid Long Header on the wire.
    pub const MIN_LONG_HDR_LEN_ON_WIRE: usize = QuicHdrLong::MIN_LEN_ON_WIRE;
    /// The minimum size of a valid Short Header on the wire.
    pub const MIN_SHORT_HDR_LEN_ON_WIRE: usize = QuicHdrShort::MIN_LEN_ON_WIRE;

    /// Creates a new `QuicHdr` with a specified logical type.
    ///
    /// # Parameters
    /// * `ht`: The desired header type (`QuicLong` or `QuicShort`).
    ///
    /// # Returns
    /// A new `QuicHdr` initialized with default values for the given type.
    #[inline(always)]
    pub fn new(ht: QuicHeaderType) -> Self {
        match ht {
            QuicHeaderType::QuicLong => Self {
                first_byte: HEADER_FORM_BIT | FIXED_BIT_MASK,
                inner: QuicHdrUn::new(),
            },
            QuicHeaderType::QuicShort { dc_id_len } => {
                let mut s = QuicHdrShort::new();
                s.dst.len = cmp::min(dc_id_len, QUIC_MAX_CID_LEN as u8);
                Self {
                    first_byte: FIXED_BIT_MASK,
                    inner: QuicHdrUn { short: s },
                }
            }
        }
    }

    /// Checks if the header is a Long Header based on the first bit.
    #[inline(always)]
    pub fn is_long_header(&self) -> bool {
        (self.first_byte & HEADER_FORM_BIT) != 0
    }

    /// Parses the raw header data into a safe, logical view.
    ///
    /// # Parameters
    /// * `dcid_len_for_short`: The expected length of the Destination Connection ID
    ///   if this is a Short Header. This value must be known from the connection's context,
    ///   as it is not encoded on the wire in Short Headers. It is ignored for Long Headers.
    ///
    /// # Returns
    /// `Ok(ParsedQuicHdr)` on success, or a `QuicHdrError` if the header contains invalid lengths.
    #[inline(always)]
    pub fn parse(&mut self, dcid_len_for_short: u8) -> Result<ParsedQuicHdr<'_>, QuicHdrError> {
        let header_type = if self.is_long_header() {
            // Safety: We have checked that this is a Long Header, so accessing `inner.long` is valid.
            let long = unsafe { &self.inner.long };
            if long.dst.len() > QUIC_MAX_CID_LEN as u8 || long.src.len() > QUIC_MAX_CID_LEN as u8 {
                return Err(QuicHdrError::InvalidLength);
            }
            QuicHeaderType::QuicLong
        } else {
            if dcid_len_for_short > QUIC_MAX_CID_LEN as u8 {
                return Err(QuicHdrError::InvalidLength);
            }
            QuicHeaderType::QuicShort {
                dc_id_len: dcid_len_for_short,
            }
        };
        Ok(ParsedQuicHdr {
            hdr: self,
            header_type,
        })
    }

    /// Validates and returns a CID length.
    ///
    /// # Parameters
    /// * `b`: The length byte to check.
    ///
    /// # Returns
    /// `Ok(usize)` if the length is valid, `Err(QuicHdrError::InvalidLength)` otherwise.
    #[inline(always)]
    pub fn parse_cid_len(b: u8) -> Result<usize, QuicHdrError> {
        if b as usize > QUIC_MAX_CID_LEN {
            Err(QuicHdrError::InvalidLength)
        } else {
            Ok(b as usize)
        }
    }
}

impl<'a> ParsedQuicHdr<'a> {
    /// Gets the raw first byte of the QUIC header.
    ///
    /// # Returns
    /// The `u8` value of the first byte.
    #[inline(always)]
    pub fn first_byte(&self) -> u8 {
        self.hdr.first_byte
    }

    /// Sets the raw first byte of the QUIC header.
    ///
    /// # Parameters
    /// * `b`: The `u8` value to set as the first byte.
    #[inline(always)]
    pub fn set_first_byte(&mut self, b: u8) {
        self.hdr.first_byte = b;
    }

    /// Checks if the header is a Long Header.
    ///
    /// This is determined by checking the Header Form bit (the most significant
    /// bit of the first byte).
    ///
    /// # Returns
    /// `true` if it is a Long Header, `false` otherwise.
    #[inline(always)]
    pub fn is_long_header(&self) -> bool {
        self.hdr.is_long_header()
    }

    /// Gets the Fixed Bit (the second most significant bit of the first byte).
    ///
    /// According to RFC 9000, this bit must be set to 1. Packets where this
    /// bit is 0 are not valid QUIC packets.
    ///
    /// # Returns
    /// The value of the fixed bit (0 or 1).
    #[inline(always)]
    pub fn fixed_bit(&self) -> u8 {
        (self.hdr.first_byte & FIXED_BIT_MASK) >> 6
    }

    /// Gets the Packet Type if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(QuicPacketType)` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn long_packet_type(&self) -> Result<QuicPacketType, QuicHdrError> {
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        let bits = unsafe { self.long_packet_type_bits_unchecked() };
        QuicPacketType::try_from(bits)
    }

    /// Gets the Reserved Bits (bits 4-5) if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(u8)` containing the 2 reserved bits if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn reserved_bits_long(&self) -> Result<u8, QuicHdrError> {
        if !self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.reserved_bits_long_unchecked() })
        }
    }

    /// Gets the encoded Packet Number Length (bits 6-7) if this is a Long Header.
    /// This value is `actual_length_in_bytes - 1`.
    ///
    /// # Returns
    /// `Ok(u8)` containing the encoded length (0-3) if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn pn_length_bits_long(&self) -> Result<u8, QuicHdrError> {
        if !self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.pn_length_bits_long_unchecked() })
        }
    }

    /// Gets the actual Packet Number Length in bytes (1-4) if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(usize)` containing the length if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn packet_number_length_long(&self) -> Result<usize, QuicHdrError> {
        self.pn_length_bits_long().map(|b| (b + 1) as usize)
    }

    /// Gets the Spin Bit (bit 2) if this is a Short Header.
    ///
    /// # Returns
    /// `Ok(bool)` with the spin bit value if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn short_spin_bit(&self) -> Result<bool, QuicHdrError> {
        if self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.short_spin_bit_unchecked() })
        }
    }

    /// Gets the Reserved Bits (bits 3-4) if this is a Short Header.
    ///
    /// # Returns
    /// `Ok(u8)` containing the 2 reserved bits if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn short_reserved_bits(&self) -> Result<u8, QuicHdrError> {
        if self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.short_reserved_bits_unchecked() })
        }
    }

    /// Gets the Key Phase Bit (bit 5) if this is a Short Header.
    ///
    /// # Returns
    /// `Ok(bool)` with the key phase value if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn short_key_phase(&self) -> Result<bool, QuicHdrError> {
        if self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.short_key_phase_unchecked() })
        }
    }

    /// Gets the encoded Packet Number Length (bits 6-7) if this is a Short Header.
    /// This value is `actual_length_in_bytes - 1`.
    ///
    /// # Returns
    /// `Ok(u8)` containing the encoded length (0-3) if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn short_pn_length_bits(&self) -> Result<u8, QuicHdrError> {
        if self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.short_pn_length_bits_unchecked() })
        }
    }

    /// Gets the actual Packet Number Length in bytes (1-4) if this is a Short Header.
    ///
    /// # Returns
    /// `Ok(usize)` containing the length if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn short_packet_number_length(&self) -> Result<usize, QuicHdrError> {
        self.short_pn_length_bits().map(|b| (b + 1) as usize)
    }

    /// Gets the QUIC Version if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(u32)` containing the version if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn version(&self) -> Result<u32, QuicHdrError> {
        if !self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.hdr.inner.long.version() })
        }
    }

    /// Gets the on-the-wire length of the Destination Connection ID if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(u8)` with the length if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn dc_id_len_on_wire(&self) -> Result<u8, QuicHdrError> {
        if !self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.hdr.inner.long.dst.len() })
        }
    }

    /// Gets the on-the-wire length of the Source Connection ID if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(u8)` with the length if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn sc_id_len_on_wire(&self) -> Result<u8, QuicHdrError> {
        if !self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.hdr.inner.long.src.len() })
        }
    }

    /// Gets the effective length of the Destination Connection ID.
    ///
    /// For Long Headers, this length is read directly from the header data. For Short
    /// Headers, this is the contextual length that was provided when [`QuicHdr::parse()`]
    /// was called.
    ///
    /// # Returns
    /// The length of the Destination Connection ID in bytes.
    #[inline(always)]
    pub fn dc_id_effective_len(&self) -> u8 {
        match self.header_type {
            // Safety: Header form is known.
            QuicHeaderType::QuicLong => unsafe { self.hdr.inner.long.dst.len() },
            QuicHeaderType::QuicShort { dc_id_len } => dc_id_len,
        }
    }

    /// Gets a slice containing the bytes of the Destination Connection ID.
    ///
    /// The length of the slice is determined by `dc_id_effective_len()`.
    ///
    /// # Returns
    /// A byte slice (`&[u8]`) representing the Destination Connection ID.
    #[inline(always)]
    pub fn dc_id(&self) -> &[u8] {
        let n = self.dc_id_effective_len() as usize;
        let raw = match self.header_type {
            // Safety: We are in a `ParsedQuicHdr`, so we know which union variant is active.
            QuicHeaderType::QuicLong => unsafe { &self.hdr.inner.long.dst.bytes },
            QuicHeaderType::QuicShort { .. } => unsafe { &self.hdr.inner.short.dst.bytes },
        };
        // Safety: `dc_id_effective_len` is bounded by `QUIC_MAX_CID_LEN` during parsing.
        unsafe { raw.get_unchecked(..n) }
    }

    /// Gets a slice of the Source Connection ID bytes if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(&[u8])` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn sc_id(&self) -> Result<&[u8], QuicHdrError> {
        if !self.is_long_header() {
            Err(QuicHdrError::InvalidHeaderForm)
        } else {
            // Safety: A header form has been checked.
            Ok(unsafe { self.hdr.inner.long.src.as_slice() })
        }
    }

    /// Returns the logical header type determined during parsing.
    ///
    /// # Returns
    /// The [`QuicHeaderType`] enum variant (`QuicLong` or `QuicShort`) for this header.
    #[inline(always)]
    pub fn header_type(&self) -> QuicHeaderType {
        self.header_type
    }

    /// Sets the Fixed Bit (bit 1 of `first_byte`).
    ///
    /// # Parameters
    /// * `v`: The bit value (0 or 1). Masked to 1 bit.
    #[inline(always)]
    pub fn set_fixed_bit(&mut self, v: u8) {
        // Safety: This operation is valid for both header forms.
        unsafe { self.set_fixed_bit_unchecked(v) }
    }

    /// Sets the Packet Type if this is a Long Header.
    ///
    /// # Parameters
    /// * `pt`: The `QuicPacketType` to set.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn set_long_packet_type(&mut self, pt: QuicPacketType) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe {
            self.set_long_packet_type_bits_unchecked(pt as u8);
        }
        Ok(())
    }

    /// Sets the Reserved Bits (bits 4-5) if this is a Long Header.
    ///
    /// # Parameters
    /// * `v`: The 2-bit value to set. Masked to 2 bits.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn set_reserved_bits_long(&mut self, v: u8) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_reserved_bits_long_unchecked(v) };
        Ok(())
    }

    /// Sets the encoded Packet Number Length (bits 6-7) if this is a Long Header.
    ///
    /// # Parameters
    /// * `v`: Encoded Packet Number Length (`actual_length_in_bytes - 1`, range 0-3). Masked to 2 bits.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn set_pn_length_bits_long(&mut self, v: u8) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_pn_length_bits_long_unchecked(v) };
        Ok(())
    }

    /// Sets the actual Packet Number Length in bytes (1-4) if this is a Long Header.
    ///
    /// # Parameters
    /// * `n`: The actual length in bytes (1-4).
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` if `n` is out of range or this is not a Long Header.
    #[inline(always)]
    pub fn set_packet_number_length_long(&mut self, n: usize) -> Result<(), QuicHdrError> {
        if !(1..=4).contains(&n) {
            return Err(QuicHdrError::InvalidLength);
        }
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A length and header form have been checked.
        unsafe { self.set_packet_number_length_long_unchecked(n) };
        Ok(())
    }

    /// Sets the Spin Bit (bit 2) if this is a Short Header.
    ///
    /// # Parameters
    /// * `b`: The boolean value for the spin bit.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn set_short_spin_bit(&mut self, b: bool) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_short_spin_bit_unchecked(b) };
        Ok(())
    }

    /// Sets the Reserved Bits (bits 3-4) if this is a Short Header.
    ///
    /// # Parameters
    /// * `v`: The 2-bit value to set. Masked to 2 bits.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn set_short_reserved_bits(&mut self, v: u8) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_short_reserved_bits_unchecked(v) };
        Ok(())
    }

    /// Sets the Key Phase Bit (bit 5) if this is a Short Header.
    ///
    /// # Parameters
    /// * `kp`: The boolean value for the key phase.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn set_short_key_phase(&mut self, kp: bool) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_short_key_phase_unchecked(kp) };
        Ok(())
    }

    /// Sets the encoded Packet Number Length (bits 6-7) if this is a Short Header.
    ///
    /// # Parameters
    /// * `v`: Encoded Packet Number Length (`actual_length_in_bytes - 1`, range 0-3). Masked to 2 bits.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if a Long Header.
    #[inline(always)]
    pub fn set_short_pn_length_bits(&mut self, v: u8) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_short_pn_length_bits_unchecked(v) };
        Ok(())
    }

    /// Sets the actual Packet Number Length in bytes (1-4) if this is a Short Header.
    ///
    /// # Parameters
    /// * `n`: The actual length in bytes (1-4).
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` if `n` is out of range or this is a Long Header.
    #[inline(always)]
    pub fn set_short_packet_number_length(&mut self, n: usize) -> Result<(), QuicHdrError> {
        if !(1..=4).contains(&n) {
            return Err(QuicHdrError::InvalidLength);
        }
        if self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A length and header form have been checked.
        unsafe { self.set_short_packet_number_length_unchecked(n) };
        Ok(())
    }

    /// Sets the QUIC Version if this is a Long Header.
    ///
    /// # Parameters
    /// * `v`: The `u32` version value.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn set_version(&mut self, v: u32) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_version_unchecked(v) };
        Ok(())
    }

    /// Sets the effective length of the Destination Connection ID.
    ///
    /// # Parameters
    /// * `l`: The new length. Will be truncated to `QUIC_MAX_CID_LEN`.
    #[inline(always)]
    pub fn set_dc_id_effective_len(&mut self, l: u8) {
        // Safety: This operation is valid for both header forms and handles the logic internally.
        unsafe { self.set_dc_id_effective_len_unchecked(l) };
    }

    /// Sets the Destination Connection ID from a slice.
    /// This also updates the effective length.
    ///
    /// # Parameters
    /// * `d`: A slice containing the new DCID.
    #[inline(always)]
    pub fn set_dc_id(&mut self, d: &[u8]) {
        // Safety: This operation is valid for both header forms and handles the logic internally.
        unsafe { self.set_dc_id_unchecked(d) };
    }

    /// Sets the on-the-wire length of the Source Connection ID if this is a Long Header.
    ///
    /// # Parameters
    /// * `l`: The new length. Will be truncated to `QUIC_MAX_CID_LEN`.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn set_sc_id_len_on_wire(&mut self, l: u8) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_sc_id_len_on_wire_unchecked(l) };
        Ok(())
    }

    /// Sets the Source Connection ID from a slice if this is a Long Header.
    /// This also updates the on-the-wire length.
    ///
    /// # Parameters
    /// * `d`: A slice containing the new SCID.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline(always)]
    pub fn set_sc_id(&mut self, d: &[u8]) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            return Err(QuicHdrError::InvalidHeaderForm);
        }
        // Safety: A header form has been checked.
        unsafe { self.set_sc_id_unchecked(d) };
        Ok(())
    }
}

// Unchecked, unsafe internal methods.
impl<'a> ParsedQuicHdr<'a> {
    /// Gets the Long Header Packet Type bits from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The Packet Type bits value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn long_packet_type_bits_unchecked(&self) -> u8 {
        (self.hdr.first_byte & LONG_PACKET_TYPE_MASK) >> LONG_PACKET_TYPE_SHIFT
    }

    /// Sets the Long Header Packet Type bits in `first_byte` without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn set_long_packet_type_bits_unchecked(&mut self, b: u8) {
        self.hdr.first_byte =
            (self.hdr.first_byte & !LONG_PACKET_TYPE_MASK) | ((b & 0x03) << LONG_PACKET_TYPE_SHIFT);
    }

    /// Gets the Reserved Bits (Long Header) from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The Reserved Bits value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn reserved_bits_long_unchecked(&self) -> u8 {
        (self.hdr.first_byte & RESERVED_BITS_LONG_MASK) >> RESERVED_BITS_LONG_SHIFT
    }

    /// Sets the Reserved Bits (Long Header) in `first_byte` without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn set_reserved_bits_long_unchecked(&mut self, v: u8) {
        self.hdr.first_byte = (self.hdr.first_byte & !RESERVED_BITS_LONG_MASK)
            | ((v & 0x03) << RESERVED_BITS_LONG_SHIFT);
    }

    /// Gets the encoded Packet Number Length bits (Long Header) from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The encoded PN length bits (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn pn_length_bits_long_unchecked(&self) -> u8 {
        self.hdr.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the encoded Packet Number Length bits (Long Header) in `first_byte` without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn set_pn_length_bits_long_unchecked(&mut self, v: u8) {
        self.hdr.first_byte =
            (self.hdr.first_byte & !PN_LENGTH_BITS_MASK) | (v & PN_LENGTH_BITS_MASK);
    }

    /// Sets the Packet Number Length (Long Header) in `first_byte` without checking header form or length validity.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true and `1 <= n <= 4`.
    #[inline(always)]
    unsafe fn set_packet_number_length_long_unchecked(&mut self, n: usize) {
        self.set_pn_length_bits_long_unchecked((n - 1) as u8);
    }

    /// Gets the Spin Bit (Short Header) from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The spin bit value.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn short_spin_bit_unchecked(&self) -> bool {
        (self.hdr.first_byte & SHORT_SPIN_BIT_MASK) != 0
    }

    /// Sets the Spin Bit (Short Header) in `first_byte` without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn set_short_spin_bit_unchecked(&mut self, b: bool) {
        if b {
            self.hdr.first_byte |= SHORT_SPIN_BIT_MASK;
        } else {
            self.hdr.first_byte &= !SHORT_SPIN_BIT_MASK;
        }
    }

    /// Gets the Reserved Bits (Short Header) from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The reserved bits value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn short_reserved_bits_unchecked(&self) -> u8 {
        (self.hdr.first_byte & SHORT_RESERVED_BITS_MASK) >> SHORT_RESERVED_BITS_SHIFT
    }

    /// Sets the Reserved Bits (Short Header) in `first_byte` without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn set_short_reserved_bits_unchecked(&mut self, v: u8) {
        self.hdr.first_byte = (self.hdr.first_byte & !SHORT_RESERVED_BITS_MASK)
            | ((v & 0x03) << SHORT_RESERVED_BITS_SHIFT);
    }

    /// Gets the Key Phase bit (Short Header) from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The key phase bit value.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn short_key_phase_unchecked(&self) -> bool {
        (self.hdr.first_byte & SHORT_KEY_PHASE_BIT_MASK) != 0
    }

    /// Sets the Key Phase bit (Short Header) in `first_byte` without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn set_short_key_phase_unchecked(&mut self, b: bool) {
        if b {
            self.hdr.first_byte |= SHORT_KEY_PHASE_BIT_MASK;
        } else {
            self.hdr.first_byte &= !SHORT_KEY_PHASE_BIT_MASK;
        }
    }

    /// Gets the encoded Packet Number Length bits (Short Header) from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The encoded PN length bits (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn short_pn_length_bits_unchecked(&self) -> u8 {
        self.hdr.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the encoded Packet Number Length bits (Short Header) in `first_byte` without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false.
    #[inline(always)]
    unsafe fn set_short_pn_length_bits_unchecked(&mut self, v: u8) {
        self.hdr.first_byte =
            (self.hdr.first_byte & !PN_LENGTH_BITS_MASK) | (v & PN_LENGTH_BITS_MASK);
    }

    /// Sets the Packet Number Length (Short Header) in `first_byte` without checking header form or length validity.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is false and `1 <= n <= 4`.
    #[inline(always)]
    unsafe fn set_short_packet_number_length_unchecked(&mut self, n: usize) {
        self.set_short_pn_length_bits_unchecked((n - 1) as u8);
    }

    /// Sets the Fixed Bit in `first_byte` without any checks.
    ///
    /// # Safety
    /// This is always safe from a memory perspective, but the caller must ensure the resulting byte is valid.
    #[inline(always)]
    unsafe fn set_fixed_bit_unchecked(&mut self, v: u8) {
        self.hdr.first_byte = (self.hdr.first_byte & !FIXED_BIT_MASK) | ((v & 1) << 6);
    }

    /// Sets the QUIC version without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn set_version_unchecked(&mut self, v: u32) {
        self.hdr.inner.long.set_version(v);
    }

    /// Sets the effective DCID length without any checks.
    ///
    /// # Safety
    /// Caller must ensure the correct `header_type` is handled and that the length is valid.
    #[inline(always)]
    unsafe fn set_dc_id_effective_len_unchecked(&mut self, l: u8) {
        let l = cmp::min(l, QUIC_MAX_CID_LEN as u8);
        match &mut self.header_type {
            QuicHeaderType::QuicLong => {
                self.hdr.inner.long.dst.len = l;
            }
            QuicHeaderType::QuicShort { dc_id_len } => *dc_id_len = l,
        }
    }

    /// Sets the DCID without any checks.
    ///
    /// # Safety
    /// Caller must ensure the correct `header_type` is handled.
    #[inline(always)]
    unsafe fn set_dc_id_unchecked(&mut self, d: &[u8]) {
        match &mut self.header_type {
            QuicHeaderType::QuicLong => self.hdr.inner.long.dst.set(d),
            QuicHeaderType::QuicShort { dc_id_len } => {
                self.hdr.inner.short.dst.set(d);
                *dc_id_len = self.hdr.inner.short.dst.len();
            }
        }
    }

    /// Sets the on-the-wire SCID length without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn set_sc_id_len_on_wire_unchecked(&mut self, l: u8) {
        self.hdr.inner.long.src.len = cmp::min(l, QUIC_MAX_CID_LEN as u8);
    }

    /// Sets the SCID without checking a header form.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline(always)]
    unsafe fn set_sc_id_unchecked(&mut self, d: &[u8]) {
        self.hdr.inner.long.src.set(d);
    }
}

impl fmt::Debug for QuicHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicHdr")
            .field("first_byte", &format_args!("{:#04x}", self.first_byte))
            .field("is_long", &self.is_long_header())
            .finish()
    }
}
impl<'a> fmt::Debug for ParsedQuicHdr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ParsedQuicHdr");
        s.field("first_byte", &format_args!("{:#04x}", self.first_byte()))
            .field(
                "form",
                &if self.is_long_header() {
                    "Long"
                } else {
                    "Short"
                },
            )
            .field("fixed", &self.fixed_bit());
        match self.header_type {
            QuicHeaderType::QuicLong => {
                s.field("version", &self.version().ok())
                    .field("dc_id", &self.dc_id())
                    .field("sc_id", &self.sc_id().ok())
                    .field("ptype", &self.long_packet_type().ok());
            }
            QuicHeaderType::QuicShort { .. } => {
                s.field("dc_id", &self.dc_id())
                    .field("spin", &self.short_spin_bit().ok())
                    .field("phase", &self.short_key_phase().ok());
            }
        };
        s.finish()
    }
}

impl TryFrom<u8> for QuicPacketType {
    type Error = QuicHdrError;

    /// Converts a byte to a `QuicPacketType`.
    ///
    /// # Returns
    /// `Ok(QuicPacketType)` on a valid value, `Err(QuicHdrError::InvalidPacketTypeBits)` otherwise.
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(QuicPacketType::Initial),
            0x01 => Ok(QuicPacketType::ZeroRTT),
            0x02 => Ok(QuicPacketType::Handshake),
            0x03 => Ok(QuicPacketType::Retry),
            _ => Err(QuicHdrError::InvalidPacketTypeBits),
        }
    }
}
impl From<QuicPacketType> for u8 {
    #[inline(always)]
    fn from(p: QuicPacketType) -> Self {
        p as u8
    }
}

#[cfg(feature = "serde")]
mod serde_header_impl {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    use serde::{
        de::{self, Deserializer, Visitor},
        ser::{Serialize, Serializer},
    };

    impl Serialize for QuicHdr {
        fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut v = Vec::with_capacity(1 + 4 + 1 + QUIC_MAX_CID_LEN + 1 + QUIC_MAX_CID_LEN);
            v.push(self.first_byte);
            if self.is_long_header() {
                // Safety: `is_long_header` is true, so `inner.long` is the active variant.
                let long = unsafe { &self.inner.long };
                v.extend_from_slice(&long.version);
                v.push(long.dst.len());
                v.extend_from_slice(long.dst.as_slice());
                v.push(long.src.len());
                v.extend_from_slice(long.src.as_slice());
            } else {
                // Safety: `is_long_header` is false, so `inner.short` is the active variant.
                let short = unsafe { &self.inner.short };
                v.extend_from_slice(short.dst.as_slice());
            }
            ser.serialize_bytes(&v)
        }
    }

    struct HdrVisitor;
    impl<'de> Visitor<'de> for HdrVisitor {
        type Value = QuicHdr;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a QUIC header")
        }

        fn visit_bytes<E>(self, b: &[u8]) -> Result<QuicHdr, E>
        where
            E: de::Error,
        {
            if b.is_empty() {
                return Err(E::custom("empty header"));
            }
            let first = b[0];
            let mut cur = &b[1..];
            let mut hdr = QuicHdr {
                first_byte: 0,
                inner: QuicHdrUn::new(),
            };
            hdr.first_byte = first;

            #[inline(always)]
            fn take<'a, E>(buf: &mut &'a [u8], n: usize, msg: &'static str) -> Result<&'a [u8], E>
            where
                E: de::Error,
            {
                if buf.len() < n {
                    Err(E::custom(msg))
                } else {
                    let (h, t) = buf.split_at(n);
                    *buf = t;
                    Ok(h)
                }
            }

            if (first & HEADER_FORM_BIT) == 0 {
                // Safety: This is a short header, so we can write to `inner.short`.
                unsafe { hdr.inner.short.dst.set(cur) };
                return Ok(hdr);
            }

            if b.len() < QuicHdr::MIN_LONG_HDR_LEN_ON_WIRE {
                return Err(E::custom("truncated long header"));
            }
            // Safety: This is a long header, so we can write to `inner.long`.
            let long = unsafe { &mut hdr.inner.long };
            long.version.copy_from_slice(take(&mut cur, 4, "version")?);

            let dcl = take(&mut cur, 1, "dcil")?[0] as usize;
            if dcl > QUIC_MAX_CID_LEN || cur.len() < dcl {
                return Err(E::custom("dcid len"));
            }
            long.dst.set(take(&mut cur, dcl, "dcid")?);

            let scl = take(&mut cur, 1, "scil")?[0] as usize;
            if scl > QUIC_MAX_CID_LEN || cur.len() < scl {
                return Err(E::custom("scid len"));
            }
            long.src.set(take(&mut cur, scl, "scid")?);

            Ok(hdr)
        }
    }

    impl<'de> de::Deserialize<'de> for QuicHdr {
        fn deserialize<D>(de: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            de.deserialize_bytes(HdrVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr::{addr_of_mut, write};

    #[cfg(feature = "serde")]
    use bincode;
    #[cfg(feature = "serde")]
    use serde_test::{assert_tokens, Token};

    use super::*;
    #[cfg(feature = "serde")]
    extern crate alloc;

    #[test]
    fn test_min_header_len_constants() {
        assert_eq!(QuicHdr::MIN_LONG_HDR_LEN_ON_WIRE, 7);
        assert_eq!(QuicHdr::MIN_SHORT_HDR_LEN_ON_WIRE, 1);
    }

    #[test]
    fn test_long_header_creation_and_accessors() {
        let mut storage = QuicHdr::new(QuicHeaderType::QuicLong);
        let mut hdr = storage.parse(0).unwrap();
        assert!(hdr.is_long_header());
        assert_eq!(hdr.first_byte() & 0xC0, HEADER_FORM_BIT | FIXED_BIT_MASK);
        assert!(hdr.set_long_packet_type(QuicPacketType::ZeroRTT).is_ok());
        assert_eq!(hdr.long_packet_type(), Ok(QuicPacketType::ZeroRTT));
        assert!(hdr.set_reserved_bits_long(0b00).is_ok());
        assert_eq!(hdr.reserved_bits_long(), Ok(0b00));
        assert!(hdr.set_packet_number_length_long(4).is_ok());
        assert_eq!(hdr.pn_length_bits_long(), Ok(0b11));
        assert_eq!(hdr.packet_number_length_long(), Ok(4));
        assert!(hdr.set_version(0x0000_0001).is_ok());
        assert_eq!(hdr.version(), Ok(0x0000_0001));
        let dcid_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let scid_data = [0xA, 0xB, 0xC, 0xD];
        hdr.set_dc_id(&dcid_data);
        assert!(hdr.set_sc_id(&scid_data).is_ok());
        assert_eq!(hdr.dc_id_effective_len(), 8);
        assert_eq!(hdr.dc_id_len_on_wire(), Ok(8));
        assert_eq!(hdr.dc_id(), &dcid_data);
        assert_eq!(hdr.sc_id_len_on_wire(), Ok(4));
        assert_eq!(hdr.sc_id().unwrap(), &scid_data);
        unsafe {
            assert_eq!(hdr.hdr.inner.long.dst.len(), 8);
            assert_eq!(hdr.hdr.inner.long.dst.as_slice(), &dcid_data);
            assert_eq!(hdr.hdr.inner.long.src.len(), 4);
            assert_eq!(hdr.hdr.inner.long.src.as_slice(), &scid_data);
        }
    }

    #[test]
    fn test_short_header_creation_and_accessors() {
        let dcid_data = [0xAA, 0xBB, 0xCC];
        let mut storage = QuicHdr::new(QuicHeaderType::QuicShort {
            dc_id_len: dcid_data.len() as u8,
        });
        let mut hdr = storage.parse(dcid_data.len() as u8).unwrap();
        assert!(!hdr.is_long_header());
        assert_eq!(hdr.first_byte() & 0xC0, FIXED_BIT_MASK); // Form bit 0, Fixed bit 1
        assert!(hdr.set_short_spin_bit(true).is_ok());
        assert_eq!(hdr.short_spin_bit(), Ok(true));
        assert!(hdr.set_short_reserved_bits(0b00).is_ok());
        assert_eq!(hdr.short_reserved_bits(), Ok(0b00));
        assert!(hdr.set_short_key_phase(false).is_ok());
        assert_eq!(hdr.short_key_phase(), Ok(false));
        assert!(hdr.set_short_packet_number_length(1).is_ok());
        assert_eq!(hdr.short_pn_length_bits(), Ok(0b00));
        assert_eq!(hdr.short_packet_number_length(), Ok(1));
        hdr.set_dc_id(&dcid_data);
        if let QuicHeaderType::QuicShort { dc_id_len } = hdr.header_type() {
            assert_eq!(dc_id_len, dcid_data.len() as u8);
        } else {
            panic!("Header type mismatch after setting DCID for short header.");
        }
        assert_eq!(hdr.dc_id_effective_len(), dcid_data.len() as u8);
        assert_eq!(hdr.dc_id(), &dcid_data);
        assert!(hdr.sc_id_len_on_wire().is_err());
        assert!(hdr.sc_id().is_err());
        assert!(hdr.version().is_err());
    }

    #[test]
    fn test_stateless_parsing_logic() {
        let mut storage = QuicHdr::new(QuicHeaderType::QuicLong);
        {
            let mut parsed_long = storage.parse(0).unwrap();
            parsed_long.set_dc_id(&[1, 2, 3]);
            assert!(parsed_long.set_version(123).is_ok());
            assert_eq!(parsed_long.dc_id(), &[1, 2, 3]);
        }
        storage.first_byte = FIXED_BIT_MASK; // a short header's first byte
        unsafe { storage.inner.short.dst.set(&[4, 5]) };
        {
            let parsed_short = storage.parse(2).unwrap();
            assert!(!parsed_short.is_long_header());
            assert_eq!(parsed_short.dc_id(), &[4, 5]);
            assert!(parsed_short.version().is_err());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_long_header_serde_roundtrip() {
        let mut storage = QuicHdr::new(QuicHeaderType::QuicLong);
        let mut hdr = storage.parse(0).unwrap();
        hdr.set_first_byte(0xC0 | (0b00 << 4) | (0b00 << 2) | 0b01);
        assert!(hdr.set_version(0x01020304).is_ok());
        hdr.set_dc_id(&[0xAA; 8]);
        assert!(hdr.set_sc_id(&[0xBB; 4]).is_ok());
        let expected_first_byte = hdr.first_byte();
        assert_eq!(expected_first_byte, 0xC1);
        let config = bincode::config::standard().with_fixed_int_encoding();
        let bytes = bincode::serde::encode_to_vec(&storage, config).expect("Serialization failed");
        let on_wire_len = 1 + 4 + 1 + 8 + 1 + 4;
        assert_eq!(bytes.len(), 8 + on_wire_len);
        let header_bytes = &bytes[8..];
        assert_eq!(header_bytes[0], expected_first_byte);
        assert_eq!(&header_bytes[1..5], &0x01020304u32.to_be_bytes()); // Version
        assert_eq!(header_bytes[5], 8); // DCIL
        assert_eq!(&header_bytes[6..14], &[0xAA; 8]); // DCID
        assert_eq!(header_bytes[14], 4); // SCIL
        assert_eq!(&header_bytes[15..19], &[0xBB; 4]); // SCID
        assert_eq!(header_bytes.len(), on_wire_len);
        let (mut de_storage, len): (QuicHdr, usize) =
            bincode::serde::decode_from_slice(&bytes, config).expect("Deserialization failed");
        assert_eq!(len, bytes.len());
        let de = de_storage.parse(0).unwrap();
        assert_eq!(de.first_byte(), expected_first_byte);
        assert!(de.is_long_header());
        assert_eq!(de.header_type(), QuicHeaderType::QuicLong);
        assert_eq!(de.version().unwrap(), 0x01020304);
        assert_eq!(de.dc_id_effective_len(), 8);
        assert_eq!(de.dc_id(), &[0xAA; 8]);
        assert_eq!(de.sc_id_len_on_wire().unwrap(), 4);
        assert_eq!(de.sc_id().unwrap(), &[0xBB; 4]);
        assert_eq!(de.long_packet_type(), Ok(QuicPacketType::Initial));
        assert_eq!(de.reserved_bits_long(), Ok(0b00));
        assert_eq!(de.pn_length_bits_long(), Ok(0b01)); // PNLEN=2
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_short_header_serde_roundtrip() {
        let dcid_data = [0xCC, 0xDD, 0xEE, 0xFF, 0x11];
        let mut storage = QuicHdr::new(QuicHeaderType::QuicShort {
            dc_id_len: dcid_data.len() as u8,
        });
        let mut hdr = storage.parse(dcid_data.len() as u8).unwrap();
        hdr.set_first_byte(0x40 | SHORT_SPIN_BIT_MASK | SHORT_KEY_PHASE_BIT_MASK | 0b00);
        hdr.set_dc_id(&dcid_data);
        let expected_first_byte = hdr.first_byte();
        assert_eq!(expected_first_byte, 0x40 | 0x20 | 0x04 | 0b00); // 0x64
        let config = bincode::config::standard().with_fixed_int_encoding();
        let bytes = bincode::serde::encode_to_vec(&storage, config).expect("Serialization failed");
        let on_wire_len = 1 + dcid_data.len();
        assert_eq!(bytes.len(), 8 + on_wire_len);
        let header_bytes = &bytes[8..];
        assert_eq!(header_bytes[0], expected_first_byte);
        assert_eq!(&header_bytes[1..], &dcid_data);
        assert_eq!(header_bytes.len(), on_wire_len);
        let (mut de_storage, len): (QuicHdr, usize) =
            bincode::serde::decode_from_slice(&bytes, config).expect("Deserialization failed");
        assert_eq!(len, bytes.len());
        let de = de_storage.parse(dcid_data.len() as u8).unwrap();
        assert_eq!(de.first_byte(), expected_first_byte);
        assert!(!de.is_long_header());
        if let QuicHeaderType::QuicShort { dc_id_len } = de.header_type() {
            assert_eq!(dc_id_len, dcid_data.len() as u8);
        } else {
            panic!("Deserialized to wrong header type: {:?}", de.header_type());
        }
        assert_eq!(de.dc_id_effective_len(), dcid_data.len() as u8);
        assert_eq!(de.dc_id(), &dcid_data);
        assert_eq!(de.short_spin_bit(), Ok(true));
        assert_eq!(de.short_reserved_bits(), Ok(0b00));
        assert_eq!(de.short_key_phase(), Ok(true));
        assert_eq!(de.short_pn_length_bits(), Ok(0b00));
    }

    #[test]
    fn test_cid_struct_helpers() {
        let mut cid_long = QuicDstConnLong::new();
        assert!(cid_long.is_empty());
        cid_long.set(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cid_long.len(), 4);
        assert!(!cid_long.is_empty());
        assert_eq!(cid_long.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut full_cid_bytes_expected = [0u8; QUIC_MAX_CID_LEN];
        full_cid_bytes_expected[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cid_long.bytes, full_cid_bytes_expected);
        let mut cid_short = QuicDstConnShort::new();
        cid_short.set(&[0x11, 0x22]);
        assert_eq!(cid_short.len(), 2);
        assert_eq!(cid_short.as_slice(), &[0x11, 0x22]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_cid_serde_long_direct() {
        let mut cid = QuicDstConnLong::new();
        cid.set(&[1, 2, 3]);
        assert_tokens(&cid, &[Token::Bytes(&[3, 1, 2, 3])]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_cid_serde_short_direct() {
        let mut cid = QuicDstConnShort::new();
        cid.set(&[1, 2, 3, 4]);
        assert_tokens(&cid, &[Token::Bytes(&[1, 2, 3, 4])]);
    }

    #[test]
    fn test_ebpf_like_agent_parsing_long_header() {
        let packet_bytes: &[u8] = &[
            0xC1, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
            0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xAB, 0xCD,
        ];
        let first_byte = packet_bytes[0];
        assert_eq!((first_byte & HEADER_FORM_BIT), HEADER_FORM_BIT);
        let mut hdr_storage = QuicHdr {
            first_byte: 0,
            inner: QuicHdrUn::new(),
        };
        hdr_storage.first_byte = first_byte;
        unsafe {
            let long = &mut hdr_storage.inner.long;
            long.version.copy_from_slice(&packet_bytes[1..5]);
            long.dst.len = packet_bytes[5];
            long.dst.bytes[..8].copy_from_slice(&packet_bytes[6..14]);
            long.src.len = packet_bytes[14];
            long.src.bytes[..5].copy_from_slice(&packet_bytes[15..20]);
        }
        let parsed = hdr_storage.parse(0).unwrap();
        assert!(parsed.is_long_header());
        assert_eq!(parsed.long_packet_type(), Ok(QuicPacketType::Initial));
        assert_eq!(parsed.packet_number_length_long(), Ok(2));
        assert_eq!(parsed.version(), Ok(0x00000001));
        assert_eq!(
            parsed.dc_id(),
            &[0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08]
        );
        assert_eq!(parsed.sc_id().unwrap(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn test_ebpf_like_agent_parsing_short_header() {
        let known_dcid_value_from_context = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let known_dcid_len = known_dcid_value_from_context.len() as u8;
        let packet_bytes: &[u8] = &[0x45, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut hdr_storage = QuicHdr {
            first_byte: 0,
            inner: QuicHdrUn::new(),
        };
        hdr_storage.first_byte = packet_bytes[0];
        unsafe {
            hdr_storage.inner.short.dst.bytes[..known_dcid_len as usize]
                .copy_from_slice(&packet_bytes[1..]);
        }
        let parsed = hdr_storage.parse(known_dcid_len).unwrap();
        assert!(!parsed.is_long_header());
        assert_eq!(parsed.short_spin_bit(), Ok(false));
        assert_eq!(parsed.short_key_phase(), Ok(true));
        assert_eq!(parsed.short_packet_number_length(), Ok(2));
        assert_eq!(parsed.dc_id_effective_len(), known_dcid_len);
        assert_eq!(parsed.dc_id(), &known_dcid_value_from_context);
    }

    #[test]
    fn test_long_packet_type_enum() {
        let mut storage = QuicHdr::new(QuicHeaderType::QuicLong);
        let mut hdr = storage.parse(0).unwrap();
        hdr.set_first_byte(0xC0);
        assert_eq!(hdr.long_packet_type(), Ok(QuicPacketType::Initial));
        hdr.set_first_byte(0xD0);
        assert_eq!(hdr.long_packet_type(), Ok(QuicPacketType::ZeroRTT));
        hdr.set_first_byte(0xE0);
        assert_eq!(hdr.long_packet_type(), Ok(QuicPacketType::Handshake));
        hdr.set_first_byte(0xF0);
        assert_eq!(hdr.long_packet_type(), Ok(QuicPacketType::Retry));
    }

    #[test]
    fn test_cid_set_truncation() {
        let mut cid = QuicDstConnShort::new();
        let oversized_data = [0u8; QUIC_MAX_CID_LEN + 5];
        cid.set(&oversized_data);
        assert_eq!(cid.len() as usize, QUIC_MAX_CID_LEN);
        assert_eq!(cid.as_slice(), &oversized_data[..QUIC_MAX_CID_LEN]);
    }

    #[test]
    fn test_parse_errors() {
        let mut storage_long_dcid = QuicHdr::new(QuicHeaderType::QuicLong);
        unsafe {
            write(
                addr_of_mut!(storage_long_dcid.inner.long.dst.len),
                (QUIC_MAX_CID_LEN + 1) as u8,
            );
        }

        assert_eq!(
            storage_long_dcid.parse(0).unwrap_err(),
            QuicHdrError::InvalidLength
        );
        let mut storage_long_scid = QuicHdr::new(QuicHeaderType::QuicLong);
        unsafe {
            write(
                addr_of_mut!(storage_long_scid.inner.long.src.len),
                (QUIC_MAX_CID_LEN + 1) as u8,
            );
        }
        assert_eq!(
            storage_long_scid.parse(0).unwrap_err(),
            QuicHdrError::InvalidLength
        );
        let mut storage_short = QuicHdr::new(QuicHeaderType::QuicShort { dc_id_len: 8 });
        assert_eq!(
            storage_short
                .parse((QUIC_MAX_CID_LEN + 1) as u8)
                .unwrap_err(),
            QuicHdrError::InvalidLength
        );
    }

    #[test]
    fn test_invalid_header_form_errors() {
        let mut long_storage = QuicHdr::new(QuicHeaderType::QuicLong);
        let mut long_hdr = long_storage.parse(0).unwrap();
        assert_eq!(
            long_hdr.short_spin_bit(),
            Err(QuicHdrError::InvalidHeaderForm)
        );
        assert_eq!(
            long_hdr.short_key_phase(),
            Err(QuicHdrError::InvalidHeaderForm)
        );
        assert_eq!(
            long_hdr.set_short_spin_bit(true),
            Err(QuicHdrError::InvalidHeaderForm)
        );
        let mut short_storage = QuicHdr::new(QuicHeaderType::QuicShort { dc_id_len: 8 });
        let mut short_hdr = short_storage.parse(8).unwrap();
        assert_eq!(short_hdr.version(), Err(QuicHdrError::InvalidHeaderForm));
        assert_eq!(
            short_hdr.long_packet_type(),
            Err(QuicHdrError::InvalidHeaderForm)
        );
        assert_eq!(short_hdr.sc_id(), Err(QuicHdrError::InvalidHeaderForm));
        assert_eq!(
            short_hdr.set_version(1),
            Err(QuicHdrError::InvalidHeaderForm)
        );
    }

    #[test]
    fn test_quic_packet_type_try_from_invalid() {
        assert_eq!(
            QuicPacketType::try_from(0x04),
            Err(QuicHdrError::InvalidPacketTypeBits)
        );
        assert_eq!(
            QuicPacketType::try_from(0xFF),
            Err(QuicHdrError::InvalidPacketTypeBits)
        );
    }

    #[test]
    fn test_display_and_debug_impls() {
        use core::fmt::Write;

        struct StringWriter<const N: usize> {
            buffer: [u8; N],
            len: usize,
        }
        impl<const N: usize> StringWriter<N> {
            fn new() -> Self {
                Self {
                    buffer: [0; N],
                    len: 0,
                }
            }
            fn as_str(&self) -> &str {
                core::str::from_utf8(&self.buffer[..self.len]).unwrap()
            }
        }
        impl<const N: usize> Write for StringWriter<N> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                if self.len + bytes.len() > self.buffer.len() {
                    return Err(core::fmt::Error);
                }
                self.buffer[self.len..self.len + bytes.len()].copy_from_slice(bytes);
                self.len += bytes.len();
                Ok(())
            }
        }
        let err = QuicHdrError::InvalidHeaderForm;
        let mut writer = StringWriter::<128>::new();
        write!(writer, "{}", err).unwrap();
        assert_eq!(
            writer.as_str(),
            "Operation invalid for current QUIC header form"
        );
        let mut cid = QuicDstConnShort::new();
        cid.set(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut writer = StringWriter::<128>::new();
        write!(writer, "{:?}", cid).unwrap();
        assert_eq!(writer.as_str(), "QuicDstConnShort(de:ad:be:ef)");
        let long_storage = QuicHdr::new(QuicHeaderType::QuicLong);
        let mut writer = StringWriter::<128>::new();
        write!(writer, "{:?}", long_storage).unwrap();
        assert!(writer.as_str().contains("is_long: true"));
    }

    #[test]
    fn test_set_packet_number_length_edge_cases() {
        let mut storage = QuicHdr::new(QuicHeaderType::QuicLong);
        let mut hdr = storage.parse(0).unwrap();
        assert_eq!(
            hdr.set_packet_number_length_long(0),
            Err(QuicHdrError::InvalidLength)
        );
        assert_eq!(
            hdr.set_packet_number_length_long(5),
            Err(QuicHdrError::InvalidLength)
        );
        assert!(hdr.set_packet_number_length_long(1).is_ok());
        assert_eq!(hdr.packet_number_length_long(), Ok(1));
        assert!(hdr.set_packet_number_length_long(4).is_ok());
        assert_eq!(hdr.packet_number_length_long(), Ok(4));
    }

    #[test]
    fn test_zero_length_cids() {
        let mut storage = QuicHdr::new(QuicHeaderType::QuicLong);
        let mut hdr = storage.parse(0).unwrap();
        hdr.set_dc_id(&[]);
        assert!(hdr.set_sc_id(&[]).is_ok());
        assert_eq!(hdr.dc_id_effective_len(), 0);
        assert_eq!(hdr.dc_id(), &[]);
        assert_eq!(hdr.sc_id_len_on_wire(), Ok(0));
        assert_eq!(hdr.sc_id().unwrap(), &[]);
        let mut short_storage = QuicHdr::new(QuicHeaderType::QuicShort { dc_id_len: 0 });
        let mut short_hdr = short_storage.parse(0).unwrap();
        short_hdr.set_dc_id(&[]);
        assert_eq!(short_hdr.dc_id_effective_len(), 0);
        assert_eq!(short_hdr.dc_id(), &[]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialization_failures() {
        let config = bincode::config::standard().with_fixed_int_encoding();
        let run_test = |bytes: &[u8]| -> Result<(QuicHdr, usize), _> {
            let encoded = bincode::serde::encode_to_vec(bytes, config).unwrap();
            bincode::serde::decode_from_slice(&encoded, config)
        };
        assert!(
            run_test(&[]).is_err(),
            "Deserializing empty bytes should fail"
        );
        assert!(
            run_test(&[0xC0, 1, 2, 3, 4, 5]).is_err(),
            "Deserializing truncated long header should fail"
        );
        let truncated_dcid = &[0xC0, 0, 0, 0, 1, 8, 4, 1, 2, 3, 4];
        assert!(
            run_test(truncated_dcid).is_err(),
            "Deserializing long header with truncated DCID should fail"
        );
        let oversized_dcil = &[0xC0, 0, 0, 0, 1, (QUIC_MAX_CID_LEN + 1) as u8, 0];
        assert!(
            run_test(oversized_dcil).is_err(),
            "Deserializing long header with oversized DCIL should fail"
        );
        let oversized_scil = &[0xC0, 0, 0, 0, 1, 0, (QUIC_MAX_CID_LEN + 1) as u8];
        assert!(
            run_test(oversized_scil).is_err(),
            "Deserializing long header with oversized SCIL should fail"
        );
    }
}
