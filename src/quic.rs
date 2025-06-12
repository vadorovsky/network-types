//! QUIC header and Connection‑ID types with full support for
//! variable‑length IDs, long/short header forms and zero‑allocation
//! (kernel‑friendly) (de)serialisation.
//!
//! Designed for use inside eBPF (`aya`) programs → `#![no_std]`,
//! fixed‑capacity buffers, no heap, packed layouts.

use core::{cmp, fmt, hash, ptr};

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

#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf, Bytes};

/// Error type for safe getter/setter operations on `QuicHdr`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QuicHdrError {
    /// Operation is not applicable to the current header form (e.g., asking for Long Packet Type on a Short Header).
    InvalidHeaderForm,
    /// Provided length for a field (e.g. CID) is invalid or exceeds maximum allowed.
    InvalidLength,
}

impl fmt::Display for QuicHdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuicHdrError::InvalidHeaderForm => {
                write!(f, "Operation invalid for current QUIC header form")
            }
            QuicHdrError::InvalidLength => {
                write!(f, "Invalid length provided for a QUIC header field")
            }
        }
    }
}

#[cfg(feature = "serde")]
mod cid_serde_helpers {
    use core::fmt;
    use serde::de::Expected;

    pub struct ExpectedCidBytesInfo {
        pub len: u8,
    }
    impl fmt::Display for ExpectedCidBytesInfo {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "CID bytes for explicit length {}", self.len)
        }
    }

    impl Expected for ExpectedCidBytesInfo {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(self, formatter)
        }
    }

    pub struct LengthExceedsMaxError {
        pub value: usize,
        pub max: usize,
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
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(self, formatter)
        }
    }
}

/// Macro to implement common functionality for Connection ID wrapper structs.
macro_rules! impl_cid_common {
    ($t:ident, $doc_name:literal, $with_len_on_wire:tt) => {
        #[doc = concat!("Wrapper for a QUIC ", $doc_name, " Connection ID.")]
        ///
        /// Stores the CID bytes in a fixed-size buffer (`QUIC_MAX_CID_LEN`)
        /// and tracks its actual current length via an internal `len` field.
        ///
        /// For CIDs in Long Headers (like `QuicDstConnLong`, `QuicSrcConnLong`), the length byte
        /// is also present on the wire preceding the CID bytes. The `len` field in these structs
        /// directly corresponds to this on-wire length byte.
        ///
        /// For CIDs in Short Headers (like `QuicDstConnShort`), the length is implicit or contextually
        /// known (e.g., from connection state). The internal `len` field in `QuicDstConnShort`
        /// still tracks the CID's actual length for consistency and for `as_slice()`, but this
        /// `len` field itself is *not* serialized as a separate byte on the wire for Short Header CIDs.
        ///
        /// # Examples
        ///
        /// ```
        /// // This example is generic. See specific types like QuicDstConnLong or QuicDstConnShort
        /// // for more tailored examples.
        /// use network_types::quic::{QuicDstConnLong, QUIC_MAX_CID_LEN}; // Using QuicDstConnLong as an example
        ///
        /// // Create a new, empty CID
        /// let mut cid = QuicDstConnLong::new();
        /// assert_eq!(cid.len(), 0);
        /// assert!(cid.is_empty());
        ///
        /// // Set the CID value
        /// let cid_data = [0x01, 0x02, 0x03, 0x04];
        /// cid.set(&cid_data);
        /// assert_eq!(cid.len(), 4);
        /// assert_eq!(cid.as_slice(), &cid_data);
        ///
        /// // Example eBPF context considerations:
        /// // If this CID struct (e.g., QuicDstConnLong) matches a part of your packet structure
        /// // that includes the length byte on the wire:
        /// // ```no_run
        /// # use core::ptr;
        /// # #[repr(C, packed)] struct MyPacketPart { a_cid: QuicDstConnLong }
        /// # let base_ptr: *const MyPacketPart = ptr::null(); // Ptr to packet data part
        /// // let cid_from_packet = unsafe { ptr::read_volatile(&((*base_ptr).a_cid)) };
        /// // assert!(cid_from_packet.len() <= QUIC_MAX_CID_LEN as u8);
        /// // Process `cid_from_packet.as_slice()`...
        /// // ```
        /// //
        /// // If the CID struct is like QuicDstConnShort where 'len' is not on wire with the CID:
        /// // You would determine 'known_cid_len' from context, read 'known_cid_len' bytes,
        /// // then use `cid.set()` to populate a stack instance of QuicDstConnShort.
        /// // ```no_run
        /// # use network_types::quic::{QuicDstConnShort};
        /// # let packet_cid_bytes_ptr: *const u8 = core::ptr::null(); // Ptr to raw CID bytes in packet
        /// # let known_cid_len: usize = 8; // Length from eBPF map or connection state
        /// let mut my_cid_short = QuicDstConnShort::new();
        /// if known_cid_len > 0 && known_cid_len <= QUIC_MAX_CID_LEN {
        ///     let mut cid_buffer = [0u8; QUIC_MAX_CID_LEN];
        ///     // In eBPF: unsafe { bpf_probe_read_kernel(...) } to copy bytes here
        ///     // For this example, assume cid_buffer is populated from packet_cid_bytes_ptr
        ///     // unsafe { core::ptr::copy_nonoverlapping(packet_cid_bytes_ptr, cid_buffer.as_mut_ptr(), known_cid_len); }
        ///     my_cid_short.set(&cid_buffer[..known_cid_len]);
        ///     // assert_eq!(my_cid_short.len(), known_cid_len as u8);
        /// }
        /// // ```
        /// ```
        #[repr(C, packed)]
        #[derive(Copy, Clone)]
        pub struct $t {
            len: u8,
            bytes: [u8; QUIC_MAX_CID_LEN],
        }

        impl $t {
            pub const LEN: usize = core::mem::size_of::<Self>();

            /// Construct a new (empty) ID – all bytes zero, length 0.
            ///
            /// # Returns
            /// A new, zero-initialized CID instance with `len = 0`.
            #[inline]
            pub const fn new() -> Self {
                Self {
                    len: 0,
                    bytes: [0u8; QUIC_MAX_CID_LEN],
                }
            }
            /// Current byte‑length of the CID.
            ///
            /// # Returns
            /// The actual length of the CID data stored, from 0 to `QUIC_MAX_CID_LEN`.
            #[inline]
            pub const fn len(&self) -> u8 {
                self.len
            }
            /// True if CID length is zero.
            ///
            /// # Returns
            /// `true` if the CID has a length of 0, `false` otherwise.
            #[inline]
            pub const fn is_empty(&self) -> bool {
                self.len == 0
            }
            /// Slice containing only the used part of the CID.
            ///
            /// # Returns
            /// A `&[u8]` slice representing the actual CID bytes.
            /// The slice length is determined by `self.len()`.
            ///
            /// # Safety
            /// This method uses `get_unchecked` for performance, relying on the invariant
            /// that `self.len` is always `<= QUIC_MAX_CID_LEN`, which is maintained by `set()`.
            #[inline]
            pub fn as_slice(&self) -> &[u8] {
                unsafe { self.bytes.get_unchecked(..self.len as usize) }
            }
            /// Mutable slice containing only the used part of the CID.
            ///
            /// # Returns
            /// A `&mut [u8]` mutable slice representing the actual CID bytes.
            /// The slice length is determined by `self.len()`.
            ///
            /// # Safety
            /// This method uses `get_unchecked_mut` for performance, relying on the invariant
            /// that `self.len` is always `<= QUIC_MAX_CID_LEN`, which is maintained by `set()`.
            #[inline]
            pub fn as_mut_slice(&mut self) -> &mut [u8] {
                unsafe { self.bytes.get_unchecked_mut(..self.len as usize) }
            }
            /// Set the ID from a byte‑slice.
            /// Excess bytes from `data` are truncated if `data.len() > QUIC_MAX_CID_LEN`.
            /// Bytes within the internal buffer beyond the new length (`n`) are zeroed
            /// to ensure consistent behavior for equality checks and hashing.
            ///
            /// # Parameters
            /// * `data`: A byte slice containing the new CID data.
            pub fn set(&mut self, data: &[u8]) {
                let n = cmp::min(data.len(), QUIC_MAX_CID_LEN);
                // Safety: `n` is guaranteed to be `<= QUIC_MAX_CID_LEN`.
                // `self.bytes.as_mut_ptr()` is valid for writes up to `QUIC_MAX_CID_LEN`.
                // `data.as_ptr()` is valid for reads up to `data.len()`.
                // `copy_nonoverlapping` is safe as `n` respects the shorter of these lengths.
                unsafe {
                    ptr::copy_nonoverlapping(data.as_ptr(), self.bytes.as_mut_ptr(), n);
                }
                if n < QUIC_MAX_CID_LEN {
                    // Zero the remaining padding to guarantee deterministic equality & hashing.
                    // Safety: `n < QUIC_MAX_CID_LEN` ensures `self.bytes.as_mut_ptr().add(n)` is valid
                    // and `QUIC_MAX_CID_LEN - n` is the correct count of bytes to zero.
                    unsafe {
                        ptr::write_bytes(self.bytes.as_mut_ptr().add(n), 0, QUIC_MAX_CID_LEN - n);
                    }
                }
                self.len = n as u8;
            }
        }

        impl Default for $t {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(", stringify!($t))?;
                for (i, b_val) in self.as_slice().iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02x}", b_val)?;
                }
                write!(f, ")")
            }
        }
        impl cmp::PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.len == other.len && self.as_slice() == other.as_slice()
            }
        }
        impl Eq for $t {}
        impl hash::Hash for $t {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                self.len.hash(state);
                state.write(self.as_slice());
            }
        }

        #[cfg(feature = "serde")]
        const _: () = {
            // Create a new scope for each expansion
            use serde::{
                de::{self, Visitor},
                ser::SerializeStruct,
                Deserializer, Serializer,
            };
            // Assumes `use serde_bytes::{ByteBuf, Bytes};` is at the top of the file.
            // Assumes helper structs are in `crate::quic::cid_serde_helpers`

            struct CidVisitor;
            impl<'de> Visitor<'de> for CidVisitor {
                type Value = $t;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    if $with_len_on_wire {
                        write!(f, "length-prefixed QUIC Connection-ID (len, bytes)")
                    } else {
                        write!(f, "raw QUIC Connection-ID bytes")
                    }
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<$t, A::Error>
                where
                    A: de::SeqAccess<'de>,
                {
                    let len: u8 = seq.next_element()?.ok_or_else(|| {
                        de::Error::invalid_length(0, &"Missing CID len in sequence")
                    })?;
                    let bytes_buf: ByteBuf = seq.next_element()?.ok_or_else(|| {
                        de::Error::invalid_length(1, &"Missing CID bytes in sequence")
                    })?;

                    if bytes_buf.len() != len as usize {
                        return Err(de::Error::invalid_value(
                            de::Unexpected::Bytes(bytes_buf.as_ref()),
                            &crate::quic::cid_serde_helpers::ExpectedCidBytesInfo { len },
                        ));
                    }
                    if len > QUIC_MAX_CID_LEN as u8 {
                        return Err(de::Error::invalid_length(
                            len as usize,
                            &crate::quic::cid_serde_helpers::LengthExceedsMaxError {
                                value: len as usize,
                                max: QUIC_MAX_CID_LEN,
                                field_name: "CID length",
                            },
                        ));
                    }
                    let mut id = $t::new();
                    id.set(bytes_buf.as_ref());
                    id.len = len;
                    Ok(id)
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<$t, E>
                where
                    E: de::Error,
                {
                    if v.len() > QUIC_MAX_CID_LEN {
                        return Err(de::Error::invalid_length(
                            v.len(),
                            &crate::quic::cid_serde_helpers::LengthExceedsMaxError {
                                value: v.len(),
                                max: QUIC_MAX_CID_LEN,
                                field_name: "CID length",
                            },
                        ));
                    }
                    let mut id = $t::new();
                    id.set(v);
                    Ok(id)
                }
            }

            impl serde::Serialize for $t {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    if $with_len_on_wire {
                        let mut st = serializer.serialize_struct(stringify!($t), 2)?;
                        st.serialize_field("len", &self.len)?;
                        st.serialize_field("bytes", &Bytes::new(self.as_slice()))?;
                        st.end()
                    } else {
                        serializer.serialize_bytes(self.as_slice())
                    }
                }
            }

            impl<'de> serde::Deserialize<'de> for $t {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    if $with_len_on_wire {
                        deserializer.deserialize_tuple(2, CidVisitor)
                    } else {
                        deserializer.deserialize_bytes(CidVisitor)
                    }
                }
            }
        };
    };
}

impl_cid_common!(QuicDstConnLong, "Destination (Long Hdr)", true);
impl_cid_common!(QuicSrcConnLong, "Source (Long Hdr)", true);
impl_cid_common!(QuicDstConnShort, "Destination (Short Hdr)", false);

/// Invariant fields specific to QUIC **Long Headers**.
///
/// Contains the QUIC version and variable-length Destination and Source Connection IDs.
///
/// # Examples
///
/// ```
/// use network_types::quic::{QuicHdrLong, QuicDstConnLong, QuicSrcConnLong};
///
/// let mut long_hdr_fields = QuicHdrLong::default();
/// long_hdr_fields.set_version(0x00000001); // QUIC v1
///
/// let dcid_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
/// let scid_data = [0xAA, 0xBB, 0xCC, 0xDD];
///
/// long_hdr_fields.dst.set(&dcid_data);
/// long_hdr_fields.src.set(&scid_data);
///
/// assert_eq!(long_hdr_fields.version(), 0x00000001);
/// assert_eq!(long_hdr_fields.dst.len(), 8);
/// assert_eq!(long_hdr_fields.dst.as_slice(), &dcid_data);
/// assert_eq!(long_hdr_fields.src.len(), 4);
/// assert_eq!(long_hdr_fields.src.as_slice(), &scid_data);
///
/// // In an eBPF program, this struct would typically be part of a `QuicHdr`'s `inner.long`
/// // field. If `quic_hdr_ptr` is a pointer to a `QuicHdr` (known to be Long Header)
/// // in packet memory:
/// // ```no_run
/// # use network_types::quic::{QuicHdr, QuicHeaderType};
/// # use core::ptr;
/// # let mut quic_hdr_on_stack = QuicHdr::new(QuicHeaderType::QuicLong); // Example stack instance
/// # let quic_hdr_ptr: *const QuicHdr = &quic_hdr_on_stack;
/// // // Assume quic_hdr_ptr is valid and points to a Long Header QuicHdr.
/// // let long_specific_ptr: *const QuicHdrLong = unsafe { &(*quic_hdr_ptr).inner.long };
/// // let version = unsafe { (*long_specific_ptr).version() };
/// // let dcid_len = unsafe { (*long_specific_ptr).dst.len() };
/// // // Access to CID bytes via: unsafe { (*long_specific_ptr).dst.as_slice() }
/// // // Important: This assumes `quic_hdr_ptr` and its `inner.long` field are correctly
/// // // populated, which requires careful parsing in eBPF.
/// // ```
/// ```
#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
pub struct QuicHdrLong {
    /// QUIC Version (e.g., `0x00000001` for v1). Network byte order.
    pub version: [u8; 4],
    /// Destination Connection ID, including its on-wire length byte (managed by `QuicDstConnLong`).
    pub dst: QuicDstConnLong,
    /// Source Connection ID, including its on-wire length byte (managed by `QuicSrcConnLong`).
    pub src: QuicSrcConnLong,
}
impl QuicHdrLong {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// The minimum length of a Long Header on the wire, consisting of:
    /// 1 (First Byte, part of `QuicHdr`) + 4 (Version) + 1 (DCID Len Byte) + 1 (SCID Len Byte) = 7 bytes.
    /// This does not include any actual CID data bytes.
    pub const MIN_LEN_ON_WIRE: usize = 7;

    /// Gets the QUIC version in host byte order.
    ///
    /// # Returns
    /// The 32-bit QUIC version number.
    #[inline]
    pub fn version(&self) -> u32 {
        u32::from_be_bytes(self.version)
    }
    /// Sets the QUIC version.
    ///
    /// # Parameters
    /// * `v`: The QUIC version in host byte order. It will be stored in network byte order.
    #[inline]
    pub fn set_version(&mut self, v: u32) {
        self.version = v.to_be_bytes();
    }
}

/// Invariant fields specific to QUIC **Short Headers** (1-RTT packets).
///
/// Contains the Destination Connection ID. The length of the DCID is not
/// encoded directly in the short header; it must be known from the connection context.
/// QUIC v1 Short Headers do not have a Source Connection ID.
///
/// # Examples
///
/// ```
/// use network_types::quic::{QuicHdrShort, QuicDstConnShort};
///
/// let mut short_hdr_fields = QuicHdrShort::default();
///
/// let dcid_data = [0x11, 0x22, 0x33, 0x44, 0x55];
/// // For short headers, the length of the DCID is known contextually.
/// // The `QuicDstConnShort` struct's `set` method will store this data
/// // and internally track its length.
/// short_hdr_fields.dst.set(&dcid_data);
///
/// assert_eq!(short_hdr_fields.dst.len(), 5);
/// assert_eq!(short_hdr_fields.dst.as_slice(), &dcid_data);
///
/// // In an eBPF program, `QuicHdrShort` would be part of `QuicHdr.inner.short`.
/// // The DCID bytes would be read from the packet based on a contextually known length.
/// // That length would also be used to initialize `QuicHdr.header_type`
/// // (e.g., `QuicHeaderType::QuicShort { dc_id_len: known_len }`).
/// //
/// // ```no_run
/// # use network_types::quic::{QuicHdr, QuicHeaderType, QUIC_MAX_CID_LEN};
/// # use core::ptr;
/// # let known_dcid_len_from_context = 5u8;
/// # let mut quic_hdr_on_stack = QuicHdr::new(QuicHeaderType::QuicShort { dc_id_len: known_dcid_len_from_context });
/// // // Populate quic_hdr_on_stack.inner.short.dst from packet data...
/// // // For example, if packet_dcid_ptr points to the DCID bytes in the packet:
/// # let packet_dcid_ptr: *const u8 = core::ptr::null(); // Example pointer to DCID data in packet
/// // if known_dcid_len_from_context > 0 {
/// //     let mut temp_cid_buf = [0u8; QUIC_MAX_CID_LEN];
/// //     // In eBPF: unsafe { bpf_probe_read_kernel(temp_cid_buf.as_mut_ptr(), known_dcid_len_from_context as u32, packet_dcid_ptr) };
/// //     // For example purposes, assume temp_cid_buf is populated:
/// //     // unsafe { ptr::copy_nonoverlapping(packet_dcid_ptr, temp_cid_buf.as_mut_ptr(), known_dcid_len_from_context as usize); }
/// //     unsafe { quic_hdr_on_stack.inner.short.dst.set(&temp_cid_buf[..known_dcid_len_from_context as usize]); }
/// // }
/// //
/// // // Accessing via the QuicHdr instance:
/// // assert_eq!(quic_hdr_on_stack.dc_id().len(), known_dcid_len_from_context as usize);
/// // ```
/// ```
#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
pub struct QuicHdrShort {
    /// Destination Connection ID. Its length is determined contextually.
    /// `QuicDstConnShort` internally tracks its `len` for `as_slice` but this `len`
    /// is not part of the on-wire format for the Short Header DCID itself.
    pub dst: QuicDstConnShort,
}
impl QuicHdrShort {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// The minimum length of a Short Header on the wire, consisting of:
    /// 1 (First Byte, part of `QuicHdr`) + 0 (DCID bytes, if DCID len is 0) = 1 byte.
    pub const MIN_LEN_ON_WIRE: usize = 1;
}

/// Union to hold either Long or Short header-specific data.
///
/// This allows `QuicHdr` to have a fixed size while representing variable structures.
/// Access must be guarded by checking `QuicHdr::is_long_header()` or `QuicHdr::header_type`.
///
/// # Note on eBPF Usage
///
/// In eBPF programs, direct access to union fields (e.g., `hdr.inner.long` or `hdr.inner.short`)
/// must be done with extreme care, ensuring that the `QuicHdr` instance's `header_type`
/// correctly reflects the actual packet type being processed. The `QuicHdr` safe accessor methods
/// (like `version()`, `dc_id()`, etc.) handle these checks.
///
/// If constructing a `QuicHdr` from packet data in eBPF, the `inner` union would be populated
/// after determining the header type and reading the relevant bytes (version, CIDs, etc.)
/// from the packet. The `QuicHdr::new()` method initializes the union appropriately based
/// on the provided `QuicHeaderType`.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union QuicHdrUn {
    /// Data for a Long Header.
    pub long: QuicHdrLong,
    /// Data for a Short Header.
    pub short: QuicHdrShort,
}

impl Default for QuicHdrUn {
    fn default() -> Self {
        Self {
            long: QuicHdrLong::default(),
        }
    }
}
impl fmt::Debug for QuicHdrUn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QuicHdrUn { ... }")
    }
}

/// Discriminator for `QuicHdr` to indicate active header form and necessary context.
/// This is a logical field, not directly part of the wire format itself, but aids in (de)serialization
/// and safe access to the `QuicHdrUn` union.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QuicHeaderType {
    /// Indicates a Long Header. All length information for CIDs is in the packet.
    QuicLong,
    /// Indicates a Short Header.
    /// `dc_id_len` is the contextual length of the Destination Connection ID, as this
    /// length is not present on the wire for Short Headers. It must be known by the
    /// endpoint processing the packet. QUIC v1 Short headers do not have a Source CID.
    QuicShort { dc_id_len: u8 },
}

/// Represents a QUIC packet header, capable of handling both Long and Short forms
/// with variable-length Connection IDs.
///
/// The `header_type` field is crucial for interpreting the `inner` union correctly
/// and for proper serialization/deserialization, especially for Short Headers where
/// the Destination CID length is not on the wire.
///
/// # Examples
///
/// ## Creating and using a Long Header
/// ```
/// use network_types::quic::{QuicHdr, QuicHeaderType, QUIC_MAX_CID_LEN};
///
/// // Create a new Long Header (e.g., for an Initial packet)
/// let mut long_hdr = QuicHdr::new(QuicHeaderType::QuicLong);
///
/// // Set Long Header specific fields
/// assert!(long_hdr.set_long_packet_type(0b00).is_ok()); // Initial packet type
/// assert!(long_hdr.set_version(0x00000001).is_ok());    // QUIC v1
/// assert!(long_hdr.set_packet_number_length_long(4).is_ok()); // 4-byte packet number
///
/// let dcid_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
/// let scid_data = [0xAA, 0xBB, 0xCC, 0xDD];
/// long_hdr.set_dc_id(&dcid_data); // Sets DCID and its length (8)
/// assert!(long_hdr.set_sc_id(&scid_data).is_ok()); // Sets SCID and its length (4)
///
/// assert!(long_hdr.is_long_header());
/// assert_eq!(long_hdr.long_packet_type(), Ok(0b00));
/// assert_eq!(long_hdr.version(), Ok(0x00000001));
/// assert_eq!(long_hdr.dc_id(), &dcid_data);
/// assert_eq!(long_hdr.sc_id().unwrap(), &scid_data);
/// assert_eq!(long_hdr.dc_id_len_on_wire(), Ok(8));
/// assert_eq!(long_hdr.sc_id_len_on_wire(), Ok(4));
///
/// // The first_byte is also partially set by `new` and field setters:
/// // Example: (Form | Fixed | Type | Reserved | PN Len)
/// //           (1    | 1     | 00   | 00       | 11) = 0b11000011 = 0xC3
/// // Actual first_byte depends on reserved bits and PN length settings.
/// // long_hdr.set_reserved_bits_long(0).unwrap(); // Explicitly set reserved bits
/// // assert_eq!(long_hdr.first_byte(), 0xC3); // If PN Len is 4 (encoded 3) and Type 0
/// ```
///
/// ## Creating and using a Short Header
/// ```
/// use network_types::quic::{QuicHdr, QuicHeaderType, QUIC_MAX_CID_LEN};
///
/// // For Short Headers, the DCID length is not on the wire, so it must be known.
/// let dcid_len_short: u8 = 8;
/// let mut short_hdr = QuicHdr::new(QuicHeaderType::QuicShort { dc_id_len: dcid_len_short });
///
/// // Set Short Header specific fields
/// assert!(short_hdr.set_short_spin_bit(true).is_ok());
/// assert!(short_hdr.set_short_key_phase(false).is_ok());
/// assert!(short_hdr.set_short_packet_number_length(2).is_ok()); // 2-byte packet number
///
/// let dcid_data_short = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
/// // Ensure dcid_data_short matches dcid_len_short if providing full slice
/// short_hdr.set_dc_id(&dcid_data_short[..dcid_len_short as usize]);
///
/// assert!(!short_hdr.is_long_header());
/// assert_eq!(short_hdr.short_spin_bit(), Ok(true));
/// assert_eq!(short_hdr.dc_id_effective_len(), dcid_len_short);
/// assert_eq!(short_hdr.dc_id(), &dcid_data_short[..dcid_len_short as usize]);
///
/// // Attempting to access Long Header fields will fail
/// assert!(short_hdr.version().is_err());
/// assert!(short_hdr.sc_id().is_err());
/// ```
///
/// ## eBPF Context Example Snippet
/// ```no_run
/// use core::{mem, ptr, cmp};
/// use aya_ebpf::programs::TcContext;
/// use aya_log_ebpf::debug as aya_ebpf_debug; // Import the debug macro appropriately
/// use network_types::eth::EthHdr;
/// use network_types::ip::Ipv4Hdr; // Assuming IPv4 for simplicity
/// // Placeholder for UDP header length if not using a full UdpHdr type
/// const UDP_HDR_LEN: usize = 8;
/// use network_types::quic::{QuicHdr, QuicHeaderType, QUIC_MAX_CID_LEN, QuicHdrError};
///
/// fn handle_quic_packet(ctx: &TcContext) -> Result<u32, ()> {
///     let data_start = ctx.data();
///     let data_end = ctx.data_end();
///     // Calculate offset to where QUIC header might start
///     // This assumes Eth + IPv4 + UDP. Adjust for IPv6 or other encapsulations.
///     let quic_offset = EthHdr::LEN + Ipv4Hdr::LEN + UDP_HDR_LEN;
///     let quic_base_ptr = unsafe { (data_start as *const u8).add(quic_offset) };
///     // Ensure there's at least one byte for the QUIC header (first_byte)
///     if unsafe { quic_base_ptr.add(1) } > (data_end as *const u8) {
///         aya_ebpf_debug!(ctx, "QUIC packet too short for first_byte");
///         return Err(());
///     }
///     let first_byte = unsafe { ptr::read_volatile(quic_base_ptr) };
///     let mut hdr_on_stack: QuicHdr;
///     let mut current_parse_offset: usize = 1; // Start parsing after the first_byte
///     if (first_byte & 0x80) != 0 { // Long Header
///         hdr_on_stack = QuicHdr::new(QuicHeaderType::QuicLong);
///         hdr_on_stack.set_first_byte(first_byte); // Set first_byte, includes type, PN len etc.
///         // --- Parse Version (4 bytes) ---
///         let version_offset = current_parse_offset;
///         if unsafe { quic_base_ptr.add(version_offset + 4) } > (data_end as *const u8) {
///             aya_ebpf_debug!(ctx, "QUIC Long: Packet too short for version");
///             return Err(());
///         }
///         let mut ver_bytes = [0u8; 4];
///         unsafe {
///             // In real eBPF, use bpf_probe_read_kernel or ctx.read_at helper if available & safe
///             ptr::copy_nonoverlapping(quic_base_ptr.add(version_offset), ver_bytes.as_mut_ptr(), 4);
///         }
///         if hdr_on_stack.set_version(u32::from_be_bytes(ver_bytes)).is_err() {
///             // Should not happen if type is QuicLong, but good practice
///             aya_ebpf_debug!(ctx, "QUIC Long: Failed to set version internally"); return Err(());
///         }
///         current_parse_offset += 4;
///         // --- Parse DCID Len (1 byte) & DCID ---
///         let dcil_offset = current_parse_offset;
///         if unsafe { quic_base_ptr.add(dcil_offset + 1) } > (data_end as *const u8) {
///             aya_ebpf_debug!(ctx, "QUIC Long: Packet too short for DCIL"); return Err(());
///         }
///         let dcil = unsafe { ptr::read_volatile(quic_base_ptr.add(dcil_offset)) };
///         current_parse_offset += 1;
///         if dcil as usize > QUIC_MAX_CID_LEN {
///             aya_ebpf_debug!(ctx, "QUIC Long: DCIL {} exceeds max {}", dcil, QUIC_MAX_CID_LEN); return Err(());
///         }
///         if unsafe { quic_base_ptr.add(current_parse_offset + dcil as usize) } > (data_end as *const u8) {
///             aya_ebpf_debug!(ctx, "QUIC Long: Packet too short for DCID data (len {})", dcil); return Err(());
///         }
///         let mut dcid_buf = [0u8; QUIC_MAX_CID_LEN]; // Max buffer
///         if dcil > 0 {
///             unsafe {
///                 ptr::copy_nonoverlapping(quic_base_ptr.add(current_parse_offset), dcid_buf.as_mut_ptr(), dcil as usize);
///             }
///         }
///         hdr_on_stack.set_dc_id(&dcid_buf[..dcil as usize]);
///         current_parse_offset += dcil as usize;
///         let scil_offset = current_parse_offset;
///         if unsafe { quic_base_ptr.add(scil_offset + 1) } > (data_end as *const u8) {
///             aya_ebpf_debug!(ctx, "QUIC Long: Packet too short for SCIL"); return Err(());
///         }
///         let scil = unsafe { ptr::read_volatile(quic_base_ptr.add(scil_offset)) };
///         current_parse_offset += 1;
///         if scil as usize > QUIC_MAX_CID_LEN {
///             aya_ebpf_debug!(ctx, "QUIC Long: SCIL {} exceeds max {}", scil, QUIC_MAX_CID_LEN); return Err(());
///         }
///         if unsafe { quic_base_ptr.add(current_parse_offset + scil as usize) } > (data_end as *const u8) {
///             aya_ebpf_debug!(ctx, "QUIC Long: Packet too short for SCID data (len {})", scil); return Err(());
///         }
///         let mut scid_buf = [0u8; QUIC_MAX_CID_LEN]; // Max buffer
///         if scil > 0 {
///             unsafe {
///                 ptr::copy_nonoverlapping(quic_base_ptr.add(current_parse_offset), scid_buf.as_mut_ptr(), scil as usize);
///             }
///         }
///         if hdr_on_stack.set_sc_id(&scid_buf[..scil as usize]).is_err() {
///             aya_ebpf_debug!(ctx, "QUIC Long: Failed to set SCID internally"); return Err(());
///         }
///         current_parse_offset += scil as usize;
///         // Long header successfully parsed into hdr_on_stack
///         if let Ok(pkt_type) = hdr_on_stack.long_packet_type() {
///             aya_ebpf_debug!(ctx, "QUIC Long: Type={}, Ver={}, DCID_len={}, SCID_len={}",
///                 pkt_type, hdr_on_stack.version().unwrap_or(0), dcil, scil);
///         }
///     } else { // Short Header
///         // For Short Headers, DCID length must be known from context (e.g., connection tracking via eBPF map)
///         // For this example, let's assume a fixed length or one fetched from a hypothetical map.
///         let known_dcid_len: u8 = 8; // Example: 8-byte DCID for short header connections
///         hdr_on_stack = QuicHdr::new(QuicHeaderType::QuicShort { dc_id_len: known_dcid_len });
///         hdr_on_stack.set_first_byte(first_byte); // Set first_byte, includes spin, key, PN len etc.
///         if known_dcid_len as usize > QUIC_MAX_CID_LEN {
///              aya_ebpf_debug!(ctx, "QUIC Short: Contextual DCID len {} exceeds max", known_dcid_len); return Err(());
///         }
///         if unsafe { quic_base_ptr.add(current_parse_offset + known_dcid_len as usize) } > (data_end as *const u8) {
///             aya_ebpf_debug!(ctx, "QUIC Short: Packet too short for DCID data (len {})", known_dcid_len); return Err(());
///         }
///         let mut dcid_buf = [0u8; QUIC_MAX_CID_LEN];
///         if known_dcid_len > 0 {
///             unsafe {
///                 ptr::copy_nonoverlapping(quic_base_ptr.add(current_parse_offset), dcid_buf.as_mut_ptr(), known_dcid_len as usize);
///             }
///         }
///         hdr_on_stack.set_dc_id(&dcid_buf[..known_dcid_len as usize]);
///         // Note: set_dc_id for short header also updates QuicHeaderType's dc_id_len field
///         // to match the actual data set, if it was shorter than `known_dcid_len` due to QUIC_MAX_CID_LEN.
///         current_parse_offset += known_dcid_len as usize;
///         // Short header successfully parsed into hdr_on_stack
///         aya_ebpf_debug!(ctx, "QUIC Short: DCID_len_ctx={}, Spin={}",
///             known_dcid_len, hdr_on_stack.short_spin_bit().unwrap_or(false) as u8);
///         if let Some(dcid_slice_preview) = hdr_on_stack.dc_id().get(..cmp::min(4, hdr_on_stack.dc_id().len())) {
///              // Log first few bytes of DCID for example
///              // aya_log_ebpf::debug! doesn't directly support byte slice formatting easily.
///              // For actual logging of slices, you might log byte by byte or a hex representation if needed.
///              aya_ebpf_debug!(ctx, "QUIC Short: DCID preview len {}", dcid_slice_preview.len());
///         }
///     }
///     // Now `hdr_on_stack` is populated. You can use its methods to access fields.
///     // For example, to get the Packet Number length (common for both forms, but different bits):
///     let pn_len_result = if hdr_on_stack.is_long_header() {
///         hdr_on_stack.packet_number_length_long()
///     } else {
///         hdr_on_stack.short_packet_number_length()
///     };
///     if let Ok(len) = pn_len_result {
///         aya_ebpf_debug!(ctx, "QUIC Packet Number actual length: {} bytes", len);
///         // Packet number itself would be after the CIDs (for long) or DCID (for short)
///         // and before the payload. Parsing it is beyond this header example.
///         // let _pn_offset = quic_offset + current_parse_offset;
///     }
///     // The actual packet number bytes follow the header fields parsed so far.
///     // Accessing them requires reading `len` bytes from `quic_base_ptr.add(current_parse_offset)`.
///     Ok(0)
/// }
/// // Important Note: The use of `ptr::copy_nonoverlapping` assumes direct memory access.
/// // In a real eBPF program, especially for TC (sk_buff context), you would typically use
/// // `ctx.load::<T>(offset)` for fixed-size reads or `bpf_probe_read_kernel` / `bpf_probe_read_user`
/// // for reading arbitrary memory into a buffer, ensuring safety and verifier compliance.
/// // This example uses raw pointers for conceptual clarity on structure parsing.
/// // Boundary checks (`if ptr.add(len) > data_end`) are crucial.
/// ```

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct QuicHdr {
    first_byte: u8,
    inner: QuicHdrUn,
    header_type: QuicHeaderType,
}

impl QuicHdr {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Minimum on-wire size of a QUIC Long Header (1 (flags/type) + 4 (version) + 1 (DCIL byte) + 1 (SCIL byte) = 7 bytes),
    /// This excludes any actual CID data bytes.
    pub const MIN_LONG_HDR_LEN_ON_WIRE: usize = QuicHdrLong::MIN_LEN_ON_WIRE;

    /// Minimum on-wire size of a QUIC Short Header (1 (flags/type) = 1 byte).
    /// This excludes any actual DCID data bytes.
    pub const MIN_SHORT_HDR_LEN_ON_WIRE: usize = QuicHdrShort::MIN_LEN_ON_WIRE;

    /// Creates a new `QuicHdr` initialized for the specified `header_type`.
    /// The `first_byte` is partially initialized based on the header form (Long/Short) and Fixed Bit.
    /// Other bits in `first_byte` (like Packet Type, PN length encoding, Spin Bit, Key Phase)
    /// must be set separately by the caller using the provided setter methods.
    ///
    /// # Parameters
    /// * `header_type`: The type of QUIC header to initialize, providing context for
    ///   Short Header DCID length.
    ///
    /// # Returns
    /// A new `QuicHdr` instance.
    pub fn new(header_type: QuicHeaderType) -> Self {
        match header_type {
            QuicHeaderType::QuicLong => {
                let first_byte = HEADER_FORM_BIT | FIXED_BIT_MASK;
                Self {
                    first_byte,
                    inner: QuicHdrUn {
                        long: QuicHdrLong::default(),
                    },
                    header_type,
                }
            }
            QuicHeaderType::QuicShort { dc_id_len } => {
                // dc_id_len captured here
                let first_byte = FIXED_BIT_MASK; // Set Fixed bit (Form bit is 0)
                let mut short_data = QuicHdrShort::default();
                // The dc_id_len from header_type is the primary source of truth
                // for effective length.
                short_data.dst.len = cmp::min(dc_id_len, QUIC_MAX_CID_LEN as u8);
                Self {
                    first_byte,
                    inner: QuicHdrUn { short: short_data },
                    header_type,
                }
            }
        }
    }

    /// Gets the raw `first_byte` of the header. This byte contains several bit-packed fields.
    ///
    /// # Returns
    /// The `u8` value of the first byte.
    #[inline]
    pub fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// Sets the raw `first_byte` of the header.
    ///
    /// # Parameters
    /// * `b`: The new `u8` value for the first byte.
    ///
    /// # Safety
    /// Caller must ensure consistency of the `first_byte`'s Header Form bit
    /// with the `self.header_type` discriminator. Use `set_header_type` for
    /// safe structural changes if the header form bit is altered by this call.
    /// It's generally safer to use specific setters like `set_long_packet_type`, etc.
    /// after `QuicHdr::new()`, and then call this if you need to set the *entire* byte
    /// from a pre-calculated value (e.g. from a packet).
    #[inline]
    pub fn set_first_byte(&mut self, b: u8) {
        self.first_byte = b;
        // Developer note: After calling this, ensure self.header_type is still valid.
        // For example, if 'b' flips the HEADER_FORM_BIT, self.header_type should be updated
        // via set_header_type() to match, which also reinitializes self.inner.
    }

    /// Checks if the Header Form bit (the most significant bit of `first_byte`)
    /// indicates a Long Header.
    ///
    /// # Returns
    /// `true` if bit 7 is 1 (Long Header), `false` if 0 (Short Header).
    #[inline]
    pub fn is_long_header(&self) -> bool {
        (self.first_byte & HEADER_FORM_BIT) == HEADER_FORM_BIT
    }

    /// Gets the Fixed Bit (bit 6 of `first_byte`).
    /// Per RFC 9000, this bit MUST be 1 for all QUIC v1 packets except Version Negotiation.
    ///
    /// # Returns
    /// The value of the Fixed Bit (0 or 1).
    #[inline]
    pub fn fixed_bit(&self) -> u8 {
        (self.first_byte & FIXED_BIT_MASK) >> 6
    }

    /// Gets the Long Packet Type (bits 5-4 of `first_byte`) if this is a Long Header.
    /// Common types for QUIC v1 (RFC 9000) are:
    /// * `0b00` (0): Initial
    /// * `0b01` (1): 0-RTT
    /// * `0b10` (2): Handshake
    /// * `0b11` (3): Retry
    ///
    /// # Returns
    /// `Ok(u8)` with the packet type (0-3) if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn long_packet_type(&self) -> Result<u8, QuicHdrError> {
        if self.is_long_header() {
            // Safety: is_long_header() ensures conditions for unchecked_long_packet_type are met.
            Ok(unsafe { self.unchecked_long_packet_type() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the Reserved Bits (bits 3-2 of `first_byte`) if this is a Long Header.
    /// For QUIC v1 Initial, 0-RTT, and Handshake packets, these bits MUST be 0.
    /// For Retry packets, these bits are part of the "Retry Packet Type" or ODCIL.
    ///
    /// # Returns
    /// `Ok(u8)` with the reserved bits value (0-3) if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn reserved_bits_long(&self) -> Result<u8, QuicHdrError> {
        if self.is_long_header() {
            // Safety: is_long_header() ensures conditions for unchecked_reserved_bits_long are met.
            Ok(unsafe { self.unchecked_reserved_bits_long() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the encoded Packet Number Length (bits 1-0 of `first_byte`) if this is a Long Header
    /// (for types that include a Packet Number: Initial, 0-RTT, Handshake).
    /// The value is `actual_length_in_bytes - 1`. So, 0b00 means 1 byte, 0b11 means 4 bytes.
    ///
    /// # Returns
    /// `Ok(u8)` with the encoded length (0-3) if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    /// Note: This doesn't check if the specific Long Packet Type actually has a packet number.
    #[inline]
    pub fn pn_length_bits_long(&self) -> Result<u8, QuicHdrError> {
        if self.is_long_header() {
            // Safety: is_long_header() ensures conditions for unchecked_pn_length_bits_long are met.
            Ok(unsafe { self.unchecked_pn_length_bits_long() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the actual Packet Number Length in bytes (1 to 4) if this is a Long Header
    /// and the header type includes a packet number.
    ///
    /// # Returns
    /// `Ok(usize)` with the actual length (1-4 bytes) if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn packet_number_length_long(&self) -> Result<usize, QuicHdrError> {
        self.pn_length_bits_long().map(|bits| (bits + 1) as usize)
    }

    /// Gets the Spin Bit (bit 5 of `first_byte`) if this is a Short Header.
    ///
    /// # Returns
    /// `Ok(bool)` (`true` if bit is 1, `false` if 0) if Short Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn short_spin_bit(&self) -> Result<bool, QuicHdrError> {
        if !self.is_long_header() {
            // Safety: !is_long_header() ensures conditions for unchecked_short_spin_bit are met.
            Ok(unsafe { self.unchecked_short_spin_bit() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the Reserved Bits (bits 4-3 of `first_byte`) if this is a Short Header.
    /// These bits MUST be 0 in QUIC v1 unless an extension defines otherwise.
    ///
    /// # Returns
    /// `Ok(u8)` with the reserved bits value (0-3) if Short Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn short_reserved_bits(&self) -> Result<u8, QuicHdrError> {
        if !self.is_long_header() {
            // Safety: !is_long_header() ensures conditions are met.
            Ok(unsafe { self.unchecked_short_reserved_bits() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the Key Phase Bit (bit 2 of `first_byte`) if this is a Short Header.
    ///
    /// # Returns
    /// `Ok(bool)` (`true` if bit is 1, `false` if 0) if Short Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn short_key_phase(&self) -> Result<bool, QuicHdrError> {
        if !self.is_long_header() {
            // Safety: !is_long_header() ensures conditions for unchecked_short_key_phase are met.
            Ok(unsafe { self.unchecked_short_key_phase() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the encoded Packet Number Length (bits 1-0 of `first_byte`) if this is a Short Header.
    /// The value is `actual_length_in_bytes - 1`.
    ///
    /// # Returns
    /// `Ok(u8)` with the encoded length (0-3) if Short Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn short_pn_length_bits(&self) -> Result<u8, QuicHdrError> {
        if !self.is_long_header() {
            // Safety: !is_long_header() ensures conditions for unchecked_short_pn_length_bits are met.
            Ok(unsafe { self.unchecked_short_pn_length_bits() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the actual Packet Number Length in bytes (1 to 4) if this is a Short Header.
    ///
    /// # Returns
    /// `Ok(usize)` with the actual length (1-4 bytes) if Short Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn short_packet_number_length(&self) -> Result<usize, QuicHdrError> {
        self.short_pn_length_bits().map(|bits| (bits + 1) as usize)
    }

    /// Gets the QUIC version in host byte order, if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(u32)` with the version if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` for Short Headers.
    #[inline]
    pub fn version(&self) -> Result<u32, QuicHdrError> {
        if self.is_long_header() {
            // Safety: is_long_header() ensures self.inner.long is the active and initialized variant.
            Ok(unsafe { self.unchecked_version() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the Destination Connection ID length as present on the wire for Long Headers.
    /// This is the value of the DCIL byte.
    ///
    /// # Returns
    /// `Ok(u8)` with the on-wire DCID length if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` for Short Headers (as DCID length is not on the wire for them).
    #[inline]
    pub fn dc_id_len_on_wire(&self) -> Result<u8, QuicHdrError> {
        if self.is_long_header() {
            // Safety: is_long_header() ensures self.inner.long is active.
            Ok(unsafe { self.unchecked_dc_id_len_on_wire() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the effective length of the Destination Connection ID.
    /// For Long Headers, this is read from the Dst CID Len byte (via `self.inner.long.dst.len()`).
    /// For Short Headers, this is the contextual length stored in `header_type.dc_id_len`.
    ///
    /// # Returns
    /// The `u8` effective length of the DCID.
    #[inline]
    pub fn dc_id_effective_len(&self) -> u8 {
        // Safety: self.header_type is always consistent with the active union variant.
        unsafe { self.unchecked_dc_id_effective_len() }
    }

    /// Gets a slice to the Destination Connection ID bytes.
    /// The length of the slice is determined by `dc_id_effective_len()`.
    ///
    /// # Returns
    /// A `&[u8]` slice of the DCID.
    #[inline]
    pub fn dc_id(&self) -> &[u8] {
        // Safety: self.header_type is consistent, and dc_id_effective_len ensures bounds.
        unsafe { self.unchecked_dc_id() }
    }

    /// Gets the Source Connection ID length as present on the wire (Long Headers only).
    /// This is the value of the SCIL byte.
    ///
    /// # Returns
    /// `Ok(u8)` with the on-wire SCID length if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` for Short Headers.
    #[inline]
    pub fn sc_id_len_on_wire(&self) -> Result<u8, QuicHdrError> {
        if self.is_long_header() {
            // Safety: is_long_header() ensures self.inner.long is active.
            Ok(unsafe { self.unchecked_sc_id_len_on_wire() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets a slice to the Source Connection ID bytes if this is a Long Header.
    ///
    /// # Returns
    /// `Ok(&[u8])` slice of the SCID if Long Header,
    /// `Err(QuicHdrError::InvalidHeaderForm)` for Short Headers.
    #[inline]
    pub fn sc_id(&self) -> Result<&[u8], QuicHdrError> {
        if self.is_long_header() {
            // Safety: is_long_header() ensures self.inner.long is active and its .src.as_slice() is valid.
            Ok(unsafe { self.unchecked_sc_id() })
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Gets the current `QuicHeaderType` discriminator.
    /// This provides context for interpreting the union and, for Short Headers, the Destination CID length.
    ///
    /// # Returns
    /// The `QuicHeaderType` of this header instance.
    #[inline]
    pub fn header_type(&self) -> QuicHeaderType {
        self.header_type
    }

    /// Sets the Header Form bit (bit 7) in `first_byte`.
    ///
    /// # Parameters
    /// * `is_long`: If `true`, sets for Long Header; `false` for Short.
    ///
    /// # Safety
    /// This method only changes the bit in `first_byte`.
    /// For a safe structural change of the header form (Long vs. Short) which also
    /// reinitialized the `inner` union data and updates `header_type`, use `set_header_type()`.
    /// If this method is used to change the header form bit, the caller is responsible for
    /// ensuring `header_type` and `inner` data are also updated to maintain consistency.
    #[inline]
    pub fn set_header_form_bit(&mut self, is_long: bool) {
        // Safety: Direct bit manipulation; caller must ensure overall consistency.
        unsafe { self.unchecked_set_header_form_bit(is_long) };
    }

    /// Sets the Fixed Bit (bit 6 of `first_byte`).
    ///
    /// # Parameters
    /// * `val`: The new value for the Fixed Bit (0 or 1). Input is masked to 1 bit.
    #[inline]
    pub fn set_fixed_bit(&mut self, val: u8) {
        // Safety: Direct bitwise operation on self.first_byte.
        unsafe { self.unchecked_set_fixed_bit(val) };
    }

    /// Sets the Long Packet Type (bits 5-4 of `first_byte`) if this is a Long Header.
    ///
    /// # Parameters
    /// * `lptype`: The Long Packet Type (0-3). Input is masked to 2 bits.
    ///
    /// # Returns
    /// `Ok(())` if the operation is applicable and successful,
    /// `Err(QuicHdrError::InvalidHeaderForm)` if called on a Short Header.
    #[inline]
    pub fn set_long_packet_type(&mut self, lptype: u8) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            // Safety: `is_long_header()` check ensures conditions for are met.
            unsafe { self.unchecked_set_long_packet_type(lptype) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the Reserved Bits (bits 3-2 of `first_byte`) if this is a Long Header.
    ///
    /// # Parameters
    /// * `val`: The Reserved Bits value (0-3). Input is masked to 2 bits.
    ///   For QUIC v1 Initial, 0-RTT, Handshake, `val` MUST typically be 0.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline]
    pub fn set_reserved_bits_long(&mut self, val: u8) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_reserved_bits_long(val) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the encoded Packet Number Length (bits 1-0 of `first_byte`) if this is a Long Header.
    ///
    /// # Parameters
    /// * `val`: Encoded Packet Number Length (`actual_length_in_bytes - 1`, range 0-3). Masked to 2 bits.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    #[inline]
    pub fn set_pn_length_bits_long(&mut self, val: u8) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_pn_length_bits_long(val) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the actual Packet Number Length (1-4 bytes) if this is a Long Header.
    /// Clamps input `len_bytes` to the valid 1-4 range if out of bounds.
    ///
    /// # Parameters
    /// * `len_bytes`: Actual PN length in bytes (1-4).
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Long Header.
    pub fn set_packet_number_length_long(&mut self, len_bytes: usize) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_packet_number_length_long(len_bytes) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the Spin Bit (bit 5 of `first_byte`) if this is a Short Header.
    ///
    /// # Parameters
    /// * `spin`: Value for the Spin Bit (`true` for 1, `false` for 0).
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Short Header.
    #[inline]
    pub fn set_short_spin_bit(&mut self, spin: bool) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_short_spin_bit(spin) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the Reserved Bits (bits 4-3 of `first_byte`) if this is a Short Header.
    ///
    /// # Parameters
    /// * `val`: The Reserved Bits value (0-3). Input is masked to 2 bits.
    ///   For QUIC v1, `val` MUST typically be 0.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Short Header.
    #[inline]
    pub fn set_short_reserved_bits(&mut self, val: u8) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_short_reserved_bits(val) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the Key Phase Bit (bit 2 of `first_byte`) if this is a Short Header.
    ///
    /// # Parameters
    /// * `key_phase`: Value for the Key Phase Bit (`true` for 1, `false` for 0).
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Short Header.
    #[inline]
    pub fn set_short_key_phase(&mut self, key_phase: bool) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_short_key_phase(key_phase) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the encoded Packet Number Length (bits 1-0 of `first_byte`) if this is a Short Header.
    ///
    /// # Parameters
    /// * `val`: Encoded Packet Number Length (`actual_length_in_bytes - 1`, range 0-3). Masked to 2 bits.
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Short Header.
    #[inline]
    pub fn set_short_pn_length_bits(&mut self, val: u8) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_short_pn_length_bits(val) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the actual Packet Number Length (1-4 bytes) if this is a Short Header.
    /// Clamps input `len_bytes` to the valid 1-4 range if out of bounds.
    ///
    /// # Parameters
    /// * `len_bytes`: Actual PN length in bytes (1-4).
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err(QuicHdrError::InvalidHeaderForm)` if not a Short Header.
    pub fn set_short_packet_number_length(&mut self, len_bytes: usize) -> Result<(), QuicHdrError> {
        if !self.is_long_header() {
            // Safety: Condition met.
            unsafe { self.unchecked_set_short_packet_number_length(len_bytes) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the QUIC version (host byte order), if this is a Long Header.
    /// Does nothing if it's a Short Header.
    ///
    /// # Parameters
    /// * `v`: The QUIC version in host byte order.
    ///
    /// # Returns
    /// `Ok(())` if successful (i.e., was a Long Header),
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    #[inline]
    pub fn set_version(&mut self, v: u32) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            // Safety: Condition met, self.inner.long is active.
            unsafe { self.unchecked_set_version(v) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the effective length of the Destination Connection ID.
    ///
    /// # Parameters
    /// * `new_len`: The new desired effective length for the DCID. Values are clamped
    ///   to `QUIC_MAX_CID_LEN`.
    ///
    /// For Long Headers, this updates the internal `len` field of `self.inner.long.dst`,
    /// which corresponds to the on-wire DCIL byte. The actual DCID bytes are *not* zeroed
    /// or changed by this call alone if the length shrinks; use `set_dc_id` to change bytes.
    /// For Short Headers, this updates the contextual `dc_id_len` in `self.header_type`
    /// and also updates the internal `len` of `self.inner.short.dst` for consistency.
    pub fn set_dc_id_effective_len(&mut self, new_len: u8) {
        // Safety: unchecked method correctly handles union based on self.header_type.
        unsafe { self.unchecked_set_dc_id_effective_len(new_len) };
    }

    /// Sets the Destination Connection ID from a slice.
    /// This updates the internal CID bytes and its length.
    /// For Long Headers, `self.inner.long.dst.len` (on-wire DCIL) is updated to `data.len()`.
    /// For Short Headers, `self.header_type.dc_id_len` (contextual length) and
    /// `self.inner.short.dst.len` (internal tracking) are updated to `data.len()`.
    ///
    /// # Parameters
    /// * `data`: A byte slice containing the new DCID. Length is clamped to `QUIC_MAX_CID_LEN`.
    pub fn set_dc_id(&mut self, data: &[u8]) {
        // Safety: unchecked method correctly handles union based on self.header_type.
        unsafe { self.unchecked_set_dc_id(data) };
    }

    /// Sets the Source Connection ID length (Long Headers only).
    /// This updates the internal `len` field of `self.inner.long.src`, which
    /// corresponds to the on-wire SCIL byte. The SCID bytes are *not* zeroed or changed.
    ///
    /// # Parameters
    /// * `len`: The new desired length for the SCID. Values are clamped to `QUIC_MAX_CID_LEN`.
    ///
    /// # Returns
    /// `Ok(())` if successful (i.e., was a Long Header),
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    pub fn set_sc_id_len_on_wire(&mut self, len: u8) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            // Safety: Condition met, self.inner.long is active.
            unsafe { self.unchecked_set_sc_id_len_on_wire(len) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the Source Connection ID from a slice (Long Headers only).
    /// This updates the internal SCID bytes and its length (`self.inner.long.src.len`).
    ///
    /// # Parameters
    /// * `data`: A byte slice containing the new SCID. Length clamped to `QUIC_MAX_CID_LEN`.
    ///
    /// # Returns
    /// `Ok(())` if successful (i.e., was a Long Header),
    /// `Err(QuicHdrError::InvalidHeaderForm)` otherwise.
    pub fn set_sc_id(&mut self, data: &[u8]) -> Result<(), QuicHdrError> {
        if self.is_long_header() {
            // Safety: Condition met, self.inner.long is active.
            unsafe { self.unchecked_set_sc_id(data) };
            Ok(())
        } else {
            Err(QuicHdrError::InvalidHeaderForm)
        }
    }

    /// Sets the `QuicHeaderType` and reinitialized the inner `QuicHdrUn` union
    /// to its default state for the new type if the fundamental header form (Long/Short) changes.
    /// This is to prevent misinterpreting stale bytes from the previous union variant.
    /// The `first_byte`'s Header Form bit and Fixed Bit are updated to match the new type.
    /// Other specific bits in `first_byte` (like packet type, PN length) are *not* reset by this
    /// method and should be configured by the caller as needed for the new type.
    ///
    /// # Parameters
    /// * `new_type`: The new `QuicHeaderType` to set.
    ///
    /// # Safety
    /// This method correctly manages union transitions by re-initializing the union.
    /// Any CID data or other header fields must be repopulated by the caller if they need to be
    /// preserved or set for the new header type.
    pub fn set_header_type(&mut self, new_type: QuicHeaderType) {
        let other_bits = self.first_byte & !(HEADER_FORM_BIT | FIXED_BIT_MASK);
        // Safety: This method correctly manages union transitions and first_byte consistency.
        unsafe { self.unchecked_set_header_type(new_type) };
        self.first_byte |= other_bits;
    }
}

// Unsafe (unchecked) methods
impl QuicHdr {
    /// Gets the Long Packet Type from `first_byte` without checking a header form.
    ///
    /// # Returns
    /// The Long Packet Type value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_long_packet_type(&self) -> u8 {
        (self.first_byte & LONG_PACKET_TYPE_MASK) >> LONG_PACKET_TYPE_SHIFT
    }

    /// Sets the Long Packet Type in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `lptype`: The Long Packet Type (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_set_long_packet_type(&mut self, lptype: u8) {
        self.first_byte = (self.first_byte & !LONG_PACKET_TYPE_MASK)
            | ((lptype & 0x03) << LONG_PACKET_TYPE_SHIFT);
    }

    /// Gets the Reserved Bits (Long Header) from `first_byte` without checking header form.
    ///
    /// # Returns
    /// The Reserved Bits value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_reserved_bits_long(&self) -> u8 {
        (self.first_byte & RESERVED_BITS_LONG_MASK) >> RESERVED_BITS_LONG_SHIFT
    }

    /// Sets the Reserved Bits (Long Header) in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `val`: The Reserved Bits value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_set_reserved_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !RESERVED_BITS_LONG_MASK)
            | ((val & 0x03) << RESERVED_BITS_LONG_SHIFT);
    }

    /// Gets the encoded Packet Number Length (Long Header) from `first_byte` without checking header form.
    ///
    /// # Returns
    /// The encoded PN Length (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true and the packet type includes a PN.
    #[inline]
    pub unsafe fn unchecked_pn_length_bits_long(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the encoded Packet Number Length (Long Header) in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `val`: Encoded PN Length (0-3).
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_set_pn_length_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    /// Sets the Packet Number Length (Long Header) from actual length without checking header form.
    ///
    /// # Parameters
    /// * `len_bytes`: Actual PN length (1-4 bytes). Values outside this range are clamped to 1.
    ///
    /// # Safety
    /// Caller must ensure `self.is_long_header()` is true.
    pub unsafe fn unchecked_set_packet_number_length_long(&mut self, len_bytes: usize) {
        let encoded_val = match len_bytes {
            1 => 0b00,
            2 => 0b01,
            3 => 0b10,
            4 => 0b11,
            _ => 0b00, // Default to 1-byte PN length if input is invalid
        };
        self.unchecked_set_pn_length_bits_long(encoded_val);
    }

    /// Gets the Spin Bit (Short Header) from `first_byte` without checking header form.
    ///
    /// # Returns
    /// `true` if Spin Bit is 1, `false` if 0.
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_short_spin_bit(&self) -> bool {
        (self.first_byte & SHORT_SPIN_BIT_MASK) != 0
    }

    /// Sets the Spin Bit (Short Header) in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `spin`: Value for the Spin Bit.
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_set_short_spin_bit(&mut self, spin: bool) {
        if spin {
            self.first_byte |= SHORT_SPIN_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_SPIN_BIT_MASK;
        }
    }

    /// Gets the Reserved Bits (Short Header) from `first_byte` without checking header form.
    ///
    /// # Returns
    /// The Reserved Bits value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_short_reserved_bits(&self) -> u8 {
        (self.first_byte & SHORT_RESERVED_BITS_MASK) >> SHORT_RESERVED_BITS_SHIFT
    }

    /// Sets the Reserved Bits (Short Header) in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `val`: The Reserved Bits value (0-3).
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_set_short_reserved_bits(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !SHORT_RESERVED_BITS_MASK)
            | ((val & 0x03) << SHORT_RESERVED_BITS_SHIFT);
    }

    /// Gets the Key Phase Bit (Short Header) from `first_byte` without checking header form.
    ///
    /// # Returns
    /// `true` if Key Phase Bit is 1, `false` if 0.
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_short_key_phase(&self) -> bool {
        (self.first_byte & SHORT_KEY_PHASE_BIT_MASK) != 0
    }

    /// Sets the Key Phase Bit (Short Header) in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `key_phase`: Value for the Key Phase Bit.
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_set_short_key_phase(&mut self, key_phase: bool) {
        if key_phase {
            self.first_byte |= SHORT_KEY_PHASE_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_KEY_PHASE_BIT_MASK;
        }
    }

    /// Gets the encoded Packet Number Length (Short Header) from `first_byte` without checking header form.
    ///
    /// # Returns
    /// The encoded PN Length (0-3).
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_short_pn_length_bits(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the encoded Packet Number Length (Short Header) in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `val`: Encoded PN Length (0-3).
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    #[inline]
    pub unsafe fn unchecked_set_short_pn_length_bits(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    /// Sets the Packet Number Length (Short Header) from actual length without checking header form.
    ///
    /// # Parameters
    /// * `len_bytes`: Actual PN length (1-4 bytes). Values outside this range are clamped to 1.
    ///
    /// # Safety
    /// Caller must ensure `!self.is_long_header()` is true.
    pub unsafe fn unchecked_set_short_packet_number_length(&mut self, len_bytes: usize) {
        let encoded_val = match len_bytes {
            1 => 0b00,
            2 => 0b01,
            3 => 0b10,
            4 => 0b11,
            _ => 0b00, // Default to 1-byte PN length
        };
        self.unchecked_set_short_pn_length_bits(encoded_val);
    }

    /// Gets the QUIC version without checking header form.
    ///
    /// # Returns
    /// The QUIC version (host byte order).
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is `QuicLong` and `self.inner.long` is initialized and active.
    #[inline]
    pub unsafe fn unchecked_version(&self) -> u32 {
        self.inner.long.version()
    }

    /// Sets the QUIC version without checking header form.
    ///
    /// # Parameters
    /// * `v`: The QUIC version (host byte order).
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is `QuicLong` and `self.inner.long` is initialized and active.
    #[inline]
    pub unsafe fn unchecked_set_version(&mut self, v: u32) {
        self.inner.long.set_version(v);
    }

    /// Gets the on-wire DCID length (Long Header) without checking header form.
    ///
    /// # Returns
    /// The on-wire DCID length from `self.inner.long.dst.len`.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is `QuicLong` and `self.inner.long` is initialized and active.
    #[inline]
    pub unsafe fn unchecked_dc_id_len_on_wire(&self) -> u8 {
        self.inner.long.dst.len()
    }

    /// Gets the effective DCID length based on `header_type` without checking union validity.
    ///
    /// # Returns
    /// The effective DCID length.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is consistent with the active union variant
    /// and that the corresponding variant's CID `len` field or `dc_id_len` context is correctly set.
    #[inline]
    pub unsafe fn unchecked_dc_id_effective_len(&self) -> u8 {
        match self.header_type {
            QuicHeaderType::QuicLong => self.inner.long.dst.len(),
            QuicHeaderType::QuicShort { dc_id_len } => dc_id_len,
        }
    }

    /// Sets the effective DCID length without checking union validity.
    ///
    /// # Parameters
    /// * `new_len`: The new effective DCID length. Clamped to `QUIC_MAX_CID_LEN`.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is consistent with the active union variant.
    /// This updates lengths in both `header_type` (for Short) and the CID struct itself.
    pub unsafe fn unchecked_set_dc_id_effective_len(&mut self, new_len: u8) {
        let validated_len = cmp::min(new_len, QUIC_MAX_CID_LEN as u8);
        match &mut self.header_type {
            QuicHeaderType::QuicLong => {
                self.inner.long.dst.len = validated_len;
            }
            QuicHeaderType::QuicShort {
                dc_id_len: current_dc_len,
            } => {
                *current_dc_len = validated_len;
                self.inner.short.dst.len = validated_len; // Keep short.dst.len consistent
            }
        }
    }

    /// Gets the DCID slice based on `header_type` without checking union validity.
    ///
    /// # Returns
    /// A slice to the DCID bytes.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is consistent with the active union variant and
    /// `unchecked_dc_id_effective_len()` returns a valid length for the active variant's buffer.
    #[inline]
    pub unsafe fn unchecked_dc_id(&self) -> &[u8] {
        let len = self.unchecked_dc_id_effective_len() as usize;
        match self.header_type {
            QuicHeaderType::QuicLong => &self.inner.long.dst.bytes[..len],
            QuicHeaderType::QuicShort { .. } => &self.inner.short.dst.bytes[..len],
        }
    }

    /// Sets the DCID without checking union validity.
    ///
    /// # Parameters
    /// * `data`: Slice containing the new DCID. Length is clamped by `set()`.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is consistent with the active union variant.
    /// This updates lengths in `header_type` (for Short) and the CID struct itself via `set()`.
    pub unsafe fn unchecked_set_dc_id(&mut self, data: &[u8]) {
        match &mut self.header_type {
            QuicHeaderType::QuicLong => {
                self.inner.long.dst.set(data);
            }
            QuicHeaderType::QuicShort {
                dc_id_len: current_dc_len,
            } => {
                self.inner.short.dst.set(data);
                *current_dc_len = self.inner.short.dst.len();
            }
        }
    }

    /// Gets the on-wire SCID length (Long Header) without checking header form.
    ///
    /// # Returns
    /// The on-wire SCID length from `self.inner.long.src.len`.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is `QuicLong` and `self.inner.long` is initialized and active.
    #[inline]
    pub unsafe fn unchecked_sc_id_len_on_wire(&self) -> u8 {
        self.inner.long.src.len()
    }

    /// Sets the on-wire SCID length (Long Header) without checking header form. CID bytes are not changed.
    ///
    /// # Parameters
    /// * `len`: The new SCID length. Clamped to `QUIC_MAX_CID_LEN`.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is `QuicLong` and `self.inner.long` is initialized and active.
    pub unsafe fn unchecked_set_sc_id_len_on_wire(&mut self, len: u8) {
        self.inner.long.src.len = cmp::min(len, QUIC_MAX_CID_LEN as u8);
    }

    /// Gets a slice to the SCID (Long Header) without checking header form.
    ///
    /// # Returns
    /// A slice to the SCID bytes.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is `QuicLong`, `self.inner.long` is initialized,
    /// and `self.inner.long.src.len()` is a valid length for `self.inner.long.src.bytes`.
    #[inline]
    pub unsafe fn unchecked_sc_id(&self) -> &[u8] {
        self.inner.long.src.as_slice()
    }

    /// Sets the SCID (Long Header) without checking header form.
    ///
    /// # Parameters
    /// * `data`: Slice containing the new SCID. Length clamped by `set()`.
    ///
    /// # Safety
    /// Caller must ensure `self.header_type` is `QuicLong` and `self.inner.long` is initialized and active.
    pub unsafe fn unchecked_set_sc_id(&mut self, data: &[u8]) {
        self.inner.long.src.set(data);
    }

    /// Sets the `QuicHeaderType` and manages union transition, without boundary checks for CIDs.
    /// The `first_byte`'s Header Form and Fixed Bits are updated according to the `new_type`.
    /// Other bits in `first_byte` are *not* touched by this specific unsafe method.
    ///
    /// # Parameters
    /// * `new_type`: The new `QuicHeaderType`.
    ///
    /// # Safety
    /// This method correctly handles the re-initialization of the `inner` union
    /// when the fundamental header form (Long/Short) changes, preventing misinterpretation
    /// of stale bytes.
    /// Caller must repopulate CID data if it needs to be preserved across such a type change.
    /// Caller should ensure other bits in `first_byte` are appropriate for `new_type`.
    pub unsafe fn unchecked_set_header_type(&mut self, new_type: QuicHeaderType) {
        let current_is_long = self.is_long_header();
        let new_is_long = match new_type {
            QuicHeaderType::QuicLong => true,
            QuicHeaderType::QuicShort { .. } => false,
        };
        if current_is_long != new_is_long {
            // Form is changing, reinitialize union and update first_byte's Form bit
            if new_is_long {
                self.inner = QuicHdrUn {
                    long: QuicHdrLong::default(),
                };
                self.first_byte = (self.first_byte | HEADER_FORM_BIT) | FIXED_BIT_MASK;
            } else {
                let dc_id_len_for_short = if let QuicHeaderType::QuicShort { dc_id_len } = new_type
                {
                    dc_id_len
                } else {
                    0
                };
                let mut short_data = QuicHdrShort::default();
                short_data.dst.len = cmp::min(dc_id_len_for_short, QUIC_MAX_CID_LEN as u8);
                self.inner = QuicHdrUn { short: short_data };
                self.first_byte = (self.first_byte & !HEADER_FORM_BIT) | FIXED_BIT_MASK;
            }
        } else {
            // Form is not changing, but QuicShort's dc_id_len might be.
            // Ensure the fixed bit is correct for the form.
            if new_is_long {
                self.first_byte |= HEADER_FORM_BIT | FIXED_BIT_MASK;
            } else {
                self.first_byte = (self.first_byte & !HEADER_FORM_BIT) | FIXED_BIT_MASK;
                // If the type is QuicShort, update inner.short.dst.len if dc_id_len changes
                if let QuicHeaderType::QuicShort { dc_id_len } = new_type {
                    self.inner.short.dst.len = cmp::min(dc_id_len, QUIC_MAX_CID_LEN as u8);
                }
            }
        }
        self.header_type = new_type;
    }

    /// Sets the Header Form bit in `first_byte` without performing structural changes.
    ///
    /// # Parameters
    /// * `is_long`: `true` for Long Header form, `false` for Short.
    ///
    /// # Safety
    /// This directly modifies the `first_byte`. Caller must ensure that `header_type` and
    /// the active `inner` union variant are consistent with this change. Prefer using
    /// the safe `set_header_type` for structural changes.
    #[inline]
    pub unsafe fn unchecked_set_header_form_bit(&mut self, is_long: bool) {
        if is_long {
            self.first_byte |= HEADER_FORM_BIT;
        } else {
            self.first_byte &= !HEADER_FORM_BIT;
        }
    }

    /// Sets the Fixed Bit in `first_byte` without checking header form.
    ///
    /// # Parameters
    /// * `val`: The new value for the Fixed Bit (0 or 1). Input masked to 1 bit.
    ///
    /// # Safety
    /// This is a direct bitwise operation on `first_byte`.
    #[inline]
    pub unsafe fn unchecked_set_fixed_bit(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !FIXED_BIT_MASK) | ((val & 1) << 6);
    }
}

impl fmt::Debug for QuicHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("QuicHdr");
        s.field(
            "first_byte",
            &format_args!(
                // format_args! is core-friendly
                "{:#04x} (Form: {}, Fixed: {}, TypeSpecific: {:#04x})",
                self.first_byte,
                if self.is_long_header() {
                    "Long"
                } else {
                    "Short"
                },
                self.fixed_bit(),
                self.first_byte & !(HEADER_FORM_BIT | FIXED_BIT_MASK)
            ),
        );
        s.field("header_type", &self.header_type);
        match self.header_type {
            QuicHeaderType::QuicLong => {
                // Safely access long header fields for debug output
                s.field("version", &self.version().ok());
                s.field("dc_id", &self.dc_id());
                s.field("sc_id", &self.sc_id().ok());
            }
            QuicHeaderType::QuicShort { .. } => {
                s.field("dc_id", &self.dc_id());
                s.field("spin_bit", &self.short_spin_bit().ok());
                s.field("key_phase", &self.short_key_phase().ok());
            }
        };
        s.finish()
    }
}

#[cfg(feature = "serde")]
mod serde_header_impl {
    use super::*;
    use core::fmt;
    use serde::{
        de::{self, Visitor},
        Deserializer, Serializer,
    };

    struct TruncatedHeaderError {
        name: &'static str,
        got: usize,
        min: usize,
    }
    impl fmt::Display for TruncatedHeaderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Truncated {}: got {} bytes, need at least {}",
                self.name, self.got, self.min
            )
        }
    }

    struct HeaderFieldLengthExceedsMaxError {
        value: usize,
        max: usize,
        field_name: &'static str,
    }
    impl fmt::Display for HeaderFieldLengthExceedsMaxError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{} {} from wire exceeds max {}",
                self.field_name, self.value, self.max
            )
        }
    }

    impl serde::Serialize for QuicHdr {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // Max possible size: 1 (first_byte) + 4 (version) + 1 (DCIL) + MAX_CID + 1 (SCIL) + MAX_CID
            let mut buf = [0u8; 7 + QUIC_MAX_CID_LEN + QUIC_MAX_CID_LEN];
            let mut current_idx = 0usize;
            buf[current_idx] = self.first_byte;
            current_idx += 1;
            match self.header_type {
                QuicHeaderType::QuicLong => {
                    // Safety: header_type check
                    let long_hdr = unsafe { &self.inner.long };
                    buf[current_idx..current_idx + 4].copy_from_slice(&long_hdr.version);
                    current_idx += 4;
                    let dc_len = long_hdr.dst.len() as usize; // Length from QuicDstConnLong
                    buf[current_idx] = long_hdr.dst.len();
                    current_idx += 1;
                    buf[current_idx..current_idx + dc_len].copy_from_slice(long_hdr.dst.as_slice());
                    current_idx += dc_len;
                    let sc_len = long_hdr.src.len() as usize; // Length from QuicSrcConnLong
                    buf[current_idx] = long_hdr.src.len();
                    current_idx += 1;
                    buf[current_idx..current_idx + sc_len].copy_from_slice(long_hdr.src.as_slice());
                    current_idx += sc_len;
                }
                QuicHeaderType::QuicShort { dc_id_len } => {
                    // For short headers, dc_id_len from header_type is authoritative.
                    // self.inner.short.dst.bytes contains the data.
                    // self.inner.short.dst.len() should match dc_id_len if consistent.
                    let short_hdr_dst_bytes = unsafe { &self.inner.short.dst.bytes }; // Safe due to header_type
                    let actual_dc_len = cmp::min(dc_id_len as usize, QUIC_MAX_CID_LEN);

                    if actual_dc_len > 0 {
                        buf[current_idx..current_idx + actual_dc_len]
                            .copy_from_slice(&short_hdr_dst_bytes[..actual_dc_len]);
                    }
                    current_idx += actual_dc_len;
                }
            }
            serializer.serialize_bytes(&buf[..current_idx])
        }
    }

    struct QuicHdrVisitor;
    impl<'de> Visitor<'de> for QuicHdrVisitor {
        type Value = QuicHdr;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "raw QUIC header bytes")
        }
        fn visit_bytes<E>(self, v: &[u8]) -> Result<QuicHdr, E>
        where
            E: de::Error,
        {
            if v.is_empty() {
                return Err(E::custom("QUIC header cannot be empty"));
            }
            let first_byte = v[0];
            let mut current_idx = 1usize;
            if (first_byte & HEADER_FORM_BIT) != 0 {
                // Long Header
                if v.len() < QuicHdr::MIN_LONG_HDR_LEN_ON_WIRE {
                    // Basic check for minimal parts
                    return Err(E::custom(TruncatedHeaderError {
                        name: "long header",
                        got: v.len(),
                        min: QuicHdr::MIN_LONG_HDR_LEN_ON_WIRE,
                    }));
                }
                let mut hdr = QuicHdr::new(QuicHeaderType::QuicLong);
                // Version
                if v.len() < current_idx + 4 {
                    return Err(E::custom("Truncated version in long header"));
                }
                let mut version_bytes = [0u8; 4];
                version_bytes.copy_from_slice(&v[current_idx..current_idx + 4]);
                hdr.set_version(u32::from_be_bytes(version_bytes))
                    .map_err(|e| E::custom(e))?;
                current_idx += 4;
                if v.len() < current_idx + 1 {
                    return Err(E::custom("Missing DCIL in long header"));
                }
                let dc_len_on_wire = v[current_idx] as usize;
                current_idx += 1;
                if dc_len_on_wire > QUIC_MAX_CID_LEN {
                    return Err(E::custom(HeaderFieldLengthExceedsMaxError {
                        value: dc_len_on_wire,
                        max: QUIC_MAX_CID_LEN,
                        field_name: "DCID length",
                    }));
                }
                if v.len() < current_idx + dc_len_on_wire {
                    return Err(E::custom("Truncated DCID in long header"));
                }
                hdr.set_dc_id(&v[current_idx..current_idx + dc_len_on_wire]);
                current_idx += dc_len_on_wire;
                if v.len() < current_idx + 1 {
                    return Err(E::custom("Missing SCIL in long header"));
                }
                let sc_len_on_wire = v[current_idx] as usize;
                current_idx += 1;
                if sc_len_on_wire > QUIC_MAX_CID_LEN {
                    return Err(E::custom(HeaderFieldLengthExceedsMaxError {
                        value: sc_len_on_wire,
                        max: QUIC_MAX_CID_LEN,
                        field_name: "SCID length",
                    }));
                }
                if v.len() < current_idx + sc_len_on_wire {
                    return Err(E::custom("Truncated SCID in long header"));
                }
                hdr.set_sc_id(&v[current_idx..current_idx + sc_len_on_wire])
                    .map_err(|e| E::custom(e))?; // Pass the error that implements Display
                hdr.set_first_byte(first_byte); // Set the original first_byte
                Ok(hdr)
            } else {
                // Short Header
                // For short headers, the length of DCID is not on the wire.
                // The deserializer must infer it from the remaining bytes.
                // This makes QuicHeaderType::QuicShort { dc_id_len } crucial.
                let dcid_bytes_from_slice = &v[current_idx..];
                let dc_id_len_parsed =
                    cmp::min(dcid_bytes_from_slice.len(), QUIC_MAX_CID_LEN) as u8;
                let mut hdr = QuicHdr::new(QuicHeaderType::QuicShort {
                    dc_id_len: dc_id_len_parsed,
                });
                hdr.set_dc_id(&dcid_bytes_from_slice[..dc_id_len_parsed as usize]);
                hdr.set_first_byte(first_byte); // Set the original first_byte
                Ok(hdr)
            }
        }
    }
    impl<'de> serde::Deserialize<'de> for QuicHdr {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(QuicHdrVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use bincode;
    #[cfg(feature = "serde")]
    use serde_test::{assert_tokens, Token};

    #[test]
    fn test_min_header_len_constants() {
        assert_eq!(QuicHdr::MIN_LONG_HDR_LEN_ON_WIRE, 7);
        assert_eq!(QuicHdr::MIN_SHORT_HDR_LEN_ON_WIRE, 1);
    }

    #[test]
    fn test_long_header_creation_and_accessors() {
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicLong);
        assert!(hdr.is_long_header());
        assert_eq!(hdr.first_byte() & 0xC0, HEADER_FORM_BIT | FIXED_BIT_MASK); // Form and Fixed bits
        assert!(hdr.set_long_packet_type(0b01).is_ok()); // 0-RTT
        assert_eq!(hdr.long_packet_type(), Ok(0b01));
        assert!(hdr.set_reserved_bits_long(0b00).is_ok());
        assert_eq!(hdr.reserved_bits_long(), Ok(0b00));
        assert!(hdr.set_packet_number_length_long(4).is_ok()); // 4 bytes PN
        assert_eq!(hdr.pn_length_bits_long(), Ok(0b11)); // Encoded as 3
        assert_eq!(hdr.packet_number_length_long(), Ok(4));
        assert!(hdr.set_version(0x0000_0001).is_ok());
        assert_eq!(hdr.version(), Ok(0x0000_0001));
        let dcid_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let scid_data = [0xA, 0xB, 0xC, 0xD];
        hdr.set_dc_id(&dcid_data); // Sets DCID and its length (8)
        assert!(hdr.set_sc_id(&scid_data).is_ok()); // Sets SCID and its length (4)
        assert_eq!(hdr.dc_id_effective_len(), 8);
        assert_eq!(hdr.dc_id_len_on_wire(), Ok(8));
        assert_eq!(hdr.dc_id(), &dcid_data);
        assert_eq!(hdr.sc_id_len_on_wire(), Ok(4));
        assert_eq!(hdr.sc_id().unwrap(), &scid_data);
        // Check the internal consistency of CIDs within the QuicHdrLong part
        unsafe {
            assert_eq!(hdr.inner.long.dst.len(), 8);
            assert_eq!(hdr.inner.long.dst.as_slice(), &dcid_data);
            assert_eq!(hdr.inner.long.src.len(), 4);
            assert_eq!(hdr.inner.long.src.as_slice(), &scid_data);
        }
    }

    #[test]
    fn test_short_header_creation_and_accessors() {
        let dcid_data = [0xAA, 0xBB, 0xCC];
        // For short headers, DCID length is contextual.
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicShort {
            dc_id_len: dcid_data.len() as u8,
        });
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
    fn test_header_type_transition_and_cid_reset() {
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicLong);
        hdr.set_dc_id(&[1, 2, 3]);
        assert!(hdr.set_version(123).is_ok());
        assert_eq!(hdr.dc_id(), &[1, 2, 3]);
        let original_first_byte_bits = hdr.first_byte() & 0x3F;
        hdr.set_header_type(QuicHeaderType::QuicShort { dc_id_len: 0 });
        assert!(!hdr.is_long_header());
        assert!(hdr.version().is_err());
        assert_eq!(hdr.dc_id_effective_len(), 0);
        assert_eq!(hdr.dc_id(), &[]);
        assert_eq!(hdr.first_byte() & HEADER_FORM_BIT, 0);
        assert_eq!(hdr.first_byte() & FIXED_BIT_MASK, FIXED_BIT_MASK);
        assert_eq!(hdr.first_byte() & 0x3F, original_first_byte_bits);
        hdr.set_dc_id(&[4, 5, 6]);
        assert_eq!(hdr.dc_id_effective_len(), 3);
        assert_eq!(hdr.dc_id(), &[4, 5, 6]);
        if let QuicHeaderType::QuicShort { dc_id_len } = hdr.header_type() {
            assert_eq!(dc_id_len, 3);
        } else {
            panic!("Not a short header!");
        }
        let short_first_byte_bits = hdr.first_byte() & 0x3F;
        hdr.set_header_type(QuicHeaderType::QuicLong);
        assert!(hdr.is_long_header());
        assert_eq!(hdr.version(), Ok(0)); // Version is reset to default
        assert_eq!(hdr.dc_id_effective_len(), 0); // DCID is reset
        assert_eq!(hdr.dc_id(), &[]);
        assert_eq!(hdr.sc_id_len_on_wire(), Ok(0)); // SCID is reset
        assert_eq!(hdr.first_byte() & HEADER_FORM_BIT, HEADER_FORM_BIT);
        assert_eq!(hdr.first_byte() & FIXED_BIT_MASK, FIXED_BIT_MASK);
        assert_eq!(hdr.first_byte() & 0x3F, short_first_byte_bits);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_long_header_serde_roundtrip() {
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicLong);
        // Set first byte: Form=1, Fixed=1, Type=0(Initial), Reserved=0, PNLEN=2 (encoded 0b01)
        hdr.set_first_byte(0xC0 | (0b00 << 4) | (0b00 << 2) | 0b01);
        assert!(hdr.set_version(0x01020304).is_ok());
        hdr.set_dc_id(&[0xAA; 8]);
        assert!(hdr.set_sc_id(&[0xBB; 4]).is_ok());
        let expected_first_byte = hdr.first_byte(); // Should be 0xC0 | 0b01 = 0xC1
        assert_eq!(expected_first_byte, 0xC1);

        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&hdr, config).expect("Serialization failed");

        assert_eq!(bytes[0], expected_first_byte);
        assert_eq!(&bytes[1..5], &0x01020304u32.to_be_bytes()); // Version
        assert_eq!(bytes[5], 8); // DCIL
        assert_eq!(&bytes[6..14], &[0xAA; 8]); // DCID
        assert_eq!(bytes[14], 4); // SCIL
        assert_eq!(&bytes[15..19], &[0xBB; 4]); // SCID
        assert_eq!(bytes.len(), 19); // Total length
        let (de, len): (QuicHdr, usize) =
            bincode::serde::decode_from_slice(&bytes, config).expect("Deserialization failed");
        assert_eq!(len, bytes.len());
        assert_eq!(de.first_byte(), expected_first_byte);
        assert!(de.is_long_header());
        assert_eq!(de.header_type(), QuicHeaderType::QuicLong); // Deserializer sets this
        assert_eq!(de.version().unwrap(), 0x01020304);
        assert_eq!(de.dc_id_effective_len(), 8);
        assert_eq!(de.dc_id(), &[0xAA; 8]);
        assert_eq!(de.sc_id_len_on_wire().unwrap(), 4);
        assert_eq!(de.sc_id().unwrap(), &[0xBB; 4]);
        assert_eq!(de.long_packet_type(), Ok(0b00));
        assert_eq!(de.reserved_bits_long(), Ok(0b00));
        assert_eq!(de.pn_length_bits_long(), Ok(0b01)); // PNLEN=2
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_short_header_serde_roundtrip() {
        let dcid_data = [0xCC, 0xDD, 0xEE, 0xFF, 0x11];
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicShort {
            dc_id_len: dcid_data.len() as u8,
        });
        hdr.set_first_byte(0x40 | SHORT_SPIN_BIT_MASK | SHORT_KEY_PHASE_BIT_MASK | 0b00); // Fixed | Spin | KeyPhase | PNLEN=1 (00)
        hdr.set_dc_id(&dcid_data);
        let expected_first_byte = hdr.first_byte();
        assert_eq!(expected_first_byte, 0x40 | 0x20 | 0x04 | 0b00); // 0x64
        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&hdr, config).expect("Serialization failed");
        assert_eq!(bytes[0], expected_first_byte);
        assert_eq!(&bytes[1..], &dcid_data); // DCID directly follows
        assert_eq!(bytes.len(), 1 + dcid_data.len());
        let (de, len): (QuicHdr, usize) =
            bincode::serde::decode_from_slice(&bytes, config).expect("Deserialization failed");
        assert_eq!(len, bytes.len());
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
        assert_eq!(de.short_reserved_bits(), Ok(0b00)); // Reserved bits are 00
        assert_eq!(de.short_key_phase(), Ok(true));
        assert_eq!(de.short_pn_length_bits(), Ok(0b00)); // PNLEN=1
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
        assert_tokens(
            &cid,
            &[
                Token::Struct {
                    name: "QuicDstConnLong",
                    len: 2,
                },
                Token::Str("len"),
                Token::U8(3),
                Token::Str("bytes"),
                Token::BorrowedBytes(&[1, 2, 3]),
                Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_cid_serde_short_direct() {
        let mut cid = QuicDstConnShort::new();
        cid.set(&[1, 2, 3, 4]);
        assert_tokens(&cid, &[Token::BorrowedBytes(&[1, 2, 3, 4])]);
    }

    #[test]
    fn test_parse_realistic_long_header_initial_packet() {
        let packet_bytes: &[u8] = &[
            0xC1, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
            0x08, 0x76, 0x05, 0x96, 0x95, 0xC0, 0x9A, 0x58, 0x57,
        ];
        let mut current_offset = 0;
        let first_byte = packet_bytes[current_offset];
        current_offset += 1;
        assert_eq!(
            (first_byte & HEADER_FORM_BIT),
            HEADER_FORM_BIT,
            "Should be Long Header according to first byte"
        );
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicLong);
        hdr.set_first_byte(first_byte);
        let mut version_bytes = [0u8; 4];
        version_bytes.copy_from_slice(&packet_bytes[current_offset..current_offset + 4]);
        current_offset += 4;
        hdr.set_version(u32::from_be_bytes(version_bytes))
            .expect("Set version failed for Long Header");
        let dcid_len_on_wire = packet_bytes[current_offset];
        current_offset += 1;
        assert!(
            dcid_len_on_wire as usize <= QUIC_MAX_CID_LEN,
            "DCID length exceeds max"
        );
        let dcid_data_from_packet =
            &packet_bytes[current_offset..current_offset + dcid_len_on_wire as usize];
        hdr.set_dc_id(dcid_data_from_packet);
        current_offset += dcid_len_on_wire as usize;
        let scid_len_on_wire = packet_bytes[current_offset];
        current_offset += 1;
        assert!(
            scid_len_on_wire as usize <= QUIC_MAX_CID_LEN,
            "SCID length exceeds max"
        );
        let scid_data_from_packet =
            &packet_bytes[current_offset..current_offset + scid_len_on_wire as usize];
        hdr.set_sc_id(scid_data_from_packet)
            .expect("Set SCID failed for Long Header");
        current_offset += scid_len_on_wire as usize;
        assert!(hdr.is_long_header());
        assert_eq!(hdr.fixed_bit(), 1);
        assert_eq!(hdr.long_packet_type(), Ok(0b00));
        assert_eq!(hdr.reserved_bits_long(), Ok(0b00));
        assert_eq!(hdr.pn_length_bits_long(), Ok(0b01));
        assert_eq!(hdr.packet_number_length_long(), Ok(2));
        assert_eq!(hdr.version(), Ok(0x00000001));
        assert_eq!(hdr.dc_id_len_on_wire(), Ok(8));
        assert_eq!(
            hdr.dc_id(),
            &[0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08]
        );
        assert_eq!(hdr.sc_id_len_on_wire(), Ok(8));
        assert_eq!(
            hdr.sc_id().unwrap(),
            &[0x76, 0x05, 0x96, 0x95, 0xC0, 0x9A, 0x58, 0x57]
        );
        assert_eq!(
            current_offset,
            1 // first_byte
                + 4 // version
                + 1 // dcil
                + 8 // dcid
                + 1 // scil
                + 8 // scid
        );
    }

    #[test]
    fn test_parse_realistic_short_header_1rtt_packet() {
        // Based on RFC 9000 Appendix A.4 (1-RTT)
        // First Byte: Short Header (0), Fixed Bit (1), Spin Bit (0), Reserved (00), Key Phase (1), PN Len (01 -> 2 bytes)
        // 01000101 = 0x45
        let dcid_from_connection_context = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];
        let contextual_dcid_len = dcid_from_connection_context.len() as u8;
        let packet_bytes: &[u8] = &[
            0x45, // First Byte
            // DCID (actual bytes, length is from context, not on wire here)
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57,
            0x08,
            // Packet number (e.g., 0x00, 0x01) would follow.
        ];
        let mut current_offset = 0;
        let first_byte = packet_bytes[current_offset];
        current_offset += 1;
        assert_eq!(
            (first_byte & HEADER_FORM_BIT),
            0,
            "Should be Short Header according to first byte"
        );
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicShort {
            dc_id_len: contextual_dcid_len,
        });
        hdr.set_first_byte(first_byte); // Set the entire first byte
        let dcid_data_from_packet =
            &packet_bytes[current_offset..current_offset + contextual_dcid_len as usize];
        hdr.set_dc_id(dcid_data_from_packet); // This sets data and updates internal length fields
        current_offset += contextual_dcid_len as usize;
        assert!(!hdr.is_long_header()); // Confirmed by first_byte set earlier
        assert_eq!(hdr.fixed_bit(), 1);
        assert_eq!(hdr.short_spin_bit(), Ok(false));
        assert_eq!(hdr.short_reserved_bits(), Ok(0b00));
        assert_eq!(hdr.short_key_phase(), Ok(true));
        assert_eq!(hdr.short_pn_length_bits(), Ok(0b01)); // Encoded: 2 bytes actual length
        assert_eq!(hdr.short_packet_number_length(), Ok(2));
        assert_eq!(hdr.dc_id_effective_len(), contextual_dcid_len);
        assert_eq!(hdr.dc_id(), &dcid_from_connection_context);
        assert_eq!(hdr.version(), Err(QuicHdrError::InvalidHeaderForm));
        assert_eq!(hdr.sc_id(), Err(QuicHdrError::InvalidHeaderForm));
        assert_eq!(
            hdr.dc_id_len_on_wire(),
            Err(QuicHdrError::InvalidHeaderForm)
        );
        assert_eq!(current_offset, 1 + contextual_dcid_len as usize);
    }

    #[test]
    fn test_ebpf_like_agent_parsing_long_header() {
        let packet_bytes: &[u8] = &[
            0xC1, // First Byte (Long, Fixed, Type=Initial, Res=0, PNLEN=2bytes)
            0x00, 0x00, 0x00, 0x01, // Version (QUIC v1)
            0x08, // DCID Len
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08, // DCID
            0x05, // SCID Len
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // SCID
            0xAB, 0xCD, // Example Packet Number (2 bytes), not parsed by QuicHdr itself
        ];
        let total_packet_data_len = packet_bytes.len(); // Simulates ctx.data_end() or available length
        let mut parse_ptr_offset = 0; // Simulates current read position in packet buffer
        let mut quic_hdr_on_stack: QuicHdr; // Represents a stack-allocated struct
        if parse_ptr_offset + 1 > total_packet_data_len {
            panic!("Packet too short for first_byte");
        }
        let first_byte = packet_bytes[parse_ptr_offset];
        parse_ptr_offset += 1;
        if (first_byte & HEADER_FORM_BIT) != 0 {
            // Is Long Header
            quic_hdr_on_stack = QuicHdr::new(QuicHeaderType::QuicLong);
            quic_hdr_on_stack.set_first_byte(first_byte); // Apply all bits from packet's first_byte
            if parse_ptr_offset + 4 > total_packet_data_len {
                panic!("Packet too short for version");
            }
            let mut ver_buf = [0u8; 4];
            ver_buf.copy_from_slice(&packet_bytes[parse_ptr_offset..parse_ptr_offset + 4]);
            quic_hdr_on_stack
                .set_version(u32::from_be_bytes(ver_buf))
                .unwrap();
            parse_ptr_offset += 4;
            if parse_ptr_offset + 1 > total_packet_data_len {
                panic!("Packet too short for DCIL byte");
            }
            let dcid_len_from_pkt = packet_bytes[parse_ptr_offset];
            parse_ptr_offset += 1;
            if dcid_len_from_pkt as usize > QUIC_MAX_CID_LEN {
                panic!("DCIL too large");
            }
            if parse_ptr_offset + dcid_len_from_pkt as usize > total_packet_data_len {
                panic!("Packet too short for DCID data");
            }
            let mut dcid_temp_buf = [0u8; QUIC_MAX_CID_LEN];
            if dcid_len_from_pkt > 0 {
                dcid_temp_buf[..dcid_len_from_pkt as usize].copy_from_slice(
                    &packet_bytes[parse_ptr_offset..parse_ptr_offset + dcid_len_from_pkt as usize],
                );
            }
            quic_hdr_on_stack.set_dc_id(&dcid_temp_buf[..dcid_len_from_pkt as usize]);
            parse_ptr_offset += dcid_len_from_pkt as usize;
            if parse_ptr_offset + 1 > total_packet_data_len {
                panic!("Packet too short for SCIL byte");
            }
            let scid_len_from_pkt = packet_bytes[parse_ptr_offset];
            parse_ptr_offset += 1;
            if scid_len_from_pkt as usize > QUIC_MAX_CID_LEN {
                panic!("SCIL too large");
            }
            if parse_ptr_offset + scid_len_from_pkt as usize > total_packet_data_len {
                panic!("Packet too short for SCID data");
            }
            let mut scid_temp_buf = [0u8; QUIC_MAX_CID_LEN];
            if scid_len_from_pkt > 0 {
                scid_temp_buf[..scid_len_from_pkt as usize].copy_from_slice(
                    &packet_bytes[parse_ptr_offset..parse_ptr_offset + scid_len_from_pkt as usize],
                );
            }
            quic_hdr_on_stack
                .set_sc_id(&scid_temp_buf[..scid_len_from_pkt as usize])
                .unwrap();
            parse_ptr_offset += scid_len_from_pkt as usize;
            assert!(quic_hdr_on_stack.is_long_header());
            assert_eq!(quic_hdr_on_stack.long_packet_type(), Ok(0b00)); // Initial
            assert_eq!(quic_hdr_on_stack.packet_number_length_long(), Ok(2));
            assert_eq!(quic_hdr_on_stack.version(), Ok(0x00000001));
            assert_eq!(
                quic_hdr_on_stack.dc_id(),
                &[0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08]
            );
            assert_eq!(
                quic_hdr_on_stack.sc_id().unwrap(),
                &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
            );
            let pn_actual_len = quic_hdr_on_stack.packet_number_length_long().unwrap();
            assert_eq!(
                &packet_bytes[parse_ptr_offset..parse_ptr_offset + pn_actual_len],
                &[0xAB, 0xCD]
            );
        } else {
            panic!("Test logic assumes Long Header based on first byte of test data.");
        }
    }

    #[test]
    fn test_ebpf_like_agent_parsing_short_header() {
        let known_dcid_value_from_context = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let known_dcid_len_from_context = known_dcid_value_from_context.len() as u8;
        let packet_bytes: &[u8] = &[
            0x45, // First Byte (Short, Fixed, Spin=0, Res=0, KeyPhase=1, PNLEN=2bytes)
            // DCID bytes follow immediately; length is known from context.
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xBE,
            0xEF, // Example Packet Number (2 bytes), not parsed by QuicHdr itself
        ];
        let total_packet_data_len = packet_bytes.len();
        let mut parse_ptr_offset = 0;
        let mut quic_hdr_on_stack: QuicHdr;
        if parse_ptr_offset + 1 > total_packet_data_len {
            panic!("Packet too short for first_byte");
        }
        let first_byte = packet_bytes[parse_ptr_offset];
        parse_ptr_offset += 1;
        if (first_byte & HEADER_FORM_BIT) == 0 {
            // Is Short Header
            quic_hdr_on_stack = QuicHdr::new(QuicHeaderType::QuicShort {
                dc_id_len: known_dcid_len_from_context,
            });
            quic_hdr_on_stack.set_first_byte(first_byte);
            if known_dcid_len_from_context as usize > QUIC_MAX_CID_LEN {
                panic!("Contextual DCID len too large");
            }
            if parse_ptr_offset + known_dcid_len_from_context as usize > total_packet_data_len {
                panic!("Packet too short for DCID data");
            }
            let mut dcid_temp_buf = [0u8; QUIC_MAX_CID_LEN];
            if known_dcid_len_from_context > 0 {
                dcid_temp_buf[..known_dcid_len_from_context as usize].copy_from_slice(
                    &packet_bytes
                        [parse_ptr_offset..parse_ptr_offset + known_dcid_len_from_context as usize],
                );
            }
            quic_hdr_on_stack.set_dc_id(&dcid_temp_buf[..known_dcid_len_from_context as usize]);
            parse_ptr_offset += known_dcid_len_from_context as usize;
            assert!(!quic_hdr_on_stack.is_long_header());
            assert_eq!(quic_hdr_on_stack.short_spin_bit(), Ok(false));
            assert_eq!(quic_hdr_on_stack.short_key_phase(), Ok(true));
            assert_eq!(quic_hdr_on_stack.short_packet_number_length(), Ok(2));
            assert_eq!(
                quic_hdr_on_stack.dc_id_effective_len(),
                known_dcid_len_from_context
            );
            assert_eq!(quic_hdr_on_stack.dc_id(), &known_dcid_value_from_context);
            let pn_actual_len = quic_hdr_on_stack.short_packet_number_length().unwrap();
            assert_eq!(
                &packet_bytes[parse_ptr_offset..parse_ptr_offset + pn_actual_len],
                &[0xBE, 0xEF]
            );
        } else {
            panic!("Test logic assumes Short Header based on first byte of test data.");
        }
    }
}
