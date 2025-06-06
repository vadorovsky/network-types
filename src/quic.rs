use core::mem;

const HEADER_FORM_BIT: u8 = 0x80;
const FIXED_BIT_MASK: u8 = 0x40;
const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const LONG_PACKET_TYPE_SHIFT: u8 = 4;
const RESERVED_BITS_LONG_MASK: u8 = 0x0C;
const RESERVED_BITS_LONG_SHIFT: u8 = 2;
const SHORT_SPIN_BIT_MASK: u8 = 0x20;
const SHORT_SPIN_BIT_SHIFT: u8 = 5;
const SHORT_RESERVED_BITS_MASK: u8 = 0x18;
const SHORT_RESERVED_BITS_SHIFT: u8 = 3;
const SHORT_KEY_PHASE_BIT_MASK: u8 = 0x04;
const SHORT_KEY_PHASE_BIT_SHIFT: u8 = 2;

const PN_LENGTH_BITS_MASK: u8 = 0x03;
/// Mask for Packet Number Length bits (bits 1-0).

/// Represents the 7-byte fixed-size prefix of a QUIC Long Header or provides methods
/// to interpret the first byte of a QUIC Short Header.
///
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicHdr {
    /// The first byte of the QUIC header. Its interpretation depends on the Header Form bit.
    /// - Bit 7: Header Form (1 for Long, 0 for Short)
    /// - Bit 6: Fixed Bit (usually 1)
    /// - Bits 5-0: Type/Flag specific bits.
    pub first_byte: u8,
    /// QUIC version (e.g., 0x00000001 for QUIC v1). Network byte order. Only in Long Headers.
    pub version: [u8; 4],
    /// Destination Connection ID Length. Only in Long Headers (explicitly). For Short Headers,
    /// this field might be used by application logic to store the known DCID length.
    pub dc_id_len: u8,
    /// Source Connection ID Length. Only in Long Headers.
    pub sc_id_len: u8,
}

impl QuicHdr {
    /// Length of the `QuicHdr` struct, relevant for Long Headers.
    pub const LEN: usize = mem::size_of::<QuicHdr>();

    /// Creates a `QuicHdr` for a Long Header, configured as an Initial packet.
    ///
    /// The first byte is set for Long Header (form bit = 1), Fixed Bit = 1,
    /// Long Packet Type = Initial (0b00), and Reserved Bits = 0.
    ///
    /// # Parameters
    /// - `version` - QUIC version (e.g., `0x00000001` for v1), host byte order.
    /// - `dc_id_len` - Destination Connection ID length.
    /// - `sc_id_len` - Source Connection ID length.
    /// - `pn_len_bits` - Encoded Packet Number Length (actual length - 1, value 0-3).
    ///
    /// # Returns
    /// A new `QuicHdr` instance.
    pub fn new(version: u32, dc_id_len: u8, sc_id_len: u8, pn_len_bits: u8) -> Self {
        let first_byte = HEADER_FORM_BIT
            | FIXED_BIT_MASK
            | (0b00 << LONG_PACKET_TYPE_SHIFT)
            | (0b00 << RESERVED_BITS_LONG_SHIFT)
            | (pn_len_bits & PN_LENGTH_BITS_MASK);
        Self {
            first_byte,
            version: version.to_be_bytes(),
            dc_id_len,
            sc_id_len,
        }
    }

    /// Creates the first byte for a QUIC Short Header.
    ///
    /// Sets Header Form to 0, Fixed Bit to 1, and specified Short Header flags.
    /// Reserved bits (4-3) are set to 0.
    ///
    /// # Parameters
    /// - `spin_bit` - The value of the Spin bit (0 or 1).
    /// - `key_phase` - The value of the Key Phase bit (0 or 1).
    /// - `pn_len_bits` - The encoded Packet Number Length (actual length - 1, value 0-3).
    ///
    /// # Returns
    /// The constructed `first_byte` for a Short Header.
    pub fn new_short_header_first_byte(spin_bit: bool, key_phase: bool, pn_len_bits: u8) -> u8 {
        let spin_val = if spin_bit { 1 } else { 0 };
        let key_phase_val = if key_phase { 1 } else { 0 };
        FIXED_BIT_MASK
            | (spin_val << SHORT_SPIN_BIT_SHIFT)
            | (key_phase_val << SHORT_KEY_PHASE_BIT_SHIFT)
            | (pn_len_bits & PN_LENGTH_BITS_MASK)
    }

    /// Returns the raw first byte of the header.
    ///
    /// # Returns
    /// The `first_byte` field.
    #[inline]
    pub fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// Sets the raw first byte of the header.
    ///
    /// # Parameters
    /// - `first_byte` - The new value for the first byte.
    #[inline]
    pub fn set_first_byte(&mut self, first_byte: u8) {
        self.first_byte = first_byte;
    }

    /// Checks if the Header Form bit (bit 7 of `first_byte`) indicates a Long Header.
    ///
    /// # Returns
    /// `true` if it's a Long Header (bit 7 is 1), `false` otherwise (Short Header).
    #[inline]
    pub fn is_long_header(&self) -> bool {
        (self.first_byte & HEADER_FORM_BIT) == HEADER_FORM_BIT
    }

    /// Sets the Header Form bit (bit 7 of `first_byte`).
    ///
    /// # Parameters
    /// - `is_long` - If `true`, sets for Long Header (bit 7 = 1); if `false`, sets for Short Header (bit 7 = 0).
    #[inline]
    pub fn set_header_form(&mut self, is_long: bool) {
        if is_long {
            self.first_byte |= HEADER_FORM_BIT;
        } else {
            self.first_byte &= !HEADER_FORM_BIT;
        }
    }

    /// Gets the Fixed Bit (bit 6 of `first_byte`).
    ///
    /// In QUIC v1 (RFC 9000):
    /// - For Long Headers: `1` for Initial, 0-RTT, Handshake, Retry. `0` for Version Negotiation.
    /// - For Short Headers: Must be `1`.
    ///
    /// # Returns
    /// The value of the Fixed Bit (0 or 1).
    #[inline]
    pub fn fixed_bit(&self) -> u8 {
        (self.first_byte & FIXED_BIT_MASK) >> 6
    }

    /// Sets the Fixed Bit (bit 6 of `first_byte`).
    ///
    /// # Parameters
    /// - `val` - The new value for the Fixed Bit (0 or 1). Input is masked to 1 bit.
    #[inline]
    pub fn set_fixed_bit(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !FIXED_BIT_MASK) | ((val & 0x01) << 6);
    }

    /// Gets the Long Packet Type (bits 5-4 of `first_byte`). Assumes Long Header.
    /// Common QUIC v1 types (RFC 9000): 00 (Initial), 01 (0-RTT), 10 (Handshake), 11 (Retry).
    ///
    /// # Returns
    /// The Long Packet Type value (0-3). Only valid if `is_long_header()` is `true` and `fixed_bit()` is `1`.
    #[inline]
    pub fn long_packet_type(&self) -> u8 {
        (self.first_byte & LONG_PACKET_TYPE_MASK) >> LONG_PACKET_TYPE_SHIFT
    }

    /// Sets the Long Packet Type (bits 5-4 of `first_byte`). Assumes Long Header.
    ///
    /// # Parameters
    /// - `lptype` - The Long Packet Type (0-3). Input is masked to 2 bits.
    #[inline]
    pub fn set_long_packet_type(&mut self, lptype: u8) {
        self.first_byte = (self.first_byte & !LONG_PACKET_TYPE_MASK)
            | ((lptype << LONG_PACKET_TYPE_SHIFT) & LONG_PACKET_TYPE_MASK);
    }

    /// Gets the Reserved Bits (bits 3-2 of `first_byte`) for common Long Headers.
    /// Must be 0 for Initial, 0-RTT, Handshake packets in QUIC v1.
    ///
    /// # Returns
    /// The Reserved Bits value (0-3). Only valid for certain Long Header types.
    #[inline]
    pub fn reserved_bits_long(&self) -> u8 {
        (self.first_byte & RESERVED_BITS_LONG_MASK) >> RESERVED_BITS_LONG_SHIFT
    }

    /// Sets the Reserved Bits (bits 3-2 of `first_byte`) for common Long Headers.
    /// `val` MUST be 0 for Initial, 0-RTT, Handshake packets in QUIC v1.
    ///
    /// # Parameters
    /// - `val` - The Reserved Bits value (0-3). Input is masked to 2 bits.
    #[inline]
    pub fn set_reserved_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !RESERVED_BITS_LONG_MASK)
            | ((val << RESERVED_BITS_LONG_SHIFT) & RESERVED_BITS_LONG_MASK);
    }

    /// Gets the Packet Number Length bits (bits 1-0 of `first_byte`) for common Long Headers.
    /// Encoded length (actual length - 1).
    ///
    /// # Returns
    /// The encoded Packet Number Length value (0-3). Valid for certain Long Header types.
    #[inline]
    pub fn pn_length_bits_long(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the Packet Number Length bits (bits 1-0 of `first_byte`) for common Long Headers.
    ///
    /// # Parameters
    /// - `val` - Encoded 2-bit value (0-3, for actual lengths 1-4 bytes). Masked to 2 bits.
    #[inline]
    pub fn set_pn_length_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    /// Gets actual Packet Number Length (bytes) for common Long Headers. (`pn_length_bits_long() + 1`).
    ///
    /// # Returns
    /// Actual Packet Number Length (1 to 4 bytes).
    #[inline]
    pub fn packet_number_length_long(&self) -> usize {
        (self.pn_length_bits_long() + 1) as usize
    }

    /// Sets Packet Number Length for common Long Headers, using actual length (1-4 bytes).
    /// Clamped if `len` is out of range.
    ///
    /// # Parameters
    /// - `len` - Actual length in bytes (1-4).
    #[inline]
    pub fn set_packet_number_length_long(&mut self, len: usize) {
        let encoded_val = match len {
            1 => 0b00,
            2 => 0b01,
            3 => 0b10,
            4 => 0b11,
            _ if len < 1 => 0b00,
            _ => 0b11,
        };
        self.set_pn_length_bits_long(encoded_val);
    }

    /// Gets the Spin Bit (bit 5 of `first_byte`). Assumes Short Header.
    ///
    /// # Returns
    /// `true` if Spin Bit is 1, `false` if 0. Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_spin_bit(&self) -> bool {
        (self.first_byte & SHORT_SPIN_BIT_MASK) != 0
    }

    /// Sets the Spin Bit (bit 5 of `first_byte`). Assumes Short Header.
    ///
    /// # Parameters
    /// - `spin` - Value for the Spin Bit (`true` for 1, `false` for 0).
    #[inline]
    pub fn set_short_spin_bit(&mut self, spin: bool) {
        if spin {
            self.first_byte |= SHORT_SPIN_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_SPIN_BIT_MASK;
        }
    }

    /// Gets the Reserved Bits (bits 4-3 of `first_byte`). Assumes Short Header.
    /// These bits MUST be 0 in QUIC v1.
    ///
    /// # Returns
    /// The value of the Reserved Bits (0-3). Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_reserved_bits(&self) -> u8 {
        (self.first_byte & SHORT_RESERVED_BITS_MASK) >> SHORT_RESERVED_BITS_SHIFT
    }

    /// Sets the Reserved Bits (bits 4-3 of `first_byte`). Assumes Short Header.
    /// These bits MUST be set to 0 (0b00) in QUIC v1. This method enforces this.
    ///
    /// # Parameters
    /// - `reserved` - The value for the Reserved Bits. If not 0, they will be set to 0.
    #[inline]
    pub fn set_short_reserved_bits(&mut self, _reserved: u8) {
        self.first_byte &= !SHORT_RESERVED_BITS_MASK;
    }

    /// Gets the Key Phase Bit (bit 2 of `first_byte`). Assumes Short Header.
    ///
    /// # Returns
    /// `true` if Key Phase Bit is 1, `false` if 0. Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_key_phase(&self) -> bool {
        (self.first_byte & SHORT_KEY_PHASE_BIT_MASK) != 0
    }

    /// Sets the Key Phase Bit (bit 2 of `first_byte`). Assumes Short Header.
    ///
    /// # Parameters
    /// - `key_phase` - Value for the Key Phase Bit (`true` for 1, `false` for 0).
    #[inline]
    pub fn set_short_key_phase(&mut self, key_phase: bool) {
        if key_phase {
            self.first_byte |= SHORT_KEY_PHASE_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_KEY_PHASE_BIT_MASK;
        }
    }

    /// Gets the Packet Number Length bits (bits 1-0 of `first_byte`). Assumes Short Header.
    /// Encoded length (actual length - 1).
    ///
    /// # Returns
    /// The encoded Packet Number Length value (0-3). Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_pn_length_bits(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the Packet Number Length bits (bits 1-0 of `first_byte`). Assumes Short Header.
    ///
    /// # Parameters
    /// - `val` - Encoded 2-bit value (0-3, for actual lengths 1-4 bytes). Masked to 2 bits.
    #[inline]
    pub fn set_short_pn_length_bits(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    /// Gets actual Packet Number Length (bytes) for Short Headers. (`short_pn_length_bits() + 1`).
    ///
    /// # Returns
    /// Actual Packet Number Length (1 to 4 bytes).
    #[inline]
    pub fn short_packet_number_length(&self) -> usize {
        (self.short_pn_length_bits() + 1) as usize
    }

    /// Sets Packet Number Length for Short Headers, using actual length (1-4 bytes).
    /// Clamped if `len` is out of range.
    ///
    /// # Parameters
    /// - `len` - Actual length in bytes (1-4).
    #[inline]
    pub fn set_short_packet_number_length(&mut self, len: usize) {
        let encoded_val = match len {
            1 => 0b00,
            2 => 0b01,
            3 => 0b10,
            4 => 0b11,
            _ if len < 1 => 0b00,
            _ => 0b11,
        };
        self.set_short_pn_length_bits(encoded_val);
    }

    /// Returns the QUIC version from the header (host byte order). Long Headers only.
    ///
    /// # Returns
    /// The QUIC version. Panics or returns garbage if called on a Short Header's `QuicHdr`.
    #[inline]
    pub fn version(&self) -> u32 {
        u32::from_be_bytes(self.version)
    }

    /// Sets the QUIC version in the header. `version` should be host byte order. Long Headers only.
    ///
    /// # Parameters
    /// - `version` - The QUIC version (host byte order).
    #[inline]
    pub fn set_version(&mut self, version: u32) {
        self.version = version.to_be_bytes();
    }

    /// Returns Destination Connection ID Length. For Long Headers, this is from the header.
    /// For Short Headers, this field in the struct is not from the wire's first byte.
    ///
    /// # Returns
    /// The DCID length.
    #[inline]
    pub fn dc_id_len(&self) -> u8 {
        self.dc_id_len
    }

    /// Sets Destination Connection ID Length.
    ///
    /// # Parameters
    /// - `len` - The new DCID length.
    #[inline]
    pub fn set_dc_id_len(&mut self, len: u8) {
        self.dc_id_len = len;
    }

    /// Returns Source Connection ID Length. Long Headers only.
    ///
    /// # Returns
    /// The SCID length.
    #[inline]
    pub fn sc_id_len(&self) -> u8 {
        self.sc_id_len
    }

    /// Sets Source Connection ID Length. Long Headers only.
    ///
    /// # Parameters
    /// - `len` - The new SCID length.
    #[inline]
    pub fn set_sc_id_len(&mut self, len: u8) {
        self.sc_id_len = len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_hdr_len() {
        assert_eq!(QuicHdr::LEN, 7, "QuicHdr::LEN should be 7 bytes");
    }

    #[test]
    fn test_quic_hdr_new_and_long_header_getters() {
        let version_val = 0x00000001;
        let dc_id_len_val = 8;
        let sc_id_len_val = 4;
        let pn_len_bits_val = 0b11;
        let hdr = QuicHdr::new(version_val, dc_id_len_val, sc_id_len_val, pn_len_bits_val);
        assert!(hdr.is_long_header());
        assert_eq!(
            hdr.fixed_bit(),
            1,
            "Fixed bit should be 1 for Initial packet"
        );
        assert_eq!(
            hdr.long_packet_type(),
            0b00,
            "Long Packet Type should be Initial (00)"
        );
        assert_eq!(hdr.reserved_bits_long(), 0b00, "Reserved bits should be 00");
        assert_eq!(hdr.pn_length_bits_long(), pn_len_bits_val);
        assert_eq!(
            hdr.packet_number_length_long(),
            (pn_len_bits_val + 1) as usize
        );
        let expected_first_byte = HEADER_FORM_BIT
            | FIXED_BIT_MASK
            | (0b00 << LONG_PACKET_TYPE_SHIFT)
            | (0b00 << RESERVED_BITS_LONG_SHIFT)
            | pn_len_bits_val;
        assert_eq!(
            hdr.first_byte(),
            expected_first_byte,
            "First byte construction for Long Header is incorrect"
        );
        assert_eq!(hdr.version(), version_val);
        assert_eq!(hdr.dc_id_len(), dc_id_len_val);
        assert_eq!(hdr.sc_id_len(), sc_id_len_val);
    }

    #[test]
    fn test_first_byte_setters_and_getters_for_long_header() {
        let mut hdr = QuicHdr::new(1, 0, 0, 0);
        hdr.set_header_form(false);
        assert!(!hdr.is_long_header());
        hdr.set_header_form(true);
        assert!(hdr.is_long_header());
        hdr.set_fixed_bit(0);
        assert_eq!(hdr.fixed_bit(), 0);
        hdr.set_fixed_bit(1);
        assert_eq!(hdr.fixed_bit(), 1);
        hdr.set_long_packet_type(0b01);
        assert_eq!(hdr.long_packet_type(), 0b01);
        hdr.set_reserved_bits_long(0b10);
        assert_eq!(hdr.reserved_bits_long(), 0b10);
        hdr.set_reserved_bits_long(0b00);
        hdr.set_pn_length_bits_long(0b01);
        assert_eq!(hdr.pn_length_bits_long(), 0b01);
        assert_eq!(hdr.packet_number_length_long(), 2);
        hdr.set_packet_number_length_long(4);
        assert_eq!(hdr.pn_length_bits_long(), 0b11);
        assert_eq!(hdr.packet_number_length_long(), 4);
        hdr.set_packet_number_length_long(0);
        assert_eq!(hdr.pn_length_bits_long(), 0b00);
        assert_eq!(hdr.packet_number_length_long(), 1);
        hdr.set_packet_number_length_long(5);
        assert_eq!(hdr.pn_length_bits_long(), 0b11);
        assert_eq!(hdr.packet_number_length_long(), 4);
    }

    #[test]
    fn test_multi_byte_field_getters_and_setters() {
        let mut hdr = QuicHdr::default();
        let test_version = 0x12345678;
        hdr.set_version(test_version);
        assert_eq!(hdr.version(), test_version);
        let test_dcid_len = 20;
        hdr.set_dc_id_len(test_dcid_len);
        assert_eq!(hdr.dc_id_len(), test_dcid_len);
        let test_scid_len = 0;
        hdr.set_sc_id_len(test_scid_len);
        assert_eq!(hdr.sc_id_len(), test_scid_len);
    }

    #[test]
    fn test_new_short_header_first_byte() {
        let fb1 = QuicHdr::new_short_header_first_byte(true, false, 0b01);
        assert_eq!(fb1, 0b01100001, "Expected 0x61");
        assert_eq!(
            (fb1 & HEADER_FORM_BIT),
            0,
            "Short header form bit incorrect"
        );
        assert_eq!(
            (fb1 & FIXED_BIT_MASK),
            FIXED_BIT_MASK,
            "Short header fixed bit incorrect"
        );
        assert_eq!(
            (fb1 & SHORT_SPIN_BIT_MASK) >> SHORT_SPIN_BIT_SHIFT,
            1,
            "Spin bit incorrect"
        );
        assert_eq!(
            (fb1 & SHORT_RESERVED_BITS_MASK),
            0,
            "Reserved bits not zero"
        );
        assert_eq!(
            (fb1 & SHORT_KEY_PHASE_BIT_MASK) >> SHORT_KEY_PHASE_BIT_SHIFT,
            0,
            "Key phase incorrect"
        );
        assert_eq!(
            (fb1 & PN_LENGTH_BITS_MASK),
            0b01,
            "PN length bits incorrect"
        );
        let fb2 = QuicHdr::new_short_header_first_byte(false, true, 0b11);
        assert_eq!(fb2, 0b01000111, "Expected 0x47");
        assert_eq!((fb2 & SHORT_SPIN_BIT_MASK) >> SHORT_SPIN_BIT_SHIFT, 0);
        assert_eq!(
            (fb2 & SHORT_KEY_PHASE_BIT_MASK) >> SHORT_KEY_PHASE_BIT_SHIFT,
            1
        );
        assert_eq!((fb2 & PN_LENGTH_BITS_MASK), 0b11);
    }

    #[test]
    fn test_short_header_setters_and_getters() {
        let mut hdr = QuicHdr::default();
        hdr.set_header_form(false);
        hdr.set_fixed_bit(1);
        hdr.set_short_spin_bit(true);
        assert!(hdr.short_spin_bit());
        assert_eq!(hdr.first_byte & SHORT_SPIN_BIT_MASK, SHORT_SPIN_BIT_MASK);
        hdr.set_short_spin_bit(false);
        assert!(!hdr.short_spin_bit());
        assert_eq!(hdr.first_byte & SHORT_SPIN_BIT_MASK, 0);
        hdr.first_byte |= SHORT_RESERVED_BITS_MASK;
        assert_eq!(hdr.short_reserved_bits(), 0b11);
        hdr.set_short_reserved_bits(0b10);
        assert_eq!(
            hdr.short_reserved_bits(),
            0b00,
            "Short reserved bits should be forced to 0"
        );
        assert_eq!(hdr.first_byte & SHORT_RESERVED_BITS_MASK, 0);
        hdr.set_short_key_phase(true);
        assert!(hdr.short_key_phase());
        assert_eq!(
            hdr.first_byte & SHORT_KEY_PHASE_BIT_MASK,
            SHORT_KEY_PHASE_BIT_MASK
        );
        hdr.set_short_key_phase(false);
        assert!(!hdr.short_key_phase());
        assert_eq!(hdr.first_byte & SHORT_KEY_PHASE_BIT_MASK, 0);
        hdr.set_short_pn_length_bits(0b10); // 3 bytes
        assert_eq!(hdr.short_pn_length_bits(), 0b10);
        assert_eq!(hdr.short_packet_number_length(), 3);
        hdr.set_short_packet_number_length(1);
        assert_eq!(hdr.short_pn_length_bits(), 0b00);
        assert_eq!(hdr.short_packet_number_length(), 1);
        hdr.set_short_packet_number_length(4);
        assert_eq!(hdr.short_pn_length_bits(), 0b11);
        assert_eq!(hdr.short_packet_number_length(), 4);
        hdr.set_short_packet_number_length(0);
        assert_eq!(hdr.short_pn_length_bits(), 0b00);
        assert_eq!(hdr.short_packet_number_length(), 1);
        hdr.set_short_packet_number_length(5);
        assert_eq!(hdr.short_pn_length_bits(), 0b11);
        assert_eq!(hdr.short_packet_number_length(), 4);
        hdr.set_header_form(false);
        hdr.set_fixed_bit(1);
        hdr.set_short_spin_bit(true);
        hdr.set_short_reserved_bits(0);
        hdr.set_short_key_phase(true);
        hdr.set_short_pn_length_bits(0b01);
        assert_eq!(
            hdr.first_byte(),
            0b01100101,
            "Constructed short header byte mismatch"
        );
    }

    #[test]
    fn test_raw_first_byte_combined_set_and_readback() {
        let mut hdr = QuicHdr::new(1, 0, 0, 0);
        // Construct first_byte: Long Header (1), Fixed (1), Type (Retry=11), Reserved (00), PN Len (2 bytes actual = 01 encoded)
        // Bit:   7  6  5  4  3  2  1  0
        // Value: 1  1  1  1  0  0  0  1  => 0xF1
        let first_byte_val = 0xF1;
        hdr.set_first_byte(first_byte_val);
        assert_eq!(hdr.first_byte(), first_byte_val);
        assert!(hdr.is_long_header());
        assert_eq!(hdr.fixed_bit(), 1);
        assert_eq!(hdr.long_packet_type(), 0b11);
        assert_eq!(hdr.reserved_bits_long(), 0b00);
        assert_eq!(hdr.pn_length_bits_long(), 0b01);
        assert_eq!(hdr.packet_number_length_long(), 2);
    }
}
