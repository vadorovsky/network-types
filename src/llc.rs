use core::mem;

/// Represents Logical Link Control according to ISO/IEC 8802-2 Definition
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LlcHdr {
    /// Destination SAP address
    pub dsap: u8,
    /// Source SAP address
    pub ssap: u8,
    /// Byte array for Control field.
    /// ctrl[0] is always used.
    /// ctrl[1] is used for I-format and S-format (16-bit control fields).
    /// For U-format (8-bit control field), ctrl[1] is not part of the logical control field.
    pub ctrl: [u8; 2],
}

/// Represents the type of LLC PDU based on its control field.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum LlcFrameType {
    I,       // Information
    S,       // Supervisory
    U,       // Unnumbered
    Invalid, // Should not happen with valid LLC frames
}

impl LlcHdr {
    pub const LEN: usize = mem::size_of::<LlcHdr>();

    /// Gets the 7-bit DSAP address part.
    #[inline]
    pub fn dsap_addr(&self) -> u8 {
        self.dsap >> 1
    }

    /// Checks if the DSAP I/G (Individual/Group) bit is set (Individual address).
    /// true if Individual address, false if Group address.
    #[inline]
    pub fn dsap_is_individual_addr(&self) -> bool {
        self.dsap & 0x01 == 0
    }

    /// Checks if the DSAP I/G (Individual/Group) bit is set (Group address).
    /// true if Group address, false if Individual address.
    #[inline]
    pub fn dsap_is_group_addr(&self) -> bool {
        self.dsap & 0x01 == 1
    }

    /// Sets the DSAP field.
    /// `addr` should be a 7-bit value.
    /// `is_group` sets the I/G bit.
    #[inline]
    pub fn set_dsap(&mut self, addr: u8, is_group: bool) {
        self.dsap = ((addr & 0x7F) << 1) | (is_group as u8);
    }

    /// Gets the 7-bit SSAP address part.
    #[inline]
    pub fn ssap_address(&self) -> u8 {
        self.ssap >> 1
    }

    /// Checks if the SSAP C/R (Command/Response) bit is set (Command PDU).
    /// Returns `true` if it's a Command PDU, `false` if it's a Response PDU.
    #[inline]
    pub fn ssap_is_command(&self) -> bool {
        self.ssap & 0x01 == 0
    }

    /// Checks if the SSAP C/R (Command/Response) bit is set (Response PDU).
    /// Returns `true` if it's a Response PDU, `false` if it's a Command PDU.
    #[inline]
    pub fn ssap_is_response(&self) -> bool {
        self.ssap & 0x01 == 1
    }

    /// Sets the SSAP field.
    /// `address` should be a 7-bit value.
    /// `is_response` sets the C/R bit.
    #[inline]
    pub fn set_ssap(&mut self, address: u8, is_response: bool) {
        self.ssap = ((address & 0x7F) << 1) | (is_response as u8);
    }

    /// Determines the LLC PDU frame type based on the control field's first byte.
    #[inline]
    pub fn frame_type(&self) -> LlcFrameType {
        let su = self.ctrl[0] & 0x03;
        if (self.ctrl[0] & 0x01) == 0x00 {
            LlcFrameType::I
        } else if (su) == 0x01 {
            LlcFrameType::S
        } else if (su) == 0x03 {
            LlcFrameType::U
        } else {
            LlcFrameType::Invalid // Should not be reachable if LLC frame is valid
        }
    }

    /// Returns true if the control field is I-format (16 bits).
    #[inline]
    pub fn is_i_format(&self) -> bool {
        self.frame_type() == LlcFrameType::I
    }

    /// Returns true if the control field is S-format (16 bits).
    #[inline]
    pub fn is_s_format(&self) -> bool {
        self.frame_type() == LlcFrameType::S
    }

    /// Returns true if the control field is U-format (8 bits).
    #[inline]
    pub fn is_u_format(&self) -> bool {
        self.frame_type() == LlcFrameType::U
    }

    /// Gets the raw value of the first byte of the control field.
    #[inline]
    pub fn control_byte0(&self) -> u8 {
        self.ctrl[0]
    }

    /// Gets the raw value of the second byte of the control field, if applicable.
    /// Returns Some(u8) for I-Frames and S-Frames, None for U-Frames or Invalid.
    #[inline]
    pub fn control_byte1(&self) -> Option<u8> {
        match self.frame_type() {
            LlcFrameType::I | LlcFrameType::S => Some(self.ctrl[1]),
            _ => None,
        }
    }
}

// --- Test Module ---
#[cfg(test)]
mod tests {
    use super::*;

    fn new_llc() -> LlcHdr {
        LlcHdr {
            dsap: 0,
            ssap: 0,
            ctrl: [0; 2],
        }
    }

    #[test]
    fn test_dsap_methods() {
        let mut llc = new_llc();

        // Test individual address
        llc.set_dsap(0x42, false); // Address 0x42 (66), Individual
        assert_eq!(llc.dsap_addr(), 0x42);
        assert!(!llc.dsap_is_group_addr());
        assert_eq!(llc.dsap, 0x42 << 1); // 0x84

        // Test group address
        llc.set_dsap(0x7F, true); // Max 7-bit address, Group
        assert_eq!(llc.dsap_addr(), 0x7F);
        assert!(llc.dsap_is_group_addr());
        assert_eq!(llc.dsap, (0x7F << 1) | 0x01); // 0xFF

        // Test setting with address larger than 7 bits (should be masked)
        llc.set_dsap(0xFF, false); // Address 0xFF (should become 0x7F), Individual
        assert_eq!(llc.dsap_addr(), 0x7F);
        assert!(!llc.dsap_is_group_addr());
        assert_eq!(llc.dsap, 0x7F << 1); // 0xFE
    }

    #[test]
    fn test_ssap_methods() {
        let mut llc = new_llc();

        // Test command PDU
        llc.set_ssap(0x3A, false); // Address 0x3A (58), Command
        assert_eq!(llc.ssap_address(), 0x3A);
        assert!(!llc.ssap_is_response());
        assert_eq!(llc.ssap, 0x3A << 1); // 0x74

        // Test response PDU
        llc.set_ssap(0x01, true); // Address 0x01, Response
        assert_eq!(llc.ssap_address(), 0x01);
        assert!(llc.ssap_is_response());
        assert_eq!(llc.ssap, (0x01 << 1) | 0x01); // 0x03

        // Test setting with address larger than 7 bits (should be masked)
        llc.set_ssap(0b10101010, true); // Address 0xAA (should become 0x2A), Response
        assert_eq!(llc.ssap_address(), 0x2A); // 0b0101010
        assert!(llc.ssap_is_response());
        assert_eq!(llc.ssap, (0x2A << 1) | 0x01); // 0x55
    }

    #[test]
    fn test_u_format_identification_and_bytes() {
        let mut llc = new_llc();
        llc.ctrl[0] = 0x03; // Typical UI frame (LSBs are 11)
        llc.ctrl[1] = 0xFF; // Should be ignored for U-format

        assert_eq!(llc.frame_type(), LlcFrameType::U);
        assert!(llc.is_u_format());
        assert!(!llc.is_i_format());
        assert!(!llc.is_s_format());
        assert_eq!(llc.control_byte0(), 0x03);
        assert_eq!(llc.control_byte1(), None); // ctrl[1] is not logically part of U-frame control

        llc.ctrl[0] = 0x6F; // (LSBs are 11)
        assert_eq!(llc.frame_type(), LlcFrameType::U);
        assert_eq!(llc.control_byte0(), 0x6F);
        assert_eq!(llc.control_byte1(), None);
    }

    #[test]
    fn test_i_format_identification_and_bytes() {
        let mut llc = new_llc();
        // I-frame: LSB of ctrl[0] is 0
        llc.ctrl[0] = 0x0A; // Example: (00001010)
        llc.ctrl[1] = 0x83; // Example: (10000011)

        assert_eq!(llc.frame_type(), LlcFrameType::I);
        assert!(llc.is_i_format());
        assert!(!llc.is_u_format());
        assert!(!llc.is_s_format());
        assert_eq!(llc.control_byte0(), 0x0A);
        assert_eq!(llc.control_byte1(), Some(0x83));

        llc.ctrl[0] = 0xFE; // Example: (1111111 -> 11111110)
        llc.ctrl[1] = 0x42; // Example: (0 1000010)
        assert_eq!(llc.frame_type(), LlcFrameType::I);
        assert_eq!(llc.control_byte0(), 0xFE);
        assert_eq!(llc.control_byte1(), Some(0x42));
    }

    #[test]
    fn test_s_format_identification_and_bytes() {
        let mut llc = new_llc();
        // S-frame: LSBs of ctrl[0] are 01
        llc.ctrl[0] = 0x01; // Example: 00000001
        llc.ctrl[1] = 0x07; // Example: (0 0000111)

        assert_eq!(llc.frame_type(), LlcFrameType::S);
        assert!(llc.is_s_format());
        assert!(!llc.is_u_format());
        assert!(!llc.is_i_format());
        assert_eq!(llc.control_byte0(), 0x01);
        assert_eq!(llc.control_byte1(), Some(0x07));

        llc.ctrl[0] = 0x0D; // LSBs 01 -> 00001101 is 0x0D
        llc.ctrl[0] = 0x09; // Example: 00001001 -> is 0x09
        llc.ctrl[1] = 0x00;
        assert_eq!(llc.frame_type(), LlcFrameType::S);
        assert_eq!(llc.control_byte0(), 0x09);
        assert_eq!(llc.control_byte1(), Some(0x00));
    }

    #[test]
    fn test_frame_type_priority() {
        // Test that I-frame (LSB=0) takes precedence if bits might also look like S/U
        let mut llc = new_llc();
        llc.ctrl[0] = 0b0000_0010; // LSB is 0 (I-Frame pattern)
        assert_eq!(llc.frame_type(), LlcFrameType::I);

        // LSBs 11 (U-Frame pattern)
        llc.ctrl[0] = 0b0000_0011;
        assert_eq!(llc.frame_type(), LlcFrameType::U);

        // LSBs 01 (S-Frame pattern)
        llc.ctrl[0] = 0b0000_0001;
        assert_eq!(llc.frame_type(), LlcFrameType::S);
    }

    #[test]
    fn test_len_constant() {
        // For a packed struct with 1 u8, 1 u8, and [u8; 2]
        assert_eq!(LlcHdr::LEN, 1 + 1 + 2);
        assert_eq!(LlcHdr::LEN, 4);
    }
}
