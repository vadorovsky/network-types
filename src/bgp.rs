// network-types/src/bgp.rs

/// Constants for BGP message types (from RFC 4271, Section 4.1)
pub const BGP_OPEN_MSG_TYPE: u8 = 1;
pub const BGP_UPDATE_MSG_TYPE: u8 = 2;
pub const BGP_NOTIFICATION_MSG_TYPE: u8 = 3;
pub const BGP_KEEPALIVE_MSG_TYPE: u8 = 4;

/// Represents a Border Gateway Protocol (BGP-4) header.
///
/// The BGP header is defined in RFC 4271, Section 4.1.
/// It has a fixed size of 19 octets.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpHdr {
    /// Marker: A 16-octet field. Included for compatibility, it MUST be set to all ones.
    pub marker: [u8; 16],
    /// Length: A 2-octet unsigned integer indicating the total length of the BGP
    /// message, including the header, in octets. The value MUST be at least 19
    /// (size of the BGP header) and no greater than 4096.
    pub length: [u8; 2],
    /// Type: A 1-octet unsigned integer indicating the message type.
    ///   - 1: OPEN
    ///   - 2: UPDATE
    ///   - 3: NOTIFICATION
    ///   - 4: KEEPALIVE
    pub msg_type: u8,
}

impl BgpHdr {
    /// The length of the BGP header in bytes (19 octets).
    pub const LEN: usize = core::mem::size_of::<BgpHdr>();

    /// Creates a new `BgpHdr` with the marker field set to all ones (as required by RFC 4271)
    /// and length and type fields initialized to zero.
    pub fn new() -> Self {
        BgpHdr {
            marker: [0xff; 16],
            length: [0, 0],
            msg_type: 0,
        }
    }

    /// Returns the marker field.
    /// This 16-octet field MUST be all ones.
    #[inline]
    pub fn marker(&self) -> [u8; 16] {
        self.marker
    }

    /// Sets the marker field to all ones, as required by RFC 4271.
    #[inline]
    pub fn set_marker_to_ones(&mut self) {
        self.marker = [0xff; 16];
    }

    /// Returns the total length of the BGP message (including header) in host byte order.
    /// The length is stored in network byte order.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    /// Sets the total length of the BGP message.
    /// `length` is in host byte order and will be stored in network byte order.
    /// The value MUST be between 19 and 4096, inclusive.
    #[inline]
    pub fn set_length(&mut self, length: u16) {
        self.length = length.to_be_bytes();
    }

    /// Returns the BGP message type.
    #[inline]
    pub fn msg_type(&self) -> u8 {
        self.msg_type
    }

    /// Sets the BGP message type.
    #[inline]
    pub fn set_type(&mut self, type_val: u8) {
        self.msg_type = type_val;
    }
}

impl Default for BgpHdr {
    /// Returns a default `BgpHdr` with the marker set to all ones,
    /// and length and type fields initialized to zero.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimum BGP message length (header only) as per RFC 4271.
    pub const BGP_MIN_MESSAGE_LEN: u16 = 19;
    /// Maximum BGP message length as per RFC 4271.
    pub const BGP_MAX_MESSAGE_LEN: u16 = 4096;

    #[test]
    fn test_bgphdr_len_constant() {
        assert_eq!(BgpHdr::LEN, 19, "BgpHdr::LEN should be 19.");
    }

    #[test]
    fn test_bgphdr_new_and_default() {
        let hdr_new = BgpHdr::new();
        let hdr_default = BgpHdr::default();
        let expected_marker = [0xff; 16];

        // Test `new()`
        assert_eq!(hdr_new.marker, expected_marker, "Marker in new() should be all ones.");
        assert_eq!(hdr_new.length(), 0, "Length in new() should be 0.");
        assert_eq!(hdr_new.msg_type(), 0, "Type in new() should be 0.");

        // Test `default()`
        assert_eq!(hdr_default.marker, expected_marker, "Marker in default() should be all ones.");
        assert_eq!(hdr_default.length(), 0, "Length in default() should be 0.");
        assert_eq!(hdr_default.msg_type(), 0, "Type in default() should be 0.");
    }

    #[test]
    fn test_bgphdr_marker_methods() {
        let mut hdr = BgpHdr::new();
        // Check initial marker
        assert_eq!(hdr.marker(), [0xff; 16], "Getter for marker should return all ones initially.");

        // Simulate marker being corrupted (if public field is directly changed)
        hdr.marker = [0xaa; 16];
        assert_ne!(hdr.marker(), [0xff; 16], "Marker was changed for test purpose.");

        // Use set_marker_to_ones to restore it
        hdr.set_marker_to_ones();
        assert_eq!(hdr.marker(), [0xff; 16], "set_marker_to_ones should restore marker to all ones.");
    }

    #[test]
    fn test_bgphdr_length_methods() {
        let mut hdr = BgpHdr::new();

        // Test initial length
        assert_eq!(hdr.length(), 0, "Initial length should be 0.");

        // Test set_length and length getter with min value
        hdr.set_length(BGP_MIN_MESSAGE_LEN);
        assert_eq!(hdr.length(), BGP_MIN_MESSAGE_LEN, "Length getter/setter failed for min value.");
        assert_eq!(hdr.length, BGP_MIN_MESSAGE_LEN.to_be_bytes(), "Length storage order is incorrect for min value."); // 19 -> [0x00, 0x13]

        // Test set_length and length getter with max value
        hdr.set_length(BGP_MAX_MESSAGE_LEN);
        assert_eq!(hdr.length(), BGP_MAX_MESSAGE_LEN, "Length getter/setter failed for max value.");
        assert_eq!(hdr.length, BGP_MAX_MESSAGE_LEN.to_be_bytes(), "Length storage order is incorrect for max value."); // 4096 -> [0x10, 0x00]

        // Test with an arbitrary value
        let arbitrary_length: u16 = 1234; // 0x04D2
        hdr.set_length(arbitrary_length);
        assert_eq!(hdr.length(), arbitrary_length, "Length getter/setter failed for arbitrary value.");
        assert_eq!(hdr.length, arbitrary_length.to_be_bytes(), "Length storage order is incorrect for arbitrary value.");
    }

    #[test]
    fn test_bgphdr_type_methods() {
        let mut hdr = BgpHdr::new();

        // Test initial type
        assert_eq!(hdr.msg_type(), 0, "Initial type should be 0.");

        // Test set_type and type_ getter for OPEN message
        hdr.set_type(BGP_OPEN_MSG_TYPE);
        assert_eq!(hdr.msg_type(), BGP_OPEN_MSG_TYPE, "Type getter/setter failed for OPEN.");
        assert_eq!(hdr.msg_type, 1, "Raw type_ field incorrect for OPEN.");

        // Test set_type and type_ getter for UPDATE message
        hdr.set_type(BGP_UPDATE_MSG_TYPE);
        assert_eq!(hdr.msg_type(), BGP_UPDATE_MSG_TYPE, "Type getter/setter failed for UPDATE.");
        assert_eq!(hdr.msg_type, 2, "Raw type_ field incorrect for UPDATE.");

        // Test set_type and type_ getter for NOTIFICATION message
        hdr.set_type(BGP_NOTIFICATION_MSG_TYPE);
        assert_eq!(hdr.msg_type(), BGP_NOTIFICATION_MSG_TYPE, "Type getter/setter failed for NOTIFICATION.");
        assert_eq!(hdr.msg_type, 3, "Raw type_ field incorrect for NOTIFICATION.");
        
        // Test set_type and type_ getter for KEEPALIVE message
        hdr.set_type(BGP_KEEPALIVE_MSG_TYPE);
        assert_eq!(hdr.msg_type(), BGP_KEEPALIVE_MSG_TYPE, "Type getter/setter failed for KEEPALIVE.");
        assert_eq!(hdr.msg_type, 4, "Raw type_ field incorrect for KEEPALIVE.");

        // Test with an arbitrary type value
        let arbitrary_type: u8 = 100;
        hdr.set_type(arbitrary_type);
        assert_eq!(hdr.msg_type(), arbitrary_type, "Type getter/setter failed for arbitrary type.");
        assert_eq!(hdr.msg_type, arbitrary_type, "Raw type_ field incorrect for arbitrary type.");
    }

    #[test]
    fn test_bgphdr_manual_construction_and_accessors() {
        let marker_val = [0xff; 16];
        let length_val: u16 = 256; // 0x0100
        let type_val = BGP_UPDATE_MSG_TYPE;

        // Construct manually (if fields are public)
        let mut hdr = BgpHdr {
            marker: marker_val,
            length: length_val.to_be_bytes(),
            msg_type: type_val,
        };

        // Check values using getters
        assert_eq!(hdr.marker(), marker_val);
        assert_eq!(hdr.length(), length_val);
        assert_eq!(hdr.msg_type(), type_val);

        // Modify using setters
        let new_length: u16 = 512; // 0x0200
        let new_type = BGP_KEEPALIVE_MSG_TYPE;
        
        hdr.set_length(new_length);
        hdr.set_type(new_type);
        // Ensure marker can be reset if it was somehow changed
        hdr.marker = [0x00; 16]; // Simulate accidental change
        hdr.set_marker_to_ones();

        assert_eq!(hdr.marker(), [0xff; 16]);
        assert_eq!(hdr.length(), new_length);
        assert_eq!(hdr.msg_type(), new_type);
    }
}