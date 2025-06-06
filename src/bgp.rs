// network-types/src/bgp.rs

use core::convert::TryInto;

/// Constants for BGP message types (from RFC 4271, Section 4.1 & RFC 2918)
pub const BGP_OPEN_MSG_TYPE: u8 = 1;
pub const BGP_UPDATE_MSG_TYPE: u8 = 2;
pub const BGP_NOTIFICATION_MSG_TYPE: u8 = 3;
pub const BGP_KEEPALIVE_MSG_TYPE: u8 = 4;
pub const BGP_ROUTE_REFRESH_MSG_TYPE: u8 = 5;

/// Represents the fixed part of a BGP OPEN message, following the common header.
/// Defined in RFC 4271, Section 4.2.
/// This struct is used as a schema for offsets and sizes.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct OpenMsgLayout {
    /// Version (1 octet): The protocol version number of BGP. Current version is 4.
    pub version: u8,
    /// My Autonomous System (2 octets): The AS number of the sender.
    pub my_as: [u8; 2],
    /// Hold Time (2 octets): The number of seconds the sender proposes for the Hold Timer.
    pub hold_time: [u8; 2],
    /// BGP Identifier (4 octets): An IP address assigned to the sender.
    pub bgp_id: [u8; 4],
    /// Optional Parameters Length (1 octet): Total length of the Optional Parameters field.
    pub opt_parm_len: u8,
}

impl OpenMsgLayout {
    /// Length of the fixed part of an OPEN message in bytes.
    pub const LEN: usize = 1 + 2 + 2 + 4 + 1; // 10
    const VERSION_OFFSET: usize = 0;
    const MY_AS_OFFSET: usize = 1;
    const HOLD_TIME_OFFSET: usize = 3;
    const BGP_ID_OFFSET: usize = 5;
    const OPT_PARM_LEN_OFFSET: usize = 9;
}

/// Represents the initial fixed part of a BGP UPDATE message.
/// Defined in RFC 4271, Section 4.3.
/// This struct is used as a schema for offsets and sizes.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct UpdateInitialMsgLayout {
    /// Withdrawn Routes Length (2 octets): Total length of the Withdrawn Routes field.
    pub withdrawn_routes_len: [u8; 2],
}

impl UpdateInitialMsgLayout {
    /// Length of the initial fixed part of an UPDATE message in bytes.
    pub const LEN: usize = 2;
    const WITHDRAWN_ROUTES_LEN_OFFSET: usize = 0;
}

/// Represents the fixed part of a BGP NOTIFICATION message.
/// Defined in RFC 4271, Section 4.5.
/// This struct is used as a schema for offsets and sizes.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotificationMsgLayout {
    /// Error Code (1 octet): Type of error.
    pub error_code: u8,
    /// Error Subcode (1 octet): More specific information about the error.
    pub error_subcode: u8,
}

impl NotificationMsgLayout {
    /// Length of the fixed part of a NOTIFICATION message in bytes.
    pub const LEN: usize = 1 + 1; // 2
    const ERROR_CODE_OFFSET: usize = 0;
    const ERROR_SUBCODE_OFFSET: usize = 1;
}

/// Represents the fixed part of a BGP ROUTE-REFRESH message.
/// Defined in RFC 2918, Section 3.
/// This struct is used as a schema for offsets and sizes.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct RouteRefreshMsgLayout {
    /// Address Family Identifier (AFI) (2 octets).
    pub afi: [u8; 2],
    /// Reserved (1 octet): Set to 0.
    pub res: u8,
    /// Subsequent Address Family Identifier (SAFI) (1 octet).
    pub safi: u8,
}

impl RouteRefreshMsgLayout {
    /// Length of the fixed part of a ROUTE-REFRESH message in bytes.
    pub const LEN: usize = 2 + 1 + 1; // 4
    const AFI_OFFSET: usize = 0;
    const RES_OFFSET: usize = 2;
    const SAFI_OFFSET: usize = 3;
}

/// Represents a Border Gateway Protocol (BGP-4) header and the initial fixed part of its payload.
#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BgpHdr {
    pub marker: [u8; 16],
    pub length: [u8; 2],
    pub msg_type: u8,
    /// Holds the bytes for the message-specific fixed payload.
    /// Its size is determined by the largest possible fixed payload (OpenMsgLayout::LEN).
    pub specific_payload_bytes: [u8; OpenMsgLayout::LEN],
}


impl BgpHdr {
    /// The length of the BGP common header part in bytes (19 octets).
    pub const COMMON_HDR_LEN: usize = 19;
    /// The length of the BGP header in bytes (19 octets).
    pub const LEN: usize = core::mem::size_of::<BgpHdr>();

    /// Creates a new `BgpHdr` with the marker field set to all ones (as required by RFC 4271)
    /// and length and type fields initialized to zero.
    pub fn new() -> Self {
        BgpHdr {
            marker: [0xff; 16],
            length: [0, 0],
            msg_type: 0,
            specific_payload_bytes: [0; OpenMsgLayout::LEN],
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
    pub fn set_msg_type(&mut self, type_val: u8) {
        self.msg_type = type_val;
    }

    // --- OPEN Message Methods ---

    pub fn open_version(&self) -> Option<u8> {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            Some(self.specific_payload_bytes[OpenMsgLayout::VERSION_OFFSET])
        } else {
            None
        }
    }

    pub fn set_open_version(&mut self, version: u8) -> bool {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            self.specific_payload_bytes[OpenMsgLayout::VERSION_OFFSET] = version;
            true
        } else {
            false
        }
    }

    pub fn open_my_as(&self) -> Option<u16> {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            let bytes: [u8; 2] = self.specific_payload_bytes
                [OpenMsgLayout::MY_AS_OFFSET..OpenMsgLayout::MY_AS_OFFSET + 2]
                .try_into().ok()?;
            Some(u16::from_be_bytes(bytes))
        } else {
            None
        }
    }

    pub fn set_open_my_as(&mut self, my_as: u16) -> bool {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            self.specific_payload_bytes
                [OpenMsgLayout::MY_AS_OFFSET..OpenMsgLayout::MY_AS_OFFSET + 2]
                .copy_from_slice(&my_as.to_be_bytes());
            true
        } else {
            false
        }
    }

    pub fn open_hold_time(&self) -> Option<u16> {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            let bytes: [u8; 2] = self.specific_payload_bytes
                [OpenMsgLayout::HOLD_TIME_OFFSET..OpenMsgLayout::HOLD_TIME_OFFSET + 2]
                .try_into().ok()?;
            Some(u16::from_be_bytes(bytes))
        } else {
            None
        }
    }

    pub fn set_open_hold_time(&mut self, hold_time: u16) -> bool {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            self.specific_payload_bytes
                [OpenMsgLayout::HOLD_TIME_OFFSET..OpenMsgLayout::HOLD_TIME_OFFSET + 2]
                .copy_from_slice(&hold_time.to_be_bytes());
            true
        } else {
            false
        }
    }

    pub fn open_bgp_id(&self) -> Option<u32> {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            let bytes: [u8; 4] = self.specific_payload_bytes
                [OpenMsgLayout::BGP_ID_OFFSET..OpenMsgLayout::BGP_ID_OFFSET + 4]
                .try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        } else {
            None
        }
    }

    pub fn set_open_bgp_id(&mut self, bgp_id: u32) -> bool {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            self.specific_payload_bytes
                [OpenMsgLayout::BGP_ID_OFFSET..OpenMsgLayout::BGP_ID_OFFSET + 4]
                .copy_from_slice(&bgp_id.to_be_bytes());
            true
        } else {
            false
        }
    }

    pub fn open_opt_parm_len(&self) -> Option<u8> {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            Some(self.specific_payload_bytes[OpenMsgLayout::OPT_PARM_LEN_OFFSET])
        } else {
            None
        }
    }

    pub fn set_open_opt_parm_len(&mut self, len: u8) -> bool {
        if self.msg_type == BGP_OPEN_MSG_TYPE {
            self.specific_payload_bytes[OpenMsgLayout::OPT_PARM_LEN_OFFSET] = len;
            true
        } else {
            false
        }
    }

    // --- UPDATE Message Methods ---

    pub fn update_withdrawn_routes_len(&self) -> Option<u16> {
        if self.msg_type == BGP_UPDATE_MSG_TYPE {
            let bytes: [u8; 2] = self.specific_payload_bytes
                [UpdateInitialMsgLayout::WITHDRAWN_ROUTES_LEN_OFFSET..UpdateInitialMsgLayout::WITHDRAWN_ROUTES_LEN_OFFSET + 2]
                .try_into().ok()?;
            Some(u16::from_be_bytes(bytes))
        } else {
            None
        }
    }

    pub fn set_update_withdrawn_routes_len(&mut self, len: u16) -> bool {
        if self.msg_type == BGP_UPDATE_MSG_TYPE {
            self.specific_payload_bytes
                [UpdateInitialMsgLayout::WITHDRAWN_ROUTES_LEN_OFFSET..UpdateInitialMsgLayout::WITHDRAWN_ROUTES_LEN_OFFSET + 2]
                .copy_from_slice(&len.to_be_bytes());
            true
        } else {
            false
        }
    }

    pub fn update_total_path_attr_len(&self, message_bytes: &[u8]) -> Option<u16> {
        if self.msg_type != BGP_UPDATE_MSG_TYPE {
            return None;
        }
        let wrl_field_end_offset = Self::COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN;
        if message_bytes.len() < wrl_field_end_offset {
            return None;
        }
        let wrl_bytes: [u8; 2] = message_bytes
            [Self::COMMON_HDR_LEN..wrl_field_end_offset]
            .try_into().ok()?;
        let wrl_val = u16::from_be_bytes(wrl_bytes);

        let tpal_offset = wrl_field_end_offset + (wrl_val as usize);
        if message_bytes.len() < tpal_offset + 2 {
            return None;
        }
        let tpal_bytes: [u8; 2] = message_bytes[tpal_offset..tpal_offset + 2]
            .try_into().ok()?;
        Some(u16::from_be_bytes(tpal_bytes))
    }

    pub fn set_update_total_path_attr_len(
        &self, // Used only to check msg_type
        message_bytes: &mut [u8],
        tpal_val: u16,
    ) -> bool {
        if self.msg_type != BGP_UPDATE_MSG_TYPE {
            return false;
        }
        let wrl_field_end_offset = Self::COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN;
        if message_bytes.len() < wrl_field_end_offset {
            return false;
        }
        let wrl_bytes_slice = &message_bytes[Self::COMMON_HDR_LEN..wrl_field_end_offset];
        let wrl_bytes: [u8; 2] = match wrl_bytes_slice.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let wrl_val = u16::from_be_bytes(wrl_bytes);

        let tpal_offset = wrl_field_end_offset + (wrl_val as usize);
        if message_bytes.len() < tpal_offset + 2 {
            return false;
        }
        message_bytes[tpal_offset..tpal_offset + 2].copy_from_slice(&tpal_val.to_be_bytes());
        true
    }

    // --- NOTIFICATION Message Methods ---

    pub fn notification_error_code(&self) -> Option<u8> {
        if self.msg_type == BGP_NOTIFICATION_MSG_TYPE {
            Some(self.specific_payload_bytes[NotificationMsgLayout::ERROR_CODE_OFFSET])
        } else {
            None
        }
    }

    pub fn set_notification_error_code(&mut self, code: u8) -> bool {
        if self.msg_type == BGP_NOTIFICATION_MSG_TYPE {
            self.specific_payload_bytes[NotificationMsgLayout::ERROR_CODE_OFFSET] = code;
            true
        } else {
            false
        }
    }

    pub fn notification_error_subcode(&self) -> Option<u8> {
        if self.msg_type == BGP_NOTIFICATION_MSG_TYPE {
            Some(self.specific_payload_bytes[NotificationMsgLayout::ERROR_SUBCODE_OFFSET])
        } else {
            None
        }
    }

    pub fn set_notification_error_subcode(&mut self, subcode: u8) -> bool {
        if self.msg_type == BGP_NOTIFICATION_MSG_TYPE {
            self.specific_payload_bytes[NotificationMsgLayout::ERROR_SUBCODE_OFFSET] = subcode;
            true
        } else {
            false
        }
    }

    // --- ROUTE-REFRESH Message Methods ---

    pub fn route_refresh_afi(&self) -> Option<u16> {
        if self.msg_type == BGP_ROUTE_REFRESH_MSG_TYPE {
            let bytes: [u8; 2] = self.specific_payload_bytes
                [RouteRefreshMsgLayout::AFI_OFFSET..RouteRefreshMsgLayout::AFI_OFFSET + 2]
                .try_into().ok()?;
            Some(u16::from_be_bytes(bytes))
        } else {
            None
        }
    }

    pub fn set_route_refresh_afi(&mut self, afi: u16) -> bool {
        if self.msg_type == BGP_ROUTE_REFRESH_MSG_TYPE {
            self.specific_payload_bytes
                [RouteRefreshMsgLayout::AFI_OFFSET..RouteRefreshMsgLayout::AFI_OFFSET + 2]
                .copy_from_slice(&afi.to_be_bytes());
            true
        } else {
            false
        }
    }

    pub fn route_refresh_res(&self) -> Option<u8> {
        if self.msg_type == BGP_ROUTE_REFRESH_MSG_TYPE {
            Some(self.specific_payload_bytes[RouteRefreshMsgLayout::RES_OFFSET])
        } else {
            None
        }
    }

    pub fn set_route_refresh_res(&mut self, res: u8) -> bool {
        if self.msg_type == BGP_ROUTE_REFRESH_MSG_TYPE {
            self.specific_payload_bytes[RouteRefreshMsgLayout::RES_OFFSET] = res;
            true
        } else {
            false
        }
    }

    pub fn route_refresh_safi(&self) -> Option<u8> {
        if self.msg_type == BGP_ROUTE_REFRESH_MSG_TYPE {
            Some(self.specific_payload_bytes[RouteRefreshMsgLayout::SAFI_OFFSET])
        } else {
            None
        }
    }

    pub fn set_route_refresh_safi(&mut self, safi: u8) -> bool {
        if self.msg_type == BGP_ROUTE_REFRESH_MSG_TYPE {
            self.specific_payload_bytes[RouteRefreshMsgLayout::SAFI_OFFSET] = safi;
            true
        } else {
            false
        }
    }
}

impl Default for BgpHdr {
    /// Returns a default `BgpHdr` with the marker set to all ones,
    /// and length and type fields initialized to zero.
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for BgpHdr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("BgpHdr");
        debug_struct.field("marker", &self.marker);
        debug_struct.field("length", &self.length());
        debug_struct.field("msg_type", &self.msg_type);

        match self.msg_type {
            BGP_OPEN_MSG_TYPE => {
                debug_struct.field("open_version", &self.open_version());
                debug_struct.field("open_my_as", &self.open_my_as());
                debug_struct.field("open_hold_time", &self.open_hold_time());
                debug_struct.field("open_bgp_id", &self.open_bgp_id());
                debug_struct.field("open_opt_parm_len", &self.open_opt_parm_len());
            }
            BGP_UPDATE_MSG_TYPE => {
                debug_struct.field("update_withdrawn_routes_len", &self.update_withdrawn_routes_len());
                // TPAL cannot be displayed without the full message buffer
                debug_struct.field("total_path_attribute_len", &"<Requires full message bytes>");
            }
            BGP_NOTIFICATION_MSG_TYPE => {
                debug_struct.field("notification_error_code", &self.notification_error_code());
                debug_struct.field("notification_error_subcode", &self.notification_error_subcode());
            }
            BGP_ROUTE_REFRESH_MSG_TYPE => {
                debug_struct.field("route_refresh_afi", &self.route_refresh_afi());
                debug_struct.field("route_refresh_res", &self.route_refresh_res());
                debug_struct.field("route_refresh_safi", &self.route_refresh_safi());
            }
            BGP_KEEPALIVE_MSG_TYPE => {
                debug_struct.field("specific_payload", &"<KeepAlive>");
            }
            _ => {
                // For unknown types, show the raw bytes of the specific_payload if it's small enough
                // or a placeholder if it's too large to be useful in a debug string.
                // Here, we just show a fixed number of bytes or a summary.
                const MAX_BYTES_TO_SHOW: usize = 4;
                if self.specific_payload_bytes.len() <= MAX_BYTES_TO_SHOW {
                    debug_struct.field("specific_payload_bytes", &self.specific_payload_bytes);
                } else {
                    let mut truncated_payload = [0u8; MAX_BYTES_TO_SHOW];
                    truncated_payload.copy_from_slice(&self.specific_payload_bytes[..MAX_BYTES_TO_SHOW]);
                    debug_struct.field("specific_payload_bytes_truncated", &truncated_payload)
                        .field("specific_payload_total_len", &self.specific_payload_bytes.len());
                }
            }
        }
        debug_struct.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    pub const BGP_MIN_MESSAGE_LEN: u16 = 19;
    pub const BGP_MAX_MESSAGE_LEN: u16 = 4096;

    #[test]
    fn test_layout_struct_sizes() {
        assert_eq!(OpenMsgLayout::LEN, 10);
        assert_eq!(UpdateInitialMsgLayout::LEN, 2);
        assert_eq!(NotificationMsgLayout::LEN, 2);
        assert_eq!(RouteRefreshMsgLayout::LEN, 4);
    }

    #[test]
    fn test_bgphdr_len_constants() {
        assert_eq!(BgpHdr::COMMON_HDR_LEN, 19);
        assert_eq!(BgpHdr::LEN, 29); // 19 (common) + 10 (OpenMsgLayout::LEN)
    }

    #[test]
    fn test_bgphdr_new_and_default() {
        let hdr_new = BgpHdr::new();
        let hdr_default = BgpHdr::default();
        let expected_marker = [0xff; 16];

        assert_eq!(hdr_new.marker, expected_marker);
        assert_eq!(hdr_new.length(), 0);
        assert_eq!(hdr_new.msg_type(), 0);
        assert_eq!(hdr_new.specific_payload_bytes, [0; OpenMsgLayout::LEN]);

        assert_eq!(hdr_default.marker, expected_marker);
        assert_eq!(hdr_default.length(), 0);
        assert_eq!(hdr_default.msg_type(), 0);
        assert_eq!(hdr_default.specific_payload_bytes, [0; OpenMsgLayout::LEN]);
    }

    #[test]
    fn test_bgphdr_common_fields_methods() {
        let mut hdr = BgpHdr::new();
        hdr.set_marker_to_ones();
        assert_eq!(hdr.marker(), [0xff; 16]);

        hdr.set_length(123);
        assert_eq!(hdr.length(), 123);

        hdr.set_msg_type(BGP_KEEPALIVE_MSG_TYPE);
        assert_eq!(hdr.msg_type(), BGP_KEEPALIVE_MSG_TYPE);
    }

    #[test]
    fn test_open_msg_fields() {
        let mut hdr = BgpHdr::new();
        hdr.set_msg_type(BGP_OPEN_MSG_TYPE);

        assert!(hdr.set_open_version(4));
        assert_eq!(hdr.open_version(), Some(4));

        assert!(hdr.set_open_my_as(65000));
        assert_eq!(hdr.open_my_as(), Some(65000));

        assert!(hdr.set_open_hold_time(180));
        assert_eq!(hdr.open_hold_time(), Some(180));

        let bgp_id_val = u32::from_be_bytes([192, 168, 1, 1]);
        assert!(hdr.set_open_bgp_id(bgp_id_val));
        assert_eq!(hdr.open_bgp_id(), Some(bgp_id_val));

        assert!(hdr.set_open_opt_parm_len(0));
        assert_eq!(hdr.open_opt_parm_len(), Some(0));

        // Test raw bytes
        assert_eq!(hdr.specific_payload_bytes[OpenMsgLayout::VERSION_OFFSET], 4);
        assert_eq!(&hdr.specific_payload_bytes[OpenMsgLayout::MY_AS_OFFSET..OpenMsgLayout::MY_AS_OFFSET+2], &65000u16.to_be_bytes());

        // Test wrong type access
        hdr.set_msg_type(BGP_UPDATE_MSG_TYPE);
        assert_eq!(hdr.open_version(), None);
        assert!(!hdr.set_open_version(4)); // Should return false
    }

    /*
    #[test]
    fn test_update_msg_fields() {
        let mut hdr = BgpHdr::new();
        hdr.set_msg_type(BGP_UPDATE_MSG_TYPE);

        assert!(hdr.set_update_withdrawn_routes_len(10));
        assert_eq!(hdr.update_withdrawn_routes_len(), Some(10));
        assert_eq!(&hdr.specific_payload_bytes[..UpdateInitialMsgLayout::LEN], &10u16.to_be_bytes());


        let mut msg_bytes = [0u8; 64];
        // Initialize common header part of msg_bytes
        msg_bytes[..BgpHdr::COMMON_HDR_LEN].copy_from_slice(&hdr.marker); // marker
        msg_bytes[16..18].copy_from_slice(&hdr.length); // length
        msg_bytes[18] = hdr.msg_type; // msg_type

        // Set withdrawn_routes_len to 4 in msg_bytes for testing TPAL
        let wrl_val: u16 = 4;
        msg_bytes[BgpHdr::COMMON_HDR_LEN..BgpHdr::COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN].copy_from_slice(&wrl_val.to_be_bytes());


        let tpal_offset = BgpHdr::COMMON_HDR_LEN + UpdateInitialMsgLayout::LEN + (wrl_val as usize);
        let tpal_val: u16 = 20;
        msg_bytes[tpal_offset..tpal_offset + 2].copy_from_slice(&tpal_val.to_be_bytes());

        // Use `hdr` (which has msg_type set to UPDATE) to call the method
        assert_eq!(hdr.update_total_path_attr_len(&msg_bytes), Some(tpal_val));

        let new_tpal_val: u16 = 30;
        assert!(hdr.set_update_total_path_attr_len(&mut msg_bytes, new_tpal_val));
        assert_eq!(hdr.update_total_path_attr_len(&msg_bytes), Some(new_tpal_val));

        let short_msg_bytes = &msg_bytes[0..tpal_offset + 1]; // too short
        assert_eq!(hdr.update_total_path_attr_len(short_msg_bytes), None);

        let mut short_msg_bytes_mut = msg_bytes[0..tpal_offset+1].to_vec();
        assert!(!hdr.set_update_total_path_attr_len(&mut short_msg_bytes_mut, 50));


        hdr.set_msg_type(BGP_OPEN_MSG_TYPE); // Change type of hdr
        assert_eq!(hdr.update_withdrawn_routes_len(), None);
        assert!(!hdr.set_update_withdrawn_routes_len(10));
        assert_eq!(hdr.update_total_path_attr_len(&msg_bytes), None); // Checks hdr.msg_type
        assert!(!hdr.set_update_total_path_attr_len(&mut msg_bytes, 10)); // Checks hdr.msg_type
    }
    
     */

    #[test]
    fn test_notification_msg_fields() {
        let mut hdr = BgpHdr::new();
        hdr.set_msg_type(BGP_NOTIFICATION_MSG_TYPE);

        assert!(hdr.set_notification_error_code(1));
        assert_eq!(hdr.notification_error_code(), Some(1));

        assert!(hdr.set_notification_error_subcode(2));
        assert_eq!(hdr.notification_error_subcode(), Some(2));

        assert_eq!(hdr.specific_payload_bytes[NotificationMsgLayout::ERROR_CODE_OFFSET], 1);
        assert_eq!(hdr.specific_payload_bytes[NotificationMsgLayout::ERROR_SUBCODE_OFFSET], 2);

        hdr.set_msg_type(BGP_OPEN_MSG_TYPE);
        assert_eq!(hdr.notification_error_code(), None);
        assert!(!hdr.set_notification_error_code(1));
    }

    #[test]
    fn test_route_refresh_msg_fields() {
        let mut hdr = BgpHdr::new();
        hdr.set_msg_type(BGP_ROUTE_REFRESH_MSG_TYPE);

        assert!(hdr.set_route_refresh_afi(1));
        assert_eq!(hdr.route_refresh_afi(), Some(1));

        assert!(hdr.set_route_refresh_res(0));
        assert_eq!(hdr.route_refresh_res(), Some(0));

        assert!(hdr.set_route_refresh_safi(1));
        assert_eq!(hdr.route_refresh_safi(), Some(1));

        assert_eq!(&hdr.specific_payload_bytes[RouteRefreshMsgLayout::AFI_OFFSET..RouteRefreshMsgLayout::AFI_OFFSET+2], &1u16.to_be_bytes());
        assert_eq!(hdr.specific_payload_bytes[RouteRefreshMsgLayout::RES_OFFSET], 0);
        assert_eq!(hdr.specific_payload_bytes[RouteRefreshMsgLayout::SAFI_OFFSET], 1);

        hdr.set_msg_type(BGP_OPEN_MSG_TYPE);
        assert_eq!(hdr.route_refresh_afi(), None);
        assert!(!hdr.set_route_refresh_afi(1));
    }

    #[test]
    fn test_keepalive_msg_no_specific_fields() {
        let mut hdr = BgpHdr::new();
        hdr.set_msg_type(BGP_KEEPALIVE_MSG_TYPE);
        hdr.set_length(BgpHdr::COMMON_HDR_LEN as u16);

        assert_eq!(hdr.open_version(), None);
        // ... and other specific getters
    }

    // Dummy structure and implementation for testing Debug output character by character
    // This is a simplified way to capture debug output in no_std without allocation.
    struct DebugCapture {
        buf: [u8; 256], // Fixed size buffer to capture output
        len: usize,
    }

    impl DebugCapture {
        fn new() -> Self {
            DebugCapture { buf: [0; 256], len: 0 }
        }
        fn as_str(&self) -> Option<&str> {
            core::str::from_utf8(&self.buf[..self.len]).ok()
        }
    }

    impl core::fmt::Write for DebugCapture {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let remaining_cap = self.buf.len() - self.len;
            let bytes_to_copy = if bytes.len() > remaining_cap { remaining_cap } else { bytes.len() };
            if bytes_to_copy > 0 {
                self.buf[self.len..self.len + bytes_to_copy].copy_from_slice(&bytes[..bytes_to_copy]);
                self.len += bytes_to_copy;
            }
            if bytes_to_copy < bytes.len() {
                Err(core::fmt::Error) // Buffer full
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

    /*
    #[test]
    fn test_debug_output_various_types() {
        let mut hdr = BgpHdr::new();

        hdr.set_msg_type(BGP_OPEN_MSG_TYPE);
        hdr.set_open_version(4);
        hdr.set_open_my_as(65001);
        assert!(custom_debug_contains(&hdr, "open_version: Some(4)"));
        assert!(custom_debug_contains(&hdr, "open_my_as: Some(65001)"));


        hdr.set_msg_type(BGP_UPDATE_MSG_TYPE);
        hdr.set_update_withdrawn_routes_len(0);
        assert!(custom_debug_contains(&hdr, "update_withdrawn_routes_len: Some(0)"));
        assert!(custom_debug_contains(&hdr, "total_path_attribute_len: \"<Requires full message bytes>\""));


        hdr.set_msg_type(BGP_NOTIFICATION_MSG_TYPE);
        hdr.set_notification_error_code(6);
        hdr.set_notification_error_subcode(1);
        assert!(custom_debug_contains(&hdr, "notification_error_code: Some(6)"));
        assert!(custom_debug_contains(&hdr, "notification_error_subcode: Some(1)"));


        hdr.set_msg_type(BGP_ROUTE_REFRESH_MSG_TYPE);
        hdr.set_route_refresh_afi(2);
        hdr.set_route_refresh_safi(128);
        assert!(custom_debug_contains(&hdr, "route_refresh_afi: Some(2)"));
        assert!(custom_debug_contains(&hdr, "route_refresh_safi: Some(128)"));


        hdr.set_msg_type(BGP_KEEPALIVE_MSG_TYPE);
        assert!(custom_debug_contains(&hdr, "specific_payload: \"<KeepAlive>\""));

        hdr.set_msg_type(99); // Unknown type
        // Check that the debug output contains a representation of the raw bytes or a summary
        // The exact string depends on the Debug impl for unknown types (truncated or full array)
        assert!(custom_debug_contains(&hdr, "specific_payload_bytes_truncated: [0, 0, 0, 0]"));
        assert!(custom_debug_contains(&hdr, "specific_payload_total_len: 10"));
    }
   
     */
}