use core::mem;

/// Represents the OSPF Version 2 (OSPFv2) packet header, according to RFC 2328.
/// This struct is designed to match the on-wire format of an OSPFv2 header.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]

pub struct OspfV2Hdr {
    /// OSPF protocol version (e.g., 2 for OSPFv2).
    pub version: u8,
    /// Type of the OSPF packet (e.g., Hello, DB Description, LS Request).
    pub type_: u8,
    /// Total length of the OSPF packet, including the header, in bytes.
    pub len: [u8; 2],
    /// The Router ID of the packet's sender.
    pub router_id: [u8; 4],
    /// The Area ID of the packet's origin.
    pub area_id: [u8; 4],
    /// Standard IP checksum of the entire OSPF packet.
    pub checksum: [u8; 2],
    /// Authentication type (e.g., 0 for Null, 1 for Simple Password, 2 for MD5).
    pub au_type: [u8; 2],
    /// Authentication data. The content varies based on `au_type`.
    /// For Null authentication, this field is zeroed.
    pub authentication: [u8; 8]
}


impl OspfV2Hdr {
    /// The fixed length of the OSPFv2 header in bytes.
    pub const LEN: usize = mem::size_of::<OspfV2Hdr>();

    /// Returns the OSPF version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the OSPF version field.
    ///
    /// # Arguments
    ///
    /// * `version_value` - The value to set for the version field.
    #[inline]
    pub fn set_version(&mut self, version_value: u8) {
        self.version = version_value;
    }

    /// Returns the OSPF packet type field.
    #[inline]
    pub fn type_(&self) -> u8 {
        self.type_
    }

    /// Sets the OSPF packet type field.
    ///
    /// # Arguments
    ///
    /// * `type_value` - The value to set for the type field.
    #[inline]
    pub fn set_type_(&mut self, type_value: u8) {
        self.type_ = type_value
    }

    /// Returns the total length of the OSPF packet in host byte order.
    #[inline]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }

    /// Sets the total length of the OSPF packet, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `len_value` - The length value to set.
    #[inline]
    pub fn set_len(&mut self, len_value: u16) {
        self.len = len_value.to_be_bytes();
    }

    /// Returns the Router ID in host byte order.
    #[inline]
    pub fn router_id(&self) -> u32 {
        u32::from_be_bytes(self.router_id)
    }

    /// Sets the Router ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `router_id_value` - The Router ID value to set.
    #[inline]
    pub fn set_router_id(&mut self, router_id_value: u32) {
        self.router_id = router_id_value.to_be_bytes()
    }

    /// Returns the Area ID in host byte order.
    #[inline]
    pub fn area_id(&self) -> u32 {
        u32::from_be_bytes(self.area_id)
    }

    /// Sets the Area ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `area_id_value` - The Area ID value to set.
    #[inline]
    pub fn set_area_id(&mut self, area_id_value: u32) {
        self.area_id = area_id_value.to_be_bytes()
    }

    /// Returns the checksum in host byte order.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the checksum, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `checksum_value` - The checksum value to set.
    #[inline]
    pub fn set_checksum(&mut self, checksum_value: u16) {
        self.checksum = checksum_value.to_be_bytes();
    }

    /// Returns the authentication type in host byte order.
    #[inline]
    pub fn au_type(&self) -> u16 {
        u16::from_be_bytes(self.au_type)
    }

    /// Sets the authentication type, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `au_type_value` - The authentication type value to set.
    #[inline]
    pub fn set_au_type(&mut self, au_type_value: u16) {
        self.au_type = au_type_value.to_be_bytes();
    }

    /// Returns the authentication data.
    #[inline]
    pub fn authentication(&self) -> [u8; 8] {
        self.authentication
    }

    /// Sets the authentication data.
    ///
    /// # Arguments
    ///
    /// * `value` - The 8-byte array of authentication data.
    #[inline]
    pub fn set_authentication(&mut self, value: [u8; 8]) {
        self.authentication = value;
    }
}

/// Represents the OSPF Version 3 (OSPFv3) packet header, according to RFC 5340.
/// This struct is designed to match the on-wire format of an OSPFv3 header.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]

pub struct OspfV3Hdr {
    /// OSPF protocol version (e.g., 3 for OSPFv3).
    pub version: u8,
    /// Type of the OSPF packet (e.g., Hello, DB Description, LS Request).
    pub type_: u8,
    /// Total length of the OSPF packet, including the header, in bytes.
    pub len: [u8; 2],
    /// The Router ID of the packet's sender.
    pub router_id: [u8; 4],
    /// The Area ID of the packet's origin.
    pub area_id: [u8; 4],
    /// Standard IP checksum of the entire OSPF packet.
    pub checksum: [u8; 2],
    /// Instance ID for OSPFv3, allowing multiple OSPF processes on the same link.
    pub instance_id: u8,
    /// Reserved field. As per RFC 5340, Section A.3.1, this field MUST be set to 0.
    pub reserved: u8,
}


impl OspfV3Hdr {
    /// The fixed length of the OSPFv3 header in bytes.
    pub const LEN: usize = mem::size_of::<OspfV3Hdr>();

    /// Returns the OSPF version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the OSPF version field.
    ///
    /// # Arguments
    ///
    /// * `version_value` - The value to set for the version field.
    #[inline]
    pub fn set_version(&mut self, version_value: u8) {
        self.version = version_value;
    }

    /// Returns the OSPF packet type field.
    #[inline]
    pub fn type_(&self) -> u8 {
        self.type_
    }

    /// Sets the OSPF packet type field.
    ///
    /// # Arguments
    ///
    /// * `type_value` - The value to set for the type field.
    #[inline]
    pub fn set_type_(&mut self, type_value: u8) {
        self.type_ = type_value
    }

    /// Returns the total length of the OSPF packet in host byte order.
    #[inline]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }

    /// Sets the total length of the OSPF packet, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `len_value` - The length value to set.
    #[inline]
    pub fn set_len(&mut self, len_value: u16) {
        self.len = len_value.to_be_bytes();
    }

    /// Returns the Router ID in host byte order.
    #[inline]
    pub fn router_id(&self) -> u32 {
        u32::from_be_bytes(self.router_id)
    }

    /// Sets the Router ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `router_id_value` - The Router ID value to set.
    #[inline]
    pub fn set_router_id(&mut self, router_id_value: u32) {
        self.router_id = router_id_value.to_be_bytes()
    }

    /// Returns the Area ID in host byte order.
    #[inline]
    pub fn area_id(&self) -> u32 {
        u32::from_be_bytes(self.area_id)
    }

    /// Sets the Area ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `area_id_value` - The Area ID value to set.
    #[inline]
    pub fn set_area_id(&mut self, area_id_value: u32) {
        self.area_id = area_id_value.to_be_bytes()
    }

    /// Returns the checksum in host byte order.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the checksum, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `checksum_value` - The checksum value to set.
    #[inline]
    pub fn set_checksum(&mut self, checksum_value: u16) {
        self.checksum = checksum_value.to_be_bytes();
    }

    /// Returns the Instance ID field.
    #[inline]
    pub fn instance_id(&self) -> u8 {
        self.instance_id
    }

    /// Sets the Instance ID field.
    ///
    /// # Arguments
    ///
    /// * `instance_id_value` - The value to set for the Instance ID field.
    #[inline]
    pub fn set_instance_id(&mut self, instance_id_value: u8) {
        self.instance_id = instance_id_value;
    }

    /// Returns the reserved field.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    /// Sets the reserved field.
    /// As per RFC 5340, Section A.3.1, this field MUST be set to 0.
    ///
    /// # Arguments
    ///
    /// * `reserved_value` - The value to set for the reserved field.
    #[inline]
    pub fn set_reserved(&mut self, reserved_value: u8) {
        self.reserved = reserved_value;
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospfv2hdr_len() {
        assert_eq!(OspfV2Hdr::LEN, 24, "OspfV2Hdr size should be 24 bytes");
    }

    #[test]
    fn test_ospfv2hdr_default_values() {
        let hdr = OspfV2Hdr::default();
        assert_eq!(hdr.version(), 0);
        assert_eq!(hdr.type_(), 0);
        assert_eq!(hdr.len(), 0);
        assert_eq!(hdr.router_id(), 0);
        assert_eq!(hdr.area_id(), 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.au_type(), 0);
        assert_eq!(hdr.authentication(), [0u8; 8]);
    }

    #[test]
    fn test_ospfv2hdr_field_getters_and_setters() {
        let mut hdr = OspfV2Hdr::default();

        // Version
        let version_val: u8 = 2;
        hdr.set_version(version_val);
        assert_eq!(hdr.version(), version_val);
        assert_eq!(hdr.version, version_val); // Check raw field

        // Type
        let type_val: u8 = 1; // OSPF_TYPE_HELLO
        hdr.set_type_(type_val);
        assert_eq!(hdr.type_(), type_val);
        assert_eq!(hdr.type_, type_val); // Check raw field

        // Packet Length
        let len_val: u16 = 48; // E.g. Hello packet on Ethernet
        hdr.set_len(len_val);
        assert_eq!(hdr.len(), len_val);
        assert_eq!(hdr.len, len_val.to_be_bytes()); // Check raw field

        // Router ID
        let router_id_val: u32 = 0xC0A80101; // 192.168.1.1
        hdr.set_router_id(router_id_val);
        assert_eq!(hdr.router_id(), router_id_val);
        assert_eq!(hdr.router_id, router_id_val.to_be_bytes()); // Check raw field

        // Area ID
        let area_id_val: u32 = 0x00000001; // Area 1
        hdr.set_area_id(area_id_val);
        assert_eq!(hdr.area_id(), area_id_val);
        assert_eq!(hdr.area_id, area_id_val.to_be_bytes()); // Check raw field

        // Checksum
        let checksum_val: u16 = 0xABCD;
        hdr.set_checksum(checksum_val);
        assert_eq!(hdr.checksum(), checksum_val);
        assert_eq!(hdr.checksum, checksum_val.to_be_bytes()); // Check raw field

        // AuType
        let au_type_val: u16 = 0; // Null authentication
        hdr.set_au_type(au_type_val);
        assert_eq!(hdr.au_type(), au_type_val);
        assert_eq!(hdr.au_type, au_type_val.to_be_bytes()); // Check raw field

        // Authentication
        let auth_data_val: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        hdr.set_authentication(auth_data_val);
        assert_eq!(hdr.authentication(), auth_data_val);
        assert_eq!(hdr.authentication, auth_data_val); // Check raw field
    }

    #[test]
    fn test_ospfv2hdr_from_bytes_representation() {
        // This test verifies the in-memory representation based on field assignments.
        // It doesn't involve unsafe casting but confirms field layouts.
        let expected_bytes: [u8; OspfV2Hdr::LEN] = [
            2,    // version
            1,    // type (Hello)
            0, 48, // len (48)
            192, 168, 1, 1, // router_id (192.168.1.1)
            0, 0, 0, 1,   // area_id (Area 1)
            0xAB, 0xCD,   // checksum
            0, 2,       // au_type (Cryptographic Authentication)
            10, 20, 30, 40, 50, 60, 70, 80, // authentication
        ];

        let mut hdr = OspfV2Hdr::default();
        hdr.set_version(2);
        hdr.set_type_(1);
        hdr.set_len(48);
        hdr.set_router_id(0xC0A80101);
        hdr.set_area_id(1);
        hdr.set_checksum(0xABCD);
        hdr.set_au_type(2); // Cryptographic Authentication
        hdr.set_authentication([10, 20, 30, 40, 50, 60, 70, 80]);

        // Verify raw field values after setters ensure correct network byte order storage
        assert_eq!(hdr.version, expected_bytes[0]);
        assert_eq!(hdr.type_, expected_bytes[1]);
        assert_eq!(hdr.len, [expected_bytes[2], expected_bytes[3]]);
        assert_eq!(hdr.router_id, [expected_bytes[4], expected_bytes[5], expected_bytes[6], expected_bytes[7]]);
        assert_eq!(hdr.area_id, [expected_bytes[8], expected_bytes[9], expected_bytes[10], expected_bytes[11]]);
        assert_eq!(hdr.checksum, [expected_bytes[12], expected_bytes[13]]);
        assert_eq!(hdr.au_type, [expected_bytes[14], expected_bytes[15]]);

        let mut auth_slice = [0u8; 8];
        auth_slice.copy_from_slice(&expected_bytes[16..24]);
        assert_eq!(hdr.authentication, auth_slice);
    }

    #[test]
    fn test_ospfv3hdr_len() {
        assert_eq!(OspfV3Hdr::LEN, 16, "OspfV3Hdr size should be 16 bytes");
    }

    #[test]
    fn test_ospfv3hdr_default_values() {
        let hdr = OspfV3Hdr::default();
        assert_eq!(hdr.version(), 0);
        assert_eq!(hdr.type_(), 0);
        assert_eq!(hdr.len(), 0);
        assert_eq!(hdr.router_id(), 0);
        assert_eq!(hdr.area_id(), 0);
        assert_eq!(hdr.checksum(), 0);
        assert_eq!(hdr.instance_id(), 0);
        assert_eq!(hdr.reserved(), 0);
    }

    #[test]
    fn test_ospfv3hdr_field_getters_and_setters() {
        let mut hdr = OspfV3Hdr::default();

        // Version
        let version_val: u8 = 3;
        hdr.set_version(version_val);
        assert_eq!(hdr.version(), version_val);
        assert_eq!(hdr.version, version_val); // Check raw field

        // Type
        let type_val: u8 = 1; // OSPF_TYPE_HELLO
        hdr.set_type_(type_val);
        assert_eq!(hdr.type_(), type_val);
        assert_eq!(hdr.type_, type_val); // Check raw field

        // Packet Length
        let len_val: u16 = 64;
        hdr.set_len(len_val);
        assert_eq!(hdr.len(), len_val);
        assert_eq!(hdr.len, len_val.to_be_bytes()); // Check raw field

        // Router ID
        let router_id_val: u32 = 0xC0A80101; // 192.168.1.1
        hdr.set_router_id(router_id_val);
        assert_eq!(hdr.router_id(), router_id_val);
        assert_eq!(hdr.router_id, router_id_val.to_be_bytes()); // Check raw field

        // Area ID
        let area_id_val: u32 = 0x00000005; // Area 5
        hdr.set_area_id(area_id_val);
        assert_eq!(hdr.area_id(), area_id_val);
        assert_eq!(hdr.area_id, area_id_val.to_be_bytes()); // Check raw field

        // Checksum
        let checksum_val: u16 = 0x1234;
        hdr.set_checksum(checksum_val);
        assert_eq!(hdr.checksum(), checksum_val);
        assert_eq!(hdr.checksum, checksum_val.to_be_bytes()); // Check raw field

        // Instance ID
        let instance_id_val: u8 = 0; // Default instance
        hdr.set_instance_id(instance_id_val);
        assert_eq!(hdr.instance_id(), instance_id_val);
        assert_eq!(hdr.instance_id, instance_id_val); // Check raw field

        // Reserved
        let reserved_val: u8 = 0; // Must be 0
        hdr.set_reserved(reserved_val);
        assert_eq!(hdr.reserved(), reserved_val);
        assert_eq!(hdr.reserved, reserved_val); // Check raw field
    }

    #[test]
    fn test_ospfv3hdr_from_bytes_representation() {
        // Expected bytes based on field assignments for an OSPFv3 header
        let expected_bytes: [u8; OspfV3Hdr::LEN] = [
            3,      // version
            1,      // type (Hello)
            0, 64,   // len (64)
            192, 168, 1, 1, // router_id (192.168.1.1)
            0, 0, 0, 5,   // area_id (Area 5)
            0x12, 0x34,   // checksum
            0,      // instance_id
            0,      // reserved
        ];

        let mut hdr = OspfV3Hdr::default();
        hdr.set_version(3);
        hdr.set_type_(1);
        hdr.set_len(64);
        hdr.set_router_id(0xC0A80101);
        hdr.set_area_id(5);
        hdr.set_checksum(0x1234);
        hdr.set_instance_id(0);
        hdr.set_reserved(0);

        // Verify raw field values after setters ensure correct network byte order storage
        assert_eq!(hdr.version, expected_bytes[0]);
        assert_eq!(hdr.type_, expected_bytes[1]);
        assert_eq!(hdr.len, [expected_bytes[2], expected_bytes[3]]);
        assert_eq!(hdr.router_id, [expected_bytes[4], expected_bytes[5], expected_bytes[6], expected_bytes[7]]);
        assert_eq!(hdr.area_id, [expected_bytes[8], expected_bytes[9], expected_bytes[10], expected_bytes[11]]);
        assert_eq!(hdr.checksum, [expected_bytes[12], expected_bytes[13]]);
        assert_eq!(hdr.instance_id, expected_bytes[14]);
        assert_eq!(hdr.reserved, expected_bytes[15]);
    }
}