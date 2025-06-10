use core::mem;

/// ARP header, which is present after the Ethernet header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ArpHdr {
    pub hardware_type: [u8; 2],
    pub protocol_type: [u8; 2],
    pub hardware_length: u8,
    pub protocol_length: u8,
    pub operation: [u8; 2],
    pub sender_hardware_address: [u8; 6],
    pub sender_protocol_address: [u8; 4],
    pub target_hardware_address: [u8; 6],
    pub target_protocol_address: [u8; 4],
}

impl ArpHdr {
    pub const LEN: usize = mem::size_of::<ArpHdr>();

    // Returns the hardware type field.
    #[inline]
    pub fn hardware_type(&self) -> [u8; 2] {
        self.hardware_type
    }

    // Sets the hardware type field.
    #[inline]
    pub fn set_hardware_type(&mut self, hardware_type: [u8; 2]) {
        self.hardware_type = hardware_type;
    }

    // Returns the protocol type field.
    #[inline]
    pub fn protocol_type(&self) -> [u8; 2] {
        self.protocol_type
    }

    // Sets the protocol type field.
    #[inline]
    pub fn set_protocol_type(&mut self, protocol_type: [u8; 2]) {
        self.protocol_type = protocol_type;
    }

    // Returns the hardware length field.
    #[inline]
    pub fn hardware_length(&self) -> u8 {
        self.hardware_length
    }

    // Sets the hardware length field.
    #[inline]
    pub fn set_hardware_length(&mut self, hardware_length: u8) {
        self.hardware_length = hardware_length;
    }

    // Returns the protocol length field.
    #[inline]
    pub fn protocol_length(&self) -> u8 {
        self.protocol_length
    }

    // Sets the protocol length field.
    #[inline]
    pub fn set_protocol_length(&mut self, protocol_length: u8) {
        self.protocol_length = protocol_length;
    }

    // Returns the operation field.
    #[inline]
    pub fn operation(&self) -> [u8; 2] {
        self.operation
    }

    // Sets the operation field.
    #[inline]
    pub fn set_operation(&mut self, operation: [u8; 2]) {
        self.operation = operation
    }

    // Returns the sender hardware address field.
    #[inline]
    pub fn sender_hardware_address(&self) -> [u8; 6] {
        self.sender_hardware_address
    }

    // Sets the sender hardware address field.
    #[inline]
    pub fn set_sender_hardware_address(&mut self, hardware_address: [u8; 6]) {
        self.sender_hardware_address = hardware_address
    }

    // Returns the sender protocol address field.
    #[inline]
    pub fn sender_protocol_address(&self) -> [u8; 4] {
        self.sender_protocol_address
    }

    // Sets the sender protocol address field.
    #[inline]
    pub fn set_sender_protocol_address(&mut self, protocol_address: [u8; 4]) {
        self.sender_protocol_address = protocol_address
    }

    // Returns the target hardware address field.
    #[inline]
    pub fn target_hardware_address(&self) -> [u8; 6] {
        self.target_hardware_address
    }

    // Sets the target hardware address field.
    #[inline]
    pub fn set_target_hardware_address(&mut self, hardware_address: [u8; 6]) {
        self.target_hardware_address = hardware_address
    }

    // Returns the target protocol address field.
    #[inline]
    pub fn target_protocol_address(&self) -> [u8; 4] {
        self.target_protocol_address
    }

    // Sets the target protocol address field.
    #[inline]
    pub fn set_target_protocol_address(&mut self, protocol_address: [u8; 4]) {
        self.target_protocol_address = protocol_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_arp_hdr() -> ArpHdr {
        ArpHdr {
            hardware_type: [0; 2],
            protocol_type: [0; 2],
            hardware_length: 0,
            protocol_length: 0,
            operation: [0; 2],
            sender_hardware_address: [0; 6],
            sender_protocol_address: [0; 4],
            target_hardware_address: [0; 6],
            target_protocol_address: [0; 4],
        }
    }

    #[test]
    fn test_len_constant() {
        assert_eq!(ArpHdr::LEN, 28);
        assert_eq!(ArpHdr::LEN, mem::size_of::<ArpHdr>());
    }

    #[test]
    fn test_hardware_type() {
        let mut hdr = default_arp_hdr();
        // Test with Ethernet (value 1)
        let hw_type = 1u16.to_be_bytes();
        hdr.set_hardware_type(hw_type);
        assert_eq!(hdr.hardware_type(), hw_type);
    }

    #[test]
    fn test_protocol_type() {
        let mut hdr = default_arp_hdr();
        // Test with IPv4 (value 0x0800)
        let proto_type = 0x0800u16.to_be_bytes();
        hdr.set_protocol_type(proto_type);
        assert_eq!(hdr.protocol_type(), proto_type);
    }

    #[test]
    fn test_hardware_length() {
        let mut hdr = default_arp_hdr();
        // Test with MAC address length
        hdr.set_hardware_length(6);
        assert_eq!(hdr.hardware_length(), 6);
    }

    #[test]
    fn test_protocol_length() {
        let mut hdr = default_arp_hdr();
        // Test with IPv4 address length
        hdr.set_protocol_length(4);
        assert_eq!(hdr.protocol_length(), 4);
    }

    #[test]
    fn test_operation() {
        let mut hdr = default_arp_hdr();
        // Test with ARP Request (1)
        let op_request = 1u16.to_be_bytes();
        hdr.set_operation(op_request);
        assert_eq!(hdr.operation(), op_request);
        // Test with ARP Reply (2)
        let op_reply = 2u16.to_be_bytes();
        hdr.set_operation(op_reply);
        assert_eq!(hdr.operation(), op_reply);
    }

    #[test]
    fn test_sender_hardware_address() {
        let mut hdr = default_arp_hdr();
        let addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        hdr.set_sender_hardware_address(addr);
        assert_eq!(hdr.sender_hardware_address(), addr);
    }

    #[test]
    fn test_sender_protocol_address() {
        let mut hdr = default_arp_hdr();
        let addr = [192, 168, 1, 1];
        hdr.set_sender_protocol_address(addr);
        assert_eq!(hdr.sender_protocol_address(), addr);
    }

    #[test]
    fn test_target_hardware_address() {
        let mut hdr = default_arp_hdr();
        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        hdr.set_target_hardware_address(addr);
        assert_eq!(hdr.target_hardware_address(), addr);
    }

    #[test]
    fn test_target_protocol_address() {
        let mut hdr = default_arp_hdr();
        let addr = [192, 168, 1, 100];
        hdr.set_target_protocol_address(addr);
        assert_eq!(hdr.target_protocol_address(), addr);
    }
}
