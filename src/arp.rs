use core::mem;

/// ARP header, which is present after the Ethernet header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ArpHdr {
    pub htype: [u8; 2],
    pub ptype: [u8; 2],
    pub hlen: u8,
    pub plen: u8,
    pub oper: [u8; 2],
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

impl ArpHdr {
    pub const LEN: usize = mem::size_of::<ArpHdr>();

    // Returns the hardware type field.
    #[inline]
    pub fn htype(&self) -> [u8; 2] {
        self.htype
    }

    // Sets the hardware type field.
    #[inline]
    pub fn set_htype(&mut self, htype: [u8; 2]) {
        self.htype = htype;
    }

    // Returns the protocol type field.
    #[inline]
    pub fn ptype(&self) -> [u8; 2] {
        self.ptype
    }

    // Sets the protocol type field.
    #[inline]
    pub fn set_ptype(&mut self, ptype: [u8; 2]) {
        self.ptype = ptype;
    }

    // Returns the hardware length field.
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    // Sets the hardware length field.
    #[inline]
    pub fn set_hlen(&mut self, hlen: u8) {
        self.hlen = hlen;
    }

    // Returns the protocol length field.
    #[inline]
    pub fn plen(&self) -> u8 {
        self.plen
    }

    // Sets the protocol length field.
    #[inline]
    pub fn set_plen(&mut self, plen: u8) {
        self.plen = plen;
    }

    // Returns the oper field.
    #[inline]
    pub fn oper(&self) -> [u8; 2] {
        self.oper
    }

    // Sets the oper field.
    #[inline]
    pub fn set_oper(&mut self, oper: [u8; 2]) {
        self.oper = oper
    }

    // Returns the sender hardware address field.
    #[inline]
    pub fn sha(&self) -> [u8; 6] {
        self.sha
    }

    // Sets the sender hardware address field.
    #[inline]
    pub fn set_sha(&mut self, hardware_address: [u8; 6]) {
        self.sha = hardware_address
    }

    // Returns the sender protocol address field.
    #[inline]
    pub fn spa(&self) -> [u8; 4] {
        self.spa
    }

    // Sets the sender protocol address field.
    #[inline]
    pub fn set_spa(&mut self, protocol_address: [u8; 4]) {
        self.spa = protocol_address
    }

    // Returns the target hardware address field.
    #[inline]
    pub fn tha(&self) -> [u8; 6] {
        self.tha
    }

    // Sets the target hardware address field.
    #[inline]
    pub fn set_tha(&mut self, hardware_address: [u8; 6]) {
        self.tha = hardware_address
    }

    // Returns the target protocol address field.
    #[inline]
    pub fn tpa(&self) -> [u8; 4] {
        self.tpa
    }

    // Sets the target protocol address field.
    #[inline]
    pub fn set_tpa(&mut self, protocol_address: [u8; 4]) {
        self.tpa = protocol_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_arp_hdr() -> ArpHdr {
        ArpHdr {
            htype: [0; 2],
            ptype: [0; 2],
            hlen: 0,
            plen: 0,
            oper: [0; 2],
            sha: [0; 6],
            spa: [0; 4],
            tha: [0; 6],
            tpa: [0; 4],
        }
    }

    #[test]
    fn test_len_constant() {
        assert_eq!(ArpHdr::LEN, 28);
        assert_eq!(ArpHdr::LEN, mem::size_of::<ArpHdr>());
    }

    #[test]
    fn test_htype() {
        let mut hdr = default_arp_hdr();
        // Test with Ethernet (value 1)
        let hw_type = 1u16.to_be_bytes();
        hdr.set_htype(hw_type);
        assert_eq!(hdr.htype(), hw_type);
    }

    #[test]
    fn test_ptype() {
        let mut hdr = default_arp_hdr();
        // Test with IPv4 (value 0x0800)
        let proto_type = 0x0800u16.to_be_bytes();
        hdr.set_ptype(proto_type);
        assert_eq!(hdr.ptype(), proto_type);
    }

    #[test]
    fn test_hlen() {
        let mut hdr = default_arp_hdr();
        // Test with MAC address length
        hdr.set_hlen(6);
        assert_eq!(hdr.hlen(), 6);
    }

    #[test]
    fn test_plen() {
        let mut hdr = default_arp_hdr();
        // Test with IPv4 address length
        hdr.set_plen(4);
        assert_eq!(hdr.plen(), 4);
    }

    #[test]
    fn test_oper() {
        let mut hdr = default_arp_hdr();
        // Test with ARP Request (1)
        let op_request = 1u16.to_be_bytes();
        hdr.set_oper(op_request);
        assert_eq!(hdr.oper(), op_request);
        // Test with ARP Reply (2)
        let op_reply = 2u16.to_be_bytes();
        hdr.set_oper(op_reply);
        assert_eq!(hdr.oper(), op_reply);
    }

    #[test]
    fn test_sha() {
        let mut hdr = default_arp_hdr();
        let addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        hdr.set_sha(addr);
        assert_eq!(hdr.sha(), addr);
    }

    #[test]
    fn test_spa() {
        let mut hdr = default_arp_hdr();
        let addr = [192, 168, 1, 1];
        hdr.set_spa(addr);
        assert_eq!(hdr.spa(), addr);
    }

    #[test]
    fn test_tha() {
        let mut hdr = default_arp_hdr();
        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        hdr.set_tha(addr);
        assert_eq!(hdr.tha(), addr);
    }

    #[test]
    fn test_tpa() {
        let mut hdr = default_arp_hdr();
        let addr = [192, 168, 1, 100];
        hdr.set_tpa(addr);
        assert_eq!(hdr.tpa(), addr);
    }
}
