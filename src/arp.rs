use core::mem::{self};
use memoffset::offset_of;
/// Represents an Address Resolution Protocol (ARP) header.
///
/// The ARP header is typically found after the Ethernet header and is used to
/// map a network protocol address (like an IPv4 address) to a hardware
/// address (like a MAC address).
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ArpHdr {
    /// Hardware type (HTYPE): Specifies the network link protocol type.
    /// E.g., Ethernet is 1.
    pub htype: [u8; 2],
    /// Protocol type (PTYPE): Specifies the internetwork protocol for which
    /// the ARP request is intended. For IPv4, this has the value 0x0800.
    pub ptype: [u8; 2],
    /// Hardware address length (HLEN): Length in bytes of a hardware address.
    /// Ethernet addresses size is 6.
    pub hlen: u8,
    /// Protocol address length (PLEN): Length in bytes of a logical address.
    /// IPv4 addresses size is 4.
    pub plen: u8,
    /// Operation (OPER): Specifies the operation that the sender is performing:
    /// 1 for request, 2 for reply.
    pub oper: [u8; 2],
    /// Sender hardware address (SHA): The hardware address of the sender.
    pub sha: [u8; 6],
    /// Sender protocol address (SPA): The protocol address of the sender.
    pub spa: [u8; 4],
    /// Target hardware address (THA): The hardware address of the intended
    /// receiver. This field is ignored in an ARP request.
    pub tha: [u8; 6],
    /// Target protocol address (TPA): The protocol address of the intended
    /// receiver.
    pub tpa: [u8; 4],
}

impl ArpHdr {
    /// The size of the ARP header in bytes.
    pub const LEN: usize = mem::size_of::<ArpHdr>();

    /// Creates a new `ArpHdr` with all fields initialized to zero.
    /// This is an alias for `ArpHdr::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the hardware type field.
    #[inline]
    pub fn htype(&self) -> u16 {
        unsafe {
            *((self as *const Self as usize + offset_of!(Self, htype)) as *const u16)
        }
        .swap_bytes()
    }

    /// Sets the hardware type field.
    ///
    /// # Arguments
    ///
    /// * `htype` - A 2-byte array representing the hardware type.
    #[inline]
    pub fn set_htype(&mut self, htype: u16) {
        self.htype = unsafe { *((&htype.swap_bytes() as *const _ as usize) as *const _) };
    }

    /// Returns the protocol type field.
    #[inline]
    pub fn ptype(&self) -> u16 {
        unsafe {
            *((self as *const Self as usize + offset_of!(Self, ptype)) as *const u16)
        }
        .swap_bytes()
    }

    /// Sets the protocol type field.
    ///
    /// # Arguments
    ///
    /// * `ptype` - A 2-byte array representing the protocol type.
    #[inline]
    pub fn set_ptype(&mut self, ptype: u16) {
        self.ptype = unsafe { *((&ptype.swap_bytes() as *const _ as usize) as *const _) };
    }

    /// Returns the hardware address length field.
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    /// Sets the hardware address length field.
    ///
    /// # Arguments
    ///
    /// * `hlen` - A u8 value for the hardware address length.
    #[inline]
    pub fn set_hlen(&mut self, hlen: u8) {
        self.hlen = hlen;
    }

    /// Returns the protocol address length field.
    #[inline]
    pub fn plen(&self) -> u8 {
        self.plen
    }

    /// Sets the protocol address length field.
    ///
    /// # Arguments
    ///
    /// * `plen` - A u8 value for the protocol address length.
    #[inline]
    pub fn set_plen(&mut self, plen: u8) {
        self.plen = plen;
    }

    /// Returns the operation field.
    #[inline]
    pub fn oper(&self) -> u16 {
        unsafe {
            *((self as *const Self as usize + offset_of!(Self, oper)) as *const u16)
        }
        .swap_bytes()
    }

    /// Sets the operation field.
    ///
    /// # Arguments
    ///
    /// * `oper` - A 2-byte array representing the operation (e.g., request or reply).
    #[inline]
    pub fn set_oper(&mut self, oper: u16) {
        self.oper = unsafe { *((&oper.swap_bytes() as *const _ as usize) as *const _) };
    }

    /// Returns the sender hardware address (SHA) field.
    #[inline]
    pub fn sha(&self) -> [u8; 6] {
        self.sha
    }

    /// Sets the sender hardware address (SHA) field.
    ///
    /// # Arguments
    ///
    /// * `hardware_address` - A 6-byte array representing the sender's hardware address.
    #[inline]
    pub fn set_sha(&mut self, hardware_address: [u8; 6]) {
        self.sha = hardware_address
    }

    /// Returns the sender protocol address (SPA) field.
    #[inline]
    pub fn spa(&self) -> [u8; 4] {
        self.spa
    }

    /// Sets the sender protocol address (SPA) field.
    ///
    /// # Arguments
    ///
    /// * `protocol_address` - A 4-byte array representing the sender's protocol address.
    #[inline]
    pub fn set_spa(&mut self, protocol_address: [u8; 4]) {
        self.spa = protocol_address
    }

    /// Returns the target hardware address (THA) field.
    #[inline]
    pub fn tha(&self) -> [u8; 6] {
        self.tha
    }

    /// Sets the target hardware address (THA) field.
    ///
    /// # Arguments
    ///
    /// * `hardware_address` - A 6-byte array representing the target's hardware address.
    #[inline]
    pub fn set_tha(&mut self, hardware_address: [u8; 6]) {
        self.tha = hardware_address
    }

    /// Returns the target protocol address (TPA) field.
    #[inline]
    pub fn tpa(&self) -> [u8; 4] {
        self.tpa
    }

    /// Sets the target protocol address (TPA) field.
    ///
    /// # Arguments
    ///
    /// * `protocol_address` - A 4-byte array representing the target's protocol address.
    #[inline]
    pub fn set_tpa(&mut self, protocol_address: [u8; 4]) {
        self.tpa = protocol_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_len_constant() {
        assert_eq!(ArpHdr::LEN, 28);
        assert_eq!(ArpHdr::LEN, mem::size_of::<ArpHdr>());
    }

    #[test]
    fn test_htype() {
        let mut hdr = ArpHdr::default();
        let hw_type = 1u16;
        hdr.set_htype(hw_type);
        assert_eq!(hdr.htype(), hw_type);
    }

    #[test]
    fn test_ptype() {
        let mut hdr = ArpHdr::default();
        let proto_type = 0x0800u16;
        hdr.set_ptype(proto_type);
        assert_eq!(hdr.ptype(), proto_type);
    }

    #[test]
    fn test_hlen() {
        let mut hdr = ArpHdr::default();
        hdr.set_hlen(6);
        assert_eq!(hdr.hlen(), 6);
    }

    #[test]
    fn test_plen() {
        let mut hdr = ArpHdr::default();
        hdr.set_plen(4);
        assert_eq!(hdr.plen(), 4);
    }

    #[test]
    fn test_oper() {
        let mut hdr = ArpHdr::default();
        let op_request = 1u16;
        hdr.set_oper(op_request);
        assert_eq!(hdr.oper(), op_request);
        let op_reply = 2u16;
        hdr.set_oper(op_reply);
        assert_eq!(hdr.oper(), op_reply);
    }

    #[test]
    fn test_sha() {
        let mut hdr = ArpHdr::default();
        let addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        hdr.set_sha(addr);
        assert_eq!(hdr.sha(), addr);
    }

    #[test]
    fn test_spa() {
        let mut hdr = ArpHdr::default();
        let addr = [192, 168, 1, 1];
        hdr.set_spa(addr);
        assert_eq!(hdr.spa(), addr);
    }

    #[test]
    fn test_tha() {
        let mut hdr = ArpHdr::default();
        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        hdr.set_tha(addr);
        assert_eq!(hdr.tha(), addr);
    }

    #[test]
    fn test_tpa() {
        let mut hdr = ArpHdr::default();
        let addr = [192, 168, 1, 100];
        hdr.set_tpa(addr);
        assert_eq!(hdr.tpa(), addr);
    }
}
