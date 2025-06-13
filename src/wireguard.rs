use core::mem::size_of;

/// WireGuard initial handshake header (Handshake Initiation).
///
/// This struct represents the header of a WireGuard handshake initiation message.
/// All fields are stored in network byte order (big-endian).
///
/// The structure follows the WireGuard protocol specification for the initial handshake message.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WgInitHdr {
    // Trailing underscore to prevent collision with reserved rust type keyword.
    pub type_: u8,
    pub _reserved: [u8; 3],
    pub sender: [u8; 4],
    pub ephemeral: [u8; 32],
    // Trailing underscore to prevent collision with reserved rust static keyword.
    pub static_: [u8; 32],
    pub timestamp: [u8; 12],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl WgInitHdr {
    /// The size of the WireGuard initial handshake header in bytes.
    pub const LEN: usize = size_of::<Self>();

    /// Returns the message type.
    ///
    /// # Returns
    /// The message type as a u8 value.
    #[inline]
    pub fn get_type(&self) -> u8 {
        self.type_
    }

    /// Sets the message type.
    ///
    /// # Parameters
    /// * `type_` - The message type to set.
    #[inline]
    pub fn set_type(&mut self, type_: u8) {
        self.type_ = type_;
    }

    /// Returns the sender ID.
    ///
    /// This method converts the sender ID from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The sender ID as a u32 value.
    #[inline]
    pub fn get_sender(&self) -> u32 {
        u32::from_be_bytes(self.sender)
    }

    /// Sets the sender ID.
    ///
    /// # Parameters
    /// * `sender` - An array of 4 bytes to set as the sender ID.
    #[inline]
    pub fn set_sender(&mut self, sender: [u8; 4]) {
        self.sender = sender;
    }

    /// Returns the ephemeral public key.
    ///
    /// # Returns
    /// An array of 32 bytes containing the ephemeral public key.
    #[inline]
    pub fn get_ephemeral(&self) -> [u8; 32] {
        self.ephemeral
    }

    /// Sets the ephemeral public key.
    ///
    /// # Parameters
    /// * `ephemeral` - An array of 32 bytes to set as the ephemeral public key.
    #[inline]
    pub fn set_ephemeral(&mut self, ephemeral: [u8; 32]) {
        self.ephemeral = ephemeral;
    }

    /// Returns the static public key (encrypted).
    ///
    /// # Returns
    /// An array of 32 bytes containing the encrypted static public key.
    #[inline]
    pub fn get_static(&self) -> [u8; 32] {
        self.static_
    }

    /// Sets the static public key (encrypted).
    ///
    /// # Parameters
    /// * `static_` - An array of 32 bytes to set as the encrypted static public key.
    #[inline]
    pub fn set_static(&mut self, static_: [u8; 32]) {
        self.static_ = static_;
    }

    /// Returns the timestamp (encrypted).
    ///
    /// # Returns
    /// An array of 12 bytes containing the encrypted timestamp.
    #[inline]
    pub fn get_timestamp(&self) -> [u8; 12] {
        self.timestamp
    }

    /// Sets the timestamp (encrypted).
    ///
    /// # Parameters
    /// * `timestamp` - An array of 12 bytes to set as the encrypted timestamp.
    #[inline]
    pub fn set_timestamp(&mut self, timestamp: [u8; 12]) {
        self.timestamp = timestamp;
    }

    /// Returns the first message authentication code (MAC).
    ///
    /// This MAC is computed over all the preceding fields.
    ///
    /// # Returns
    /// An array of 16 bytes containing the first MAC.
    #[inline]
    pub fn get_mac1(&self) -> [u8; 16] {
        self.mac1
    }

    /// Sets the first message authentication code (MAC).
    ///
    /// # Parameters
    /// * `mac1` - An array of 16 bytes to set as the first MAC.
    #[inline]
    pub fn set_mac1(&mut self, mac1: [u8; 16]) {
        self.mac1 = mac1;
    }

    /// Returns the second message authentication code (MAC).
    ///
    /// This MAC is computed over all the preceding fields and the peer's public key.
    ///
    /// # Returns
    /// An array of 16 bytes containing the second MAC.
    #[inline]
    pub fn get_mac2(&self) -> [u8; 16] {
        self.mac2
    }

    /// Sets the second message authentication code (MAC).
    ///
    /// # Parameters
    /// * `mac2` - An array of 16 bytes to set as the second MAC.
    #[inline]
    pub fn set_mac2(&mut self, mac2: [u8; 16]) {
        self.mac2 = mac2;
    }
}

/// WireGuard response handshake header (Handshake Response).
///
/// This struct represents the header of a WireGuard handshake response message.
/// All fields are stored in network byte order (big-endian).
///
/// The structure follows the WireGuard protocol specification for the handshake response message.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WgResHdr {
    // Trailing underscore to prevent collision with reserved rust type keyword.
    pub type_: u8,
    pub _reserved: [u8; 3],
    pub sender: [u8; 4],
    pub receiver: [u8; 4],
    pub ephemeral: [u8; 32],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl WgResHdr {
    /// The size of the WireGuard response handshake header in bytes.
    pub const LEN: usize = size_of::<Self>();

    /// Returns the message type.
    ///
    /// # Returns
    /// The message type as a u8 value.
    #[inline]
    pub fn get_type(&self) -> u8 {
        self.type_
    }

    /// Sets the message type.
    ///
    /// # Parameters
    /// * `type_` - The message type to set.
    #[inline]
    pub fn set_type(&mut self, type_: u8) {
        self.type_ = type_;
    }

    /// Returns the sender ID.
    ///
    /// This method converts the sender ID from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The sender ID as a u32 value.
    #[inline]
    pub fn get_sender(&self) -> u32 {
        u32::from_be_bytes(self.sender)
    }

    /// Sets the sender ID.
    ///
    /// # Parameters
    /// * `sender` - An array of 4 bytes to set as the sender ID.
    #[inline]
    pub fn set_sender(&mut self, sender: [u8; 4]) {
        self.sender = sender;
    }

    /// Returns the receiver ID.
    ///
    /// This method converts the receiver ID from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The receiver ID as a u32 value.
    #[inline]
    pub fn get_receiver(&self) -> u32 {
        u32::from_be_bytes(self.receiver)
    }

    /// Sets the receiver ID.
    ///
    /// # Parameters
    /// * `receiver` - An array of 4 bytes to set as the receiver ID.
    #[inline]
    pub fn set_receiver(&mut self, receiver: [u8; 4]) {
        self.receiver = receiver;
    }

    /// Returns the ephemeral public key.
    ///
    /// # Returns
    /// An array of 32 bytes containing the ephemeral public key.
    #[inline]
    pub fn get_ephemeral(&self) -> [u8; 32] {
        self.ephemeral
    }

    /// Sets the ephemeral public key.
    ///
    /// # Parameters
    /// * `ephemeral` - An array of 32 bytes to set as the ephemeral public key.
    #[inline]
    pub fn set_ephemeral(&mut self, ephemeral: [u8; 32]) {
        self.ephemeral = ephemeral;
    }

    /// Returns the first message authentication code (MAC).
    ///
    /// This MAC is computed over all the preceding fields.
    ///
    /// # Returns
    /// An array of 16 bytes containing the first MAC.
    #[inline]
    pub fn get_mac1(&self) -> [u8; 16] {
        self.mac1
    }

    /// Sets the first message authentication code (MAC).
    ///
    /// # Parameters
    /// * `mac1` - An array of 16 bytes to set as the first MAC.
    #[inline]
    pub fn set_mac1(&mut self, mac1: [u8; 16]) {
        self.mac1 = mac1;
    }

    /// Returns the second message authentication code (MAC).
    ///
    /// This MAC is computed over all the preceding fields and the peer's public key.
    ///
    /// # Returns
    /// An array of 16 bytes containing the second MAC.
    #[inline]
    pub fn get_mac2(&self) -> [u8; 16] {
        self.mac2
    }

    /// Sets the second message authentication code (MAC).
    ///
    /// # Parameters
    /// * `mac2` - An array of 16 bytes to set as the second MAC.
    #[inline]
    pub fn set_mac2(&mut self, mac2: [u8; 16]) {
        self.mac2 = mac2;
    }
}

/// WireGuard transport header (Data Transport Message).
///
/// This struct represents the header of a WireGuard data transport message.
/// All fields are stored in network byte order (big-endian).
///
/// The structure follows the WireGuard protocol specification for data transport messages.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WgTransHdr {
    // Trailing underscore to prevent collision with reserved rust type keyword.
    pub type_: u8,
    pub _reserved: [u8; 3],
    pub receiver: [u8; 4],
    pub counter: [u8; 8],
}

impl WgTransHdr {
    /// The size of the WireGuard transport header in bytes.
    pub const LEN: usize = size_of::<Self>();

    /// Returns the message type.
    ///
    /// This method converts the type from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The message type as a u8 value.
    pub fn get_type(&self) -> u8 {
        u8::from_be(self.type_)
    }

    /// Sets the message type.
    ///
    /// This method converts the type from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `type_` - The message type to set.
    pub fn set_type(&mut self, type_: u8) {
        self.type_ = type_.to_be();
    }

    /// Returns the receiver ID.
    ///
    /// This method converts the receiver ID from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The receiver ID as a u32 value.
    pub fn get_receiver(&self) -> u32 {
        u32::from_be_bytes(self.receiver)
    }

    /// Returns the counter value.
    ///
    /// This counter is used to prevent replay attacks and is incremented for each packet.
    /// This method converts the counter from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The counter as a u64 value.
    pub fn get_counter(&self) -> u64 {
        u64::from_be_bytes(self.counter)
    }
}

/// A safe, zero-copy "view" or "parser" for the entire WireGuard transport packet.
///
/// This struct wraps a byte buffer and provides safe methods to access the
/// fixed-size header and the variable-length packet payload that follows.
/// It allows for efficient parsing of WireGuard transport packets without copying data.
#[derive(Debug, Copy, Clone)]
pub struct WgTransPktView<'a> {
    /// The underlying byte buffer containing the complete packet.
    buffer: &'a [u8],
}

impl<'a> WgTransPktView<'a> {
    /// Creates a new view for a WireGuard transport packet from a byte slice.
    ///
    /// # Parameters
    /// * `buffer` - A byte slice containing the complete packet data.
    ///
    /// # Returns
    /// * `Some(WgTransPktView)` if the buffer is large enough to contain a valid header.
    /// * `None` if the buffer is too short to contain the fixed-size header.
    pub fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() < WgTransHdr::LEN {
            return None;
        }
        Some(Self { buffer })
    }

    /// Returns a safe reference to the fixed-size header at the beginning of the packet.
    ///
    /// This method provides access to the WireGuard transport header fields.
    ///
    /// # Returns
    /// A reference to the WgTransHdr structure.
    pub fn header(&self) -> &WgTransHdr {
        // This unsafe block is guaranteed to be safe because of the length check in the `new()` constructor.
        unsafe { &*(self.buffer.as_ptr() as *const WgTransHdr) }
    }

    /// Returns a slice representing the variable-length packet payload.
    ///
    /// This is the encrypted data that comes immediately after the fixed header
    /// and extends to the end of the buffer.
    ///
    /// # Returns
    /// A byte slice containing the packet payload.
    pub fn packet(&self) -> &'a [u8] {
        &self.buffer[WgTransHdr::LEN..]
    }
}

/// WireGuard cookie reply header (Cookie Reply Message).
///
/// This struct represents the header of a WireGuard cookie reply message.
/// All fields are stored in network byte order (big-endian).
///
/// The structure follows the WireGuard protocol specification for cookie reply messages,
/// which are used as part of the DoS mitigation mechanism.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WgCookieRplHdr {
    pub type_: u8,
    pub _reserved: [u8; 3],
    pub receiver: [u8; 4],
    pub nonce: [u8; 24],
    pub cookie: [u8; 16],
}

impl WgCookieRplHdr {
    /// The size of the WireGuard cookie reply header in bytes.
    pub const LEN: usize = size_of::<Self>();

    /// Returns the message type.
    ///
    /// This method converts the type from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The message type as a u8 value.
    pub fn get_type(&self) -> u8 {
        u8::from_be(self.type_)
    }

    /// Sets the message type.
    ///
    /// This method converts the type from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `type_` - The message type to set.
    pub fn set_type(&mut self, type_: u8) {
        self.type_ = type_.to_be();
    }

    /// Returns the receiver ID.
    ///
    /// This method converts the receiver ID from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The receiver ID as a u32 value.
    pub fn get_receiver(&self) -> u32 {
        u32::from_be_bytes(self.receiver)
    }

    /// Sets the receiver ID.
    ///
    /// # Parameters
    /// * `receiver` - An array of 4 bytes to set as the receiver ID.
    pub fn set_receiver(&mut self, receiver: [u8; 4]) {
        self.receiver = receiver
    }

    /// Returns the nonce used for cookie encryption.
    ///
    /// # Returns
    /// An array of 24 bytes containing the nonce.
    pub fn get_nonce(&self) -> [u8; 24] {
        self.nonce
    }

    /// Sets the nonce used for cookie encryption.
    ///
    /// # Parameters
    /// * `nonce` - An array of 24 bytes to set as the nonce.
    pub fn set_nonce(&mut self, nonce: [u8; 24]) {
        self.nonce = nonce;
    }

    /// Returns the encrypted cookie.
    ///
    /// The cookie is used as part of the DoS mitigation mechanism.
    ///
    /// # Returns
    /// An array of 16 bytes containing the encrypted cookie.
    pub fn get_cookie(&self) -> [u8; 16] {
        self.cookie
    }

    /// Sets the encrypted cookie.
    ///
    /// # Parameters
    /// * `cookie` - An array of 16 bytes to set as the encrypted cookie.
    pub fn set_cookie(&mut self, cookie: [u8; 16]) {
        self.cookie = cookie;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper functions to create test headers
    fn create_test_wg_init_hdr() -> WgInitHdr {
        WgInitHdr {
            type_: 1,
            _reserved: [0, 0, 0],
            sender: [1, 2, 3, 4],
            ephemeral: [1; 32],
            static_: [2; 32],
            timestamp: [3; 12],
            mac1: [4; 16],
            mac2: [5; 16],
        }
    }

    fn create_test_wg_res_hdr() -> WgResHdr {
        WgResHdr {
            type_: 2,
            _reserved: [0, 0, 0],
            sender: [5, 6, 7, 8],
            receiver: [1, 2, 3, 4],
            ephemeral: [6; 32],
            mac1: [7; 16],
            mac2: [8; 16],
        }
    }

    fn create_test_wg_trans_hdr() -> WgTransHdr {
        WgTransHdr {
            type_: 3,
            _reserved: [0, 0, 0],
            receiver: [1, 2, 3, 4],
            counter: [0, 0, 0, 0, 0, 0, 0, 1],
        }
    }

    fn create_test_wg_cookie_rpl_hdr() -> WgCookieRplHdr {
        WgCookieRplHdr {
            type_: 4,
            _reserved: [0, 0, 0],
            receiver: [1, 2, 3, 4],
            nonce: [9; 24],
            cookie: [10; 16],
        }
    }

    #[test]
    fn test_wg_init_hdr_size() {
        assert_eq!(WgInitHdr::LEN, size_of::<WgInitHdr>());
    }

    #[test]
    fn test_wg_init_hdr_fields() {
        let mut hdr = create_test_wg_init_hdr();

        assert_eq!(hdr.get_type(), 1);
        hdr.set_type(5);
        assert_eq!(hdr.get_type(), 5);

        assert_eq!(hdr.get_sender(), 0x01020304);
        let new_sender = [5, 6, 7, 8];
        hdr.set_sender(new_sender);
        assert_eq!(hdr.get_sender(), 0x05060708);

        assert_eq!(hdr.get_ephemeral(), [1; 32]);
        let new_ephemeral = [11; 32];
        hdr.set_ephemeral(new_ephemeral);
        assert_eq!(hdr.get_ephemeral(), new_ephemeral);

        assert_eq!(hdr.get_static(), [2; 32]);
        let new_static = [12; 32];
        hdr.set_static(new_static);
        assert_eq!(hdr.get_static(), new_static);

        assert_eq!(hdr.get_timestamp(), [3; 12]);
        let new_timestamp = [13; 12];
        hdr.set_timestamp(new_timestamp);
        assert_eq!(hdr.get_timestamp(), new_timestamp);

        assert_eq!(hdr.get_mac1(), [4; 16]);
        let new_mac1 = [14; 16];
        hdr.set_mac1(new_mac1);
        assert_eq!(hdr.get_mac1(), new_mac1);

        assert_eq!(hdr.get_mac2(), [5; 16]);
        let new_mac2 = [15; 16];
        hdr.set_mac2(new_mac2);
        assert_eq!(hdr.get_mac2(), new_mac2);
    }

    #[test]
    fn test_wg_res_hdr_size() {
        assert_eq!(WgResHdr::LEN, size_of::<WgResHdr>());
    }

    #[test]
    fn test_wg_res_hdr_fields() {
        let mut hdr = create_test_wg_res_hdr();

        assert_eq!(hdr.get_type(), 2);
        hdr.set_type(6);
        assert_eq!(hdr.get_type(), 6);
        
        assert_eq!(hdr.get_sender(), 0x05060708);
        let new_sender = [9, 10, 11, 12];
        hdr.set_sender(new_sender);
        assert_eq!(hdr.get_sender(), 0x090A0B0C);

        assert_eq!(hdr.get_receiver(), 0x01020304);
        let new_receiver = [13, 14, 15, 16];
        hdr.set_receiver(new_receiver);
        assert_eq!(hdr.get_receiver(), 0x0D0E0F10);

        assert_eq!(hdr.get_ephemeral(), [6; 32]);
        let new_ephemeral = [16; 32];
        hdr.set_ephemeral(new_ephemeral);
        assert_eq!(hdr.get_ephemeral(), new_ephemeral);

        assert_eq!(hdr.get_mac1(), [7; 16]);
        let new_mac1 = [17; 16];
        hdr.set_mac1(new_mac1);
        assert_eq!(hdr.get_mac1(), new_mac1);

        assert_eq!(hdr.get_mac2(), [8; 16]);
        let new_mac2 = [18; 16];
        hdr.set_mac2(new_mac2);
        assert_eq!(hdr.get_mac2(), new_mac2);
    }

    #[test]
    fn test_wg_trans_hdr_size() {
        assert_eq!(WgTransHdr::LEN, size_of::<WgTransHdr>());
    }

    #[test]
    fn test_wg_trans_hdr_fields() {
        let mut hdr = create_test_wg_trans_hdr();

        assert_eq!(hdr.get_type(), 3);
        hdr.set_type(7);
        assert_eq!(hdr.get_type(), 7);

        assert_eq!(hdr.get_receiver(), 0x01020304); 

        assert_eq!(hdr.get_counter(), 1);
    }

    #[test]
    fn test_wg_trans_pkt_view() {
        // Create a buffer with a valid header and some payload
        let hdr = create_test_wg_trans_hdr();
        let mut buffer = [0u8; 26]; // WgTransHdr::LEN (16) + 10 bytes payload

        // Copy header bytes to the buffer
        unsafe {
            let hdr_ptr = &hdr as *const WgTransHdr as *const u8;
            let buffer_ptr = buffer.as_mut_ptr();
            core::ptr::copy_nonoverlapping(hdr_ptr, buffer_ptr, WgTransHdr::LEN);
        }

        // Fill payload with a pattern
        for i in 0..10 {
            buffer[WgTransHdr::LEN + i] = i as u8;
        }

        // Create a view
        let view = WgTransPktView::new(&buffer).unwrap();

        // Test header access
        assert_eq!(view.header().get_type(), 3);
        assert_eq!(view.header().get_receiver(), 0x01020304);
        assert_eq!(view.header().get_counter(), 1);

        // Test payload access
        assert_eq!(view.packet().len(), 10);
        for i in 0..10 {
            assert_eq!(view.packet()[i], i as u8);
        }

        // Test with too small buffer
        let small_buffer = [0u8; 15]; // WgTransHdr::LEN (16) - 1
        assert!(WgTransPktView::new(&small_buffer).is_none());
    }

    #[test]
    fn test_wg_cookie_rpl_hdr_size() {
        assert_eq!(WgCookieRplHdr::LEN, size_of::<WgCookieRplHdr>());
    }

    #[test]
    fn test_wg_cookie_rpl_hdr_fields() {
        let mut hdr = create_test_wg_cookie_rpl_hdr();

        assert_eq!(hdr.get_type(), 4);
        hdr.set_type(8);
        assert_eq!(hdr.get_type(), 8);

        assert_eq!(hdr.get_receiver(), 0x01020304); 
        let new_receiver = [5, 6, 7, 8];
        hdr.set_receiver(new_receiver);
        assert_eq!(hdr.get_receiver(), 0x05060708);

        assert_eq!(hdr.get_nonce(), [9; 24]);
        let new_nonce = [19; 24];
        hdr.set_nonce(new_nonce);
        assert_eq!(hdr.get_nonce(), new_nonce);

        assert_eq!(hdr.get_cookie(), [10; 16]);
        let new_cookie = [20; 16];
        hdr.set_cookie(new_cookie);
        assert_eq!(hdr.get_cookie(), new_cookie);
    }
}
