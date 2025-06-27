#![no_std]

pub const C_FLAG_MASK: u8 = 0x80;
pub const K_FLAG_MASK: u8 = 0x20;
pub const S_FLAG_MASK: u8 = 0x10;
pub const VER_MASK: u8 = 0x07;

/// Parses a GRE header from a network packet.
///
/// This macro extracts a GRE header from a packet buffer, handling the variable-length
/// optional fields based on the flags in the header. It returns a `Result<GreHdr, ()>`.
///
/// # Parameters
/// * `$ctx`: The context providing the `load` method to read from the packet buffer.
/// * `$off`: An identifier representing the current offset in the packet buffer, which will be updated.
///
/// # Returns
/// A `Result` containing either the parsed `GreHdr` or an error `()`.
///
#[macro_export]
macro_rules! parse_gre_hdr {
    ($ctx:expr, $off:ident) => {
        (|| -> Result<GreHdr, ()> {
            use network_types::gre::*;
            use network_types::macros;
            
            let fixed_hdr = match $ctx.load($off) {
                Ok(val) => val,
                Err(_) => return Err(()),
            };
            $off += 4;

            let mut gre_hdr = GreHdr::new(fixed_hdr);
            let optional_fields_count =
                (gre_hdr.fixed.flgs_res0_ver[0] & (C_FLAG_MASK | K_FLAG_MASK | S_FLAG_MASK))
                    .count_ones();

            if optional_fields_count >= 1 {
                // Individual match/err cases are required to satisfy borrow checker
                gre_hdr.opt1 = match $ctx.load($off) {
                    Ok(val) => val,
                    Err(_) => return Err(()),
                };
                $off += 4;
            }
            if optional_fields_count >= 2 {
                gre_hdr.opt2 = match $ctx.load($off) {
                    Ok(val) => val,
                    Err(_) => return Err(()),
                };
                $off += 4;
            }
            if optional_fields_count >= 3 {
                gre_hdr.opt3 = match $ctx.load($off) {
                    Ok(val) => val,
                    Err(_) => return Err(()),
                };
                $off += 4;
            }

            Ok(gre_hdr)
        })();
    };
}
/// Represents the fixed part of a GRE header.
///
/// This struct contains the first 4 bytes of a GRE header, which includes
/// flags, reserved bits, version, and protocol type.
///
/// # Fields
/// * `flgs_res0_ver`: A 2-byte array containing flags, reserved bits, and version.
/// * `proto`: A 2-byte array containing the protocol type.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct GreFixedHdr {
    pub flgs_res0_ver: [u8; 2],
    pub proto: [u8; 2]
}

/// Represents a complete GRE (Generic Routing Encapsulation) header.
///
/// This struct contains the fixed part of the GRE header and optional fields
/// that may be present depending on the flags set in the fixed header.
///
/// # Fields
/// * `fixed`: The fixed part of the GRE header.
/// * `opt1`: First optional field (checksum/reserved1 if C flag is set, key if K flag is set, sequence number if S flag is set).
/// * `opt2`: Second optional field (key if both C and K flags are set, sequence number if C or K flag is set).
/// * `opt3`: Third optional field (sequence number if both C and K flags are set).
#[derive(Debug, Copy, Clone, Default)]
pub struct GreHdr {
    pub fixed: GreFixedHdr,
    pub opt1: [u8; 4],
    pub opt2: [u8; 4],
    pub opt3: [u8; 4],
}

impl GreHdr {
    /// The total size of a `GreHdr` in bytes, including all optional fields.
    pub const LEN: usize = size_of::<GreHdr>();

    /// Creates a new `GreHdr` with the specified fixed header and zeroed optional fields.
    ///
    /// # Parameters
    /// * `fixed`: The fixed part of the GRE header.
    ///
    /// # Returns
    /// A new `GreHdr` instance with the provided fixed header and zeroed optional fields.
    pub fn new(fixed: GreFixedHdr) -> Self {
        Self {
            fixed,
            opt1: [0; 4],
            opt2: [0; 4],
            opt3: [0; 4],
        }
    }

    /// Checks if the Checksum Present flag (C) is set.
    ///
    /// # Returns
    /// `true` if the Checksum Present flag is set, `false` otherwise.
    #[inline]
    pub fn ck_flg(&self) -> bool {
        self.fixed.flgs_res0_ver[0] & C_FLAG_MASK != 0
    }

    /// Sets or clears the Checksum Present flag (C).
    ///
    /// # Parameters
    /// * `ck_flg`: `true` to set the flag, `false` to clear it.
    #[inline]
    pub fn set_ck_flg(&mut self, ck_flg: bool) {
        if ck_flg {
            self.fixed.flgs_res0_ver[0] |= C_FLAG_MASK;
        } else {
            self.fixed.flgs_res0_ver[0] &= !C_FLAG_MASK;
        }
    }

    /// Checks if the Key Present flag (K) is set.
    ///
    /// # Returns
    /// `true` if the Key Present flag is set, `false` otherwise.
    #[inline]
    pub fn key_flg(&self) -> bool {
        self.fixed.flgs_res0_ver[0] & K_FLAG_MASK != 0
    }

    /// Sets or clears the Key Present flag (K).
    ///
    /// # Parameters
    /// * `key_flg`: `true` to set the flag, `false` to clear it.
    #[inline]
    pub fn set_key_flg(&mut self, key_flg: bool) {
        if key_flg {
            self.fixed.flgs_res0_ver[0] |= K_FLAG_MASK;
        } else {
            self.fixed.flgs_res0_ver[0] &= !K_FLAG_MASK;
        }
    }

    /// Checks if the Sequence Number Present flag (S) is set.
    ///
    /// # Returns
    /// `true` if the Sequence Number Present flag is set, `false` otherwise.
    #[inline]
    pub fn seq_flg(&self) -> bool {
        self.fixed.flgs_res0_ver[0] & S_FLAG_MASK != 0
    }

    /// Sets or clears the Sequence Number Present flag (S).
    ///
    /// # Parameters
    /// * `seq_flg`: `true` to set the flag, `false` to clear it.
    #[inline]
    pub fn set_seq_flg(&mut self, seq_flg: bool) {
        if seq_flg {
            self.fixed.flgs_res0_ver[0] |= S_FLAG_MASK;
        } else {
            self.fixed.flgs_res0_ver[0] &= !S_FLAG_MASK;
        }
    }

    /// Reads the version number from the header bytes.
    /// This method is left as-is to allow validation of incoming packets.
    #[inline]
    pub fn version(&self) -> u8 {
        self.fixed.flgs_res0_ver[1] & VER_MASK
    }

    /// Sets the GRE version. Per RFC 2784, the version MUST be 0.
    /// This method enforces this by ignoring the input and always setting the version to 0.
    #[inline]
    pub fn set_version(&mut self, _version: u8) {
        // This clears the version bits in the flag byte, enforcing version 0.
        self.fixed.flgs_res0_ver[1] &= !VER_MASK;
    }

    /// Gets the Protocol Type field from the GRE header.
    ///
    /// This field indicates the protocol type of the payload packet.
    /// Common values include 0x0800 for IPv4 and 0x86DD for IPv6.
    ///
    /// # Returns
    /// The protocol type as a 16-bit unsigned integer in host byte order.
    #[inline]
    pub fn proto(&self) -> u16 {
        u16::from_be_bytes(self.fixed.proto)
    }

    /// Sets the Protocol Type field in the GRE header.
    ///
    /// # Parameters
    /// * `proto`: The protocol type as a 16-bit unsigned integer in host byte order.
    ///           Common values include 0x0800 for IPv4 and 0x86DD for IPv6.
    #[inline]
    pub fn set_proto(&mut self, proto: u16) {
        self.fixed.proto = proto.to_be_bytes();
    }

    /// Gets the Checksum and Reserved1 field from the GRE header.
    ///
    /// This field is only present if the Checksum Present flag (C) is set.
    /// The first 16 bits contain the checksum, and the second 16 bits are reserved.
    ///
    /// # Returns
    /// The 32-bit value containing both the checksum and reserved1 fields in host byte order.
    /// Returns 0 if the Checksum Present flag is not set.
    pub fn ck_res1(&self) -> u32 {
        if !self.ck_flg() {
            return 0;
        }
        u32::from_be_bytes(self.opt1)
    }

    /// Sets the Checksum and Reserved1 field in the GRE header.
    ///
    /// This method also sets the Checksum Present flag (C) if it's not already set,
    /// and rearranges the optional fields as needed.
    ///
    /// # Parameters
    /// * `ck_res1`: The 32-bit value containing both the checksum and reserved1 fields in host byte order.
    #[inline]
    pub fn set_ck_res1(&mut self, ck_res1: u32) {
        if !self.ck_flg() {
            self.opt3 = self.opt2;
            self.opt2 = self.opt1;
            self.set_ck_flg(true);
        }
        self.opt1 = ck_res1.to_be_bytes();
    }

    /// Gets the Key field from the GRE header.
    ///
    /// This field is only present if the Key Present flag (K) is set.
    /// The position of the Key field depends on whether the Checksum Present flag (C) is also set.
    ///
    /// # Returns
    /// The 32-bit Key value in host byte order.
    /// Returns 0 if the Key Present flag is not set.
    #[inline]
    pub fn key(&self) -> u32 {
        if !self.key_flg() {
            return 0;
        }

        if self.ck_flg() {
            u32::from_be_bytes(self.opt2)
        } else {
            u32::from_be_bytes(self.opt1)
        }
    }

    /// Sets the Key field in the GRE header.
    ///
    /// This method also sets the Key Present flag (K) if it's not already set,
    /// and rearranges the optional fields as needed based on which other flags are set.
    ///
    /// # Parameters
    /// * `key`: The 32-bit Key value in host byte order.
    #[inline]
    pub fn set_key(&mut self, key: u32) {
        if !self.key_flg() {
            if self.ck_flg() {
                self.opt3 = self.opt2;
            } else {
                self.opt2 = self.opt1;
            }
            self.set_key_flg(true);
        }

        if self.ck_flg() {
            self.opt2 = key.to_be_bytes();
        } else {
            self.opt1 = key.to_be_bytes();
        }
    }

    /// Gets the Sequence Number field from the GRE header.
    ///
    /// This field is only present if the Sequence Number Present flag (S) is set.
    /// The position of the Sequence Number field depends on whether the Checksum Present flag (C)
    /// and/or the Key Present flag (K) are also set.
    ///
    /// # Returns
    /// The 32-bit Sequence Number value in host byte order.
    /// Returns 0 if the Sequence Number Present flag is not set.
    #[inline]
    pub fn seq(&self) -> u32 {
        if !self.seq_flg() {
            return 0;
        }

        if self.ck_flg() && self.key_flg() {
            u32::from_be_bytes(self.opt3)
        } else if self.ck_flg() || self.key_flg() {
            u32::from_be_bytes(self.opt2)
        } else {
            u32::from_be_bytes(self.opt1)
        }
    }

    /// Sets the Sequence Number field in the GRE header.
    ///
    /// This method also sets the Sequence Number Present flag (S) if it's not already set.
    /// The position where the Sequence Number is stored depends on whether the Checksum Present flag (C)
    /// and/or the Key Present flag (K) are also set.
    ///
    /// # Parameters
    /// * `seq`: The 32-bit Sequence Number value in host byte order.
    #[inline]
    pub fn set_seq(&mut self, seq: u32) {
        if !self.seq_flg() {
            self.set_seq_flg(true);
        }

        if self.ck_flg() && self.key_flg() {
            self.opt3 = seq.to_be_bytes();
        } else if self.ck_flg() || self.key_flg() {
            self.opt2 = seq.to_be_bytes();
        } else {
            self.opt1 = seq.to_be_bytes();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    // Helper to create a default GreFixedHdr for tests
    fn default_gre_fixed_hdr() -> GreFixedHdr {
        GreFixedHdr {
            flgs_res0_ver: [0; 2],
            proto: [0; 2],
        }
    }

    // Helper to create a default GreHdr for tests
    fn default_gre_hdr() -> GreHdr {
        GreHdr {
            fixed: default_gre_fixed_hdr(),
            opt1: [0; 4],
            opt2: [0; 4],
            opt3: [0; 4],
        }
    }

    #[test]
    fn test_gre_hdr_size() {
        assert_eq!(size_of::<GreHdr>(), 16); // 4 bytes fixed + 3 * 4 bytes optional
    }

    #[test]
    fn test_gre_hdr_new() {
        let fixed = default_gre_fixed_hdr();
        let hdr = GreHdr::new(fixed);

        assert_eq!(hdr.fixed.flgs_res0_ver, [0; 2]);
        assert_eq!(hdr.fixed.proto, [0; 2]);
        assert_eq!(hdr.opt1, [0; 4]);
        assert_eq!(hdr.opt2, [0; 4]);
        assert_eq!(hdr.opt3, [0; 4]);
    }

    #[test]
    fn test_ck_flg() {
        let mut hdr = default_gre_hdr();

        // Initially false
        assert_eq!(hdr.ck_flg(), false);

        // Set to true
        hdr.set_ck_flg(true);
        assert_eq!(hdr.ck_flg(), true);
        assert_eq!(hdr.fixed.flgs_res0_ver[0] & C_FLAG_MASK, C_FLAG_MASK);

        // Set to false
        hdr.set_ck_flg(false);
        assert_eq!(hdr.ck_flg(), false);
        assert_eq!(hdr.fixed.flgs_res0_ver[0] & C_FLAG_MASK, 0);
    }

    #[test]
    fn test_key_flg() {
        let mut hdr = default_gre_hdr();

        // Initially false
        assert_eq!(hdr.key_flg(), false);

        // Set to true
        hdr.set_key_flg(true);
        assert_eq!(hdr.key_flg(), true);
        assert_eq!(hdr.fixed.flgs_res0_ver[0] & K_FLAG_MASK, K_FLAG_MASK);

        // Set to false
        hdr.set_key_flg(false);
        assert_eq!(hdr.key_flg(), false);
        assert_eq!(hdr.fixed.flgs_res0_ver[0] & K_FLAG_MASK, 0);
    }

    #[test]
    fn test_seq_flg() {
        let mut hdr = default_gre_hdr();

        // Initially false
        assert_eq!(hdr.seq_flg(), false);

        // Set to true
        hdr.set_seq_flg(true);
        assert_eq!(hdr.seq_flg(), true);
        assert_eq!(hdr.fixed.flgs_res0_ver[0] & S_FLAG_MASK, S_FLAG_MASK);

        // Set to false
        hdr.set_seq_flg(false);
        assert_eq!(hdr.seq_flg(), false);
        assert_eq!(hdr.fixed.flgs_res0_ver[0] & S_FLAG_MASK, 0);
    }

    #[test]
    fn test_version() {
        let mut hdr = default_gre_hdr();

        // Initially 0
        assert_eq!(hdr.version(), 0);

        // Set to 1, but set_version should force it to 0.
        hdr.set_version(1);
        assert_eq!(hdr.version(), 0);

        // Set to max valid value (7); should still be forced to 0.
        hdr.set_version(7);
        assert_eq!(hdr.version(), 0);
    }

    #[test]
    fn test_proto() {
        let mut hdr = default_gre_hdr();

        // Initially 0
        assert_eq!(hdr.proto(), 0);

        // Set to IPv4 (0x0800)
        hdr.set_proto(0x0800);
        assert_eq!(hdr.proto(), 0x0800);

        // Set to IPv6 (0x86DD)
        hdr.set_proto(0x86DD);
        assert_eq!(hdr.proto(), 0x86DD);
    }

    #[test]
    fn test_ck_res1() {
        let mut hdr = default_gre_hdr();

        // Initially 0 when flag is not set
        assert_eq!(hdr.ck_flg(), false);
        assert_eq!(hdr.ck_res1(), 0);

        // Set checksum
        let test_ck = 0x12345678;
        hdr.set_ck_res1(test_ck);

        // Flag should be set and value should be stored
        assert_eq!(hdr.ck_flg(), true);
        assert_eq!(hdr.ck_res1(), test_ck);
        assert_eq!(hdr.opt1, test_ck.to_be_bytes());
    }

    #[test]
    fn test_key() {
        let mut hdr = default_gre_hdr();

        // Initially 0 when flag is not set
        assert_eq!(hdr.key_flg(), false);

        // Set key when no other flags are set
        let test_key = 0xABCDEF01;
        hdr.set_key(test_key);

        // Flag should be set and value should be stored in opt1
        assert_eq!(hdr.key_flg(), true);
        assert_eq!(hdr.key(), test_key);
        assert_eq!(hdr.opt1, test_key.to_be_bytes());

        // Reset and test with checksum flag set
        hdr = default_gre_hdr();
        hdr.set_ck_flg(true);
        hdr.opt1 = [0x11, 0x22, 0x33, 0x44]; // Set checksum value

        // Set key when checksum flag is set
        hdr.set_key(test_key);

        // Key should be stored in opt2
        assert_eq!(hdr.key_flg(), true);
        assert_eq!(hdr.key(), test_key);
        assert_eq!(hdr.opt2, test_key.to_be_bytes());
    }

    #[test]
    fn test_seq() {
        let mut hdr = default_gre_hdr();

        // Initially 0 when flag is not set
        assert_eq!(hdr.seq_flg(), false);

        // Set sequence when no other flags are set
        let test_seq = 0x12345678;
        hdr.set_seq(test_seq);

        // Flag should be set and value should be stored in opt1
        assert_eq!(hdr.seq_flg(), true);
        assert_eq!(hdr.seq(), test_seq);
        assert_eq!(hdr.opt1, test_seq.to_be_bytes());

        // Reset and test with checksum flag set
        hdr = default_gre_hdr();
        hdr.set_ck_flg(true);
        hdr.opt1 = [0x11, 0x22, 0x33, 0x44]; // Set checksum value

        // Set sequence when checksum flag is set
        hdr.set_seq(test_seq);

        // Sequence should be stored in opt2
        assert_eq!(hdr.seq_flg(), true);
        assert_eq!(hdr.seq(), test_seq);
        assert_eq!(hdr.opt2, test_seq.to_be_bytes());

        // Reset and test with key flag set
        hdr = default_gre_hdr();
        hdr.set_key_flg(true);
        hdr.opt1 = [0xAA, 0xBB, 0xCC, 0xDD]; // Set key value

        // Set sequence when key flag is set
        hdr.set_seq(test_seq);

        // Sequence should be stored in opt2
        assert_eq!(hdr.seq_flg(), true);
        assert_eq!(hdr.seq(), test_seq);
        assert_eq!(hdr.opt2, test_seq.to_be_bytes());

        // Reset and test with both checksum and key flags set
        hdr = default_gre_hdr();
        hdr.set_ck_flg(true);
        hdr.set_key_flg(true);
        hdr.opt1 = [0x11, 0x22, 0x33, 0x44]; // Set checksum value
        hdr.opt2 = [0xAA, 0xBB, 0xCC, 0xDD]; // Set key value

        // Set sequence when both flags are set
        hdr.set_seq(test_seq);

        // Sequence should be stored in opt3
        assert_eq!(hdr.seq_flg(), true);
        assert_eq!(hdr.seq(), test_seq);
        assert_eq!(hdr.opt3, test_seq.to_be_bytes());
    }

    #[test]
    fn test_multiple_flags() {
        let mut hdr = default_gre_hdr();

        // Set all flags and values
        let test_ck = 0x11223344;
        let test_key = 0xAABBCCDD;
        let test_seq = 0x55667788;

        hdr.set_ck_res1(test_ck);
        hdr.set_key(test_key);
        hdr.set_seq(test_seq);

        // All flags should be set
        assert_eq!(hdr.ck_flg(), true);
        assert_eq!(hdr.key_flg(), true);
        assert_eq!(hdr.seq_flg(), true);

        // Values should be stored in the correct fields
        assert_eq!(hdr.ck_res1(), test_ck);
        assert_eq!(hdr.key(), test_key);
        assert_eq!(hdr.seq(), test_seq);

        assert_eq!(hdr.opt1, test_ck.to_be_bytes());
        assert_eq!(hdr.opt2, test_key.to_be_bytes());
        assert_eq!(hdr.opt3, test_seq.to_be_bytes());
    }
}
