use core::mem;

use crate::bitfield::BitfieldUnit;

/// VXLAN header, which is present at the beginning of every UDP payload containing VXLAN packets.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VxlanHdr {
    /// VXLAN flags. See [`VxlanHdr::vni_valid`] and [`VxlanHdr::set_vni_valid`].
    pub flags: BitfieldUnit<[u8; 1usize]>,
    pub _reserved: [u8; 3],
    /// VXLAN Virtual Network Identifier.
    ///
    /// This is a 24-bit number combined with reserved bytes, see [`VxlanHdr::vni`] and
    /// [`VxlanHdr::set_vni`].
    pub vni: u32,
}

impl VxlanHdr {
    pub const LEN: usize = mem::size_of::<Self>();

    #[inline]
    pub fn vni_valid(&self) -> bool {
        self.flags.get_bit(4)
    }

    #[inline]
    pub fn set_vni_valid(&mut self, val: bool) {
        self.flags.set_bit(4, val)
    }

    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be(self.vni) >> 8
    }

    #[inline]
    pub fn set_vni(&mut self, vni: u32) -> u32 {
        (vni << 8).to_be()
    }
}
