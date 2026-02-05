use core::mem;

use crate::bitfield::BitfieldU16;

pub const TCP_HDR_LEN: usize = mem::size_of::<TcpHdr>();

/// TCP header, which is present after the IP header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TcpHdr {
    pub source: [u8; 2],
    pub dest: [u8; 2],
    pub seq: [u8; 4],
    pub ack_seq: [u8; 4],
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: BitfieldU16,
    pub window: [u8; 2],
    pub check: [u8; 2],
    pub urg_ptr: [u8; 2],
}

impl TcpHdr {
    pub const LEN: usize = mem::size_of::<TcpHdr>();

    #[inline]
    pub fn res1(&self) -> u16 {
        self._bitfield_1.get(0usize, 4u8) as u16
    }
    #[inline]
    pub fn set_res1(&mut self, val: u16) {
        self._bitfield_1.set(0usize, 4u8, val.into())
    }
    #[inline]
    pub fn doff(&self) -> u16 {
        self._bitfield_1.get(4usize, 4u8) as u16
    }
    #[inline]
    pub fn set_doff(&mut self, val: u16) {
        self._bitfield_1.set(4usize, 4u8, val.into())
    }
    #[inline]
    pub fn fin(&self) -> u16 {
        self._bitfield_1.get(8usize, 1u8) as u16
    }
    #[inline]
    pub fn set_fin(&mut self, val: u16) {
        self._bitfield_1.set(8usize, 1u8, val.into())
    }
    #[inline]
    pub fn syn(&self) -> u16 {
        self._bitfield_1.get(9usize, 1u8) as u16
    }
    #[inline]
    pub fn set_syn(&mut self, val: u16) {
        self._bitfield_1.set(9usize, 1u8, val.into())
    }
    #[inline]
    pub fn rst(&self) -> u16 {
        self._bitfield_1.get(10usize, 1u8) as u16
    }
    #[inline]
    pub fn set_rst(&mut self, val: u16) {
        self._bitfield_1.set(10usize, 1u8, val.into())
    }
    #[inline]
    pub fn psh(&self) -> u16 {
        self._bitfield_1.get(11usize, 1u8) as u16
    }
    #[inline]
    pub fn set_psh(&mut self, val: u16) {
        self._bitfield_1.set(11usize, 1u8, val.into())
    }
    #[inline]
    pub fn ack(&self) -> u16 {
        self._bitfield_1.get(12usize, 1u8) as u16
    }
    #[inline]
    pub fn set_ack(&mut self, val: u16) {
        self._bitfield_1.set(12usize, 1u8, val.into())
    }
    #[inline]
    pub fn urg(&self) -> u16 {
        self._bitfield_1.get(13usize, 1u8) as u16
    }
    #[inline]
    pub fn set_urg(&mut self, val: u16) {
        self._bitfield_1.set(13usize, 1u8, val.into())
    }
    #[inline]
    pub fn ece(&self) -> u16 {
        self._bitfield_1.get(14usize, 1u8) as u16
    }
    #[inline]
    pub fn set_ece(&mut self, val: u16) {
        self._bitfield_1.set(14usize, 1u8, val.into())
    }
    #[inline]
    pub fn cwr(&self) -> u16 {
        self._bitfield_1.get(15usize, 1u8) as u16
    }
    #[inline]
    pub fn set_cwr(&mut self, val: u16) {
        self._bitfield_1.set(15usize, 1u8, val.into())
    }
    #[inline]
    #[expect(clippy::too_many_arguments)]
    pub fn new_bitfield_1(
        res1: u16,
        doff: u16,
        fin: u16,
        syn: u16,
        rst: u16,
        psh: u16,
        ack: u16,
        urg: u16,
        ece: u16,
        cwr: u16,
    ) -> BitfieldU16 {
        let mut bitfield_unit: BitfieldU16 = Default::default();
        bitfield_unit.set(0usize, 4u8, res1.into());
        bitfield_unit.set(4usize, 4u8, doff.into());
        bitfield_unit.set(8usize, 1u8, fin.into());
        bitfield_unit.set(9usize, 1u8, syn.into());
        bitfield_unit.set(10usize, 1u8, rst.into());
        bitfield_unit.set(11usize, 1u8, psh.into());
        bitfield_unit.set(12usize, 1u8, ack.into());
        bitfield_unit.set(13usize, 1u8, urg.into());
        bitfield_unit.set(14usize, 1u8, ece.into());
        bitfield_unit.set(15usize, 1u8, cwr.into());
        bitfield_unit
    }
}
