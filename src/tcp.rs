use core::mem;

use crate::bitfield::BitfieldUnit;

pub const TCP_HDR_LEN: usize = mem::size_of::<TcpHdr>();

/// TCP header, which is present after the IP header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: BitfieldUnit<[u8; 2usize]>,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

impl TcpHdr {
    pub const LEN: usize = mem::size_of::<TcpHdr>();

    #[inline]
    pub fn res1(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u16) }
    }
    #[inline]
    pub fn set_res1(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn doff(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(4usize, 4u8) as u16) }
    }
    #[inline]
    pub fn set_doff(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn fin(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(8usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_fin(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(8usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn syn(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(9usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_syn(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(9usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn rst(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(10usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_rst(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(10usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn psh(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(11usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_psh(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(11usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn ack(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(12usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_ack(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(12usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn urg(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(13usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_urg(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(13usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn ece(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(14usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_ece(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(14usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn cwr(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(15usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set_cwr(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_1.set(15usize, 1u8, val as u64)
        }
    }
    #[inline]
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
    ) -> BitfieldUnit<[u8; 2usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 2usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, {
            let res1: u16 = unsafe { ::core::mem::transmute(res1) };
            res1 as u64
        });
        bitfield_unit.set(4usize, 4u8, {
            let doff: u16 = unsafe { ::core::mem::transmute(doff) };
            doff as u64
        });
        bitfield_unit.set(8usize, 1u8, {
            let fin: u16 = unsafe { ::core::mem::transmute(fin) };
            fin as u64
        });
        bitfield_unit.set(9usize, 1u8, {
            let syn: u16 = unsafe { ::core::mem::transmute(syn) };
            syn as u64
        });
        bitfield_unit.set(10usize, 1u8, {
            let rst: u16 = unsafe { ::core::mem::transmute(rst) };
            rst as u64
        });
        bitfield_unit.set(11usize, 1u8, {
            let psh: u16 = unsafe { ::core::mem::transmute(psh) };
            psh as u64
        });
        bitfield_unit.set(12usize, 1u8, {
            let ack: u16 = unsafe { ::core::mem::transmute(ack) };
            ack as u64
        });
        bitfield_unit.set(13usize, 1u8, {
            let urg: u16 = unsafe { ::core::mem::transmute(urg) };
            urg as u64
        });
        bitfield_unit.set(14usize, 1u8, {
            let ece: u16 = unsafe { ::core::mem::transmute(ece) };
            ece as u64
        });
        bitfield_unit.set(15usize, 1u8, {
            let cwr: u16 = unsafe { ::core::mem::transmute(cwr) };
            cwr as u64
        });
        bitfield_unit
    }
}
