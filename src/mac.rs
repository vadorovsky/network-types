use crate::bitfield::BitfieldUnit;

#[repr(C, packed)]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MacHdr {
    _bitfield_frame_ctl: BitfieldUnit<[u8; 2]>,
    duration_id: [u8; 2],
    address1: [u8; 6],
    address2: [u8; 6],
    address3: [u8; 6],
    sequence_ctl: [u8; 2],
    address4: [u8; 6],
    qos_ctl: [u8; 2],
}

impl MacHdr {
    pub const LEN: usize = ::core::mem::size_of::<MacHdr>();

    #[inline]
    pub fn protocol_version(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(0, 2) as u16) }
    }
    #[inline]
    pub fn set_protocol_version(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(0, 2, val as u64)
        }
    }
    #[inline]
    pub fn ty(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(2, 4) as u16) }
    }
    #[inline]
    pub fn set_ty(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(2, 4, val as u64)
        }
    }
    #[inline]
    pub fn sub_ty(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(4, 8) as u16) }
    }
    #[inline]
    pub fn set_sub_ty(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(4, 8, val as u64)
        }
    }
    #[inline]
    pub fn tds(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(8, 9) as u16) }
    }
    #[inline]
    pub fn set_tds(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(8, 9, val as u64)
        }
    }
    #[inline]
    pub fn fds(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(9, 10) as u16) }
    }
    // set to from_ds
    #[inline]
    pub fn set_fds(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(9, 10, val as u64)
        }
    }
    #[inline]
    pub fn mflag(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(10, 11) as u16) }
    }
    #[inline]
    pub fn set_mflag(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(10, 11, val as u64)
        }
    }
    #[inline]
    pub fn retry(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(11, 12) as u16) }
    }
    #[inline]
    pub fn set_retry(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(11, 12, val as u64)
        }
    }
    #[inline]
    pub fn pmgmt(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(12, 13) as u16) }
    }
    // set to power_mgmt
    #[inline]
    pub fn set_pmgmt(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(12, 13, val as u64)
        }
    }
    #[inline]
    pub fn mdata(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(13, 14) as u16) }
    }
    // set to power_mgmt
    #[inline]
    pub fn set_mdata(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(13, 14, val as u64)
        }
    }
    #[inline]
    pub fn protected_frame(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(14, 15) as u16) }
    }
    #[inline]
    pub fn set_protected_frame(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(14, 15, val as u64)
        }
    }
    #[inline]
    pub fn order(&self) -> u16 {
        unsafe { ::core::mem::transmute(self._bitfield_frame_ctl.get(15, 16) as u16) }
    }
    #[inline]
    pub fn set_order(&mut self, val: u16) {
        unsafe {
            let val: u16 = ::core::mem::transmute(val);
            self._bitfield_frame_ctl.set(15, 16, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_frame_ctl(
        protocol_version: u16,
        ty: u16,
        sub_ty: u16,
        tds: u16,
        fds: u16,
        mflag: u16,
        retry: u16,
        pmgmt: u16,
        mdata: u16,
        protected_frame: u16,
        order: u16,
    ) -> BitfieldUnit<[u8; 2usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 2]> = Default::default();
        bitfield_unit.set(0, 2, {
            let protocol_version: u16 = unsafe { ::core::mem::transmute(protocol_version) };
            protocol_version as u64
        });
        bitfield_unit.set(2, 2, {
            let ty: u16 = unsafe { ::core::mem::transmute(ty) };
            ty as u64
        });
        bitfield_unit.set(4, 4, {
            let sub_ty: u16 = unsafe { ::core::mem::transmute(sub_ty) };
            sub_ty as u64
        });
        bitfield_unit.set(8, 1, {
            let tds: u16 = unsafe { ::core::mem::transmute(tds) };
            tds as u64
        });
        bitfield_unit.set(9, 1, {
            let fds: u16 = unsafe { ::core::mem::transmute(fds) };
            fds as u64
        });
        bitfield_unit.set(10, 1, {
            let mflag: u16 = unsafe { ::core::mem::transmute(mflag) };
            mflag as u64
        });
        bitfield_unit.set(11, 1, {
            let retry: u16 = unsafe { ::core::mem::transmute(retry) };
            retry as u64
        });
        bitfield_unit.set(12, 1, {
            let pmgmt: u16 = unsafe { ::core::mem::transmute(pmgmt) };
            pmgmt as u64
        });
        bitfield_unit.set(13, 1, {
            let mdata: u16 = unsafe { ::core::mem::transmute(mdata) };
            mdata as u64
        });
        bitfield_unit.set(14, 1, {
            let protected_frame: u16 = unsafe { ::core::mem::transmute(protected_frame) };
            protected_frame as u64
        });
        bitfield_unit.set(15, 1, {
            let order: u16 = unsafe { ::core::mem::transmute(order) };
            order as u64
        });
        bitfield_unit
    }
}