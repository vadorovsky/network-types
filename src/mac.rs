use crate::bitfield::BitfieldU16;

#[repr(C, packed)]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacHdr {
    _bitfield_frame_ctl: BitfieldU16,
    duration_id: [u8; 2],
    address1: [u8; 6],
    address2: [u8; 6],
    address3: [u8; 6],
    sequence_ctl: [u8; 2],
    address4: [u8; 6],
    qos_ctl: [u8; 2],
}

impl MacHdr {
    pub const LEN: usize = core::mem::size_of::<MacHdr>();

    #[inline]
    pub fn protocol_version(&self) -> u16 {
        self._bitfield_frame_ctl.get(0, 2) as u16
    }
    #[inline]
    pub fn set_protocol_version(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(0, 2, val.into())
    }
    #[inline]
    pub fn ty(&self) -> u16 {
        self._bitfield_frame_ctl.get(2, 4) as u16
    }
    #[inline]
    pub fn set_ty(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(2, 4, val.into())
    }
    #[inline]
    pub fn sub_ty(&self) -> u16 {
        self._bitfield_frame_ctl.get(4, 8) as u16
    }
    #[inline]
    pub fn set_sub_ty(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(4, 8, val.into())
    }
    #[inline]
    pub fn tds(&self) -> u16 {
        self._bitfield_frame_ctl.get(8, 9) as u16
    }
    #[inline]
    pub fn set_tds(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(8, 9, val.into())
    }
    #[inline]
    pub fn fds(&self) -> u16 {
        self._bitfield_frame_ctl.get(9, 10) as u16
    }
    // set to from_ds
    #[inline]
    pub fn set_fds(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(9, 10, val.into())
    }
    #[inline]
    pub fn mflag(&self) -> u16 {
        self._bitfield_frame_ctl.get(10, 11) as u16
    }
    #[inline]
    pub fn set_mflag(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(10, 11, val.into())
    }
    #[inline]
    pub fn retry(&self) -> u16 {
        self._bitfield_frame_ctl.get(11, 12) as u16
    }
    #[inline]
    pub fn set_retry(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(11, 12, val.into())
    }
    #[inline]
    pub fn pmgmt(&self) -> u16 {
        self._bitfield_frame_ctl.get(12, 13) as u16
    }
    // set to power_mgmt
    #[inline]
    pub fn set_pmgmt(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(12, 13, val.into())
    }
    #[inline]
    pub fn mdata(&self) -> u16 {
        self._bitfield_frame_ctl.get(13, 14) as u16
    }
    // set to power_mgmt
    #[inline]
    pub fn set_mdata(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(13, 14, val.into())
    }
    #[inline]
    pub fn protected_frame(&self) -> u16 {
        self._bitfield_frame_ctl.get(14, 15) as u16
    }
    #[inline]
    pub fn set_protected_frame(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(14, 15, val.into())
    }
    #[inline]
    pub fn order(&self) -> u16 {
        self._bitfield_frame_ctl.get(15, 16) as u16
    }
    #[inline]
    pub fn set_order(&mut self, val: u16) {
        self._bitfield_frame_ctl.set(15, 16, val.into())
    }
    #[inline]
    #[expect(clippy::too_many_arguments)]
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
    ) -> BitfieldU16 {
        let mut bitfield_unit: BitfieldU16 = Default::default();
        bitfield_unit.set(0, 2, protocol_version.into());
        bitfield_unit.set(2, 2, ty.into());
        bitfield_unit.set(4, 4, sub_ty.into());
        bitfield_unit.set(8, 1, tds.into());
        bitfield_unit.set(9, 1, fds.into());
        bitfield_unit.set(10, 1, mflag.into());
        bitfield_unit.set(11, 1, retry.into());
        bitfield_unit.set(12, 1, pmgmt.into());
        bitfield_unit.set(13, 1, mdata.into());
        bitfield_unit.set(14, 1, protected_frame.into());
        bitfield_unit.set(15, 1, order.into());
        bitfield_unit
    }
}
