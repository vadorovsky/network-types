#![doc = include_str!("../README.md")]
#![no_std]

pub mod arp;
pub mod bitfield;
pub mod eth;
pub mod geneve;
pub mod icmp;
pub mod igmp;
pub mod ip;
pub mod llc;
pub mod mac;
pub mod mpls;
pub mod sctp;
pub mod tcp;
pub mod udp;
pub mod vlan;
pub mod vxlan;

/// Gets the value of the given big-endian field using pointer arithmetic, raw
/// pointer conversion and, if the target is little-endian, the `swap_bytes`
/// method. That performs better than `from_be_bytes`.
///
/// # Safety
///
/// Caller needs to ensure that the provided field name is in bounds of the struct.
/// Caller needs to ensure that the targeted field is aligned
#[cfg(target_endian = "big")]
#[macro_export]
macro_rules! getter_be {
    ($self:expr, $field:ident, $ty:ty) => {
        ::core::ptr::read(
            (($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field)) as *const $ty,
        )
    };
}
#[cfg(target_endian = "little")]
#[macro_export]
macro_rules! getter_be {
    ($self:expr, $field:ident, $ty:ty) => {
        ::core::ptr::read(
            (($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field)) as *const $ty,
        )
        .swap_bytes()
    };
}

/// Sets the value of the given big-endian field using pointer arithmetic, raw
/// pointer conversion and, if the target is litte-endian, the `swap_bytes`
/// method. That performs better than `to_be_bytes`.
///
/// # Safety
///
/// Caller needs to ensure that the provided field name is in bounds of the struct.
#[cfg(target_endian = "big")]
#[macro_export]
macro_rules! setter_be {
    ($self:expr, $field:ident, $val:expr) => {
        // SAFETY: Pointer arithmetics in bounds of the given struct.
        $self.$field = *((&$val as *const _ as usize) as *const _);
    };
}
#[cfg(target_endian = "little")]
#[macro_export]
macro_rules! setter_be {
    ($self:expr, $field:ident, $val:expr) => {
        // SAFETY: Pointer arithmetics in bounds of the given struct.
        $self.$field = *((&$val.swap_bytes() as *const _ as usize) as *const _)
    };
}
