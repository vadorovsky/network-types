#![doc = include_str!("../README.md")]
#![no_std]

pub mod arp;
pub mod bitfield;
pub mod eth;
pub mod geneve;
pub mod icmp;
pub mod ip;
pub mod llc;
pub mod mac;
pub mod mpls;
pub mod sctp;
pub mod tcp;
pub mod udp;
pub mod vlan;
pub mod vxlan;

#[cfg(target_endian = "big")]
#[macro_export]
macro_rules! getter_be {
    ($self:expr, $field:ident, $ty:ty) => {
        // SAFETY: Pointer arithmetics is done in bounds of the given struct.
        // The byte arrays are always used as a storage for integer types and
        // have an appropriate size.
        unsafe {
            ::core::ptr::read_unaligned(
                (($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field))
                    as *const $ty,
            )
        }
    };
}

#[cfg(target_endian = "little")]
#[macro_export]
macro_rules! getter_be {
    ($self:expr, $field:ident, $ty:ty) => {
        // SAFETY: Pointer arithmetics in bounds of the given struct.
        // The byte arrays are always used as a storage for integer types and
        // have an appropriate size.
        unsafe {
            ::core::ptr::read_unaligned(
                (($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field))
                    as *const $ty,
            )
        }
        .swap_bytes()
    };
}

#[cfg(target_endian = "big")]
#[macro_export]
macro_rules! setter_be {
    ($self:expr, $field:ident, $val:expr) => {
        // SAFETY: Pointer arithmetics in bounds of the given struct.
        unsafe {
            $self.$field = *((&$val as *const _ as usize) as *const _);
        }
    };
}

#[cfg(target_endian = "little")]
#[macro_export]
macro_rules! setter_be {
    ($self:expr, $field:ident, $val:expr) => {
        // SAFETY: Pointer arithmetics in bounds of the given struct.
        unsafe {
            $self.$field = *((&$val.swap_bytes() as *const _ as usize) as *const _);
        }
    };
}
