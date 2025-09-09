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
    ($self:expr, $field:ident, $ty:ty) => {{
        #[cfg(test)]
        if ((($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field))
            % ::core::mem::align_of::<$ty>()
            != 0)
        {
            panic!(
                "getter_be called on unaligned field {} ptr 0x{:x} align {} base_ptr 0x{:x} offset {} modulo {}",
                stringify!($field),
                ($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field),
                ::core::mem::align_of::<$ty>(),
		$self as *const Self as usize,
                ::memoffset::offset_of!(Self, $field),
                (($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field))
                    % ::core::mem::align_of::<$ty>(),
            );
        }

        ::core::ptr::read(
            (($self as *const Self as usize) + ::memoffset::offset_of!(Self, $field)) as *const $ty,
        )
        .swap_bytes()
    }};
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

#[cfg(test)]
mod test {
    use super::*;

    #[repr(C, packed)]
    #[derive(Default)]
    struct HdrWithUnalignedFields {
        a: u8,  // Aligned
        b: u16, // Non-alligned
    }

    impl HdrWithUnalignedFields {
        fn b(&self) -> u16 {
            unsafe { getter_be!(self, b, u16) }
        }

        fn set_b(&mut self, b: u16) {
            unsafe { setter_be!(self, b, b) }
        }
    }

    #[test]
    fn test_unaligned_read() {
        let mut hdr = HdrWithUnalignedFields::default();
        let b_val = 1657;
        hdr.set_b(b_val);
        assert_eq!(hdr.b(), b_val) // Should panic
    }
}
