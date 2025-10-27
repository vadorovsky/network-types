//! A Rust bitfield implementation, copied from
//! [bindgen](https://github.com/rust-lang/rust-bindgen/blob/master/bindgen/codegen/bitfield_unit.rs)
//! which is licensed under the
//! [BSD 3-Clause license](https://github.com/rust-lang/rust-bindgen/blob/master/LICENSE).

#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BitfieldUnit<Storage> {
    storage: Storage,
}

impl<Storage> BitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}

impl<Storage> BitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());

        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];

        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };

        let mask = 1 << bit_index;

        byte & mask == mask
    }

    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());

        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];

        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };

        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }

    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());

        let mut val = 0;

        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }

        val
    }

    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());

        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_prop_tests {
    use super::*;
    use bincode::config;
    use bincode::serde::{decode_from_slice, encode_to_vec};
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;
    use serde_cbor::{from_slice as cbor_from_slice, to_vec as cbor_to_vec};

    fn round_trip_bincode(unit: &BitfieldUnit<[u8; 2]>) -> BitfieldUnit<[u8; 2]> {
        let cfg = config::standard();
        let bytes = encode_to_vec(unit, cfg).unwrap();
        decode_from_slice(&bytes, cfg).unwrap().0
    }

    fn round_trip_cbor(unit: &BitfieldUnit<[u8; 2]>) -> BitfieldUnit<[u8; 2]> {
        let bytes = cbor_to_vec(unit).unwrap();
        cbor_from_slice(&bytes).unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn bitfield_unit_round_trip(initial in proptest::array::uniform2(any::<u8>())) {
            let mut unit = BitfieldUnit::new(initial);
            let bit = (initial[0] as usize) % (initial.len() * 8);
            unit.set_bit(bit, true);

            let via_bincode = round_trip_bincode(&unit);
            let via_cbor = round_trip_cbor(&unit);

            prop_assert_eq!(via_bincode.storage, unit.storage);
            prop_assert_eq!(via_cbor.storage, unit.storage);
        }
    }
}
