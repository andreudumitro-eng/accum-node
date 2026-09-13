//! ACCUM types

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::constants::*;

pub type Hash32 = [u8; 32];
pub type MinerId = [u8; 20];
pub type Timestamp = u64;
pub type Height = u64;
pub type Txid = Hash32;
pub type OutPoint = (Txid, u32);
pub type PeerId = [u8; 32];

pub type Amount = u64;
pub type EpochIndex = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target(pub Hash32);

impl Target {
    pub fn genesis() -> Self {
        Target([
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ])
    }

    pub fn is_met_by(&self, hash: &Hash32) -> bool {
        for i in 0..32 {
            match hash[i].cmp(&self.0[i]) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
        true
    }

    pub fn share_target(&self) -> Self {
        let mut result = [0u8; 32];
        let mut carry = 0u32;

        for i in (0..32).rev() {
            let val = (self.0[i] as u32) * SHARE_DIFFICULTY_RATIO as u32 + carry;
            result[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }

        if carry > 0 {
            return Target([0xFF; 32]);
        }
        Target(result)
    }

    pub fn prefilter_target(&self) -> Self {
        let share_target = self.share_target();
        let mut result = [0u8; 32];
        let mut carry = 0u64;

        for i in (0..32).rev() {
            let val = (share_target.0[i] as u64) * SHARE_PREFILTER_RATIO + carry;
            result[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }

        if carry > 0 {
            return Target([0xFF; 32]);
        }
        Target(result)
    }

    pub fn adjust(&self, factor: f64) -> Self {
        let mut result = [0u8; 32];
        let mut carry = 0u64;
        let factor_fixed = (factor * 1_000_000.0) as u64;

        for i in (0..32).rev() {
            let val = (self.0[i] as u64) * factor_fixed + carry;
            result[i] = (val / 1_000_000) as u8;
            carry = val % 1_000_000;
        }

        Target(result)
    }

    pub fn to_difficulty(&self) -> f64 {
        let mut target_val = 0u128;
        for i in 0..32 {
            target_val = (target_val << 8) | (self.0[i] as u128);
        }
        if target_val == 0 {
            return f64::INFINITY;
        }
        (u128::MAX as f64) / (target_val as f64)
    }

    pub fn shift_left(&self, bits: usize) -> Self {
        let mut result = [0u8; 32];
        let bytes_to_shift = bits / 8;
        let bit_shift = bits % 8;

        for i in 0..32 {
            if i + bytes_to_shift < 32 {
                let mut val = self.0[i] as u16;

                if bit_shift > 0 {
                    val = (val << bit_shift) & 0xFF;
                    if i + bytes_to_shift + 1 < 32 {
                        result[i + bytes_to_shift + 1] |= (self.0[i] >> (8 - bit_shift)) as u8;
                    }
                }

                result[i + bytes_to_shift] |= val as u8;
            }
        }

        Target(result)
    }

    pub fn scaled(&self, factor: f64) -> Self {
        if factor <= 0.0 {
            return Target([0u8; 32]);
        }
        if factor == 1.0 {
            return *self;
        }

        let mut result = [0u8; 32];
        let mut carry = 0u16;

        for i in (0..32).rev() {
            let val = (self.0[i] as u16) * (factor * 256.0) as u16 + carry;
            result[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }

        if carry > 0 {
            return Target([0xFF; 32]);
        }

        Target(result)
    }

    pub fn scaled_integer(&self, numerator: u64, denominator: u64) -> Self {
        if denominator == 0 {
            return Target([0u8; 32]);
        }
        if numerator == denominator {
            return *self;
        }

        let mut result = [0u8; 32];
        let mut remaining = 0u128;

        for i in 0..32 {
            let cur = (remaining << 8) + self.0[i] as u128;
            let product = cur * numerator as u128;
            result[i] = (product / denominator as u128) as u8;
            remaining = product % denominator as u128;
        }

        Target(result)
    }

    pub fn compact(&self) -> u32 {
        let bytes = self.0;

        let mut size = 32;
        for (i, &b) in bytes.iter().enumerate() {
            if b != 0 {
                size = i;
                break;
            }
        }

        if size == 32 {
            return 0;
        }

        let exponent = (32 - size) as u32;
        let mantissa = ((bytes[size] as u32) << 16)
            | ((bytes[size + 1] as u32) << 8)
            | (bytes[size + 2] as u32);

        (exponent << 24) | mantissa
    }

    pub fn from_compact(compact: u32) -> Self {
        let exponent = (compact >> 24) & 0xFF;
        let mantissa = compact & 0x00FFFFFF;

        let mut bytes = [0u8; 32];

        if exponent <= 3 {
            bytes[31 - exponent as usize] = (mantissa >> 16) as u8;
            if exponent > 1 {
                bytes[32 - exponent as usize] = (mantissa >> 8) as u8;
            }
            if exponent > 2 {
                bytes[33 - exponent as usize] = mantissa as u8;
            }
        } else {
            let pos = 32 - exponent as usize;
            if pos < 32 {
                bytes[pos] = (mantissa >> 16) as u8;
                if pos + 1 < 32 {
                    bytes[pos + 1] = (mantissa >> 8) as u8;
                }
                if pos + 2 < 32 {
                    bytes[pos + 2] = mantissa as u8;
                }
            }
        }

        Target(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_left_8() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[2] = 0x56;
        bytes[3] = 0x78;

        let target = Target(bytes);
        let shifted = target.shift_left(8);

        assert_eq!(shifted.0[0], 0x12);
        assert_eq!(shifted.0[1], 0x34);
        assert_eq!(shifted.0[2], 0x56);
        assert_eq!(shifted.0[3], 0x00);
        assert_eq!(shifted.0[4], 0x78);
    }

    #[test]
    fn test_shift_left_4() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xF0;
        bytes[1] = 0x0F;

        let target = Target(bytes);
        let shifted = target.shift_left(4);

        assert_eq!(shifted.0[0], 0x00);
        assert_eq!(shifted.0[1], 0xFF);
        assert_eq!(shifted.0[2], 0x00);
    }

    #[test]
    fn test_scaled() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80;

        let target = Target(bytes);

        let scaled_up = target.scaled(1.25);
        let scaled_down = target.scaled(0.75);

        assert_ne!(target.0, scaled_up.0);
        assert_ne!(target.0, scaled_down.0);
    }

    #[test]
    fn test_is_met_by() {
        let target = Target([0x80; 32]);

        let hash_less = [0x7F; 32];
        assert!(target.is_met_by(&hash_less));

        let hash_greater = [0x81; 32];
        assert!(!target.is_met_by(&hash_greater));

        let hash_equal = [0x80; 32];
        assert!(target.is_met_by(&hash_equal));
    }

    #[test]
    fn test_compact_roundtrip() {
        let target = Target([
            0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);

        let compact = target.compact();
        let recovered = Target::from_compact(compact);

        assert_eq!(target.0[0], recovered.0[0]);
        assert_eq!(target.0[1], recovered.0[1]);
        assert_eq!(target.0[2], recovered.0[2]);
    }
}

use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_timestamp() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}