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
    /// Максимальный target — все байты 0xFF.
    /// Такой target пропускает любой хеш (используется как «заглушка» при переполнении).
    pub const MAX: Target = Target([0xFF; 32]);

    /// Нулевой target — не пропускает ни один хеш (майнить невозможно).
    pub const ZERO: Target = Target([0x00; 32]);

    /// Genesis target
    pub fn genesis() -> Self {
        Target([
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ])
    }
    pub fn new(bytes: Hash32) -> Self {
        Target(bytes)
    }

    pub fn as_bytes(&self) -> &Hash32 {
        &self.0
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
        let mut carry = 0u64;

        for i in (0..32).rev() {
            let val = (self.0[i] as u64) * SHARE_DIFFICULTY_RATIO + carry;
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
        if !factor.is_finite() || factor <= 0.0 {
            return Target([0xFF; 32]);
        }

        let factor_fixed_u128 = (factor * (1u128 << 32) as f64).round() as u128;
        if factor_fixed_u128 == 0 {
            return Target([0xFF; 32]);
        }
        if factor_fixed_u128 >= (1u128 << 64) {
            return Target([0xFF; 32]);
        }
        let factor_fixed = factor_fixed_u128 as u64;

        // Разбор target на 4 слова u64 (big-endian)
        let mut words = [0u64; 4];
        for i in 0..4 {
            let mut w: u64 = 0;
            for j in 0..8 {
                w = (w << 8) | (self.0[i * 8 + j] as u64);
            }
            words[i] = w;
        }

        // Умножаем на factor_fixed (Q32.32)
        let mut product = [0u64; 5];
        let mut carry: u128 = 0;
        for i in (0..4).rev() {
            let val = (words[i] as u128) * (factor_fixed as u128) + carry;
            product[i + 1] = (val & 0xFFFF_FFFF_FFFF_FFFF) as u64;
            carry = val >> 64;
        }
        product[0] = carry as u64;

        let mut result_words = [0u64; 4];
        for i in 0..4 {
            // product >> 32: берём младшие 32 бита product[i]
            // и старшие 32 бита product[i+1].
            let hi = product[i] & 0xFFFF_FFFF;
            let lo = product[i + 1] >> 32;
            result_words[i] = (hi << 32) | lo;
        }

        // Переполнение: если в product[0] есть биты выше 32-го
        if (product[0] >> 32) != 0 {
            return Target([0xFF; 32]);
        }

        // Сборка big-endian
        let mut out = [0u8; 32];
        for i in 0..4 {
            let w = result_words[i];
            for j in 0..8 {
                out[i * 8 + j] = ((w >> (8 * (7 - j))) & 0xFF) as u8;
            }
        }

        Target(out)
    }

    /// Сложность = genesis_target / target.
    ///
    /// genesis = [0x00, 0xFF, 0xFF, ..., 0xFF] — «сложность 1».
    /// Для genesis возвращает 1.0; для target в 2 раза меньше — 2.0;
    /// для target в 2 раза больше — 0.5; для нулевого target — INFINITY.
    pub fn to_difficulty(&self) -> f64 {
        const GENESIS: [u8; 32] = [
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let (t_mant, t_exp) = Self::mantissa_exp(&self.0);
        if t_mant == 0.0 {
            return f64::INFINITY;
        }
        let (g_mant, g_exp) = Self::mantissa_exp(&GENESIS);

        (g_mant / t_mant) * 2f64.powi(g_exp - t_exp)
    }

    /// Возвращает (мантисса как f64 из старших 8 значащих байт, экспонента в битах).
    /// Число = mantissa * 2^exp, где mantissa ∈ [2^56, 2^64) для ненулевого входа.
    fn mantissa_exp(bytes: &[u8; 32]) -> (f64, i32) {
        let mut first = 0;
        while first < 32 && bytes[first] == 0 {
            first += 1;
        }
        if first == 32 {
            return (0.0, 0);
        }

        let mut mant = 0.0f64;
        let mut used = 0;
        while used < 8 && first + used < 32 {
            mant = mant * 256.0 + bytes[first + used] as f64;
            used += 1;
        }
        let dropped = 32 - first - used;
        (mant, (dropped as i32) * 8)
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

        // Умножаем self на numerator в 40-байтовый буфер (с запасом на overflow)
        let mut product = [0u8; 40];
        let mut carry: u64 = 0;
        for i in (0..32).rev() {
            let cur = (self.0[i] as u64) * numerator + carry;
            product[i + 8] = (cur & 0xFF) as u8;
            carry = cur >> 8;
        }
        let mut c = carry;
        for i in (0..8).rev() {
            product[i] = (c & 0xFF) as u8;
            c >>= 8;
        }

        // Делим product на denominator
        let mut quotient = [0u8; 40];
        let mut rem: u128 = 0;
        for i in 0..40 {
            let cur = (rem << 8) | (product[i] as u128);
            quotient[i] = (cur / denominator as u128) as u8;
            rem = cur % denominator as u128;
        }

        // Если верхние 8 байт не нули — overflow, насыщаемся
        if quotient[0..8].iter().any(|&b| b != 0) {
            return Target([0xFF; 32]);
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&quotient[8..40]);
        Target(out)
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

        assert_eq!(shifted.0[0], 0x00);
        assert_eq!(shifted.0[1], 0x12);
        assert_eq!(shifted.0[2], 0x34);
        assert_eq!(shifted.0[3], 0x56);
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

    #[test]
    fn test_scaled_integer_no_overflow() {
        // Максимальный target (все 0xFF), умножаем на 125/100.
        // Результат должен насытиться до [0xFF; 32], а не обернуться.
        let target = Target([0xFF; 32]);
        let result = target.scaled_integer(125, 100);
        assert_eq!(result.0, [0xFF; 32], "должно насытиться максимумом");
    }

    #[test]
    fn test_scaled_integer_large_numerator() {
        // target = 0x80.., numerator = u64::MAX.
        // Раньше это давало переполнение u64 в цикле умножения.
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80;
        let target = Target(bytes);

        let result = target.scaled_integer(u64::MAX, 1);
        // Результат должен быть либо [0xFF; 32] (насыщение), либо корректным
        // большим числом. Главное — не паника и не мусор.
        assert_ne!(result.0, [0u8; 32], "не должно быть нулём");
    }

    #[test]
    fn test_scaled_integer_exact() {
        // Простой случай: 100 * 2 / 2 = 100.
        let mut bytes = [0u8; 32];
        bytes[31] = 100;
        let target = Target(bytes);

        let result = target.scaled_integer(2, 2);
        assert_eq!(
            result.0, target.0,
            "numerator == denominator → без изменений"
        );

        let result = target.scaled_integer(4, 2);
        let mut expected = [0u8; 32];
        expected[31] = 200;
        assert_eq!(result.0, expected, "100 * 4 / 2 = 200");
    }
}
// ============================================================
// Тесты для adjust (ретаргет)
// ============================================================

#[test]
fn test_adjust_identity_genesis() {
    // adjust(genesis, 1.0) должен вернуть genesis
    let g = Target::genesis();
    let r = g.adjust(1.0);
    assert_eq!(
        r,
        g,
        "adjust(genesis, 1.0) сломан: \n  got  = {:02x?}\n  want = {:02x?}",
        &r.0[..8],
        &g.0[..8]
    );
}

#[test]
fn test_adjust_identity_simple() {
    // adjust(1, 1.0) == 1
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let t = Target(bytes);
    let r = t.adjust(1.0);
    assert_eq!(r, t, "adjust(1, 1.0) должен вернуть 1");
}

#[test]
fn test_adjust_double_simple() {
    // adjust(1, 2.0) == 2
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let t = Target(bytes);
    let r = t.adjust(2.0);
    let mut expected = [0u8; 32];
    expected[31] = 2;
    assert_eq!(r, Target(expected), "adjust(1, 2.0) должен вернуть 2");
}

#[test]
fn test_adjust_half_simple() {
    // adjust(4, 0.5) == 2
    let mut bytes = [0u8; 32];
    bytes[31] = 4;
    let t = Target(bytes);
    let r = t.adjust(0.5);
    let mut expected = [0u8; 32];
    expected[31] = 2;
    assert_eq!(r, Target(expected), "adjust(4, 0.5) должен вернуть 2");
}

#[test]
fn test_adjust_125_percent() {
    // adjust(100, 1.25) == 125
    let mut bytes = [0u8; 32];
    bytes[31] = 100;
    let t = Target(bytes);
    let r = t.adjust(1.25);
    let mut expected = [0u8; 32];
    expected[31] = 125;
    assert_eq!(r, Target(expected), "adjust(100, 1.25) должен вернуть 125");
}

#[test]
fn test_adjust_75_percent() {
    // adjust(100, 0.75) == 75
    let mut bytes = [0u8; 32];
    bytes[31] = 100;
    let t = Target(bytes);
    let r = t.adjust(0.75);
    let mut expected = [0u8; 32];
    expected[31] = 75;
    assert_eq!(r, Target(expected), "adjust(100, 0.75) должен вернуть 75");
}

// ============================================================
// Тесты для to_difficulty
// ============================================================

#[test]
fn test_difficulty_genesis_is_one() {
    // genesis должен давать сложность 1.0
    // ВНИМАНИЕ: этот тест пройдёт только после фикса to_difficulty
    // (замены u64::MAX на genesis target).
    let d = Target::genesis().to_difficulty();
    assert!(
        (d - 1.0).abs() < 1e-9,
        "genesis().to_difficulty() должен быть 1.0, получено {}",
        d
    );
}

#[test]
fn test_difficulty_zero_is_inf() {
    assert!(
        Target::ZERO.to_difficulty().is_infinite(),
        "ZERO.to_difficulty() должен быть INFINITY"
    );
}

use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_timestamp() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
