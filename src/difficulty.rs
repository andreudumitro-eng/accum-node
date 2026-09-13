//! Difficulty adjustment algorithm

use crate::constants::*;
use crate::types::{Hash32, Target, Timestamp};
use std::cmp::Ordering;

pub fn adjust_difficulty(timestamps: &[Timestamp], current_target: &Target) -> Target {
    if timestamps.len() < DIFFICULTY_ADJUSTMENT_INTERVAL as usize + 1 {
        return *current_target;
    }

    let start_idx = timestamps.len() - DIFFICULTY_ADJUSTMENT_INTERVAL as usize - 1;
    let start = timestamps[start_idx];
    let end = *timestamps.last().unwrap();
    let actual_time = end - start;

    if actual_time == 0 {
        return *current_target;
    }

    let expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME; // 7200

    // factor = expected / actual, зажат в [0.75, 1.25].
    // Значит actual зажат в [expected/1.25, expected/0.75] = [5760, 9600].
    let clamped_actual = actual_time.clamp(5760, 9600);

    // adjusted = current_target * (expected / clamped_actual)
    let adjusted = current_target.scaled_integer(expected_time, clamped_actual);

    // Границы: от genesis до genesis/1000.
    let min_difficulty = Target::genesis();          // самый «лёгкий» target
    let max_difficulty = min_difficulty.scaled_integer(1, 1000);  // самый «тяжёлый»

    if adjusted.0 > min_difficulty.0 {
        return min_difficulty;
    }
    if adjusted.0 < max_difficulty.0 {
        return max_difficulty;
    }

    adjusted
}

pub fn calculate_time_span(timestamps: &[Timestamp], interval: usize) -> Option<u64> {
    if timestamps.len() < interval + 1 {
        return None;
    }
    let start = timestamps[timestamps.len() - interval - 1];
    let end = timestamps[timestamps.len() - 1];
    Some(end - start)
}

pub fn compact_from_target(target: &Target) -> u32 {
    let bytes = target.0;

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

pub fn target_from_compact(compact: u32) -> Target {
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

pub fn hash_meets_target(hash: &Hash32, target: &Target) -> bool {
    for i in 0..32 {
        match hash[i].cmp(&target.0[i]) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => continue,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_adjustment() {
        let mut timestamps = vec![0u64; 121];
        for (i, t) in timestamps.iter_mut().enumerate() {
            *t = i as u64 * 60;
        }
        let target = Target::genesis();
        let adjusted = adjust_difficulty(&timestamps, &target);
        let _ = adjusted;
    }

    #[test]
    fn test_compact_conversion() {
        let target = Target([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
        ]);

        let compact = compact_from_target(&target);
        let recovered = target_from_compact(compact);

        assert_eq!(target.0[29], recovered.0[29]);
        assert_eq!(target.0[30], recovered.0[30]);
        assert_eq!(target.0[31], recovered.0[31]);
    }
}