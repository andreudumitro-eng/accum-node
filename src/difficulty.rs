//! ACCUM deterministic difficulty adjustment.
//!
//! Difficulty adjustment is fully deterministic: only integer arithmetic,
//! no f64. The result depends only on the input data.

use crate::constants::*;
use crate::types::{Hash32, Target, Timestamp};
use std::cmp::Ordering;

// NOTE: MIN_TARGET_NUMERATOR / MIN_TARGET_DENOMINATOR / MAX_TARGET_NUMERATOR /
// MAX_TARGET_DENOMINATOR are defined in `crate::constants`. Local duplicates
// were removed to avoid divergence between the two definitions.
// See `constants.rs` for the canonical values.

/// Deterministic difficulty adjustment with an explicit `interval`.
///
/// This is the core of the algorithm. The public wrapper [`adjust_difficulty`]
/// substitutes `DIFFICULTY_ADJUSTMENT_INTERVAL`. Parameterization is needed to
/// test all branches, including `interval == 0`.
///
/// * `timestamps` — the last `interval` block timestamps (in seconds).
/// * `current_target` — the current target.
/// * `interval` — number of blocks in the window (must be >= 2 to be meaningful).
///
/// Returns a new target clamped to `[current * 0.75, current * 1.25]`
/// and never larger than `Target::genesis()`.
pub fn adjust_difficulty_with_interval(
    timestamps: &[Timestamp],
    current_target: &Target,
    interval: usize,
) -> Target {
    // Point 1: guard against zero interval.
    // interval == 0 → no data to adjust.
    // interval == 1 → no intervals between blocks (expected_time = 0).
    if interval < 2 {
        return *current_target;
    }

    // Point 2: exactly `interval` timestamps are required.
    if timestamps.len() < interval {
        return *current_target;
    }

    // Take exactly `interval` timestamps: from `len - interval` to `len - 1`.
    // No `.max(1)`: if the window starts at index 0 that is fine — the only
    // important thing is that `actual_time` and `expected_time` are computed
    // over the same number of intervals (`interval - 1`).
    let start_idx = timestamps.len() - interval;
    let start = timestamps[start_idx];
    let end = timestamps[timestamps.len() - 1];

    // Point 3: monotonicity. end < start → reject.
    let actual_time = match end.checked_sub(start) {
        Some(value) if value > 0 => value,
        _ => return *current_target,
    };

    // Point 4: `interval` blocks = `interval - 1` intervals.
    // checked_mul protects against overflow with extreme constants.
    let expected_time = match TARGET_BLOCK_TIME.checked_mul(interval as u64 - 1) {
        Some(value) if value > 0 => value,
        _ => return *current_target,
    };

    // Point 5: clamp boundaries on time.
    //   actual == min_actual_time → new_target = current * 0.75
    //   actual == max_actual_time → new_target = current * 1.25
    let min_actual_time =
        expected_time.saturating_mul(MIN_TARGET_NUMERATOR) / MIN_TARGET_DENOMINATOR;

    let max_actual_time =
        expected_time.saturating_mul(MAX_TARGET_NUMERATOR) / MAX_TARGET_DENOMINATOR;

    // Point 6: guard against degenerate constants.
    let lower = min_actual_time.max(1);
    let upper = max_actual_time.max(lower);

    let clamped_time = actual_time.clamp(lower, upper);

    // Point 7: target grows when blocks are slow and shrinks when they are fast.
    let mut new_target = current_target.scaled_integer(clamped_time, expected_time);

    // Point 8: never make mining easier than genesis.
    // NOTE: `Target::genesis()` is the pow_limit. When `current_target` is
    // already at the pow_limit and blocks are slower than `TARGET_BLOCK_TIME`,
    // this clamp keeps the target at genesis and the difficulty does not
    // change. That is intentional: the network cannot become easier than
    // the pow_limit, by design.
    let genesis = Target::genesis();
    if new_target.0 > genesis.0 {
        new_target = genesis;
    }

    new_target
}

/// Public wrapper: uses `DIFFICULTY_ADJUSTMENT_INTERVAL`.
pub fn adjust_difficulty(timestamps: &[Timestamp], current_target: &Target) -> Target {
    adjust_difficulty_with_interval(
        timestamps,
        current_target,
        DIFFICULTY_ADJUSTMENT_INTERVAL as usize,
    )
}

/// Time span between `interval` timestamps.
///
/// Returns `None` if there is not enough data, if `interval < 2`,
/// or if the timestamps are not monotonic.
pub fn calculate_time_span(timestamps: &[Timestamp], interval: usize) -> Option<u64> {
    if interval < 2 || timestamps.len() < interval {
        return None;
    }

    let start = timestamps[timestamps.len() - interval];
    let end = timestamps[timestamps.len() - 1];

    end.checked_sub(start)
}

/// Compact representation of a target (nBits).
pub fn compact_from_target(target: &Target) -> u32 {
    target.compact()
}

/// Restore a target from its compact representation.
pub fn target_from_compact(compact: u32) -> Target {
    Target::from_compact(compact)
}

/// Check that a hash does not exceed the target (lexicographic, big-endian).
///
/// NOTE: this is equivalent to `Target::is_met_by`; it is kept as a free
/// function because it is part of the public API of this module.
pub fn hash_meets_target(hash: &Hash32, target: &Target) -> bool {
    for i in 0..32 {
        match hash[i].cmp(&target.0[i]) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_INTERVAL: usize = 120;

    fn make_timestamps(count: usize, seconds_per_block: u64) -> Vec<Timestamp> {
        (0..count).map(|i| (i as u64) * seconds_per_block).collect()
    }

    fn expected_time_for(interval: usize) -> u64 {
        TARGET_BLOCK_TIME * (interval as u64 - 1)
    }

    /// Test target: guaranteed to be below genesis so that the genesis
    /// clamp does not mask the checks.
    fn test_target() -> Target {
        Target::genesis().scaled_integer(1, 2)
    }

    // -----------------------------------------------------------------
    // adjust_difficulty_with_interval — all branches
    // -----------------------------------------------------------------

    #[test]
    fn zero_interval_keeps_target() {
        let target = test_target();
        let ts = make_timestamps(TEST_INTERVAL, TARGET_BLOCK_TIME);

        assert_eq!(adjust_difficulty_with_interval(&ts, &target, 0), target);
    }

    #[test]
    fn one_interval_keeps_target() {
        // interval == 1 → expected_time = 0 → no intervals.
        let target = test_target();
        let ts = make_timestamps(TEST_INTERVAL, TARGET_BLOCK_TIME);

        assert_eq!(adjust_difficulty_with_interval(&ts, &target, 1), target);
    }

    #[test]
    fn insufficient_timestamps_keep_target() {
        let target = test_target();

        let ts = make_timestamps(TEST_INTERVAL - 1, TARGET_BLOCK_TIME);
        assert_eq!(
            adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL),
            target
        );
    }

    #[test]
    fn empty_timestamps_keep_target() {
        let target = test_target();
        let ts: Vec<Timestamp> = Vec::new();

        assert_eq!(
            adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL),
            target
        );
    }

    #[test]
    fn equal_timestamps_keep_target() {
        let target = test_target();
        let mut ts = make_timestamps(TEST_INTERVAL, TARGET_BLOCK_TIME);
        let last = ts.len() - 1;
        ts[last] = ts[0];

        assert_eq!(
            adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL),
            target
        );
    }

    #[test]
    fn exact_target_time_keeps_difficulty() {
        let target = test_target();
        let ts = make_timestamps(TEST_INTERVAL, TARGET_BLOCK_TIME);

        assert_eq!(
            adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL),
            target
        );
    }

    #[test]
    fn slow_blocks_increase_target_up_to_max() {
        let target = test_target();

        // 119 intervals of 100 s → factor > 1.25 → clamped to 1.25.
        let ts = make_timestamps(TEST_INTERVAL, 100);
        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, target.scaled_integer(125, 100));
    }

    #[test]
    fn fast_blocks_decrease_target_to_min() {
        let target = test_target();

        // 119 intervals of 30 s → factor = 0.5 → clamped to 0.75.
        let ts = make_timestamps(TEST_INTERVAL, 30);
        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, target.scaled_integer(75, 100));
    }

    #[test]
    fn exact_max_boundary_is_clamped_to_125() {
        let target = test_target();
        let expected = expected_time_for(TEST_INTERVAL);
        let actual = expected * MAX_TARGET_NUMERATOR / MAX_TARGET_DENOMINATOR;

        let mut ts = vec![0u64; TEST_INTERVAL];
        for (i, t) in ts.iter_mut().enumerate() {
            *t = (i as u64) * (actual / (TEST_INTERVAL as u64 - 1));
        }
        ts[TEST_INTERVAL - 1] = ts[0] + actual;

        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, target.scaled_integer(125, 100));
    }

    #[test]
    fn exact_min_boundary_is_clamped_to_075() {
        let target = test_target();
        let expected = expected_time_for(TEST_INTERVAL);
        let actual = expected * MIN_TARGET_NUMERATOR / MIN_TARGET_DENOMINATOR;

        let mut ts = vec![0u64; TEST_INTERVAL];
        for (i, t) in ts.iter_mut().enumerate() {
            *t = (i as u64) * (actual / (TEST_INTERVAL as u64 - 1));
        }
        ts[TEST_INTERVAL - 1] = ts[0] + actual;

        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, target.scaled_integer(75, 100));
    }

    #[test]
    fn very_slow_blocks_are_clamped() {
        let target = test_target();
        let ts = make_timestamps(TEST_INTERVAL, 300);
        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, target.scaled_integer(125, 100));
    }

    #[test]
    fn very_fast_blocks_are_clamped() {
        let target = test_target();
        let ts = make_timestamps(TEST_INTERVAL, 1);
        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, target.scaled_integer(75, 100));
    }

    #[test]
    fn genesis_ceiling_is_enforced() {
        // target is close to genesis, blocks are very slow:
        // new_target = target * 1.25 > genesis → replaced with genesis.
        let genesis = Target::genesis();
        let target = genesis.scaled_integer(9, 10);

        let ts = make_timestamps(TEST_INTERVAL, 300);
        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, genesis);
    }

    #[test]
    fn genesis_ceiling_not_triggered_when_below() {
        // target is far from genesis: the clamp must not trigger.
        let target = test_target();
        let ts = make_timestamps(TEST_INTERVAL, 300);
        let adjusted = adjust_difficulty_with_interval(&ts, &target, TEST_INTERVAL);

        assert_eq!(adjusted, target.scaled_integer(125, 100));
        assert!(adjusted.0 < Target::genesis().0);
    }

    // -----------------------------------------------------------------
    // adjust_difficulty — thin wrapper
    // -----------------------------------------------------------------

    #[test]
    fn wrapper_uses_constant_interval() {
        let target = test_target();
        let interval = DIFFICULTY_ADJUSTMENT_INTERVAL as usize;

        let ts = make_timestamps(interval, TARGET_BLOCK_TIME);

        assert_eq!(adjust_difficulty(&ts, &target), target);
    }

    #[test]
    fn wrapper_matches_inner() {
        let target = test_target();
        let interval = DIFFICULTY_ADJUSTMENT_INTERVAL as usize;
        let ts = make_timestamps(interval, 100);

        assert_eq!(
            adjust_difficulty(&ts, &target),
            adjust_difficulty_with_interval(&ts, &target, interval),
        );
    }

    // -----------------------------------------------------------------
    // calculate_time_span
    // -----------------------------------------------------------------

    #[test]
    fn calculate_time_span_is_correct() {
        let ts = make_timestamps(TEST_INTERVAL, TARGET_BLOCK_TIME);
        let expected = expected_time_for(TEST_INTERVAL);

        assert_eq!(calculate_time_span(&ts, TEST_INTERVAL), Some(expected));
    }

    #[test]
    fn calculate_time_span_zero_interval_is_none() {
        let ts = make_timestamps(10, 60);
        assert_eq!(calculate_time_span(&ts, 0), None);
    }

    #[test]
    fn calculate_time_span_one_interval_is_none() {
        let ts = make_timestamps(10, 60);
        assert_eq!(calculate_time_span(&ts, 1), None);
    }

    #[test]
    fn calculate_time_span_insufficient_data_is_none() {
        let ts = make_timestamps(5, 60);
        assert_eq!(calculate_time_span(&ts, 10), None);
    }

    #[test]
    fn calculate_time_span_reversed_is_none() {
        let ts = vec![100u64, 50u64];
        assert_eq!(calculate_time_span(&ts, 2), None);
    }

    // -----------------------------------------------------------------
    // hash_meets_target
    // -----------------------------------------------------------------

    #[test]
    fn hash_equal_target_is_valid() {
        let target = Target::genesis();
        assert!(hash_meets_target(&target.0, &target));
    }

    #[test]
    fn hash_below_target_is_valid() {
        let target = Target([0x80; 32]);
        let hash = [0x7F; 32];
        assert!(hash_meets_target(&hash, &target));
    }

    #[test]
    fn hash_above_target_is_invalid() {
        let target = Target([0x80; 32]);
        let hash = [0x81; 32];
        assert!(!hash_meets_target(&hash, &target));
    }

    #[test]
    fn hash_equal_prefix_then_less_is_valid() {
        let mut target = [0x80; 32];
        target[31] = 0x10;
        let target = Target(target);

        let mut hash = [0x80; 32];
        hash[31] = 0x0F;

        assert!(hash_meets_target(&hash, &target));
    }

    #[test]
    fn hash_equal_prefix_then_greater_is_invalid() {
        let mut target = [0x80; 32];
        target[31] = 0x10;
        let target = Target(target);

        let mut hash = [0x80; 32];
        hash[31] = 0x11;

        assert!(!hash_meets_target(&hash, &target));
    }
}