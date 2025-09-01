
use crate::epoch::Anchor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub difficulty: u32,
    pub mem_kib: u32,
}

// ---------- Consensus constants (v1) ----------
pub const GENESIS_PARAMS: Params = Params {
    difficulty: 2,
    mem_kib: 16_192,
};

pub const RETARGET_INTERVAL: u64 = 2000;
pub const TARGET_COINS_PER_EPOCH: u64 = 11;

// Difficulty bounds
pub const DIFFICULTY_MIN: u32 = 1;
pub const DIFFICULTY_MAX: u32 = 12;

// Memory bounds (KiB)
pub const MIN_MEM_KIB: u32 = 16_192;
pub const MAX_MEM_KIB: u32 = 512_007;

// Fixed-point scale (6 decimals)
pub const PRECISION: u64 = 1_000_000;

// Memory adjustment clamp: max = ×1.02, min = ÷1.02 (integer fixed-point)
pub const MAX_ADJ_NUM: u64 = 102;
pub const MAX_ADJ_DEN: u64 = 100;
pub const MIN_ADJ_NUM: u64 = 100;
pub const MIN_ADJ_DEN: u64 = 102;

// Difficulty retarget bands (% of target)
pub const RETARGET_UPPER_PCT: u64 = 110;
pub const RETARGET_LOWER_PCT: u64 = 90;

// ---- Back-compat aliases for existing imports in epoch.rs/network.rs ----
pub const TARGET_LEADING_ZEROS: usize = GENESIS_PARAMS.difficulty as usize;
pub const DEFAULT_MEM_KIB: u32 = GENESIS_PARAMS.mem_kib;

#[derive(Debug)]
pub enum ConsensusError {
    ParamMismatch { expected: Params, got: Params },
    WindowSize { expected: u64, got: u64 },
}

impl core::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConsensusError::ParamMismatch { expected, got } => {
                write!(f, "consensus params mismatch: expected={:?} got={:?}", expected, got)
            }
            ConsensusError::WindowSize { expected, got } => {
                write!(f, "retarget window size mismatch: expected={} got={}", expected, got)
            }
        }
    }
}


impl std::error::Error for ConsensusError {}

// ---------- Helpers ----------
#[inline]
pub fn params_from_anchor(a: &Anchor) -> Params {
    Params {
        difficulty: a.difficulty as u32,
        mem_kib: a.mem_kib,
    }
}

#[inline]
pub fn clamp_params(mut p: Params) -> Params {
    p.difficulty = p.difficulty.clamp(DIFFICULTY_MIN, DIFFICULTY_MAX);
    p.mem_kib = p.mem_kib.clamp(MIN_MEM_KIB, MAX_MEM_KIB);
    p
}

// ---------- Core retarget (Params) ----------
fn calculate_retarget_params(recent_anchors: &[Anchor]) -> Params {
    if recent_anchors.is_empty() {
        return GENESIS_PARAMS;
    }

    let last = match recent_anchors.last() {
        Some(a) => a,
        None => return GENESIS_PARAMS,
    };
    let last_params = params_from_anchor(last);

    // Average coins/epoch in window (fixed-point)
    let total_coins: u64 = recent_anchors.iter().map(|a| a.coin_count as u64).sum();
    let epochs: u64 = recent_anchors.len() as u64;
    let avg_coins_x = (total_coins.saturating_mul(PRECISION)) / epochs;
    let target_x = TARGET_COINS_PER_EPOCH.saturating_mul(PRECISION);

    // Difficulty step (±1 within bounds) based on bands
    let upper = (target_x.saturating_mul(RETARGET_UPPER_PCT)) / 100;
    let lower = (target_x.saturating_mul(RETARGET_LOWER_PCT)) / 100;

    let mut new_diff = if avg_coins_x > upper {
        last_params.difficulty.saturating_add(1)
    } else if avg_coins_x < lower {
        last_params.difficulty.saturating_sub(1)
    } else {
        last_params.difficulty
    };
    new_diff = new_diff.clamp(DIFFICULTY_MIN, DIFFICULTY_MAX);

    // Memory adjust via fixed-point ratio, clamped to [1/1.02, 1.02]
    let current_mem = last_params.mem_kib as u64;
    let mut ratio_x = if avg_coins_x > 0 {
        (target_x.saturating_mul(PRECISION)) / avg_coins_x
    } else {
        PRECISION
    };

    let max_adj = (PRECISION * MAX_ADJ_NUM) / MAX_ADJ_DEN; // ~1.02 * PRECISION
    let min_adj = (PRECISION * MIN_ADJ_NUM) / MIN_ADJ_DEN; // ~0.98 * PRECISION
    ratio_x = ratio_x.clamp(min_adj, max_adj);

    let new_mem = ((current_mem.saturating_mul(ratio_x)) / PRECISION)
        .clamp(MIN_MEM_KIB as u64, MAX_MEM_KIB as u64) as u32;

    clamp_params(Params {
        difficulty: new_diff,
        mem_kib: new_mem,
    })
}

// ---------- Public API ----------

/// Tuple-returning shim to match existing code:
/// returns (difficulty as usize, mem_kib as u32)
pub fn calculate_retarget_consensus(recent_anchors: &[Anchor]) -> (usize, u32) {
    let p = calculate_retarget_params(recent_anchors);
    (p.difficulty as usize, p.mem_kib)
}

/// Expected params at `height`:
/// - height 0: GENESIS_PARAMS
/// - non-retarget heights: inherit parent
/// - retarget heights: compute from `window` (must be last `RETARGET_INTERVAL` anchors)
pub fn expected_params(
    parent: Option<&Anchor>,
    height: u64,
    window: &[Anchor],
) -> Result<Params, ConsensusError> {
    if height == 0 {
        return Ok(GENESIS_PARAMS);
    }

    let parent_params = parent.map(params_from_anchor).ok_or_else(|| {
        ConsensusError::WindowSize {
            expected: RETARGET_INTERVAL,
            got: window.len() as u64,
        }
    })?;

    if height % RETARGET_INTERVAL != 0 {
        return Ok(clamp_params(parent_params));
    }

    if window.len() as u64 != RETARGET_INTERVAL {
        return Err(ConsensusError::WindowSize {
            expected: RETARGET_INTERVAL,
            got: window.len() as u64,
        });
    }

    Ok(calculate_retarget_params(window))
}

/// Validate an anchor's `(difficulty, mem_kib)` against consensus.
/// `parent`: previous anchor (None at genesis)
/// `height`: this anchor's height
/// `window`: the last `RETARGET_INTERVAL` anchors ending at parent (for retarget heights)
pub fn validate_header_params(
    parent: Option<&Anchor>,
    height: u64,
    window: &[Anchor],
    got: Params,
) -> Result<(), ConsensusError> {
    let exp = expected_params(parent, height, window)?;
    if got != exp {
        return Err(ConsensusError::ParamMismatch { expected: exp, got });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_anchor(difficulty: u32, mem_kib: u32, coin_count: u32) -> Anchor {
        Anchor {
            num: 0,
            hash: [0; 32],
            merkle_root: [0; 32],
            difficulty: difficulty as usize, // Anchor uses usize; convert here only.
            coin_count,
            cumulative_work: 0,
            mem_kib,
        }
    }

    #[test]
    fn genesis_fixed() {
        assert_eq!(GENESIS_PARAMS, Params { difficulty: 2, mem_kib: 16_192 });
        assert_eq!(TARGET_LEADING_ZEROS, 2usize);
        assert_eq!(DEFAULT_MEM_KIB, 16_192u32);
    }

    #[test]
    fn inherit_between_retargets() {
        let parent = mk_anchor(4, MIN_MEM_KIB, TARGET_COINS_PER_EPOCH as u32);
        let p = expected_params(Some(&parent), 1, &[]).unwrap();
        assert_eq!(p.difficulty, 4);
        assert_eq!(p.mem_kib, MIN_MEM_KIB);
    }

    #[test]
    fn tuple_shim_shape() {
        let window = vec![mk_anchor(4, MIN_MEM_KIB, TARGET_COINS_PER_EPOCH as u32)];
        let (d, m) = calculate_retarget_consensus(&window);
        assert_eq!(d, 4usize);
        assert_eq!(m, MIN_MEM_KIB);
    }
}