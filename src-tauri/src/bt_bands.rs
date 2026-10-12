//! Proximity bands for the Bluetooth map: Touching, Same room, Nearby, Far.
//! A signal-strength distance estimate jumps around by a factor of two or
//! more, so each device's distance is smoothed and it only changes band once
//! it is clearly past a boundary.

/// Where one band ends and the next begins, in metres.
pub const EDGES_M: [f32; 3] = [1.0, 3.0, 10.0];
/// A device must pass a boundary by this factor (25%) before it changes band.
const MARGIN: f32 = 1.25;
/// Time constant of the distance smoothing.
const SMOOTH_TAU_MS: f32 = 8_000.0;

/// Exponential moving average of the distance, taken in log space because
/// signal strength is linear in the log of the distance. `dt_ms` is the time
/// since the previous update.
pub fn smooth_m(prev: Option<f32>, raw: f32, dt_ms: u64) -> f32 {
    let raw = raw.max(0.1);
    let Some(prev) = prev.filter(|p| *p > 0.0) else { return raw };
    let alpha = 1.0 - (-(dt_ms as f32) / SMOOTH_TAU_MS).exp();
    (prev.ln() + alpha * (raw.ln() - prev.ln())).exp()
}

/// The band (0 Touching, 1 Same room, 2 Nearby, 3 Far) for a smoothed
/// distance. A first sighting lands in its plain band. After that the device
/// stays where it was until it is past the boundary by the margin, which can
/// cross several bands at once.
pub fn band_for(prev: Option<u8>, m: f32) -> u8 {
    let Some(prev) = prev.filter(|p| *p <= 3) else {
        return EDGES_M.iter().filter(|e| m >= **e).count() as u8;
    };
    let mut b = prev as usize;
    while b < 3 && m >= EDGES_M[b] * MARGIN {
        b += 1;
    }
    while b > 0 && m < EDGES_M[b - 1] / MARGIN {
        b -= 1;
    }
    b as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sighting_lands_in_its_plain_band() {
        assert_eq!(band_for(None, 0.4), 0);
        assert_eq!(band_for(None, 1.0), 1);
        assert_eq!(band_for(None, 2.9), 1);
        assert_eq!(band_for(None, 3.0), 2);
        assert_eq!(band_for(None, 9.9), 2);
        assert_eq!(band_for(None, 10.0), 3);
        assert_eq!(band_for(None, 80.0), 3);
    }

    #[test]
    fn jitter_around_a_boundary_does_not_flip_the_band() {
        // In "Same room" (1-3 m), readings wobbling around 3 m stay put.
        let mut band = Some(1);
        for m in [2.9, 3.1, 2.95, 3.2, 3.5, 3.0, 2.6] {
            band = Some(band_for(band, m));
            assert_eq!(band, Some(1), "flipped at {m} m");
        }
        // Likewise from the other side: in "Nearby", dipping just under 3 m.
        let mut band = Some(2);
        for m in [2.9, 3.1, 2.95, 2.5, 2.45] {
            band = Some(band_for(band, m));
            assert_eq!(band, Some(2), "flipped at {m} m");
        }
    }

    #[test]
    fn clear_crossings_change_band() {
        assert_eq!(band_for(Some(1), 3.8), 2);
        assert_eq!(band_for(Some(2), 2.3), 1);
        assert_eq!(band_for(Some(0), 1.3), 1);
        assert_eq!(band_for(Some(1), 0.7), 0);
        assert_eq!(band_for(Some(2), 12.6), 3);
        assert_eq!(band_for(Some(3), 7.0), 2);
    }

    #[test]
    fn jumps_can_skip_bands() {
        assert_eq!(band_for(Some(0), 20.0), 3);
        assert_eq!(band_for(Some(3), 0.5), 0);
        assert_eq!(band_for(Some(0), 5.0), 2);
        assert_eq!(band_for(Some(3), 2.0), 1);
        // A stale or out-of-range previous band is treated as a first sighting.
        assert_eq!(band_for(Some(9), 5.0), 2);
    }

    #[test]
    fn smoothing_takes_the_first_reading_and_damps_outliers() {
        assert_eq!(smooth_m(None, 4.2, 2_000), 4.2);
        // One wild reading moves the estimate only part of the way.
        let s = smooth_m(Some(2.0), 20.0, 2_000);
        assert!(s > 2.0 && s < 4.0, "got {s}");
        // A longer gap since the last update trusts the new reading more.
        assert!(smooth_m(Some(2.0), 20.0, 10_000) > s);
        // It settles on a steady reading.
        let mut v = Some(1.0);
        for _ in 0..60 {
            v = Some(smooth_m(v, 6.0, 2_000));
        }
        assert!((v.unwrap() - 6.0).abs() < 0.05);
    }

    #[test]
    fn smoothed_noisy_signal_stays_in_one_band() {
        // A device really about 3 m away, read as 2.4 m and 3.8 m in turn.
        let mut dist = None;
        let mut band = Some(1);
        for i in 0..40 {
            let raw = if i % 2 == 0 { 2.4 } else { 3.8 };
            let s = smooth_m(dist, raw, 2_000);
            dist = Some(s);
            band = Some(band_for(band, s));
            assert_eq!(band, Some(1), "flapped at step {i} ({s:.2} m)");
        }
    }
}
