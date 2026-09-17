//! Pure, offline attack-size → time estimation. This module is pure arithmetic;
//! only the `bench` command runs hashcat. The hash rate here is supplied by the
//! caller (a documented assumed default or --hashrate).

pub fn estimate_seconds(keyspace: u64, hashrate: u64) -> f64 {
    if hashrate == 0 {
        f64::INFINITY
    } else {
        keyspace as f64 / hashrate as f64
    }
}

/// Compact human duration: the two largest non-zero units.
pub fn format_duration(secs: f64) -> String {
    if !secs.is_finite() {
        return "∞".to_string();
    }
    if secs < 1.0 {
        return "<1s".to_string();
    }
    let total = secs as u128;
    const YEAR: u128 = 365 * 86_400;
    if total >= 1000 * YEAR {
        return ">1000y".to_string();
    }
    let units = [
        (total / YEAR, "y"),
        ((total % YEAR) / 86_400, "d"),
        ((total % 86_400) / 3_600, "h"),
        ((total % 3_600) / 60, "m"),
        (total % 60, "s"),
    ];
    let mut parts = Vec::new();
    for (v, u) in units {
        if v > 0 {
            parts.push(format!("{v}{u}"));
            if parts.len() == 2 {
                break;
            }
        }
    }
    if parts.is_empty() {
        "<1s".to_string()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seconds_basic() {
        assert_eq!(estimate_seconds(1_000, 1_000), 1.0);
        assert!(estimate_seconds(10, 0).is_infinite());
    }
    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(0.4), "<1s");
        assert_eq!(format_duration(45.0), "45s");
        assert_eq!(format_duration(90.0), "1m 30s");
        assert_eq!(format_duration(3660.0), "1h 1m");
        assert_eq!(format_duration(90061.0), "1d 1h");
        assert_eq!(format_duration(f64::INFINITY), "∞");
        assert_eq!(format_duration(1e30), ">1000y");
    }
}
