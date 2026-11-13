//! Window membership and stable identities for already-expanded occurrences.

use crate::{ids::validate_id, ValidationError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub fn overlaps_window(
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    from_ms: i64,
    to_ms: i64,
) -> bool {
    let (Some(start), Some(end)) = (start_ms, end_ms) else {
        return false;
    };
    if from_ms >= to_ms || end < start {
        return false;
    }
    if start == end {
        from_ms <= start && start < to_ms
    } else {
        start < to_ms && end > from_ms
    }
}

/// Use the series' original occurrence start, never an override's moved start.
/// Encoding the series component avoids delimiter collisions in opaque ids.
pub fn occurrence_id(series_id: &str, original_start_ms: i64) -> Result<String, ValidationError> {
    validate_id("series_id", series_id)?;
    let id = format!(
        "occ1.{}.{}",
        URL_SAFE_NO_PAD.encode(series_id),
        original_start_ms
    );
    validate_id("id", &id)?;
    Ok(id)
}

/// The source must still verify that this occurrence exists in the series.
pub fn parse_occurrence_id(id: &str) -> Result<(String, i64), ValidationError> {
    validate_id("id", id)?;
    let parse = || -> Option<(String, i64)> {
        let rest = id.strip_prefix("occ1.")?;
        let (series, start) = rest.split_once('.')?;
        let series = String::from_utf8(URL_SAFE_NO_PAD.decode(series).ok()?).ok()?;
        let start: i64 = start.parse().ok()?;
        (occurrence_id(&series, start).ok()?.as_str() == id).then_some((series, start))
    };
    parse().ok_or_else(|| ValidationError::new("id", "invalid occurrence id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_edges_and_zero_length_belong_to_one_adjacent_window() {
        for (start, end, first, second) in [
            (0, 10, true, false),
            (10, 20, false, true),
            (9, 11, true, true),
            (0, 0, true, false),
            (10, 10, false, true),
            (20, 20, false, false),
        ] {
            assert_eq!(overlaps_window(Some(start), Some(end), 0, 10), first);
            assert_eq!(overlaps_window(Some(start), Some(end), 10, 20), second);
        }
        assert!(!overlaps_window(None, Some(1), 0, 10));
        assert!(!overlaps_window(Some(2), Some(1), 0, 10));
    }

    #[test]
    fn occurrence_ids_round_trip_original_starts_without_collisions() {
        let a = occurrence_id("series.é/", -10).unwrap();
        let b = occurrence_id("series.é/", 20).unwrap();
        assert_ne!(a, b);
        assert_eq!(parse_occurrence_id(&a).unwrap(), ("series.é/".into(), -10));
        assert_eq!(parse_occurrence_id(&b).unwrap(), ("series.é/".into(), 20));
        for bad in [
            "occ1..0",
            "occ1.YQ.01",
            "occ1.YQ.0.extra",
            "occ1.YQ==.0",
            "other.YQ.0",
        ] {
            assert!(parse_occurrence_id(bad).is_err(), "{bad}");
        }
        assert!(occurrence_id(&"s".repeat(2048), 0).is_err());
    }
}
