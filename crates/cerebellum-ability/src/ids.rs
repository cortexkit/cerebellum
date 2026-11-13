use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::ValidationError;

pub const MAX_ID_BYTES: usize = 2048;
pub const APPLE_EPOCH_UNIX_MS: i64 = 978_307_200_000;

pub fn validate_id(field: &str, id: &str) -> Result<(), ValidationError> {
    if id.is_empty() || id.len() > MAX_ID_BYTES {
        return Err(ValidationError::new(
            field,
            "id must contain 1 to 2048 UTF-8 bytes",
        ));
    }
    Ok(())
}

pub fn windows_id(store_id: &[u8], entry_id: &[u8]) -> Result<String, ValidationError> {
    if store_id.is_empty() || entry_id.is_empty() {
        return Err(ValidationError::new("id", "empty Windows id component"));
    }
    let id = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(store_id),
        URL_SAFE_NO_PAD.encode(entry_id)
    );
    validate_id("id", &id)?;
    Ok(id)
}

pub fn parse_windows_id(id: &str) -> Result<(Vec<u8>, Vec<u8>), ValidationError> {
    validate_id("id", id)?;
    let decode = || -> Option<(Vec<u8>, Vec<u8>)> {
        let (store, entry) = id.split_once('.')?;
        if store.is_empty() || entry.is_empty() {
            return None;
        }
        Some((
            URL_SAFE_NO_PAD.decode(store).ok()?,
            URL_SAFE_NO_PAD.decode(entry).ok()?,
        ))
    };
    decode().ok_or_else(|| ValidationError::new("id", "invalid unpadded base64url Windows id"))
}

/// NSDate-style seconds, including the valid date at Apple's epoch itself.
/// Non-finite or unrepresentable dates stay null.
pub fn apple_seconds_to_unix_ms(seconds: f64) -> Option<i64> {
    if !seconds.is_finite() {
        return None;
    }
    let ms = (seconds * 1000.0).round();
    if ms < i64::MIN as f64 || ms >= i64::MAX as f64 {
        return None;
    }
    (ms as i64).checked_add(APPLE_EPOCH_UNIX_MS)
}

/// For stores that use seconds and reserve zero for an absent message date.
pub fn apple_store_seconds_to_unix_ms(seconds: f64) -> Option<i64> {
    if seconds == 0.0 {
        None
    } else {
        apple_seconds_to_unix_ms(seconds)
    }
}

/// chat.db nanoseconds since 2001. Zero is a missing store date, not the epoch.
pub fn apple_nanoseconds_to_unix_ms(nanoseconds: i64) -> Option<i64> {
    if nanoseconds == 0 {
        return None;
    }
    (nanoseconds.div_euclid(1_000_000)).checked_add(APPLE_EPOCH_UNIX_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_id_has_canonical_unpadded_base64url_components() {
        assert_eq!(windows_id(&[0xfb, 0xff], &[0, 1, 2]).unwrap(), "-_8.AAEC");
        assert_eq!(
            parse_windows_id("-_8.AAEC").unwrap(),
            (vec![0xfb, 0xff], vec![0, 1, 2])
        );
        for id in [
            "", ".AA", "AA.", "AA.AA.AA", "AA==.AA", "+w.AA", "/w.AA", "AB.AA", "é.AA",
        ] {
            assert!(parse_windows_id(id).is_err(), "{id}");
        }
        assert!(windows_id(&[], &[0]).is_err());
        assert!(windows_id(&[0; 1536], &[0]).is_err());
        assert!(parse_windows_id(&"A".repeat(2049)).is_err());
    }

    #[test]
    fn apple_dates_convert_to_unix_ms_and_zero_is_absent() {
        assert_eq!(apple_seconds_to_unix_ms(1.25), Some(978_307_201_250));
        assert_eq!(apple_seconds_to_unix_ms(-1.0), Some(978_307_199_000));
        assert_eq!(
            apple_nanoseconds_to_unix_ms(1_250_000_000),
            Some(978_307_201_250)
        );
        assert_eq!(apple_nanoseconds_to_unix_ms(-1), Some(978_307_199_999));
        assert_eq!(apple_seconds_to_unix_ms(0.0), Some(978_307_200_000));
        assert_eq!(apple_store_seconds_to_unix_ms(0.0), None);
        assert_eq!(apple_store_seconds_to_unix_ms(1.25), Some(978_307_201_250));
        assert_eq!(apple_nanoseconds_to_unix_ms(0), None);
        for n in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MAX] {
            assert_eq!(apple_seconds_to_unix_ms(n), None);
        }
    }
}
