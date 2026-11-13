//! Shared event and reminder time conversion against bundled IANA rules.
//!
//! Sources supply the computer's current IANA zone name once per read, even
//! for an empty result or an item whose timestamps already denote instants.
//! A missing or unknown name, or a conversion error, must fail the source read
//! with `ability_source_failed`; callers must not substitute UTC.
//! This module never discovers a host zone or reads the system clock.

use crate::{items::Event, ValidationError};
use chrono::{DateTime, LocalResult, TimeZone};
use chrono_tz::{GapInfo, Tz};

pub use chrono::{NaiveDate, NaiveDateTime};

/// The source's explicitly supplied zone, validated before reading any items.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTimeZone(Tz);

/// A reminder's source value, before conversion to Unix epoch milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReminderDue {
    Date(NaiveDate),
    /// A floating date-time with no zone in the source.
    LocalDateTime(NaiveDateTime),
    /// An already-resolved instant, including a source value with its own zone.
    InstantMs(i64),
}

impl SourceTimeZone {
    /// Accept only a database name, not an offset or a platform-specific zone id.
    pub fn from_iana_name(name: Option<&str>) -> Result<Self, ValidationError> {
        let name =
            name.ok_or_else(|| ValidationError::new("time_zone", "missing IANA zone name"))?;
        name.parse()
            .map(Self)
            .map_err(|_| ValidationError::new("time_zone", "unknown IANA zone name"))
    }

    /// Resolve a repeated time to its earlier instant and a removed time to
    /// the first instant after the gap, not the requested minutes after it.
    pub fn local_datetime_ms(&self, local: NaiveDateTime) -> Result<i64, ValidationError> {
        Ok(self.resolve_local(local)?.timestamp_millis())
    }

    /// Midnight is not always present or unique. A wholly skipped date has no
    /// first instant and is an error rather than an instant on another date.
    pub fn first_instant_ms(&self, date: NaiveDate) -> Result<i64, ValidationError> {
        let midnight = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| ValidationError::new("date", "unrepresentable midnight"))?;
        let first = self.resolve_local(midnight)?;
        if first.date_naive() != date {
            return Err(ValidationError::new("date", "date has no instant in zone"));
        }
        Ok(first.timestamp_millis())
    }

    /// Set all-day instants from the source's YYYY-MM-DD dates (end exclusive).
    /// For other events, preserve the source instants and clear both dates.
    /// On error the event is unchanged, so no partially converted item escapes.
    pub fn normalize_event(&self, event: &mut Event) -> Result<(), ValidationError> {
        if event.all_day == Some(true) {
            let start = parse_date(event.start_date.as_deref(), "start_date")?;
            let end = parse_date(event.end_date.as_deref(), "end_date")?;
            if end <= start {
                return Err(ValidationError::new(
                    "end_date",
                    "exclusive end must follow start date",
                ));
            }
            let start_ms = self.first_instant_ms(start)?;
            let end_ms = self.first_instant_ms(end)?;
            event.start_ms = Some(start_ms);
            event.end_ms = Some(end_ms);
        } else {
            event.start_date = None;
            event.end_date = None;
        }
        Ok(())
    }

    pub fn reminder_due_ms(
        &self,
        due: Option<ReminderDue>,
    ) -> Result<Option<i64>, ValidationError> {
        due.map(|due| match due {
            ReminderDue::Date(date) => self.first_instant_ms(date),
            ReminderDue::LocalDateTime(local) => self.local_datetime_ms(local),
            ReminderDue::InstantMs(ms) => Ok(ms),
        })
        .transpose()
    }

    fn resolve_local(&self, local: NaiveDateTime) -> Result<DateTime<Tz>, ValidationError> {
        match self.0.from_local_datetime(&local) {
            LocalResult::Single(instant) => Ok(instant),
            LocalResult::Ambiguous(a, b) => Ok(a.min(b)),
            LocalResult::None => GapInfo::new(&local, &self.0)
                .and_then(|gap| gap.end)
                .ok_or_else(|| ValidationError::new("date", "cannot resolve local time in zone")),
        }
    }
}

fn parse_date(value: Option<&str>, field: &'static str) -> Result<NaiveDate, ValidationError> {
    value
        .filter(|value| crate::items::valid_date(value))
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        .ok_or_else(|| ValidationError::new(field, "expected YYYY-MM-DD"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(name: &str) -> SourceTimeZone {
        SourceTimeZone::from_iana_name(Some(name)).unwrap()
    }

    fn date(value: &str) -> NaiveDate {
        value.parse().unwrap()
    }

    fn local(value: &str) -> NaiveDateTime {
        value.parse().unwrap()
    }

    fn utc_ms(value: &str) -> i64 {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .timestamp_millis()
    }

    fn all_day(start: &str, end: &str) -> Event {
        Event {
            id: "event".into(),
            calendar: "calendar".into(),
            all_day: Some(true),
            start_date: Some(start.into()),
            end_date: Some(end.into()),
            ..Event::default()
        }
    }

    #[test]
    fn all_day_dates_remain_exclusive_across_a_short_day() {
        let mut event = all_day("2025-03-09", "2025-03-10");
        zone("America/New_York")
            .normalize_event(&mut event)
            .unwrap();
        let wire = serde_json::to_value(&event).unwrap();
        assert_eq!(wire["all_day"], true);
        assert_eq!(wire["start_date"], "2025-03-09");
        assert_eq!(wire["end_date"], "2025-03-10");
        assert_eq!(wire["start_ms"], utc_ms("2025-03-09T05:00:00Z"));
        assert_eq!(wire["end_ms"], utc_ms("2025-03-10T04:00:00Z"));
        assert_eq!(event.end_ms.unwrap() - event.start_ms.unwrap(), 82_800_000);
    }

    #[test]
    fn removed_midnight_starts_at_the_dates_first_instant() {
        // Sao Paulo skipped 00:00 through 00:59:59 on this date.
        let time_zone = zone("America/Sao_Paulo");
        let mut event = all_day("2018-11-04", "2018-11-05");
        time_zone.normalize_event(&mut event).unwrap();
        assert_eq!(event.start_ms, Some(utc_ms("2018-11-04T03:00:00Z")));
        assert_eq!(event.end_ms, Some(utc_ms("2018-11-05T02:00:00Z")));
        assert_eq!(
            time_zone
                .reminder_due_ms(Some(ReminderDue::Date(date("2018-11-04"))))
                .unwrap(),
            Some(utc_ms("2018-11-04T03:00:00Z"))
        );
    }

    #[test]
    fn repeated_midnight_uses_its_first_occurrence() {
        let mut event = all_day("2025-11-02", "2025-11-03");
        zone("America/Havana").normalize_event(&mut event).unwrap();
        assert_eq!(event.start_ms, Some(utc_ms("2025-11-02T04:00:00Z")));
        assert_eq!(event.end_ms, Some(utc_ms("2025-11-03T05:00:00Z")));
    }

    #[test]
    fn non_all_day_events_clear_dates_and_preserve_instants() {
        for all_day in [Some(false), None] {
            let mut event = all_day_event_with_flag(all_day);
            zone("Asia/Kathmandu").normalize_event(&mut event).unwrap();
            assert_eq!(event.start_ms, Some(123));
            assert_eq!(event.end_ms, Some(456));
            let wire = serde_json::to_value(&event).unwrap();
            assert!(wire["start_date"].is_null());
            assert!(wire["end_date"].is_null());
        }
    }

    fn all_day_event_with_flag(flag: Option<bool>) -> Event {
        Event {
            all_day: flag,
            start_ms: Some(123),
            end_ms: Some(456),
            ..all_day("2025-01-01", "2025-01-02")
        }
    }

    #[test]
    fn reminder_date_and_floating_datetime_use_only_the_supplied_zone() {
        let time_zone = zone("Asia/Kathmandu");
        assert_eq!(
            time_zone
                .reminder_due_ms(Some(ReminderDue::Date(date("2025-01-01"))))
                .unwrap(),
            Some(utc_ms("2024-12-31T18:15:00Z"))
        );
        assert_eq!(
            time_zone
                .reminder_due_ms(Some(ReminderDue::LocalDateTime(local(
                    "2025-01-01T12:30:00.125"
                ))))
                .unwrap(),
            Some(utc_ms("2025-01-01T06:45:00.125Z"))
        );
        assert_eq!(time_zone.reminder_due_ms(None).unwrap(), None);
        assert_eq!(
            time_zone
                .reminder_due_ms(Some(ReminderDue::InstantMs(-123)))
                .unwrap(),
            Some(-123)
        );
    }

    #[test]
    fn new_york_repeated_due_time_uses_the_earlier_instant() {
        assert_eq!(
            zone("America/New_York")
                .reminder_due_ms(Some(ReminderDue::LocalDateTime(local(
                    "2025-11-02T01:30:00"
                ))))
                .unwrap(),
            Some(utc_ms("2025-11-02T05:30:00Z"))
        );
    }

    #[test]
    fn new_york_removed_due_time_uses_the_gap_end_not_shifted_minutes() {
        assert_eq!(
            zone("America/New_York")
                .reminder_due_ms(Some(ReminderDue::LocalDateTime(local(
                    "2025-03-09T02:30:00"
                ))))
                .unwrap(),
            Some(utc_ms("2025-03-09T07:00:00Z"))
        );
    }

    #[test]
    fn missing_unknown_and_non_iana_zones_never_fall_back_to_utc() {
        for name in [
            None,
            Some(""),
            Some("Mars/Olympus"),
            Some("Eastern Standard Time"),
            Some("+05:45"),
        ] {
            let error = SourceTimeZone::from_iana_name(name).unwrap_err();
            assert_eq!(error.field, "time_zone");
            assert!(!error.to_string().contains("Mars"));
        }
        assert!(SourceTimeZone::from_iana_name(Some("UTC")).is_ok());
    }

    #[test]
    fn invalid_all_day_dates_fail_without_changing_the_event() {
        let time_zone = zone("America/New_York");
        let mut missing = all_day("2025-01-01", "2025-01-02");
        missing.end_date = None;
        for mut event in [
            missing,
            all_day("2025-2-01", "2025-02-02"),
            all_day("2025-02-29", "2025-03-01"),
            all_day("2025-03-10", "2025-03-09"),
            all_day("2025-03-09", "2025-03-09"),
        ] {
            event.start_ms = Some(123);
            event.end_ms = Some(456);
            let before = event.clone();
            assert!(time_zone.normalize_event(&mut event).is_err());
            assert_eq!(event, before);
        }
        let mut leap_day = all_day("2024-02-29", "2024-03-01");
        assert!(time_zone.normalize_event(&mut leap_day).is_ok());
    }

    #[test]
    fn a_wholly_skipped_date_has_no_first_instant() {
        assert!(zone("Pacific/Apia")
            .first_instant_ms(date("2011-12-30"))
            .is_err());
        let mut event = all_day("2011-12-29", "2011-12-30");
        let before = event.clone();
        assert!(zone("Pacific/Apia").normalize_event(&mut event).is_err());
        assert_eq!(event, before);
    }
}
