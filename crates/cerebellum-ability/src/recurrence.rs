//! Host-neutral recurrence-set arithmetic. Unsupported input fails closed.

use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Weekday};
use std::collections::{BTreeMap, BTreeSet};

use crate::ical::{DateValue, ParseError};

const MAX_PERIODS: usize = 200_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Frequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Clone, Debug)]
struct ByDay {
    ordinal: Option<i32>,
    weekday: Weekday,
}

/// The deliberately bounded RRULE dialect supported by the ability reader.
#[derive(Clone, Debug)]
pub struct Rule {
    frequency: Frequency,
    interval: u32,
    count: Option<usize>,
    pub(crate) until: Option<DateValue>,
    by_day: Vec<ByDay>,
    month_days: Vec<i32>,
    months: Vec<u32>,
    positions: Vec<i32>,
    week_start: Weekday,
}

pub(crate) fn parts(text: &str) -> Result<BTreeMap<&str, &str>, ParseError> {
    let mut parts = BTreeMap::new();
    for part in text.split(';') {
        let (name, value) = part.split_once('=').ok_or(ParseError::Unsupported)?;
        if name.is_empty() || value.is_empty() || parts.insert(name, value).is_some() {
            return Err(ParseError::Unsupported);
        }
    }
    Ok(parts)
}

impl Rule {
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let p = parts(text)?;
        if p.keys().any(|k| {
            !matches!(
                *k,
                "FREQ"
                    | "INTERVAL"
                    | "COUNT"
                    | "UNTIL"
                    | "BYDAY"
                    | "BYMONTHDAY"
                    | "BYMONTH"
                    | "BYSETPOS"
                    | "WKST"
            )
        }) {
            return Err(ParseError::Unsupported);
        }
        let frequency = match p.get("FREQ").copied() {
            Some("DAILY") => Frequency::Daily,
            Some("WEEKLY") => Frequency::Weekly,
            Some("MONTHLY") => Frequency::Monthly,
            Some("YEARLY") => Frequency::Yearly,
            _ => return Err(ParseError::Unsupported),
        };
        let interval = p
            .get("INTERVAL")
            .map(|s| positive(s))
            .transpose()?
            .unwrap_or(1);
        let count = p
            .get("COUNT")
            .map(|s| positive(s).map(|n| n as usize))
            .transpose()?;
        let until = p.get("UNTIL").map(|s| DateValue::bare(s)).transpose()?;
        if count.is_some() && until.is_some() {
            return Err(ParseError::Unsupported);
        }
        let mut by_day = Vec::new();
        if let Some(text) = p.get("BYDAY") {
            for value in text.split(',') {
                if value.len() < 2 || !value.is_ascii() {
                    return Err(ParseError::Unsupported);
                }
                let (ordinal, day) = value.split_at(value.len() - 2);
                let ordinal = if ordinal.is_empty() {
                    None
                } else {
                    Some(bounded_signed(ordinal, 53)?)
                };
                if ordinal.is_some() && matches!(frequency, Frequency::Daily | Frequency::Weekly) {
                    return Err(ParseError::Unsupported);
                }
                by_day.push(ByDay {
                    ordinal,
                    weekday: weekday(day)?,
                });
            }
        }
        let month_days = signed_list(p.get("BYMONTHDAY"), 31)?;
        if frequency == Frequency::Weekly && !month_days.is_empty() {
            return Err(ParseError::Unsupported);
        }
        let months = signed_list(p.get("BYMONTH"), 12)?
            .into_iter()
            .map(|n| u32::try_from(n).map_err(|_| ParseError::Unsupported))
            .collect::<Result<Vec<_>, _>>()?;
        let positions = signed_list(p.get("BYSETPOS"), 366)?;
        if !positions.is_empty() && by_day.is_empty() && month_days.is_empty() && months.is_empty()
        {
            return Err(ParseError::Unsupported);
        }
        Ok(Self {
            frequency,
            interval,
            count,
            until,
            by_day,
            month_days,
            months,
            positions,
            week_start: p
                .get("WKST")
                .map(|s| weekday(s))
                .transpose()?
                .unwrap_or(Weekday::Mon),
        })
    }

    /// Enumerate local wall times, leaving UNTIL's zone comparison to the caller.
    /// A resource limit is an error, never a truncated recurrence set.
    pub(crate) fn candidates(
        &self,
        start: NaiveDateTime,
        stop: NaiveDateTime,
    ) -> Result<Vec<NaiveDateTime>, ParseError> {
        let mut period = match self.frequency {
            Frequency::Daily => start.date(),
            Frequency::Weekly => start
                .date()
                .checked_sub_signed(Duration::days(
                    (7 + start.weekday().num_days_from_monday() as i64
                        - self.week_start.num_days_from_monday() as i64)
                        % 7,
                ))
                .ok_or(ParseError::Unsupported)?,
            Frequency::Monthly => date(start.year(), start.month(), 1)?,
            Frequency::Yearly => date(start.year(), 1, 1)?,
        };
        let mut output = Vec::new();
        let mut count = 0;
        for _ in 0..MAX_PERIODS {
            if period > stop.date() {
                return Ok(output);
            }
            let next = self.next_period(period, 1)?;
            let mut candidates = Vec::new();
            let mut day = period;
            while day < next {
                if self.matches(day, start.date()) {
                    candidates.push(day.and_time(start.time()));
                }
                day = day.succ_opt().ok_or(ParseError::Unsupported)?;
            }
            if !self.positions.is_empty() {
                let selected: BTreeSet<_> = self
                    .positions
                    .iter()
                    .filter_map(|&position| {
                        let index = if position > 0 {
                            position as isize - 1
                        } else {
                            candidates.len() as isize + position as isize
                        };
                        usize::try_from(index)
                            .ok()
                            .and_then(|i| candidates.get(i))
                            .copied()
                    })
                    .collect();
                candidates = selected.into_iter().collect();
            }
            for candidate in candidates {
                if candidate < start {
                    continue;
                }
                if candidate > stop {
                    return Ok(output);
                }
                count += 1;
                if self.count.is_some_and(|limit| count > limit) {
                    return Ok(output);
                }
                output.push(candidate);
            }
            period = self.next_period(period, self.interval)?;
        }
        Err(ParseError::Unsupported)
    }

    fn next_period(&self, period: NaiveDate, step: u32) -> Result<NaiveDate, ParseError> {
        match self.frequency {
            Frequency::Daily | Frequency::Weekly => period
                .checked_add_signed(Duration::days(
                    i64::from(step)
                        * if self.frequency == Frequency::Weekly {
                            7
                        } else {
                            1
                        },
                ))
                .ok_or(ParseError::Unsupported),
            Frequency::Monthly => {
                let n =
                    i64::from(period.year()) * 12 + i64::from(period.month0()) + i64::from(step);
                date(
                    i32::try_from(n.div_euclid(12)).map_err(|_| ParseError::Unsupported)?,
                    n.rem_euclid(12) as u32 + 1,
                    1,
                )
            }
            Frequency::Yearly => date(
                period
                    .year()
                    .checked_add(i32::try_from(step).map_err(|_| ParseError::Unsupported)?)
                    .ok_or(ParseError::Unsupported)?,
                1,
                1,
            ),
        }
    }

    fn matches(&self, day: NaiveDate, start: NaiveDate) -> bool {
        if !self.months.is_empty() && !self.months.contains(&day.month()) {
            return false;
        }
        let month_length = days_in_month(day);
        if !self.month_days.is_empty()
            && !self.month_days.iter().any(|&n| {
                if n > 0 {
                    day.day() as i32 == n
                } else {
                    day.day() as i32 == month_length + n + 1
                }
            })
        {
            return false;
        }
        if !self.by_day.is_empty()
            && !self.by_day.iter().any(|b| {
                if b.weekday != day.weekday() {
                    return false;
                }
                let Some(n) = b.ordinal else {
                    return true;
                };
                let (position, length) =
                    if self.frequency == Frequency::Yearly && self.months.is_empty() {
                        (
                            day.ordinal() as i32,
                            if date(day.year(), 12, 31).is_ok_and(|d| d.ordinal() == 366) {
                                366
                            } else {
                                365
                            },
                        )
                    } else {
                        (day.day() as i32, month_length)
                    };
                if n > 0 {
                    (position - 1) / 7 + 1 == n
                } else {
                    -((length - position) / 7 + 1) == n
                }
            })
        {
            return false;
        }
        match self.frequency {
            Frequency::Weekly if self.by_day.is_empty() => day.weekday() == start.weekday(),
            Frequency::Monthly if self.by_day.is_empty() && self.month_days.is_empty() => {
                day.day() == start.day()
            }
            Frequency::Yearly => {
                if self.by_day.is_empty() && self.month_days.is_empty() && day.day() != start.day()
                {
                    return false;
                }
                if self.months.is_empty()
                    && self.by_day.is_empty()
                    && self.month_days.is_empty()
                    && day.month() != start.month()
                {
                    return false;
                }
                true
            }
            _ => true,
        }
    }
}

pub(crate) fn date(year: i32, month: u32, day: u32) -> Result<NaiveDate, ParseError> {
    NaiveDate::from_ymd_opt(year, month, day).ok_or(ParseError::Unsupported)
}
fn days_in_month(day: NaiveDate) -> i32 {
    (28..=31)
        .rev()
        .find(|&n| NaiveDate::from_ymd_opt(day.year(), day.month(), n).is_some())
        .unwrap() as i32
}
fn positive(s: &str) -> Result<u32, ParseError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::Unsupported);
    }
    s.parse::<u32>()
        .ok()
        .filter(|&n| n > 0)
        .ok_or(ParseError::Unsupported)
}
fn bounded_signed(s: &str, bound: i32) -> Result<i32, ParseError> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::Unsupported);
    }
    s.parse::<i32>()
        .ok()
        .filter(|&n| n != 0 && n.checked_abs().is_some_and(|n| n <= bound))
        .ok_or(ParseError::Unsupported)
}
fn signed_list(text: Option<&&str>, bound: i32) -> Result<Vec<i32>, ParseError> {
    text.map(|s| s.split(',').map(|v| bounded_signed(v, bound)).collect())
        .unwrap_or_else(|| Ok(Vec::new()))
}
fn weekday(text: &str) -> Result<Weekday, ParseError> {
    match text {
        "MO" => Ok(Weekday::Mon),
        "TU" => Ok(Weekday::Tue),
        "WE" => Ok(Weekday::Wed),
        "TH" => Ok(Weekday::Thu),
        "FR" => Ok(Weekday::Fri),
        "SA" => Ok(Weekday::Sat),
        "SU" => Ok(Weekday::Sun),
        _ => Err(ParseError::Unsupported),
    }
}
