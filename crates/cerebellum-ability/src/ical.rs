//! Owned iCalendar content-line reader and host-neutral event/task projection.
//!
//! Adapters pass the computer's validated IANA zone and the source container id.
//! No system store, clock, locale or native calendar library is consulted.

use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, TimeZone};
use chrono_tz::{GapInfo, Tz};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    events::{occurrence_id, overlaps_window, parse_occurrence_id},
    items::{Event, Reminder},
    recurrence::{parts, Rule},
    time::SourceTimeZone,
};

const DAY_MS: i64 = 86_400_000;

/// Adapters map Unsupported to ability_recurrence_unsupported for event reads,
/// and SourceTimeZone/Syntax/IdTooLong to ability_source_failed. No input text is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Syntax,
    Unsupported,
    SourceTimeZone,
    IdTooLong,
}
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Syntax => "malformed content",
                Self::Unsupported => "unsupported calendar value",
                Self::SourceTimeZone => "unresolved computer time zone",
                Self::IdTooLong => "calendar occurrence id exceeds the id cap",
            }
        )
    }
}
impl std::error::Error for ParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Property {
    pub name: String,
    pub params: BTreeMap<String, String>,
    pub value: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Component {
    pub name: String,
    pub properties: Vec<Property>,
    pub children: Vec<Component>,
}
impl Component {
    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> {
        self.properties.iter().filter(move |p| p.name == name)
    }
    fn one(&self, name: &str) -> Result<Option<&Property>, ParseError> {
        let mut found = self.properties.iter().filter(|p| p.name == name);
        let first = found.next();
        if found.next().is_some() {
            return Err(ParseError::Unsupported);
        }
        Ok(first)
    }
    pub(crate) fn text(&self, name: &str) -> Result<Option<String>, ParseError> {
        self.one(name)?.map(|p| unescape(&p.value)).transpose()
    }
    fn required(&self, name: &str) -> Result<&Property, ParseError> {
        self.one(name)?.ok_or(ParseError::Unsupported)
    }
}

fn eds_components(texts: &[String]) -> Result<Vec<Component>, ParseError> {
    let mut result = Vec::new();
    for text in texts {
        for root in components(text)? {
            if root.name == "VCALENDAR" {
                result.extend(root.children);
            } else {
                result.push(root);
            }
        }
    }
    Ok(result)
}

/// EDS can return bare components without their VTIMEZONE definitions. Fetch
/// only referenced definitions not already carried by the source snapshot.
pub fn eds_missing_time_zones(texts: &[String]) -> Result<Vec<String>, ParseError> {
    fn collect(component: &Component, ids: &mut BTreeSet<String>) {
        for p in &component.properties {
            if let Some(id) = p.params.get("TZID") {
                ids.insert(id.clone());
            }
        }
        for child in &component.children {
            collect(child, ids);
        }
    }
    let components = eds_components(texts)?;
    let mut referenced = BTreeSet::new();
    let mut defined = BTreeSet::new();
    for component in components {
        if component.name == "VTIMEZONE" {
            defined.insert(component.text("TZID")?.ok_or(ParseError::Unsupported)?);
        } else {
            collect(&component, &mut referenced);
        }
    }
    Ok(referenced.difference(&defined).cloned().collect())
}

/// Join one EDS source's object list before projecting it. Detached overrides
/// must be parsed with their masters, not as independent events. Repeated,
/// identical zone definitions are harmless; conflicting ones fail closed.
pub fn join_eds_objects(texts: &[String]) -> Result<String, ParseError> {
    fn render(component: &Component, out: &mut String) -> Result<(), ParseError> {
        out.push_str(&format!("BEGIN:{}\r\n", component.name));
        for p in &component.properties {
            out.push_str(&p.name);
            for (key, value) in &p.params {
                if value.contains('"') {
                    return Err(ParseError::Unsupported);
                }
                out.push_str(&format!(";{key}=\"{value}\""));
            }
            out.push(':');
            out.push_str(&p.value);
            out.push_str("\r\n");
        }
        for child in &component.children {
            render(child, out)?;
        }
        out.push_str(&format!("END:{}\r\n", component.name));
        Ok(())
    }
    let mut zones = BTreeMap::new();
    let mut output = String::new();
    for component in eds_components(texts)? {
        if component.name == "VTIMEZONE" {
            let id = component.text("TZID")?.ok_or(ParseError::Unsupported)?;
            if let Some(prior) = zones.insert(id, component.clone()) {
                if prior != component {
                    return Err(ParseError::Unsupported);
                }
                continue;
            }
        } else if !matches!(component.name.as_str(), "VEVENT" | "VTODO") {
            return Err(ParseError::Unsupported);
        }
        render(&component, &mut output)?;
    }
    Ok(output)
}

#[cfg(test)]
mod eds_tests {
    use super::*;

    #[test]
    fn ical_eds_object_lists_keep_overrides_with_masters_and_deduplicate_equal_zones() {
        let zone = "BEGIN:VTIMEZONE\nTZID:Private/Zone\nBEGIN:STANDARD\nDTSTART:19700101T000000\nTZOFFSETFROM:+0100\nTZOFFSETTO:+0100\nEND:STANDARD\nEND:VTIMEZONE";
        let master = "BEGIN:VEVENT\nUID:series\nDTSTART;TZID=Private/Zone:20250101T090000\nDURATION:PT1H\nRRULE:FREQ=DAILY;COUNT=2\nEND:VEVENT";
        let detached = "BEGIN:VEVENT\nUID:series\nRECURRENCE-ID;TZID=Private/Zone:20250102T090000\nDTSTART;TZID=Private/Zone:20250102T110000\nDURATION:PT1H\nEND:VEVENT";
        assert_eq!(
            eds_missing_time_zones(&[master.into(), detached.into()]).unwrap(),
            ["Private/Zone"]
        );
        let texts = [
            format!("BEGIN:VCALENDAR\n{master}\n{zone}\nEND:VCALENDAR"),
            format!("BEGIN:VCALENDAR\n{zone}\n{detached}\nEND:VCALENDAR"),
        ];
        assert!(eds_missing_time_zones(&texts).unwrap().is_empty());
        let joined = join_eds_objects(&texts).unwrap();
        let calendar = Calendar::parse(&joined, Some("Europe/Berlin")).unwrap();
        let events = calendar
            .events("source", 1_735_689_600_000, 1_735_948_800_000)
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].start_ms, Some(1_735_718_400_000));
        assert_eq!(events[1].start_ms, Some(1_735_812_000_000));
        for event in events {
            assert_eq!(calendar.event("source", &event.id).unwrap(), Some(event));
        }
        assert_eq!(
            join_eds_objects(&[texts[0].clone(), zone.replace("+0100", "+0200")]),
            Err(ParseError::Unsupported)
        );
    }

    #[test]
    fn ical_eds_unresolved_zones_and_malformed_snapshots_never_become_utc() {
        let text = "BEGIN:VEVENT\nUID:zone\nDTSTART;TZID=Unknown/Zone:20250101T090000\nEND:VEVENT";
        let joined = join_eds_objects(&[text.into()]).unwrap();
        let calendar = Calendar::parse(&joined, Some("Europe/Berlin")).unwrap();
        assert_eq!(
            calendar.events("source", 1_735_689_600_000, 1_735_948_800_000),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            join_eds_objects(&["BEGIN:VEVENT\nEND:VTODO".into()]),
            Err(ParseError::Syntax)
        );
    }
}

/// Unfold before splitting content lines; quoted parameter delimiters are data.
pub(crate) fn components(text: &str) -> Result<Vec<Component>, ParseError> {
    let mut lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with([' ', '\t']) {
            lines
                .last_mut()
                .ok_or(ParseError::Syntax)?
                .push_str(&line[1..]);
        } else if !line.is_empty() {
            lines.push(line.to_owned());
        }
    }
    let mut stack: Vec<Component> = Vec::new();
    let mut roots = Vec::new();
    for line in lines {
        let colon = delimiter(&line, ':').ok_or(ParseError::Syntax)?;
        let (head, value) = (&line[..colon], &line[colon + 1..]);
        let fields = split_quoted(head, ';')?;
        let name = fields
            .first()
            .ok_or(ParseError::Syntax)?
            .to_ascii_uppercase();
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            || name.is_empty()
        {
            return Err(ParseError::Syntax);
        }
        let mut params = BTreeMap::new();
        for field in &fields[1..] {
            let (key, value) = field.split_once('=').ok_or(ParseError::Syntax)?;
            if key.is_empty()
                || value.is_empty()
                || params
                    .insert(key.to_ascii_uppercase(), value.trim_matches('"').to_owned())
                    .is_some()
            {
                return Err(ParseError::Syntax);
            }
        }
        if name == "BEGIN" {
            if !params.is_empty() || stack.len() >= 16 {
                return Err(ParseError::Syntax);
            }
            stack.push(Component {
                name: value.to_ascii_uppercase(),
                properties: Vec::new(),
                children: Vec::new(),
            });
        } else if name == "END" {
            let component = stack.pop().ok_or(ParseError::Syntax)?;
            if !component.name.eq_ignore_ascii_case(value) || !params.is_empty() {
                return Err(ParseError::Syntax);
            }
            if let Some(parent) = stack.last_mut() {
                parent.children.push(component);
            } else {
                roots.push(component);
            }
        } else {
            stack
                .last_mut()
                .ok_or(ParseError::Syntax)?
                .properties
                .push(Property {
                    name,
                    params,
                    value: value.to_owned(),
                });
        }
    }
    if !stack.is_empty() || roots.is_empty() {
        return Err(ParseError::Syntax);
    }
    Ok(roots)
}
fn delimiter(text: &str, needle: char) -> Option<usize> {
    let mut quoted = false;
    for (i, ch) in text.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch == needle && !quoted {
            return Some(i);
        }
    }
    None
}
pub(crate) fn split_quoted(text: &str, delimiter: char) -> Result<Vec<&str>, ParseError> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
        }
        if ch == delimiter && !quoted {
            parts.push(&text[start..i]);
            start = i + ch.len_utf8();
        }
    }
    if quoted || escaped {
        return Err(ParseError::Syntax);
    }
    parts.push(&text[start..]);
    Ok(parts)
}
pub(crate) fn unescape(text: &str) -> Result<String, ParseError> {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        out.push(match chars.next() {
            Some('n' | 'N') => '\n',
            Some(ch @ ('\\' | ',' | ';' | ':')) => ch,
            _ => return Err(ParseError::Syntax),
        });
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub(crate) struct DateValue {
    pub local: NaiveDateTime,
    pub date_only: bool,
    pub zone: Option<String>,
}
impl DateValue {
    pub(crate) fn bare(text: &str) -> Result<Self, ParseError> {
        let (value, utc) = text
            .strip_suffix('Z')
            .map(|s| (s, true))
            .unwrap_or((text, false));
        let date_only = value.len() == 8;
        let local = if date_only {
            if utc {
                return Err(ParseError::Unsupported);
            }
            NaiveDate::parse_from_str(value, "%Y%m%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
        } else if value.len() == 15 {
            NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S").ok()
        } else {
            None
        }
        .ok_or(ParseError::Unsupported)?;
        if local
            .format(if date_only { "%Y%m%d" } else { "%Y%m%dT%H%M%S" })
            .to_string()
            != value
        {
            return Err(ParseError::Unsupported);
        }
        Ok(Self {
            local,
            date_only,
            zone: utc.then(|| "UTC".to_owned()),
        })
    }
    fn property(p: &Property) -> Result<Self, ParseError> {
        let mut value = Self::bare(&p.value)?;
        if p.params
            .get("VALUE")
            .is_some_and(|kind| kind != if value.date_only { "DATE" } else { "DATE-TIME" })
        {
            return Err(ParseError::Unsupported);
        }
        if let Some(zone) = p.params.get("TZID") {
            if value.zone.is_some() || value.date_only {
                return Err(ParseError::Unsupported);
            }
            value.zone = Some(zone.clone());
        }
        Ok(value)
    }
    fn at(&self, local: NaiveDateTime) -> Self {
        Self {
            local,
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug)]
struct Span {
    days: i64,
    seconds: i64,
    nominal: bool,
}
impl Span {
    fn parse(text: &str) -> Result<Self, ParseError> {
        let text = text.strip_prefix('P').ok_or(ParseError::Unsupported)?;
        let (mut number, mut days, mut seconds, mut time, mut any, mut last) =
            (String::new(), 0i64, 0i64, false, false, 0);
        for ch in text.chars() {
            if ch.is_ascii_digit() {
                number.push(ch);
                continue;
            }
            if ch == 'T' && !time && number.is_empty() {
                time = true;
                last = 0;
                continue;
            }
            let n: i64 = number.parse().map_err(|_| ParseError::Unsupported)?;
            number.clear();
            let (rank, scale) = match (time, ch) {
                (false, 'W') => (1, 7),
                (false, 'D') => (2, 1),
                (true, 'H') => (1, 3600),
                (true, 'M') => (2, 60),
                (true, 'S') => (3, 1),
                _ => return Err(ParseError::Unsupported),
            };
            if rank <= last {
                return Err(ParseError::Unsupported);
            }
            last = rank;
            let target = if time { &mut seconds } else { &mut days };
            *target = target
                .checked_add(n.checked_mul(scale).ok_or(ParseError::Unsupported)?)
                .ok_or(ParseError::Unsupported)?;
            any = true;
        }
        if !any
            || !number.is_empty()
            || text.ends_with('T')
            || (text.contains('W') && (text.contains('D') || time))
        {
            return Err(ParseError::Unsupported);
        }
        Ok(Self {
            days,
            seconds,
            nominal: text.contains(['D', 'W']),
        })
    }
}

/// Parsed calendar. Keep all detached overrides for a UID in the same object;
/// otherwise neither expansion nor the unsupported-event exclusion proof is safe.
#[derive(Clone, Debug)]
pub struct Calendar {
    objects: Vec<Component>,
    zones: BTreeMap<String, Component>,
    source_zone: SourceTimeZone,
}
impl Calendar {
    pub fn parse(text: &str, computer_zone: Option<&str>) -> Result<Self, ParseError> {
        let source_zone = SourceTimeZone::from_iana_name(computer_zone)
            .map_err(|_| ParseError::SourceTimeZone)?;
        let roots = components(text)?;
        let mut objects = Vec::new();
        let mut zones = BTreeMap::new();
        for root in roots {
            let children = if root.name == "VCALENDAR" {
                root.children
            } else {
                vec![root]
            };
            for child in children {
                match child.name.as_str() {
                    "VTIMEZONE" => {
                        let id = child.text("TZID")?.ok_or(ParseError::Unsupported)?;
                        if zones.insert(id, child).is_some() {
                            return Err(ParseError::Unsupported);
                        }
                    }
                    "VEVENT" | "VTODO" => objects.push(child),
                    _ => return Err(ParseError::Unsupported),
                }
            }
        }
        Ok(Self {
            objects,
            zones,
            source_zone,
        })
    }

    pub fn events(
        &self,
        calendar: &str,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<Event>, ParseError> {
        if from_ms >= to_ms {
            return Err(ParseError::Syntax);
        }
        let mut output = Vec::new();
        for (uid, objects) in self.series()? {
            let master = master(&objects)?;
            match self.expand(&uid, master, &objects, calendar, from_ms, to_ms) {
                Ok(items) => output.extend(items),
                Err(_) if self.proved_outside(master, &objects, from_ms, to_ms) => {}
                Err(e) => return Err(e),
            }
        }
        output.sort_by(|a, b| {
            a.start_ms
                .cmp(&b.start_ms)
                .then(a.id.as_bytes().cmp(b.id.as_bytes()))
        });
        Ok(output)
    }

    /// Lookup validates the complete series, then verifies original-start membership.
    /// The caller maps None identically to an unknown or out-of-scope source id.
    pub fn event(&self, calendar: &str, id: &str) -> Result<Option<Event>, ParseError> {
        let occurrence = parse_occurrence_id(id).ok();
        let uid = occurrence
            .as_ref()
            .map(|(uid, _)| uid.as_str())
            .unwrap_or(id);
        let series = self.series()?;
        let Some(objects) = series.get(uid) else {
            return Ok(None);
        };
        let master = master(objects)?;
        let target = occurrence
            .as_ref()
            .map(|(_, start)| *start)
            .unwrap_or(self.resolve(&DateValue::property(master.required("DTSTART")?)?)?);
        let end = target.checked_add(1).ok_or(ParseError::Unsupported)?;
        // Include moved overrides even when their original start is outside this window.
        let items = self.expand(uid, master, objects, calendar, target, end)?;
        if let Some(item) = items.into_iter().find(|e| e.id == id) {
            return Ok(Some(item));
        }
        for object in objects {
            if let Some(recur) = object.one("RECURRENCE-ID")? {
                if self.resolve(&DateValue::property(recur)?)? == target {
                    if object.text("STATUS")?.as_deref() == Some("CANCELLED") {
                        return Ok(None);
                    }
                    let moved = self.resolve(&DateValue::property(object.required("DTSTART")?)?)?;
                    let items = self.expand(
                        uid,
                        master,
                        objects,
                        calendar,
                        moved,
                        moved.checked_add(1).ok_or(ParseError::Unsupported)?,
                    )?;
                    return Ok(items.into_iter().find(|e| e.id == id));
                }
            }
        }
        Ok(None)
    }

    pub fn reminders(&self, list: &str) -> Result<Vec<Reminder>, ParseError> {
        self.objects
            .iter()
            .filter(|o| o.name == "VTODO")
            .map(|o| {
                let due_ms = o
                    .one("DUE")?
                    .map(|p| DateValue::property(p).and_then(|d| self.resolve(&d)))
                    .transpose()?;
                let completed_ms = o
                    .one("COMPLETED")?
                    .map(|p| DateValue::property(p).and_then(|d| self.resolve(&d)))
                    .transpose()?;
                Ok(Reminder {
                    id: o.text("UID")?.ok_or(ParseError::Unsupported)?,
                    list: list.to_owned(),
                    title: o.text("SUMMARY")?,
                    notes: o.text("DESCRIPTION")?,
                    due_ms,
                    completed: Some(
                        o.text("STATUS")?.as_deref() == Some("COMPLETED") || completed_ms.is_some(),
                    ),
                    completed_ms,
                    ..Reminder::default()
                })
            })
            .collect()
    }

    fn series(&self) -> Result<BTreeMap<String, Vec<&Component>>, ParseError> {
        let mut series: BTreeMap<String, Vec<&Component>> = BTreeMap::new();
        for object in self.objects.iter().filter(|o| o.name == "VEVENT") {
            let uid = object
                .text("UID")?
                .filter(|s| !s.is_empty())
                .ok_or(ParseError::Unsupported)?;
            series.entry(uid).or_default().push(object);
        }
        Ok(series)
    }
}
fn master<'a>(objects: &[&'a Component]) -> Result<&'a Component, ParseError> {
    let mut masters = Vec::new();
    for object in objects {
        if object.one("RECURRENCE-ID")?.is_none() {
            masters.push(*object);
        }
    }
    if masters.len() != 1 {
        return Err(ParseError::Unsupported);
    }
    Ok(masters[0])
}

#[derive(Clone, Debug)]
enum Length {
    Exact(i64),
    Nominal { days: i64, seconds: i64 },
}
#[derive(Clone, Debug)]
struct EventDef {
    start: DateValue,
    length: Length,
}
impl Calendar {
    fn definition(&self, object: &Component) -> Result<EventDef, ParseError> {
        let start = DateValue::property(object.required("DTSTART")?)?;
        self.resolve(&start)?;
        let end = object.one("DTEND")?;
        let duration = object.one("DURATION")?;
        if end.is_some() && duration.is_some() {
            return Err(ParseError::Unsupported);
        }
        let length = if let Some(end) = end {
            let end = DateValue::property(end)?;
            if start.date_only != end.date_only {
                return Err(ParseError::Unsupported);
            }
            if start.date_only {
                Length::Nominal {
                    days: (end.local - start.local).num_days(),
                    seconds: 0,
                }
            } else {
                Length::Exact(
                    self.resolve(&end)?
                        .checked_sub(self.resolve(&start)?)
                        .ok_or(ParseError::Unsupported)?,
                )
            }
        } else if let Some(duration) = duration {
            let span = Span::parse(&duration.value)?;
            if start.date_only && span.seconds != 0 {
                return Err(ParseError::Unsupported);
            }
            if span.nominal || start.date_only {
                Length::Nominal {
                    days: span.days,
                    seconds: span.seconds,
                }
            } else {
                Length::Exact(
                    span.seconds
                        .checked_mul(1000)
                        .ok_or(ParseError::Unsupported)?,
                )
            }
        } else if start.date_only {
            Length::Nominal {
                days: 1,
                seconds: 0,
            }
        } else {
            Length::Exact(0)
        };
        let def = EventDef { start, length };
        let (start, end) = self.bounds(&def)?;
        if end < start || (def.start.date_only && end == start) {
            return Err(ParseError::Unsupported);
        }
        Ok(def)
    }
    fn bounds(&self, def: &EventDef) -> Result<(i64, i64), ParseError> {
        let start = self.resolve(&def.start)?;
        let end = match def.length {
            Length::Exact(ms) => start.checked_add(ms),
            Length::Nominal { days, seconds } => {
                let local = def
                    .start
                    .local
                    .checked_add_signed(Duration::try_days(days).ok_or(ParseError::Unsupported)?)
                    .ok_or(ParseError::Unsupported)?;
                self.resolve(&def.start.at(local))?
                    .checked_add(seconds.checked_mul(1000).ok_or(ParseError::Unsupported)?)
            }
        }
        .ok_or(ParseError::Unsupported)?;
        Ok((start, end))
    }
    fn values(
        &self,
        object: &Component,
        name: &str,
        master: &EventDef,
    ) -> Result<Vec<EventDef>, ParseError> {
        let mut values = Vec::new();
        for property in object.all(name) {
            for text in property.value.split(',') {
                let (start, end) = text
                    .split_once('/')
                    .map(|(a, b)| (a, Some(b)))
                    .unwrap_or((text, None));
                let mut p = property.clone();
                p.value = start.to_owned();
                if end.is_some() {
                    if name != "RDATE"
                        || p.params.get("VALUE").map(String::as_str) != Some("PERIOD")
                    {
                        return Err(ParseError::Unsupported);
                    }
                    p.params.remove("VALUE");
                }
                let start = DateValue::property(&p)?;
                if start.date_only != master.start.date_only {
                    return Err(ParseError::Unsupported);
                }
                let length = if let Some(end) = end {
                    if start.date_only {
                        return Err(ParseError::Unsupported);
                    }
                    if end.starts_with('P') {
                        let span = Span::parse(end)?;
                        if span.nominal {
                            Length::Nominal {
                                days: span.days,
                                seconds: span.seconds,
                            }
                        } else {
                            Length::Exact(
                                span.seconds
                                    .checked_mul(1000)
                                    .ok_or(ParseError::Unsupported)?,
                            )
                        }
                    } else {
                        p.value = end.to_owned();
                        let end = DateValue::property(&p)?;
                        if end.date_only {
                            return Err(ParseError::Unsupported);
                        }
                        Length::Exact(
                            self.resolve(&end)?
                                .checked_sub(self.resolve(&start)?)
                                .ok_or(ParseError::Unsupported)?,
                        )
                    }
                } else {
                    master.length.clone()
                };
                let def = EventDef { start, length };
                let (start, end) = self.bounds(&def)?;
                if end < start {
                    return Err(ParseError::Unsupported);
                }
                values.push(def);
            }
        }
        Ok(values)
    }
    fn expand(
        &self,
        uid: &str,
        master: &Component,
        objects: &[&Component],
        calendar: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<Event>, ParseError> {
        let def = self.definition(master)?;
        if master.one("EXRULE")?.is_some() {
            return Err(ParseError::Unsupported);
        }
        let rules = master
            .all("RRULE")
            .map(|p| Rule::parse(&p.value))
            .collect::<Result<Vec<_>, _>>()?;
        let rdates = self.values(master, "RDATE", &def)?;
        let exclusions = self
            .values(master, "EXDATE", &def)?
            .iter()
            .map(|d| self.resolve(&d.start))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let recurring =
            !rules.is_empty() || !rdates.is_empty() || objects.len() > 1 || !exclusions.is_empty();
        let mut overrides = BTreeMap::new();
        let mut stop = from_ms(to)?
            .checked_add_signed(Duration::days(2))
            .ok_or(ParseError::Unsupported)?;
        for object in objects {
            let Some(recur) = object.one("RECURRENCE-ID")? else {
                continue;
            };
            if recur.params.contains_key("RANGE")
                || object.all("RRULE").next().is_some()
                || object.all("RDATE").next().is_some()
                || object.all("EXDATE").next().is_some()
            {
                return Err(ParseError::Unsupported);
            }
            let original = DateValue::property(recur)?;
            if original.date_only != def.start.date_only {
                return Err(ParseError::Unsupported);
            }
            let original_ms = self.resolve(&original)?;
            stop = stop.max(original.local);
            let cancelled = object.text("STATUS")?.as_deref() == Some("CANCELLED");
            let replacement = if cancelled && object.one("DTSTART")?.is_none() {
                EventDef {
                    start: original,
                    length: def.length.clone(),
                }
            } else {
                self.definition(object)?
            };
            if overrides
                .insert(original_ms, (*object, replacement, cancelled))
                .is_some()
            {
                return Err(ParseError::Unsupported);
            }
        }
        let mut occurrences = BTreeMap::new();
        occurrences.insert(self.resolve(&def.start)?, def.clone());
        for rule in rules {
            let until = rule
                .until
                .as_ref()
                .map(|u| self.until_ms(u, &def.start))
                .transpose()?;
            let rule_stop = if let Some(until) = until {
                stop.min(
                    from_ms(until)?
                        .checked_add_signed(Duration::days(2))
                        .ok_or(ParseError::Unsupported)?,
                )
            } else {
                stop
            };
            for local in rule.candidates(def.start.local, rule_stop)? {
                let candidate = EventDef {
                    start: def.start.at(local),
                    length: def.length.clone(),
                };
                let ms = self.resolve(&candidate.start)?;
                if until.is_none_or(|until| ms <= until) {
                    occurrences.entry(ms).or_insert(candidate);
                }
            }
        }
        for rdate in rdates {
            occurrences.insert(self.resolve(&rdate.start)?, rdate);
        }
        if overrides
            .keys()
            .any(|original| !occurrences.contains_key(original))
        {
            return Err(ParseError::Unsupported);
        }
        let mut items = Vec::new();
        for (original, mut value) in occurrences {
            if exclusions.contains(&original) {
                continue;
            }
            let mut object = master;
            if let Some((replacement, replacement_def, cancelled)) = overrides.remove(&original) {
                if cancelled {
                    continue;
                }
                object = replacement;
                value = replacement_def;
            }
            if master.text("STATUS")?.as_deref() == Some("CANCELLED") {
                continue;
            }
            let (start, end) = self.bounds(&value)?;
            if !overlaps_window(Some(start), Some(end), from, to) {
                continue;
            }
            let end_date = if value.start.date_only {
                match value.length {
                    Length::Nominal { days, .. } => Some(
                        value
                            .start
                            .local
                            .checked_add_signed(
                                Duration::try_days(days).ok_or(ParseError::Unsupported)?,
                            )
                            .ok_or(ParseError::Unsupported)?
                            .date()
                            .to_string(),
                    ),
                    _ => return Err(ParseError::Unsupported),
                }
            } else {
                None
            };
            items.push(Event {
                id: if recurring {
                    occurrence_id(uid, original).map_err(|_| ParseError::IdTooLong)?
                } else {
                    uid.to_owned()
                },
                calendar: calendar.to_owned(),
                title: object.text("SUMMARY")?.or(master.text("SUMMARY")?),
                start_ms: Some(start),
                end_ms: Some(end),
                all_day: Some(value.start.date_only),
                start_date: value
                    .start
                    .date_only
                    .then(|| value.start.local.date().to_string()),
                end_date,
                location: object.text("LOCATION")?.or(master.text("LOCATION")?),
                notes: object.text("DESCRIPTION")?.or(master.text("DESCRIPTION")?),
                recurring: Some(recurring),
                ..Event::default()
            });
        }
        Ok(items)
    }
    fn until_ms(&self, until: &DateValue, start: &DateValue) -> Result<i64, ParseError> {
        if until.date_only {
            return Ok(until.local.and_utc().timestamp_millis());
        }
        let mut until = until.clone();
        if until.zone.is_none() {
            until.zone = start.zone.clone();
        }
        self.resolve(&until)
    }

    fn proved_outside(
        &self,
        master: &Component,
        objects: &[&Component],
        from: i64,
        to: i64,
    ) -> bool {
        let proof = || -> Result<bool, ParseError> {
            let def = self.definition(master)?;
            let (master_start, master_end) = self.bounds(&def)?;
            if overlaps_window(Some(master_start), Some(master_end), from, to) {
                return Ok(false);
            }
            let rules: Vec<_> = master.all("RRULE").collect();
            if master.one("EXRULE")?.is_some() {
                return Ok(false);
            }
            for rule in &rules {
                validate_proof_rule(&rule.value)?;
            }
            // Even excluded values must be parseable; malformed data proves nothing.
            self.values(master, "EXDATE", &def)?;
            for extra in self.values(master, "RDATE", &def)? {
                let (start, end) = self.bounds(&extra)?;
                if overlaps_window(Some(start), Some(end), from, to) {
                    return Ok(false);
                }
            }
            for object in objects {
                if let Some(recur) = object.one("RECURRENCE-ID")? {
                    if recur.params.contains_key("RANGE") {
                        return Ok(false);
                    }
                    self.resolve(&DateValue::property(recur)?)?;
                    if object.all("RRULE").next().is_some()
                        || object.all("RDATE").next().is_some()
                        || object.all("EXDATE").next().is_some()
                    {
                        return Ok(false);
                    }
                    let (start, end) = self.bounds(&self.definition(object)?)?;
                    if overlaps_window(Some(start), Some(end), from, to) {
                        return Ok(false);
                    }
                }
            }
            if self.resolve(&def.start)? >= to {
                return Ok(true);
            }
            let Length::Exact(length) = def.length else {
                return Ok(false);
            };
            if def.start.date_only || rules.is_empty() {
                return Ok(false);
            }
            let mut latest = i64::MIN;
            for rule in rules {
                let p = parts(&rule.value)?;
                let Some(until) = p.get("UNTIL") else {
                    return Ok(false);
                };
                latest = latest.max(self.until_ms(&DateValue::bare(until)?, &def.start)?);
            }
            Ok(latest
                .checked_add(length)
                .and_then(|n| n.checked_add(2 * DAY_MS))
                .is_some_and(|end| end < from))
        };
        proof().unwrap_or(false)
    }
}
fn from_ms(ms: i64) -> Result<NaiveDateTime, ParseError> {
    DateTime::from_timestamp_millis(ms)
        .map(|d| d.naive_utc())
        .ok_or(ParseError::Unsupported)
}

// Validate the syntax even of unsupported RFC 5545 parts before using UNTIL.
// Unknown extensions have no known grammar and therefore cannot prove absence.
fn validate_proof_rule(text: &str) -> Result<(), ParseError> {
    let p = parts(text)?;
    let frequency = p.get("FREQ").copied().ok_or(ParseError::Unsupported)?;
    if (p.contains_key("BYWEEKNO") && frequency != "YEARLY")
        || (p.contains_key("BYYEARDAY") && matches!(frequency, "DAILY" | "WEEKLY" | "MONTHLY"))
        || (p.contains_key("BYWEEKNO")
            && p.get("BYDAY")
                .is_some_and(|v| v.split(',').any(|d| d.len() != 2)))
    {
        return Err(ParseError::Unsupported);
    }
    let mut supported = Vec::new();
    for (&name, &value) in &p {
        let bound = match name {
            "BYSECOND" => Some((0, 60)),
            "BYMINUTE" => Some((0, 59)),
            "BYHOUR" => Some((0, 23)),
            "BYYEARDAY" => Some((-366, 366)),
            "BYWEEKNO" => Some((-53, 53)),
            _ => None,
        };
        if let Some((min, max)) = bound {
            for value in value.split(',') {
                let n: i32 = value.parse().map_err(|_| ParseError::Unsupported)?;
                if n < min || n > max || (min < 0 && n == 0) {
                    return Err(ParseError::Unsupported);
                }
            }
        } else if name == "FREQ" && matches!(value, "SECONDLY" | "MINUTELY" | "HOURLY") {
            supported.push("FREQ=DAILY".to_owned());
        } else {
            supported.push(format!("{name}={value}"));
        }
    }
    Rule::parse(&supported.join(";"))?;
    Ok(())
}

impl Calendar {
    fn resolve(&self, value: &DateValue) -> Result<i64, ParseError> {
        if value.date_only {
            return self
                .source_zone
                .first_instant_ms(value.local.date())
                .map_err(|_| ParseError::Unsupported);
        }
        let Some(zone) = value.zone.as_deref() else {
            return self
                .source_zone
                .local_datetime_ms(value.local)
                .map_err(|_| ParseError::Unsupported);
        };
        if zone == "UTC" {
            return Ok(value.local.and_utc().timestamp_millis());
        }
        if let Some(zone) = self.zones.get(zone) {
            return resolve_custom(zone, value.local);
        }
        let zone: Tz = zone.parse().map_err(|_| ParseError::Unsupported)?;
        match zone.from_local_datetime(&value.local) {
            LocalResult::Single(d) => Ok(d.timestamp_millis()),
            LocalResult::Ambiguous(a, b) => Ok(a.min(b).timestamp_millis()),
            LocalResult::None => GapInfo::new(&value.local, &zone)
                .and_then(|g| g.end)
                .map(|d| d.timestamp_millis())
                .ok_or(ParseError::Unsupported),
        }
    }
}

fn offset(text: &str) -> Result<i64, ParseError> {
    let bytes = text.as_bytes();
    if !matches!(bytes.len(), 5 | 7)
        || !matches!(bytes[0], b'+' | b'-')
        || !bytes[1..].iter().all(u8::is_ascii_digit)
    {
        return Err(ParseError::Unsupported);
    }
    let h: i64 = text[1..3].parse().map_err(|_| ParseError::Unsupported)?;
    let m: i64 = text[3..5].parse().map_err(|_| ParseError::Unsupported)?;
    let s: i64 = if bytes.len() == 7 {
        text[5..7].parse().map_err(|_| ParseError::Unsupported)?
    } else {
        0
    };
    if h > 23 || m > 59 || s > 59 {
        return Err(ParseError::Unsupported);
    }
    Ok((h * 3600 + m * 60 + s) * if bytes[0] == b'-' { -1 } else { 1 })
}
fn resolve_custom(zone: &Component, local: NaiveDateTime) -> Result<i64, ParseError> {
    let stop = crate::recurrence::date(
        local.year().checked_add(2).ok_or(ParseError::Unsupported)?,
        1,
        1,
    )?
    .and_hms_opt(0, 0, 0)
    .ok_or(ParseError::Unsupported)?;
    let mut transitions = BTreeMap::new();
    let mut offsets = BTreeSet::new();
    for obs in &zone.children {
        if !matches!(obs.name.as_str(), "STANDARD" | "DAYLIGHT") {
            return Err(ParseError::Unsupported);
        }
        if obs.all("EXDATE").next().is_some() || obs.all("EXRULE").next().is_some() {
            return Err(ParseError::Unsupported);
        }
        let start = DateValue::property(obs.required("DTSTART")?)?;
        if start.date_only || start.zone.is_some() {
            return Err(ParseError::Unsupported);
        }
        let from = offset(&obs.required("TZOFFSETFROM")?.value)?;
        let to = offset(&obs.required("TZOFFSETTO")?.value)?;
        offsets.extend([from, to]);
        let mut dates = BTreeSet::from([start.local]);
        for p in obs.all("RRULE") {
            let rule = Rule::parse(&p.value)?;
            if rule.until.as_ref().is_some_and(|u| u.date_only) {
                return Err(ParseError::Unsupported);
            }
            for candidate in rule.candidates(start.local, stop)? {
                let instant = candidate
                    .and_utc()
                    .timestamp()
                    .checked_sub(from)
                    .ok_or(ParseError::Unsupported)?;
                if rule.until.as_ref().is_none_or(|u| {
                    !u.date_only
                        && if u.zone.is_some() {
                            instant <= u.local.and_utc().timestamp()
                        } else {
                            candidate <= u.local
                        }
                }) {
                    dates.insert(candidate);
                }
            }
        }
        for p in obs.all("RDATE") {
            for date in p.value.split(',') {
                let value = DateValue::bare(date)?;
                if value.date_only || value.zone.is_some() {
                    return Err(ParseError::Unsupported);
                }
                dates.insert(value.local);
            }
        }
        for date in dates {
            let utc = date
                .and_utc()
                .timestamp()
                .checked_sub(from)
                .ok_or(ParseError::Unsupported)?;
            if let Some(old) = transitions.insert(utc, (from, to)) {
                if old != (from, to) {
                    return Err(ParseError::Unsupported);
                }
            }
        }
    }
    let Some((_, &(initial, _))) = transitions.first_key_value() else {
        return Err(ParseError::Unsupported);
    };
    let mut previous = initial;
    for &(from, to) in transitions.values() {
        if from != previous {
            return Err(ParseError::Unsupported);
        }
        previous = to;
    }
    let wall = local.and_utc().timestamp();
    let mut matches = Vec::new();
    for off in offsets {
        let utc = wall.checked_sub(off).ok_or(ParseError::Unsupported)?;
        let active = transitions
            .range(..=utc)
            .next_back()
            .map(|(_, &(_, to))| to)
            .unwrap_or(initial);
        if off == active {
            matches.push(utc);
        }
    }
    if let Some(utc) = matches.into_iter().min() {
        return utc.checked_mul(1000).ok_or(ParseError::Unsupported);
    }
    for (&utc, &(from, to)) in &transitions {
        if to > from && wall >= utc + from && wall < utc + to {
            return utc.checked_mul(1000).ok_or(ParseError::Unsupported);
        }
    }
    Err(ParseError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(text: &str) -> i64 {
        DateValue::bare(text)
            .unwrap()
            .local
            .and_utc()
            .timestamp_millis()
    }
    fn calendar(properties: &str, extra: &str) -> Calendar {
        Calendar::parse(&format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:series\n{properties}\nSUMMARY:Master\nEND:VEVENT\n{extra}\nEND:VCALENDAR"), Some("UTC")).unwrap()
    }
    fn list(calendar: &Calendar, from: &str, to: &str) -> Result<Vec<Event>, ParseError> {
        calendar.events("source", ms(from), ms(to))
    }
    fn dates(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| {
                from_ms(e.start_ms.unwrap())
                    .unwrap()
                    .format("%Y%m%dT%H%M%S")
                    .to_string()
            })
            .collect()
    }
    fn override_event(original: &str, start: &str, end: &str) -> String {
        format!("BEGIN:VEVENT\nUID:series\nRECURRENCE-ID:{original}\nDTSTART:{start}\nDTEND:{end}\nSUMMARY:Moved\nEND:VEVENT")
    }

    #[test]
    fn ical_fixtures_expand_daily_weekly_monthly_and_yearly_rules() {
        let cases = [
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;INTERVAL=2;COUNT=3", "20250101T090000,20250103T090000,20250105T090000"),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=WEEKLY;INTERVAL=2;COUNT=4;BYDAY=MO,WE;WKST=SU", "20250101T090000,20250113T090000,20250115T090000,20250127T090000"),
            ("DTSTART:20250131T090000Z\nRRULE:FREQ=MONTHLY;COUNT=3", "20250131T090000,20250331T090000,20250531T090000"),
            ("DTSTART:20250131T090000Z\nRRULE:FREQ=MONTHLY;COUNT=3;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1", "20250131T090000,20250228T090000,20250331T090000"),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=MONTHLY;COUNT=3;BYMONTHDAY=-1", "20250101T090000,20250131T090000,20250228T090000,20250331T090000"),
            ("DTSTART:20250113T090000Z\nRRULE:FREQ=MONTHLY;COUNT=3;BYDAY=2MO", "20250113T090000,20250210T090000,20250310T090000"),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=YEARLY;COUNT=3;BYMONTH=2;BYMONTHDAY=1", "20250101T090000,20250201T090000,20260201T090000,20270201T090000"),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=YEARLY;COUNT=2;BYDAY=-1MO", "20250101T090000,20251229T090000,20261228T090000"),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=YEARLY;COUNT=2;BYMONTH=3;BYDAY=2SU", "20250101T090000,20250309T090000,20260308T090000"),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;UNTIL=20250103T090000Z", "20250101T090000,20250102T090000,20250103T090000"),
        ];
        for (properties, expected) in cases {
            let c = calendar(properties, "");
            let events = list(&c, "20250101T000000Z", "20280101T000000Z").unwrap();
            assert_eq!(dates(&events).join(","), expected, "{properties}");
            assert!(events.iter().all(|e| e.recurring == Some(true)));
        }
    }

    #[test]
    fn ical_recurrence_ids_preserve_moved_identity_and_excluded_ids_are_absent() {
        let extra = override_event("20250102T090000Z", "20250103T090000Z", "20250103T100000Z");
        let c = calendar("DTSTART:20250101T090000Z\nDTEND:20250101T100000Z\nRRULE:FREQ=DAILY;COUNT=4\nEXDATE:20250104T090000Z\nRDATE:20250106T090000Z", &extra);
        let events = list(&c, "20250101T000000Z", "20250107T000000Z").unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[1].start_ms, events[2].start_ms);
        assert_ne!(events[1].id, events[2].id);
        for item in &events {
            assert_eq!(c.event("source", &item.id).unwrap().as_ref(), Some(item));
        }
        for date in ["20250104T090000Z", "20250105T090000Z"] {
            assert_eq!(
                c.event("source", &occurrence_id("series", ms(date)).unwrap())
                    .unwrap(),
                None
            );
        }
        assert_eq!(c.event("source", "series").unwrap(), None);
        assert_eq!(c.event("source", "unknown").unwrap(), None);
    }

    #[test]
    fn ical_moved_override_is_listed_even_when_original_is_outside_window() {
        let extra = override_event("20250110T090000Z", "20250102T090000Z", "20250102T100000Z");
        let c = calendar(
            "DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;COUNT=10",
            &extra,
        );
        let events = list(&c, "20250102T000000Z", "20250103T000000Z").unwrap();
        assert_eq!(events.len(), 2);
        let moved = events
            .iter()
            .find(|e| e.title.as_deref() == Some("Moved"))
            .unwrap();
        assert_eq!(
            parse_occurrence_id(&moved.id).unwrap().1,
            ms("20250110T090000Z")
        );
        assert_eq!(c.event("source", &moved.id).unwrap().as_ref(), Some(moved));
    }

    #[test]
    fn ical_rdate_periods_and_cancelled_overrides_use_their_own_bounds() {
        let extra = "BEGIN:VEVENT\nUID:series\nRECURRENCE-ID:20250102T090000Z\nSTATUS:CANCELLED\nEND:VEVENT";
        let c = calendar("DTSTART:20250101T090000Z\nDURATION:PT1H\nRRULE:FREQ=DAILY;COUNT=2\nRDATE;VALUE=PERIOD:20250103T090000Z/20250105T090000Z,20250106T090000Z/PT3H", extra);
        let events = list(&c, "20250102T000000Z", "20250107T000000Z").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].end_ms, Some(ms("20250105T090000Z")));
        assert_eq!(events[1].end_ms, Some(ms("20250106T120000Z")));
        assert!(c
            .event(
                "source",
                &occurrence_id("series", ms("20250102T090000Z")).unwrap()
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn ical_oversized_recurring_uid_is_not_an_unsupported_rule() {
        let uid = "u".repeat(1600);
        let text = format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:{uid}\nDTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;COUNT=1\nEND:VEVENT\nEND:VCALENDAR");
        let c = Calendar::parse(&text, Some("UTC")).unwrap();
        assert_eq!(
            list(&c, "20250101T000000Z", "20250102T000000Z"),
            Err(ParseError::IdTooLong)
        );
        assert_eq!(c.event("source", &uid), Err(ParseError::IdTooLong));
        let unsupported = calendar("DTSTART:20250101T090000Z\nRRULE:FREQ=HOURLY", "");
        assert_eq!(
            list(&unsupported, "20250101T000000Z", "20250102T000000Z"),
            Err(ParseError::Unsupported)
        );
    }

    #[test]
    fn ical_one_fixture_per_unsupported_rule_part_and_frequency_refuses_get_and_list() {
        for rule in [
            "FREQ=DAILY;BYSECOND=10",
            "FREQ=DAILY;BYMINUTE=10",
            "FREQ=DAILY;BYHOUR=10",
            "FREQ=YEARLY;BYYEARDAY=100",
            "FREQ=YEARLY;BYWEEKNO=10",
            "FREQ=DAILY;X-UNKNOWN=1",
            "FREQ=HOURLY",
            "FREQ=MINUTELY",
            "FREQ=SECONDLY",
        ] {
            let c = calendar(&format!("DTSTART:20250101T090000Z\nRRULE:{rule}"), "");
            assert_eq!(
                list(&c, "20250101T000000Z", "20250102T000000Z"),
                Err(ParseError::Unsupported),
                "{rule}"
            );
            assert_eq!(
                c.event("source", "series"),
                Err(ParseError::Unsupported),
                "{rule}"
            );
        }
        let c = calendar(
            "DTSTART;TZID=Missing/Zone:20250101T090000\nRRULE:FREQ=DAILY;COUNT=1",
            "",
        );
        assert_eq!(
            list(&c, "20250101T000000Z", "20250102T000000Z"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(c.event("source", "series"), Err(ParseError::Unsupported));
        assert_eq!(
            list(&c, "20240101T000000Z", "20240102T000000Z"),
            Err(ParseError::Unsupported)
        );
    }

    #[test]
    fn ical_unsupported_rule_proof_requires_both_halves_and_strict_margin() {
        let rule = "DTSTART:20250101T090000Z\nDTEND:20250101T100000Z\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250102T090000Z";
        let c = calendar(rule, "");
        assert!(list(&c, "20250105T000000Z", "20250106T000000Z")
            .unwrap()
            .is_empty());
        assert!(list(&c, "20241231T000000Z", "20250101T090000Z")
            .unwrap()
            .is_empty());
        assert_eq!(c.event("source", "series"), Err(ParseError::Unsupported));
        // The margin is strict: exactly UNTIL + length + 48 h is not a proof.
        for from in ["20250102T090000Z", "20250104T090000Z", "20250104T100000Z"] {
            assert_eq!(
                list(&c, from, "20250106T000000Z"),
                Err(ParseError::Unsupported),
                "{from}"
            );
        }
        let extras = [
            (format!("{rule}\nRDATE:20250105T090000Z"), String::new()),
            (format!("{rule}\nRDATE;VALUE=PERIOD:20250104T090000Z/20250105T090000Z"), String::new()),
            (rule.to_owned(), override_event("20250102T090000Z", "20250105T090000Z", "20250105T100000Z")),
            ("DTSTART:20250101T090000Z\nDURATION:PT96H\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250102T090000Z".to_owned(), String::new()),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;BYHOUR=9;COUNT=1".to_owned(), String::new()),
            (format!("{rule}\nRRULE:FREQ=DAILY;BYMINUTE=1"), String::new()),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250104".to_owned(), String::new()),
            ("DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250105T000000Z".to_owned(), String::new()),
        ];
        for (properties, extra) in extras {
            let c = calendar(&properties, &extra);
            assert_eq!(
                list(&c, "20250105T000000Z", "20250106T000000Z"),
                Err(ParseError::Unsupported),
                "{properties}\n{extra}"
            );
        }
        let outside_rdate = calendar(
            &format!("{rule}\nRDATE:20250106T000000Z"),
            &override_event("20250102T090000Z", "20250104T090000Z", "20250105T000000Z"),
        );
        assert!(list(&outside_rdate, "20250105T000000Z", "20250106T000000Z")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ical_unparseable_rules_values_or_overrides_never_prove_outside() {
        for bad in [
            "FREQ=DAILY;BYHOUR=bad;UNTIL=20250102T090000Z",
            "FREQ=DAILY;BYHOUR=9;UNTIL=bad",
            "FREQ=DAILY;UNTIL=20250102T090000Z;BYMONTH=13",
            "FREQ=DAILY;UNTIL=20250102T090000Z;COUNT=2",
            "FREQ=DAILY;UNTIL=20250102T090000Z;UNTIL=20250103T090000Z",
            "FREQ=DAILY;UNTIL=20250102T090000Z;X-UNKNOWN=1",
        ] {
            let c = calendar(&format!("DTSTART:20250101T090000Z\nRRULE:{bad}"), "");
            assert_eq!(
                list(&c, "20250201T000000Z", "20250202T000000Z"),
                Err(ParseError::Unsupported),
                "{bad}"
            );
        }
        let base = "DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250102T090000Z";
        for suffix in [
            "RDATE:bad",
            "EXDATE:bad",
            "RDATE;TZID=Unknown:20250101T090000",
            "RDATE;VALUE=PERIOD:20250101T090000Z/bad",
        ] {
            let c = calendar(&format!("{base}\n{suffix}"), "");
            assert_eq!(
                list(&c, "20250201T000000Z", "20250202T000000Z"),
                Err(ParseError::Unsupported),
                "{suffix}"
            );
        }
        let c = calendar(
            base,
            &override_event("bad", "20250101T090000Z", "20250101T100000Z"),
        );
        assert_eq!(
            list(&c, "20250201T000000Z", "20250202T000000Z"),
            Err(ParseError::Unsupported)
        );
        let c = calendar(
            base,
            &override_event("20250102T090000Z", "bad", "20250101T100000Z"),
        );
        assert_eq!(
            list(&c, "20250201T000000Z", "20250202T000000Z"),
            Err(ParseError::Unsupported)
        );
    }

    const CUSTOM_ZONE: &str = "BEGIN:VTIMEZONE\nTZID:Private/Eastern\nBEGIN:DAYLIGHT\nDTSTART:20250309T020000\nTZOFFSETFROM:-0500\nTZOFFSETTO:-0400\nRRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU\nEND:DAYLIGHT\nBEGIN:STANDARD\nDTSTART:20251102T020000\nTZOFFSETFROM:-0400\nTZOFFSETTO:-0500\nRRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU\nEND:STANDARD\nEND:VTIMEZONE";
    #[test]
    fn ical_vtimezone_and_iana_recurrences_preserve_wall_time_across_dst() {
        for (zone, extra) in [("America/New_York", ""), ("Private/Eastern", CUSTOM_ZONE)] {
            let c = calendar(
                &format!(
                    "DTSTART;TZID={zone}:20250308T090000\nDURATION:PT1H\nRRULE:FREQ=DAILY;COUNT=3"
                ),
                extra,
            );
            let events = list(&c, "20250308T000000Z", "20250311T000000Z").unwrap();
            assert_eq!(
                dates(&events),
                ["20250308T140000", "20250309T130000", "20250310T130000"]
            );
            for e in &events {
                assert_eq!(c.event("source", &e.id).unwrap().as_ref(), Some(e));
            }
            let c = calendar(
                &format!("DTSTART;TZID={zone}:20251102T013000\nRRULE:FREQ=DAILY;COUNT=1"),
                extra,
            );
            assert_eq!(
                list(&c, "20251102T000000Z", "20251103T000000Z").unwrap()[0].start_ms,
                Some(ms("20251102T053000Z"))
            );
            let c = calendar(&format!("DTSTART;TZID={zone}:20250309T023000"), extra);
            assert_eq!(
                list(&c, "20250309T000000Z", "20250310T000000Z").unwrap()[0].start_ms,
                Some(ms("20250309T070000Z"))
            );
        }
    }

    #[test]
    fn ical_nominal_master_lengths_never_support_the_until_proof() {
        for properties in [
            "DTSTART;VALUE=DATE:20250101\nDTEND;VALUE=DATE:20250102\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250102",
            "DTSTART:20250101T090000Z\nDURATION:P1W\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250102T090000Z",
            "DTSTART;TZID=Private/Eastern:20250308T090000\nDURATION:P3D\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250309T130000Z",
        ] {
            let c = calendar(properties, CUSTOM_ZONE);
            // This is later than UNTIL + the master's elapsed length + 48 h.
            assert_eq!(list(&c, "20250401T000000Z", "20250402T000000Z"), Err(ParseError::Unsupported), "{properties}");
        }
        let exact = calendar("DTSTART:20250101T090000Z\nDURATION:PT72H\nRRULE:FREQ=DAILY;BYHOUR=9;UNTIL=20250102T090000Z", "");
        assert!(list(&exact, "20250201T000000Z", "20250202T000000Z")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ical_vtodo_floating_dates_dst_folds_and_gaps_use_the_computer_zone() {
        let text = "BEGIN:VCALENDAR\nBEGIN:VTODO\nUID:date\nDUE;VALUE=DATE:20251102\nSUMMARY:A folded\n  title\nDESCRIPTION:line one\\nline two\nEND:VTODO\nBEGIN:VTODO\nUID:fold\nDUE:20251102T013000\nSTATUS:COMPLETED\nCOMPLETED:20251102T060000Z\nEND:VTODO\nBEGIN:VTODO\nUID:gap\nDUE:20250309T023000\nEND:VTODO\nBEGIN:VTODO\nUID:none\nEND:VTODO\nEND:VCALENDAR";
        let c = Calendar::parse(text, Some("America/New_York")).unwrap();
        let tasks = c.reminders("list").unwrap();
        assert_eq!(tasks[0].due_ms, Some(ms("20251102T040000Z")));
        assert_eq!(tasks[0].title.as_deref(), Some("A folded title"));
        assert_eq!(tasks[0].notes.as_deref(), Some("line one\nline two"));
        assert_eq!(tasks[1].due_ms, Some(ms("20251102T053000Z")));
        assert_eq!(tasks[1].completed, Some(true));
        assert_eq!(tasks[1].completed_ms, Some(ms("20251102T060000Z")));
        assert_eq!(tasks[2].due_ms, Some(ms("20250309T070000Z")));
        assert_eq!(tasks[3].due_ms, None);
        for zone in [None, Some("Unknown/Zone")] {
            assert_eq!(
                Calendar::parse(text, zone).unwrap_err(),
                ParseError::SourceTimeZone
            );
        }
    }

    #[test]
    fn ical_all_day_uses_source_dates_and_missing_midnight_first_instant() {
        let c = Calendar::parse("BEGIN:VEVENT\nUID:date\nDTSTART;VALUE=DATE:20181104\nDTEND;VALUE=DATE:20181105\nRRULE:FREQ=DAILY;COUNT=2\nEND:VEVENT", Some("America/Sao_Paulo")).unwrap();
        let events = list(&c, "20181104T000000Z", "20181107T000000Z").unwrap();
        assert_eq!(events[0].start_ms, Some(ms("20181104T030000Z")));
        assert_eq!(events[0].end_ms, Some(ms("20181105T020000Z")));
        assert_eq!(events[0].start_date.as_deref(), Some("2018-11-04"));
        assert_eq!(events[0].end_date.as_deref(), Some("2018-11-05"));
        assert_eq!(events[0].all_day, Some(true));
        assert_eq!(
            c.event("source", &events[0].id).unwrap().as_ref(),
            Some(&events[0])
        );
    }

    #[test]
    fn ical_exact_dtend_length_and_nominal_duration_differ_at_zone_transitions() {
        for (length, expected_end) in [
            (
                "DTEND;TZID=America/New_York:20250309T090000",
                "20250310T120000Z",
            ),
            ("DURATION:P1D", "20250310T130000Z"),
            ("DURATION:PT24H", "20250310T130000Z"),
        ] {
            let c = calendar(&format!("DTSTART;TZID=America/New_York:20250308T090000\n{length}\nRRULE:FREQ=DAILY;COUNT=2"), "");
            let events = list(&c, "20250309T000000Z", "20250311T000000Z").unwrap();
            let last = events.last().unwrap();
            assert_eq!(last.end_ms, Some(ms(expected_end)), "{length}");
        }
    }

    #[test]
    fn ical_bad_structure_dates_duplicate_masters_and_ranges_fail_closed() {
        assert!(
            Calendar::parse("BEGIN:VCALENDAR\nBEGIN:VEVENT\nEND:VCALENDAR", Some("UTC")).is_err()
        );
        for properties in [
            "DTSTART:20250230T090000Z",
            "DTSTART:20250101T090000Z\nDTEND:20250101T080000Z",
            "DTSTART:20250101T090000Z\nDURATION:P",
            "DTSTART:20250101T090000Z\nDURATION:PT-1H",
            "DTSTART:20250101T090000Z\nRRULE:FREQ=MONTHLY;BYMONTHDAY=-2147483648",
        ] {
            assert!(
                list(
                    &calendar(properties, ""),
                    "20250101T000000Z",
                    "20250301T000000Z"
                )
                .is_err(),
                "{properties}"
            );
        }
        let c = calendar("DTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;COUNT=3", "BEGIN:VEVENT\nUID:series\nDTSTART:20250102T090000Z\nRECURRENCE-ID;RANGE=THISANDFUTURE:20250102T090000Z\nEND:VEVENT");
        assert!(list(&c, "20250101T000000Z", "20250104T000000Z").is_err());
    }
}

#[cfg(test)]
mod recurrence_edges {
    use super::*;
    fn ms(text: &str) -> i64 {
        DateValue::bare(text)
            .unwrap()
            .local
            .and_utc()
            .timestamp_millis()
    }
    #[test]
    fn ical_week_start_changes_interval_buckets_and_filters_intersect() {
        for (wkst, expected) in [
            (
                "MO",
                vec!["2025-01-05", "2025-01-13", "2025-01-19", "2025-01-27"],
            ),
            (
                "SU",
                vec!["2025-01-05", "2025-01-06", "2025-01-19", "2025-01-20"],
            ),
        ] {
            let c = Calendar::parse(&format!("BEGIN:VEVENT\nUID:week\nDTSTART:20250105T090000Z\nRRULE:FREQ=WEEKLY;INTERVAL=2;COUNT=4;BYDAY=SU,MO;WKST={wkst}\nEND:VEVENT"), Some("UTC")).unwrap();
            let events = c
                .events("source", ms("20250101T000000Z"), ms("20250201T000000Z"))
                .unwrap();
            let actual: Vec<_> = events
                .iter()
                .map(|e| from_ms(e.start_ms.unwrap()).unwrap().date().to_string())
                .collect();
            assert_eq!(actual, expected);
        }
        let c = Calendar::parse("BEGIN:VEVENT\nUID:intersect\nDTSTART:20250101T090000Z\nRRULE:FREQ=MONTHLY;BYMONTHDAY=1,2,3,4,5,6,7;BYDAY=MO;COUNT=3\nRRULE:FREQ=DAILY;COUNT=2\nEND:VEVENT", Some("UTC")).unwrap();
        let events = c
            .events("source", ms("20250101T000000Z"), ms("20250401T000000Z"))
            .unwrap();
        let actual: Vec<_> = events
            .iter()
            .map(|e| from_ms(e.start_ms.unwrap()).unwrap().date().to_string())
            .collect();
        assert_eq!(
            actual,
            [
                "2025-01-01",
                "2025-01-02",
                "2025-01-06",
                "2025-02-03",
                "2025-03-03"
            ]
        );
    }

    #[test]
    fn ical_start_after_window_proof_checks_rdates_overrides_and_rule_syntax() {
        let master =
            "BEGIN:VEVENT\nUID:future\nDTSTART:20250201T090000Z\nRRULE:FREQ=DAILY;BYHOUR=9";
        let from = ms("20250101T000000Z");
        let to = ms("20250102T000000Z");
        for extra in [
            "RDATE:20250101T090000Z",
            "RDATE:bad",
            "EXDATE:bad",
            "RRULE:FREQ=DAILY;BYHOUR=bad",
            "RRULE:FREQ=DAILY;BYWEEKNO=1",
        ] {
            let c =
                Calendar::parse(&format!("{master}\n{extra}\nEND:VEVENT"), Some("UTC")).unwrap();
            assert_eq!(
                c.events("source", from, to),
                Err(ParseError::Unsupported),
                "{extra}"
            );
        }
        let moved = "BEGIN:VEVENT\nUID:future\nRECURRENCE-ID:20250201T090000Z\nDTSTART:20250101T090000Z\nDTEND:20250101T100000Z\nEND:VEVENT";
        let c = Calendar::parse(
            &format!("BEGIN:VCALENDAR\n{master}\nEND:VEVENT\n{moved}\nEND:VCALENDAR"),
            Some("UTC"),
        )
        .unwrap();
        assert_eq!(c.events("source", from, to), Err(ParseError::Unsupported));
        let c = Calendar::parse(&format!("{master}\nEND:VEVENT"), Some("UTC")).unwrap();
        assert!(c.events("source", from, to).unwrap().is_empty());
    }
}
