//! Host-neutral vCard 3.0/4.0 text projection, without native address-book APIs.

use crate::{
    ical::{components, split_quoted, unescape, ParseError, Property},
    items::{Contact, LabeledValue},
};

/// Decode cards, leaving groups empty. The adapter must attach the record's
/// actual source memberships before the shared scope filter sees the contact.
/// Binary/encoded text is refused rather than presented as a guessed name.
pub fn parse(text: &str) -> Result<Vec<Contact>, ParseError> {
    components(text)?
        .into_iter()
        .map(|card| {
            if card.name != "VCARD" || !card.children.is_empty() {
                return Err(ParseError::Syntax);
            }
            if !matches!(card.text("VERSION")?.as_deref(), Some("3.0" | "4.0")) {
                return Err(ParseError::Unsupported);
            }
            let id = card
                .text("UID")?
                .filter(|s| !s.is_empty())
                .ok_or(ParseError::Syntax)?;
            let mut contact = Contact {
                id,
                ..Contact::default()
            };
            let (mut has_name, mut has_org) = (false, false);
            for property in card.properties {
                let name = property.name.rsplit('.').next().ok_or(ParseError::Syntax)?;
                if !matches!(name, "N" | "ORG" | "EMAIL" | "TEL") {
                    continue;
                }
                if property.params.contains_key("ENCODING")
                    || property
                        .params
                        .get("CHARSET")
                        .is_some_and(|s| !s.eq_ignore_ascii_case("UTF-8"))
                {
                    return Err(ParseError::Unsupported);
                }
                match name {
                    "N" => {
                        if has_name {
                            return Err(ParseError::Syntax);
                        }
                        has_name = true;
                        let names = split_quoted(&property.value, ';')?;
                        if names.len() != 5 {
                            return Err(ParseError::Syntax);
                        }
                        contact.family_name = nonempty(unescape(names[0])?);
                        contact.given_name = nonempty(unescape(names[1])?);
                    }
                    "ORG" => {
                        if has_org {
                            return Err(ParseError::Syntax);
                        }
                        has_org = true;
                        contact.organization = nonempty(
                            split_quoted(&property.value, ';')?
                                .into_iter()
                                .map(unescape)
                                .collect::<Result<Vec<_>, _>>()?
                                .join(" "),
                        );
                    }
                    "EMAIL" => {
                        let value = unescape(&property.value)?;
                        contact.emails.push(LabeledValue {
                            label: label(&property),
                            value: value.strip_prefix("mailto:").unwrap_or(&value).to_owned(),
                        });
                    }
                    "TEL" => {
                        let value = unescape(&property.value)?;
                        contact.phones.push(LabeledValue {
                            label: label(&property),
                            value: value.strip_prefix("tel:").unwrap_or(&value).to_owned(),
                        });
                    }
                    _ => unreachable!(),
                }
            }
            Ok(contact)
        })
        .collect()
}
fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
fn label(property: &Property) -> Option<String> {
    property.params.get("TYPE").cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vcard_fixtures_decode_structured_escaped_folded_and_grouped_fields() {
        let cards = parse("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:one\r\nN:Björk;Juniper;;;\r\nORG:Cortex\\;Kit;Re\r\n search\r\nitem1.EMAIL;TYPE=\"home,internet\":juniper@example.test\r\nTEL;TYPE=work:+123\r\nEND:VCARD\r\nBEGIN:VCARD\nVERSION:4.0\nUID:two\nN:Doe;Jane;;;\nTEL;VALUE=uri:tel:+456\nEMAIL:mailto:jane@example.test\nEND:VCARD").unwrap();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].family_name.as_deref(), Some("Björk"));
        assert_eq!(cards[0].given_name.as_deref(), Some("Juniper"));
        assert_eq!(
            cards[0].organization.as_deref(),
            Some("Cortex;Kit Research")
        );
        assert_eq!(cards[0].emails[0].label.as_deref(), Some("home,internet"));
        assert_eq!(cards[1].phones[0].value, "+456");
        assert_eq!(cards[1].emails[0].value, "jane@example.test");
        assert!(cards.iter().all(|c| c.groups.is_empty()));
    }
    #[test]
    fn malformed_or_encoded_vcard_text_is_not_guessed() {
        for property in [
            "N:Doe;Jane",
            "N;ENCODING=QUOTED-PRINTABLE:Doe;Jane;;;",
            "ORG;CHARSET=ISO-8859-1:Name",
            "N:Doe;Jane;;;\nN:Other;Jane;;;",
        ] {
            assert!(parse(&format!(
                "BEGIN:VCARD\nVERSION:3.0\nUID:one\n{property}\nEND:VCARD"
            ))
            .is_err());
        }
        assert!(parse("BEGIN:VCARD\nVERSION:4.0\nUID:a\nEND:VEVENT").is_err());
    }
}
