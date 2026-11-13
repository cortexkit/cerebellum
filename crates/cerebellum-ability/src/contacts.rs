//! Contact predicates shared by every source, rather than store-specific searches.

use crate::items::Contact;

/// Search the original fields before output caps can shorten them. Unicode
/// lowercasing is deliberate: neither locale collation nor normalization applies.
pub fn matches_query(contact: &Contact, query: Option<&str>) -> bool {
    let Some(query) = query else { return true };
    let query = query.to_lowercase();
    contact
        .given_name
        .iter()
        .chain(contact.family_name.iter())
        .chain(contact.organization.iter())
        .map(String::as_str)
        .chain(contact.emails.iter().map(|email| email.value.as_str()))
        .any(|field| field.to_lowercase().contains(&query))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::LabeledValue;

    #[test]
    fn query_matches_mid_word_unicode_organization_and_email_values() {
        let contact = Contact {
            given_name: Some("Marianne".into()),
            family_name: Some("ÖZTÜRK".into()),
            organization: Some("Research Lab".into()),
            emails: vec![LabeledValue {
                label: Some("private".into()),
                value: "test@EXAMPLE.org".into(),
            }],
            ..Default::default()
        };
        for query in ["rian", "öztürk", "SEARCH", "@example."] {
            assert!(matches_query(&contact, Some(query)), "{query}");
        }
        for query in ["private", "absent", "ozturk"] {
            assert!(!matches_query(&contact, Some(query)), "{query}");
        }
        assert!(matches_query(&contact, None));
    }
}
