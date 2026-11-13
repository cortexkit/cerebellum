//! Caps count JSON string content bytes, including escapes but excluding quotes.

use crate::items::{Address, LabeledValue};

pub const FREE_TEXT_BYTES: usize = 16 * 1024;
pub const BODY_BYTES: usize = 256 * 1024;
pub const ENTRY_BYTES: usize = 256;
pub const LABELED_ENTRIES: usize = 64;
pub const ADDRESS_ENTRIES: usize = 256;
pub const ITEM_BYTES: usize = 1024 * 1024;

/// This is serde_json's escaping for a string in an ordinary JSON value.
pub fn serialized_string_bytes(value: &str) -> usize {
    value.chars().map(char_bytes).sum()
}

fn char_bytes(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        '\u{0}'..='\u{1f}' => 6,
        _ => c.len_utf8(),
    }
}

/// Keep the longest character-aligned prefix within the serialized byte cap.
pub fn cut_string(value: &mut String, cap: usize) -> bool {
    let mut bytes = 0;
    for (index, c) in value.char_indices() {
        bytes += char_bytes(c);
        if bytes > cap {
            value.truncate(index);
            return true;
        }
    }
    false
}

pub(crate) fn optional_string(value: &mut Option<String>, cap: usize) -> bool {
    value.as_mut().is_some_and(|text| cut_string(text, cap))
}

pub(crate) fn free_text(value: &mut Option<String>) -> bool {
    optional_string(value, FREE_TEXT_BYTES)
}

fn cut_list<T>(values: &mut Vec<T>, cap: usize) -> bool {
    let cut = values.len() > cap;
    values.truncate(cap);
    cut
}

pub(crate) fn labeled_values(values: &mut Vec<LabeledValue>) -> bool {
    let mut cut = cut_list(values, LABELED_ENTRIES);
    for entry in values {
        cut |= optional_string(&mut entry.label, ENTRY_BYTES);
        cut |= cut_string(&mut entry.value, ENTRY_BYTES);
    }
    cut
}

fn address(value: &mut Address) -> bool {
    let name_cut = optional_string(&mut value.name, ENTRY_BYTES);
    cut_string(&mut value.address, ENTRY_BYTES) || name_cut
}

pub(crate) fn optional_address(value: &mut Option<Address>) -> bool {
    value.as_mut().is_some_and(address)
}

pub(crate) fn addresses(values: &mut Vec<Address>) -> bool {
    let mut cut = cut_list(values, ADDRESS_ENTRIES);
    for entry in values {
        cut |= address(entry);
    }
    cut
}

/// The caller orders handles before this function drops entries or cuts strings.
pub(crate) fn participants(values: &mut Vec<String>) -> bool {
    let mut cut = cut_list(values, ADDRESS_ENTRIES);
    for entry in values {
        cut |= cut_string(entry, ENTRY_BYTES);
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{items::*, schema};
    use serde_json::json;

    fn json_bytes(text: &str) -> usize {
        serde_json::to_string(text).unwrap().len() - 2
    }

    #[test]
    fn cuts_count_serialized_escapes_and_keep_character_boundaries() {
        let all_controls: String = (0..32).map(char::from).collect();
        for input in [
            "plain",
            "é中😀",
            "\"\\\n\t\r\u{8}\u{c}",
            all_controls.as_str(),
        ] {
            assert_eq!(serialized_string_bytes(input), json_bytes(input));
            for cap in 0..=json_bytes(input) + 1 {
                let mut cut = input.to_owned();
                let changed = cut_string(&mut cut, cap);
                assert!(input.starts_with(&cut));
                assert!(json_bytes(&cut) <= cap);
                assert_eq!(changed, json_bytes(input) > cap);
                if let Some(next) = input[cut.len()..].chars().next() {
                    let longer = format!("{cut}{next}");
                    assert!(json_bytes(&longer) > cap);
                }
            }
        }
        let mut text = "\"".repeat(9000);
        assert!(cut_string(&mut text, 16 * 1024));
        assert_eq!(text.len(), 8192);
        assert_eq!(json_bytes(&text), 16 * 1024);
        let mut body = "é".repeat(140_000);
        assert!(cut_string(&mut body, 256 * 1024));
        assert_eq!(body.len(), 256 * 1024);
    }

    #[test]
    fn groups_and_overlong_participants_order_before_the_list_and_string_cuts() {
        let mut contact = Item::Contact(Contact {
            id: "id".into(),
            groups: vec!["é".into(), "中".into(), "a".into(), "ä".into(), "Z".into()],
            ..Default::default()
        });
        contact.normalize().unwrap();
        assert_eq!(
            serde_json::to_value(contact).unwrap()["groups"],
            json!(["Z", "a", "ä", "é", "中"])
        );
        let handles = (0..300)
            .rev()
            .map(|n| format!("u{n:04}{}", "é".repeat(200)))
            .collect();
        let mut item = Item::Conversation(Conversation {
            id: "id".into(),
            participants: handles,
            ..Default::default()
        });
        item.normalize().unwrap();
        let value = serde_json::to_value(item).unwrap();
        let handles = value["participants"].as_array().unwrap();
        assert_eq!(handles.len(), 256);
        for (n, handle) in handles.iter().enumerate() {
            assert_eq!(
                handle.as_str().unwrap(),
                format!("u{n:04}{}", "é".repeat(125))
            );
            assert_eq!(json_bytes(handle.as_str().unwrap()), 255);
        }
        assert_eq!(value["truncated"], json!(["participants"]));
    }

    #[test]
    fn entry_caps_keep_source_order_and_mark_each_member_once_in_table_order() {
        let entries = (0..70)
            .map(|n| LabeledValue {
                label: Some("l".repeat(300)),
                value: format!("{n:02}{}", "v".repeat(300)),
            })
            .collect::<Vec<_>>();
        let mut contact = Item::Contact(Contact {
            id: "id".into(),
            given_name: Some("a".repeat(17000)),
            family_name: Some("b".repeat(17000)),
            organization: Some("c".repeat(17000)),
            emails: entries.clone(),
            phones: entries,
            ..Default::default()
        });
        contact.normalize().unwrap();
        let contact = serde_json::to_value(contact).unwrap();
        assert_eq!(
            contact["truncated"],
            json!([
                "given_name",
                "family_name",
                "organization",
                "emails",
                "phones"
            ])
        );
        for field in ["emails", "phones"] {
            let entries = contact[field].as_array().unwrap();
            assert_eq!(entries.len(), 64);
            for (n, entry) in entries.iter().enumerate() {
                assert_eq!(entry["label"].as_str().unwrap().len(), 256);
                assert_eq!(
                    entry["value"].as_str().unwrap(),
                    format!("{n:02}{}", "v".repeat(254))
                );
            }
        }
        let address = Address {
            name: Some("n".repeat(300)),
            address: "a".repeat(300),
        };
        let addresses = (0..300)
            .map(|n| Address {
                name: address.name.clone(),
                address: format!("{n:03}{}", address.address),
            })
            .collect::<Vec<_>>();
        let mut mail = Item::MailMessage(MailMessage {
            id: "id".into(),
            mailbox: "mailbox".into(),
            from: Some(address),
            to: addresses.clone(),
            cc: addresses,
            subject: Some("s".repeat(17000)),
            body: Some("b".repeat(270000)),
            body_state: BodyState::Ok,
            truncated: vec!["body".into(), "from".into(), "body".into()],
            ..Default::default()
        });
        mail.normalize().unwrap();
        let once = mail.clone();
        mail.normalize().unwrap();
        assert_eq!(mail, once);
        let value = serde_json::to_value(mail).unwrap();
        assert_eq!(
            value["truncated"],
            json!(["from", "to", "cc", "subject", "body"])
        );
        assert_eq!(value["body"].as_str().unwrap().len(), 256 * 1024);
        for key in ["name", "address"] {
            assert_eq!(value["from"][key].as_str().unwrap().len(), 256);
        }
        for field in ["to", "cc"] {
            let entries = value[field].as_array().unwrap();
            assert_eq!(entries.len(), 256);
            for (n, entry) in entries.iter().enumerate() {
                assert_eq!(entry["name"].as_str().unwrap().len(), 256);
                assert_eq!(
                    entry["address"].as_str().unwrap(),
                    format!("{n:03}{}", "a".repeat(253))
                );
            }
        }
    }

    #[test]
    fn all_free_text_account_and_sender_caps_are_applied() {
        for item in test_items() {
            let kind = item.kind();
            let mut value = serde_json::to_value(item).unwrap();
            let mut expected = Vec::new();
            for field in [
                "title",
                "account",
                "given_name",
                "family_name",
                "organization",
                "location",
                "notes",
                "subject",
                "text",
                "body",
                "sender",
            ] {
                if value.get(field).is_some() {
                    value[field] = json!("x".repeat(270000));
                    expected.push(field);
                }
            }
            if value.get("text_state").is_some() {
                value["text_state"] = json!("ok");
            }
            if value.get("body_state").is_some() {
                value["body_state"] = json!("ok");
            }
            let mut item = Item::from_json(kind, value).unwrap();
            item.normalize().unwrap();
            let value = serde_json::to_value(item).unwrap();
            for field in expected.iter() {
                let cap = match *field {
                    "sender" => 256,
                    "body" => 256 * 1024,
                    _ => 16 * 1024,
                };
                assert_eq!(json_bytes(value[field].as_str().unwrap()), cap, "{field}");
            }
            let expected = kind
                .members()
                .iter()
                .filter(|member| expected.contains(member))
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(value["truncated"], json!(expected));
        }
    }

    #[test]
    fn every_maximal_item_is_below_one_mib_even_with_escaped_ids() {
        // Independent conservative bounds include JSON punctuation and keys.
        // Ids can expand sixfold, unlike already-capped serialized text.
        let contact_bound = 2048 * 6 + 64 * (2048 * 6 + 3) + 3 * 16384 + 128 * (512 + 40) + 4096;
        let mail_bound = 2 * 2048 * 6 + 16384 + 262144 + 513 * (512 + 40) + 4096;
        assert!(contact_bound < 1024 * 1024);
        assert!(mail_bound < 1024 * 1024);
        let escaped_id = "\0".repeat(2048);
        let long = "\0".repeat(50000);
        let entry = "\0".repeat(300);
        for item in test_items() {
            let kind = item.kind();
            let mut value = serde_json::to_value(item).unwrap();
            for field in kind.members() {
                value[*field] = match *field {
                    "id" | "calendar" | "list" | "conversation" | "mailbox" => json!(escaped_id),
                    "title" | "account" | "given_name" | "family_name" | "organization"
                    | "location" | "notes" | "subject" | "text" | "body" | "sender" => json!(long),
                    "groups" => json!((0..64)
                        .map(|n| format!("{}{:04}", "\0".repeat(2044), n))
                        .collect::<Vec<_>>()),
                    "emails" | "phones" => json!(vec![json!({"label": entry, "value": entry}); 65]),
                    "participants" => json!(vec![entry.clone(); 257]),
                    "from" => json!({"name": entry, "address": entry}),
                    "to" | "cc" => json!(vec![json!({"name": entry, "address": entry}); 257]),
                    "start_date" | "end_date" => json!("2025-11-02"),
                    "text_state" | "body_state" => json!("ok"),
                    "all_day" => json!(true),
                    _ => value[*field].clone(),
                };
            }
            let mut item = Item::from_json(kind, value).unwrap();
            item.normalize().unwrap();
            let bytes = serde_json::to_vec(&item).unwrap();
            assert!(bytes.len() < 1024 * 1024, "{kind:?}: {}", bytes.len());
            schema::validate_shape(
                &schema::item_schema(kind),
                &serde_json::to_value(item).unwrap(),
                "item",
            )
            .unwrap();
        }
        // Memberships cannot grow beyond the bound set; they are not a free-text list.
        let mut too_many_groups = Item::Contact(Contact {
            id: "id".into(),
            groups: vec!["group".into(); 65],
            ..Default::default()
        });
        assert!(too_many_groups.normalize().is_err());
        assert_eq!(ITEM_BYTES, 1024 * 1024);
    }
}
