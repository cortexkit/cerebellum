//! Scope checks use the item's own containers, never the scope used to fetch it.

use crate::{
    items::{Contact, Item},
    BoundScope, ValidationError,
};
use std::collections::BTreeSet;

/// Source-only metadata; container tags are not extra members of wire items.
/// Adapters must populate these from the returned record, not the requested ids.
pub struct TaggedItem {
    pub item: Item,
    pub container_ids: BTreeSet<String>,
}

impl TaggedItem {
    pub fn new(item: Item, reported_containers: impl IntoIterator<Item = String>) -> Self {
        Self {
            item,
            container_ids: reported_containers.into_iter().collect(),
        }
    }

    /// For records whose container is carried in the wire shape. Contacts need
    /// `contact` instead when the source also reports an owning account.
    pub fn from_item(item: Item) -> Self {
        let ids = match &item {
            Item::Event(v) => vec![v.calendar.clone()],
            Item::Reminder(v) => vec![v.list.clone()],
            Item::Contact(v) => v.groups.clone(),
            Item::Message(v) => vec![v.conversation.clone()],
            Item::MailSummary(v) => vec![v.mailbox.clone()],
            Item::MailMessage(v) => vec![v.mailbox.clone()],
            _ => vec![item.id().to_owned()],
        };
        Self::new(item, ids)
    }

    /// Accounts and groups share the contacts scope namespace. Include the
    /// owning account even when the contact belongs to no membership group.
    pub fn contact(contact: Contact, account: Option<String>) -> Self {
        let mut ids = contact.groups.clone();
        ids.extend(account);
        Self::new(Item::Contact(contact), ids)
    }
}

pub fn retain_in_scope(scope: &BoundScope, mut tagged: TaggedItem) -> Option<Item> {
    if tagged.container_ids.is_disjoint(scope.ids()) {
        return None;
    }
    if let Item::Contact(contact) = &mut tagged.item {
        contact.groups = tagged
            .container_ids
            .intersection(scope.ids())
            .cloned()
            .collect();
    }
    Some(tagged.item)
}

/// Apply to a whole helper reply before forwarding any item or its cursor.
/// Contact helpers carry the bound account/group tags in `groups`.
pub fn check_page_scope(scope: &BoundScope, items: &[Item]) -> Result<(), ValidationError> {
    if items.iter().any(|item| {
        TaggedItem::from_item(item.clone())
            .container_ids
            .is_disjoint(scope.ids())
    }) {
        return Err(ValidationError::new(
            "items",
            "source page contains an out-of-scope item",
        ));
    }
    if items.iter().any(|item| matches!(item, Item::Contact(contact) if contact.groups.iter().any(|id| !scope.contains(id)))) {
        return Err(ValidationError::new("groups", "source page exposes an unbound membership"));
    }
    Ok(())
}

/// Unknown and out-of-scope lookups have the same absence result. Map `None`
/// to the same item-not-found refusal, without exposing whether a record exists.
pub fn scoped_get(
    scope: &BoundScope,
    candidate: Option<TaggedItem>,
) -> Result<Option<Item>, ValidationError> {
    let Some(mut item) = candidate.and_then(|item| retain_in_scope(scope, item)) else {
        return Ok(None);
    };
    item.normalize()?;
    Ok(Some(item))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{items::test_items, validate_scope, Token};
    use serde_json::json;

    #[test]
    fn every_item_kind_uses_own_tags_and_get_hides_scope_misses() {
        for item in test_items() {
            let scope = validate_scope(Token::Calendar, &json!({"calendar": ["bound"]})).unwrap();
            assert!(
                retain_in_scope(&scope, TaggedItem::new(item.clone(), ["outside".into()]))
                    .is_none()
            );
            assert!(retain_in_scope(
                &scope,
                TaggedItem::new(item.clone(), ["outside".into(), "bound".into()])
            )
            .is_some());
            assert_eq!(
                scoped_get(&scope, None).unwrap(),
                scoped_get(&scope, Some(TaggedItem::new(item, ["outside".into()]))).unwrap()
            );
        }
    }

    #[test]
    fn contact_memberships_are_intersected_and_account_membership_counts() {
        let scope = validate_scope(Token::Contacts, &json!({"group": ["g:yes", "a:yes"]})).unwrap();
        for (groups, account, expected) in [
            (vec!["g:no", "g:yes"], None, Some(vec!["g:yes"])),
            (vec!["g:no"], None, None),
            (vec!["g:no"], Some("a:yes"), Some(vec!["a:yes"])),
            (vec!["g:yes"], Some("a:yes"), Some(vec!["a:yes", "g:yes"])),
        ] {
            let contact = Contact {
                id: "c".into(),
                groups: groups.into_iter().map(str::to_owned).collect(),
                ..Default::default()
            };
            let result = retain_in_scope(
                &scope,
                TaggedItem::contact(contact, account.map(str::to_owned)),
            );
            assert_eq!(
                result.as_ref().map(|item| match item {
                    Item::Contact(v) => v.groups.iter().map(String::as_str).collect::<Vec<_>>(),
                    _ => unreachable!(),
                }),
                expected
            );
            if let Some(item) = result {
                check_page_scope(&scope, &[item]).unwrap();
            }
        }
        assert!(check_page_scope(
            &scope,
            &[Item::Contact(Contact {
                groups: vec!["g:yes".into(), "g:no".into()],
                ..Default::default()
            })]
        )
        .is_err());
    }
}
