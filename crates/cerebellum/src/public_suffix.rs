//! Registrable DNS domains under the pinned ICANN and PRIVATE Public Suffix List.
use std::collections::HashSet;
use std::sync::OnceLock;

pub const PSL_SHA256: &str = "f42812d8a54bd25ec992d84bbb23dabab91aaa2d5c600ff38af4165edaa507ff";
const LIST: &str = include_str!("../resources/public_suffix_list.dat");

fn rules() -> &'static HashSet<&'static str> {
    static RULES: OnceLock<HashSet<&'static str>> = OnceLock::new();
    RULES.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let digest = format!("{:x}", Sha256::digest(LIST.as_bytes()));
        assert_eq!(digest, PSL_SHA256, "the bundled PSL must match its pin");
        LIST.lines()
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .collect()
    })
}

/// The registrable domain (public suffix plus one preceding label), or no
/// domain for a suffix itself or an invalid ASCII DNS name.
pub fn registrable_domain(host: &str) -> Option<String> {
    if host.is_empty() || host.starts_with('.') || !host.is_ascii() {
        return None;
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let labels: Vec<_> = host.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    let rules = rules();
    let mut suffix_len = 1;
    for index in 0..labels.len() {
        let suffix = labels[index..].join(".");
        if rules.contains(format!("!{suffix}").as_str()) {
            suffix_len = labels.len() - index - 1;
            break;
        }
        if rules.contains(suffix.as_str()) {
            suffix_len = suffix_len.max(labels.len() - index);
        }
        if index > 0 && rules.contains(format!("*.{suffix}").as_str()) {
            suffix_len = suffix_len.max(labels.len() - index + 1);
        }
    }
    (labels.len() > suffix_len).then(|| labels[labels.len() - suffix_len - 1..].join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_public_suffix_vectors() {
        for line in include_str!("../resources/test_psl_ascii.txt").lines() {
            let (input, expected) = line.split_once('\t').unwrap();
            let actual = registrable_domain(input);
            assert_eq!(
                actual.as_deref(),
                (expected != "null").then_some(expected),
                "{input}"
            );
        }
    }
}
