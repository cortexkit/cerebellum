//! Fixed DOM functions admitted by the extension's SHA-256 allowlist.
//! Whitespace is part of each digest. Never interpolate page or typed text into
//! a declaration; CDP parameters carry object identities and text separately.

pub(super) const SELECT: &str = "function() { if (typeof this.select === 'function') { this.select(); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } }";
pub(super) const APPEND_CARET: &str = "function() { if (typeof this.setSelectionRange === 'function') { const end = this.value.length; this.setSelectionRange(end, end); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); range.collapse(false); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } return true; }";
pub(super) const HAS_FOCUS: &str = "function() { return this.ownerDocument.hasFocus() && this.getRootNode().activeElement === this; }";
pub(crate) const CHOOSE_OPTION: &str = "function() { if (!(this instanceof HTMLOptionElement)) { throw new Error('target is not an option'); } const select = this.closest('select'); if (!select) { throw new Error('option has no select'); } const group = this.closest('optgroup'); if (this.disabled || select.disabled || (group && group.disabled)) { throw new Error('option, optgroup or select is disabled'); } this.selected = select.multiple ? !this.selected : true; select.dispatchEvent(new Event('input', {bubbles:true})); select.dispatchEvent(new Event('change', {bubbles:true})); return {value:select.value, selectedIndex:select.selectedIndex}; }";

#[cfg(test)]
pub(super) const ALL: [(&str, &str); 4] = [
    ("SELECT", SELECT),
    ("APPEND_CARET", APPEND_CARET),
    ("HAS_FOCUS", HAS_FOCUS),
    ("CHOOSE_OPTION", CHOOSE_OPTION),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn extension_protocol_pins_every_runtime_function_when_present() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extension/PROTOCOL.md");
        let protocol = match std::fs::read_to_string(path) {
            Ok(protocol) => Some(protocol),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("cannot read the extension's function pins: {error}"),
        };
        for (name, declaration) in ALL {
            let digest = format!("{:x}", Sha256::digest(declaration.as_bytes()));
            let expected = match name {
                "SELECT" => "5642611a1b2f6289d347bf6b0182feca100bb1cd024a91730bf48236a9924689",
                "APPEND_CARET" => {
                    "ac62bcd9e6db95e84a42a90a37f286117b8ce6d3b0760ae1d1083c084d96bba7"
                }
                "HAS_FOCUS" => "2cd006d8e531e4e1c03b2e4bfebec513fe642134af0ddc6d7fb602ca9c835ffe",
                "CHOOSE_OPTION" => {
                    "b324ab559e352cc33aaeed89829c47aff9d34d6a8ef74a9e38c2a44d3a6cf0ff"
                }
                _ => unreachable!("fixed function list"),
            };
            assert_eq!(
                digest, expected,
                "{name} differs from the extension's pinned declaration"
            );
            println!("{name}: {digest}");
            if let Some(protocol) = &protocol {
                assert!(
                    protocol.contains(&digest),
                    "extension protocol is missing {name}: {digest}"
                );
            }
        }
        if protocol.is_none() {
            println!("extension/PROTOCOL.md is not present; digest cross-check awaits extension integration");
        }
    }
}
