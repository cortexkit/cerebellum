//! Independent reader for the v4, little-endian NSArchiver typedstream grammar.
//!
//! Text is taken only from the NSString field of a supported attributed-string
//! root. Unknown encodings, class versions and malformed graphs are undecodable;
//! searching a blob for printable bytes would mistake attribute data for text.

use crate::{caps, items::TextState};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_ENTRIES: usize = 4096;
const MAX_VALUES: usize = 65_536;
const NEW: u8 = 0x84;
const NIL: u8 = 0x85;
const END: u8 = 0x86;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedText {
    pub text: Option<String>,
    pub text_state: TextState,
    pub truncated: Vec<String>,
}

pub fn decode_attributed_body(input: &[u8]) -> DecodedText {
    match Reader::text(input) {
        Ok(mut text) => {
            let cut = caps::cut_string(&mut text, caps::FREE_TEXT_BYTES);
            DecodedText {
                text: Some(text),
                text_state: TextState::Ok,
                truncated: if cut { vec!["text".into()] } else { Vec::new() },
            }
        }
        Err(Undecodable) => DecodedText {
            text: None,
            text_state: TextState::Undecodable,
            truncated: Vec::new(),
        },
    }
}

#[derive(Clone, Copy, Debug)]
struct Undecodable;
type Result<T> = std::result::Result<T, Undecodable>;

#[derive(Clone, Copy)]
struct Class<'a> {
    name: &'a [u8],
    version: i64,
}

enum Value<'a> {
    Object(Option<usize>),
    Bytes(&'a [u8]),
    Other,
}

struct Group<'a> {
    encoding: &'a [u8],
    values: Vec<Value<'a>>,
}

enum Entry<'a> {
    Pending,
    Class(Vec<Class<'a>>),
    Object {
        classes: Vec<Class<'a>>,
        fields: Vec<Group<'a>>,
    },
    CString,
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
    strings: Vec<&'a [u8]>,
    entries: Vec<Entry<'a>>,
    values: usize,
}

impl<'a> Reader<'a> {
    fn text(input: &'a [u8]) -> Result<String> {
        if input.len() > MAX_BYTES {
            return Err(Undecodable);
        }
        let mut reader = Self {
            input,
            offset: 0,
            strings: Vec::new(),
            entries: Vec::new(),
            values: 0,
        };
        if reader.take(13)? != b"\x04\x0bstreamtyped" || reader.integer()? != 1000 {
            return Err(Undecodable);
        }
        let root = reader.group(0)?;
        if reader.offset != input.len() || root.encoding != b"@" {
            return Err(Undecodable);
        }
        let [Value::Object(Some(root))] = root.values.as_slice() else {
            return Err(Undecodable);
        };
        let Entry::Object { classes, fields } = &reader.entries[*root] else {
            return Err(Undecodable);
        };
        let names: Vec<_> = classes.iter().map(|c| (c.name, c.version)).collect();
        if names != [(b"NSAttributedString".as_slice(), 0), (b"NSObject", 0)]
            && names
                != [
                    (b"NSMutableAttributedString".as_slice(), 0),
                    (b"NSAttributedString", 0),
                    (b"NSObject", 0),
                ]
        {
            return Err(Undecodable);
        }
        let first = fields.first().ok_or(Undecodable)?;
        if first.encoding != b"@" {
            return Err(Undecodable);
        }
        let [Value::Object(Some(string))] = first.values.as_slice() else {
            return Err(Undecodable);
        };
        let Entry::Object { classes, fields } = &reader.entries[*string] else {
            return Err(Undecodable);
        };
        let names: Vec<_> = classes.iter().map(|c| (c.name, c.version)).collect();
        if names != [(b"NSString".as_slice(), 1), (b"NSObject", 0)]
            && names
                != [
                    (b"NSMutableString".as_slice(), 1),
                    (b"NSString", 1),
                    (b"NSObject", 0),
                ]
        {
            return Err(Undecodable);
        }
        let [field] = fields.as_slice() else {
            return Err(Undecodable);
        };
        if field.encoding != b"+" {
            return Err(Undecodable);
        }
        let [Value::Bytes(bytes)] = field.values.as_slice() else {
            return Err(Undecodable);
        };
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Undecodable)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(Undecodable)?;
        let bytes = self.input.get(self.offset..end).ok_or(Undecodable)?;
        self.offset = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn integer(&mut self) -> Result<i64> {
        let first = self.byte()?;
        self.integer_from(first)
    }

    fn integer_from(&mut self, first: u8) -> Result<i64> {
        match first {
            0x81 => {
                Ok(i16::from_le_bytes(self.take(2)?.try_into().map_err(|_| Undecodable)?) as i64)
            }
            0x82 => {
                Ok(i32::from_le_bytes(self.take(4)?.try_into().map_err(|_| Undecodable)?) as i64)
            }
            0x87 => Ok(i64::from_le_bytes(
                self.take(8)?.try_into().map_err(|_| Undecodable)?,
            )),
            0x80..=0x91 => Err(Undecodable),
            _ => Ok(i64::from(first as i8)),
        }
    }

    fn reference(&mut self, first: u8) -> Result<usize> {
        // The reference sequence starts at signed -110 (byte 0x92) and
        // continues through tagged integers once one-byte values run out.
        usize::try_from(
            self.integer_from(first)?
                .checked_add(110)
                .ok_or(Undecodable)?,
        )
        .map_err(|_| Undecodable)
    }

    fn unshared(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.integer()?).map_err(|_| Undecodable)?;
        self.take(length)
    }

    fn shared(&mut self) -> Result<&'a [u8]> {
        match self.byte()? {
            NEW => {
                if self.strings.len() == MAX_ENTRIES {
                    return Err(Undecodable);
                }
                let text = self.unshared()?;
                self.strings.push(text);
                Ok(text)
            }
            first => {
                let index = self.reference(first)?;
                self.strings.get(index).copied().ok_or(Undecodable)
            }
        }
    }

    fn reserve(&mut self) -> Result<usize> {
        if self.entries.len() == MAX_ENTRIES {
            return Err(Undecodable);
        }
        let index = self.entries.len();
        self.entries.push(Entry::Pending);
        Ok(index)
    }

    fn classes(&mut self) -> Result<Vec<Class<'a>>> {
        let mut new_classes = Vec::new();
        let mut chain = loop {
            match self.byte()? {
                NIL => break Vec::new(),
                NEW => {
                    if new_classes.len() == MAX_DEPTH {
                        return Err(Undecodable);
                    }
                    let index = self.reserve()?;
                    let name = self.shared()?;
                    let version = self.integer()?;
                    new_classes.push((index, Class { name, version }));
                }
                first => {
                    let index = self.reference(first)?;
                    let Some(Entry::Class(chain)) = self.entries.get(index) else {
                        return Err(Undecodable);
                    };
                    break chain.clone();
                }
            }
        };
        for (index, class) in new_classes.into_iter().rev() {
            if chain.len() == MAX_DEPTH {
                return Err(Undecodable);
            }
            chain.insert(0, class);
            self.entries[index] = Entry::Class(chain.clone());
        }
        Ok(chain)
    }

    fn object(&mut self, depth: usize) -> Result<Value<'a>> {
        if depth > MAX_DEPTH {
            return Err(Undecodable);
        }
        match self.byte()? {
            NIL => Ok(Value::Object(None)),
            NEW => {
                let index = self.reserve()?;
                let classes = self.classes()?;
                let mut fields = Vec::new();
                while self.input.get(self.offset) != Some(&END) {
                    fields.push(self.group(depth + 1)?);
                }
                self.byte()?;
                self.entries[index] = Entry::Object { classes, fields };
                Ok(Value::Object(Some(index)))
            }
            first => {
                let index = self.reference(first)?;
                if !matches!(
                    self.entries.get(index),
                    Some(Entry::Object { .. } | Entry::Pending)
                ) {
                    return Err(Undecodable);
                }
                Ok(Value::Object(Some(index)))
            }
        }
    }

    fn group(&mut self, depth: usize) -> Result<Group<'a>> {
        if depth > MAX_DEPTH {
            return Err(Undecodable);
        }
        let encoding = self.shared()?;
        if encoding.is_empty() || encoding.len() > 256 {
            return Err(Undecodable);
        }
        let mut values = Vec::new();
        for ty in encoding {
            self.values += 1;
            if self.values > MAX_VALUES {
                return Err(Undecodable);
            }
            values.push(match ty {
                b'@' => self.object(depth)?,
                b'+' => Value::Bytes(self.unshared()?),
                b'c' | b'C' => {
                    self.byte()?;
                    Value::Other
                }
                b's' | b'S' | b'i' | b'I' | b'l' | b'L' | b'q' | b'Q' | b'B' => {
                    self.integer()?;
                    Value::Other
                }
                b'f' | b'd' => {
                    let first = self.byte()?;
                    if first == 0x83 {
                        self.take(if *ty == b'f' { 4 } else { 8 })?;
                    } else {
                        self.integer_from(first)?;
                    }
                    Value::Other
                }
                b':' | b'%' => {
                    self.shared()?;
                    Value::Other
                }
                b'*' => {
                    match self.byte()? {
                        NIL => (),
                        NEW => {
                            let index = self.reserve()?;
                            self.shared()?;
                            self.entries[index] = Entry::CString;
                        }
                        first => {
                            let index = self.reference(first)?;
                            if !matches!(self.entries.get(index), Some(Entry::CString)) {
                                return Err(Undecodable);
                            }
                        }
                    }
                    Value::Other
                }
                // Compound layouts need a positively supported encoding before
                // they can be skipped safely; unknown types are not byte scans.
                _ => return Err(Undecodable),
            });
        }
        Ok(Group { encoding, values })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built from the v4 grammar: separate shared-string and archived-object
    // tables, an attributed-string root, NSString text and an empty dictionary.
    const IMMUTABLE: &[u8] = b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+\x05hello\x86\x84\x02iI\x01\x05\x92\x84\x84\x84\x0cNSDictionary\x00\x94\x84\x01i\x00\x86\x86";

    fn mutable(text: &[u8]) -> Vec<u8> {
        let mut bytes = b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x19NSMutableAttributedString\x00\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x0fNSMutableString\x01\x84\x84\x08NSString\x01\x95\x84\x01+".to_vec();
        bytes.push(0x82);
        bytes.extend_from_slice(&(text.len() as i32).to_le_bytes());
        bytes.extend_from_slice(text);
        bytes.extend_from_slice(b"\x86\x86");
        bytes
    }

    #[test]
    fn built_attributed_body_fixtures_return_only_the_nsstring_text() {
        let decoded = decode_attributed_body(IMMUTABLE);
        assert_eq!(decoded.text.as_deref(), Some("hello"));
        assert_eq!(decoded.text_state, TextState::Ok);
        assert!(decoded.truncated.is_empty());
        for text in [
            "",
            "café 日本語 😀",
            "text containing NSString and streamtyped",
        ] {
            let decoded = decode_attributed_body(&mutable(text.as_bytes()));
            assert_eq!(decoded.text.as_deref(), Some(text));
            assert_eq!(decoded.text_state, TextState::Ok);
        }
    }

    #[test]
    fn text_caps_do_not_split_utf8() {
        let prefix = "x".repeat(caps::FREE_TEXT_BYTES - 1);
        let decoded = decode_attributed_body(&mutable(format!("{prefix}😀").as_bytes()));
        assert_eq!(decoded.text.as_deref(), Some(prefix.as_str()));
        assert_eq!(decoded.truncated, vec!["text"]);
    }

    #[test]
    fn unsupported_or_invalid_bodies_are_undecodable_never_guessed() {
        let mut wrong_class = IMMUTABLE.to_vec();
        let name = wrong_class
            .windows(18)
            .position(|w| w == b"NSAttributedString")
            .unwrap();
        wrong_class[name] = b'X';
        let mut wrong_version = IMMUTABLE.to_vec();
        wrong_version[name + 18] = 2;
        let mut bad_reference = IMMUTABLE.to_vec();
        let superclass = bad_reference.iter().position(|b| *b == 0x94).unwrap();
        bad_reference[superclass] = 0xff;
        let mut trailing = IMMUTABLE.to_vec();
        trailing.extend_from_slice(b"guess this text");
        for input in [
            b"printable but not archived".as_slice(),
            mutable(b"\xff").as_slice(),
            &wrong_class,
            &wrong_version,
            &bad_reference,
            &trailing,
        ] {
            let decoded = decode_attributed_body(input);
            assert_eq!(decoded.text, None);
            assert_eq!(decoded.text_state, TextState::Undecodable);
            assert!(decoded.truncated.is_empty());
        }
    }

    #[test]
    fn truncated_and_garbled_typedstream_never_panics() {
        for end in 0..IMMUTABLE.len() {
            let decoded = decode_attributed_body(&IMMUTABLE[..end]);
            assert_eq!(decoded.text_state, TextState::Undecodable, "prefix {end}");
            assert_eq!(decoded.text, None);
        }
        for index in 0..IMMUTABLE.len() {
            for byte in [0, 0x81, 0x82, 0x84, 0x85, 0x86, 0x87, 0xff] {
                let mut garbled = IMMUTABLE.to_vec();
                garbled[index] = byte;
                let decoded = decode_attributed_body(&garbled);
                if decoded.text_state != TextState::Ok {
                    assert_eq!(decoded.text, None);
                }
            }
        }
        let oversized = vec![0; MAX_BYTES + 1];
        assert_eq!(
            decode_attributed_body(&oversized).text_state,
            TextState::Undecodable
        );
    }
}
