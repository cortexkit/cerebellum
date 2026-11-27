//! Read the image's own version resource from its locked bytes, not an
//! adjacent language DLL or a second open of the image path.

type ReadResult<T> = Result<T, ()>;

fn word(bytes: &[u8], offset: usize) -> ReadResult<usize> {
    Ok(u16::from_le_bytes(span(bytes, offset, 2)?.try_into().map_err(|_| ())?) as usize)
}

fn dword(bytes: &[u8], offset: usize) -> ReadResult<usize> {
    Ok(u32::from_le_bytes(span(bytes, offset, 4)?.try_into().map_err(|_| ())?) as usize)
}

fn span(bytes: &[u8], offset: usize, length: usize) -> ReadResult<&[u8]> {
    bytes
        .get(offset..offset.checked_add(length).ok_or(())?)
        .ok_or(())
}

pub(super) struct VersionFacts {
    pub has_certificate_table: bool,
    pub original_filename: Option<String>,
    pub description: Option<String>,
}

struct Section {
    virtual_address: usize,
    offset: usize,
    length: usize,
}

pub(super) fn image_version(bytes: &[u8]) -> ReadResult<VersionFacts> {
    if !bytes.starts_with(b"MZ") {
        return Err(());
    }
    let pe = dword(bytes, 60)?;
    let coff = bytes
        .get(pe..)
        .and_then(|b| b.strip_prefix(b"PE\0\0"))
        .ok_or(())?;
    let optional_size = word(coff, 16)?;
    let optional = span(coff, 20, optional_size)?;
    let dir = match word(optional, 0)? {
        0x10b => 96,
        0x20b => 112,
        _ => return Err(()),
    };
    let directories = dword(optional, dir - 4)?;
    let data_directory = |index: usize| {
        if directories <= index {
            return Ok((0, 0));
        }
        let offset = dir + index * 8;
        Ok((dword(optional, offset)?, dword(optional, offset + 4)?))
    };
    let (cert_offset, cert_length) = data_directory(4)?;
    let has_certificate_table = cert_offset != 0 || cert_length != 0;
    let size_of_headers = dword(optional, 60)?;
    if has_certificate_table {
        // The certificate table is excluded from Authenticode hashing; no
        // part of the headers or mapped resource sections may overlap it.
        if cert_length == 0 || cert_offset < size_of_headers || cert_offset % 8 != 0 {
            return Err(());
        }
        span(bytes, cert_offset, cert_length)?;
    }
    let section_table = span(coff, 20 + optional_size, 40 * word(coff, 2)?)?;
    let mut sections = Vec::<Section>::new();
    for entry in section_table.as_chunks::<40>().0 {
        let virtual_address = dword(entry, 12)?;
        let length = dword(entry, 16)?;
        let offset = dword(entry, 20)?;
        if length != 0 {
            span(bytes, offset, length)?;
            if offset < size_of_headers || (has_certificate_table && offset + length > cert_offset)
            {
                return Err(());
            }
            sections.push(Section {
                virtual_address,
                offset,
                length,
            });
        }
    }
    sections.sort_unstable_by_key(|section| section.offset);
    if sections
        .windows(2)
        .any(|pair| pair[0].offset + pair[0].length > pair[1].offset)
    {
        return Err(());
    }
    let translate = |address: usize, length: usize| -> ReadResult<&[u8]> {
        let mut candidates = sections.iter().filter_map(|section| {
            let relative = address.checked_sub(section.virtual_address)?;
            (relative.checked_add(length)? <= section.length).then(|| section.offset + relative)
        });
        let offset = candidates.next().ok_or(())?;
        if candidates.next().is_some() {
            return Err(());
        }
        span(bytes, offset, length)
    };
    let (resource, resource_length) = data_directory(2)?;
    let mut facts = VersionFacts {
        has_certificate_table,
        original_filename: None,
        description: None,
    };
    if resource == 0 && resource_length == 0 {
        return Ok(facts);
    }
    let directory = translate(resource, resource_length)?;
    // Invalid or conflicting version data does not provide a program name.
    let mut values = Vec::new();
    if versions(directory, &translate, &mut values).is_ok() {
        facts.original_filename = unanimous(&values, |v| v.0.as_deref());
        facts.description = unanimous(&values, |v| v.1.as_deref());
    }
    Ok(facts)
}

type Strings = (Option<String>, Option<String>);

fn unanimous(values: &[Strings], get: impl Fn(&Strings) -> Option<&str>) -> Option<String> {
    let name = get(values.first()?)?;
    values
        .iter()
        .all(|other| get(other) == Some(name))
        .then(|| name.to_owned())
}

fn entries(directory: &[u8], offset: usize) -> ReadResult<impl Iterator<Item = &[u8; 8]>> {
    let header = span(directory, offset, 16)?;
    let count = word(header, 12)? + word(header, 14)?;
    Ok(span(directory, offset + 16, count * 8)?
        .as_chunks::<8>()
        .0
        .iter())
}

fn versions<'a>(
    directory: &[u8],
    translate: &impl Fn(usize, usize) -> ReadResult<&'a [u8]>,
    values: &mut Vec<Strings>,
) -> ReadResult<()> {
    for kind in entries(directory, 0)? {
        if dword(kind, 0)? != 16 {
            continue;
        }
        let names = subdirectory(kind)?;
        for name in entries(directory, names)? {
            for language in entries(directory, subdirectory(name)?)? {
                let leaf = span(directory, dword(language, 4)?, 16)?;
                let version = translate(dword(leaf, 0)?, dword(leaf, 4)?)?;
                version_strings(version, values)?;
                if values.len() > 256 {
                    return Err(());
                }
            }
        }
    }
    Ok(())
}

fn subdirectory(entry: &[u8]) -> ReadResult<usize> {
    let target = dword(entry, 4)?;
    (target & 0x8000_0000 != 0)
        .then_some(target & 0x7fff_ffff)
        .ok_or(())
}

fn utf16(bytes: &[u8]) -> ReadResult<String> {
    let (units, tail) = bytes.as_chunks::<2>();
    if !tail.is_empty() {
        return Err(());
    }
    let data: Vec<_> = units.iter().copied().map(u16::from_le_bytes).collect();
    if data.contains(&0) {
        return Err(());
    }
    String::from_utf16(&data).map_err(|_| ())
}

fn aligned(offset: usize) -> usize {
    (offset + 3) & !3
}

struct Block<'a> {
    key: String,
    value: &'a [u8],
    children: &'a [u8],
}

fn block(bytes: &[u8]) -> ReadResult<(Block<'_>, &[u8])> {
    let length = word(bytes, 0)?;
    let bytes_in_block = span(bytes, 0, length)?;
    let kind = word(bytes_in_block, 4)?;
    let value_size = word(bytes_in_block, 2)? * if kind == 1 { 2 } else { 1 };
    let key_bytes = bytes_in_block.get(6..).ok_or(())?;
    let key_len = 2 * key_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .position(|pair| *pair == [0, 0])
        .ok_or(())?;
    let key = utf16(span(key_bytes, 0, key_len)?)?;
    let value_offset = aligned(6 + key_len + 2).min(length);
    let value = span(bytes_in_block, value_offset, value_size)?;
    let children = &bytes_in_block[aligned(value_offset + value_size).min(length)..];
    Ok((
        Block {
            key,
            value,
            children,
        },
        &bytes[aligned(length).min(bytes.len())..],
    ))
}

fn children(mut bytes: &[u8], mut each: impl FnMut(Block<'_>) -> ReadResult<()>) -> ReadResult<()> {
    while bytes.len() >= 6 {
        let (child, rest) = block(bytes)?;
        each(child)?;
        bytes = rest;
    }
    Ok(())
}

fn version_strings(bytes: &[u8], values: &mut Vec<Strings>) -> ReadResult<()> {
    let (root, _) = block(bytes)?;
    if root.key != "VS_VERSION_INFO" {
        return Err(());
    }
    let start = values.len();
    children(root.children, |group| {
        if group.key != "StringFileInfo" {
            return Ok(());
        }
        children(group.children, |table| {
            let (mut original, mut description) = (None, None);
            children(table.children, |entry| {
                let slot = match entry.key.as_str() {
                    "OriginalFilename" => &mut original,
                    "FileDescription" => &mut description,
                    _ => return Ok(()),
                };
                let value = utf16(entry.value.strip_suffix(&[0, 0]).ok_or(())?)?;
                if slot.replace(value).is_some() {
                    return Err(());
                }
                Ok(())
            })?;
            values.push((
                original.filter(|value| !value.trim().is_empty()),
                description.filter(|value| !value.trim().is_empty()),
            ));
            if values.len() > 256 {
                return Err(());
            }
            Ok(())
        })
    })?;
    if values.len() == start {
        values.push((None, None));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn set32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn make_block(name: &str, text: &str, children: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0; 6];
        for ch in name.encode_utf16().chain([0]) {
            bytes.extend(ch.to_le_bytes());
        }
        bytes.resize(aligned(bytes.len()), 0);
        set16(&mut bytes, 4, 1);
        if !text.is_empty() {
            set16(&mut bytes, 2, (text.encode_utf16().count() + 1) as u16);
            for ch in text.encode_utf16().chain([0]) {
                bytes.extend(ch.to_le_bytes());
            }
        }
        for child in children {
            bytes.resize(aligned(bytes.len()), 0);
            bytes.extend(child);
        }
        let size = bytes.len() as u16;
        set16(&mut bytes, 0, size);
        bytes
    }

    fn version_image(originals: &[&str]) -> Vec<u8> {
        let tables: Vec<_> = originals
            .iter()
            .enumerate()
            .map(|(i, name)| {
                make_block(
                    &format!("{i:08X}"),
                    "",
                    &[
                        make_block("OriginalFilename", name, &[]),
                        make_block("FileDescription", "Fixture", &[]),
                    ],
                )
            })
            .collect();
        let version = make_block(
            "VS_VERSION_INFO",
            "",
            &[make_block("StringFileInfo", "", &tables)],
        );
        let mut bytes = vec![0; 2048];
        bytes[..2].copy_from_slice(b"MZ");
        set32(&mut bytes, 60, 64);
        bytes[64..68].copy_from_slice(b"PE\0\0");
        set16(&mut bytes, 70, 1);
        set16(&mut bytes, 84, 224);
        let opt = 88;
        set16(&mut bytes, opt, 0x10b);
        set32(&mut bytes, opt + 60, 512);
        set32(&mut bytes, opt + 92, 16);
        set32(&mut bytes, opt + 112, 4096);
        set32(&mut bytes, opt + 116, 1536);
        let section = opt + 224;
        set32(&mut bytes, section + 12, 4096);
        set32(&mut bytes, section + 16, 1536);
        set32(&mut bytes, section + 20, 512);
        let resource = &mut bytes[512..];
        set16(resource, 14, 1);
        set32(resource, 16, 16);
        set32(resource, 20, 0x8000_0018);
        set16(resource, 38, 1);
        set32(resource, 40, 1);
        set32(resource, 44, 0x8000_0030);
        set16(resource, 62, 1);
        set32(resource, 64, 0x409);
        set32(resource, 68, 72);
        set32(resource, 72, 4096 + 88);
        set32(resource, 76, version.len() as u32);
        resource[88..88 + version.len()].copy_from_slice(&version);
        bytes
    }

    #[test]
    fn original_filename_comes_from_the_images_version_tables() {
        let found = image_version(&version_image(&["Fixture.exe", "Fixture.exe"])).unwrap();
        assert!(!found.has_certificate_table);
        assert_eq!(found.original_filename.as_deref(), Some("Fixture.exe"));
        assert_eq!(found.description.as_deref(), Some("Fixture"));
        assert_eq!(
            image_version(&version_image(&["Fixture.exe", "Other.exe"]))
                .unwrap()
                .original_filename,
            None
        );
        assert_eq!(
            image_version(&version_image(&[]))
                .unwrap()
                .original_filename,
            None
        );
    }

    #[test]
    fn a_certificate_table_cannot_supply_unsigned_version_bytes() {
        let mut bytes = version_image(&["Fixture.exe"]);
        set32(&mut bytes, 88 + 96 + 32, 600);
        set32(&mut bytes, 88 + 96 + 36, 512);
        assert!(image_version(&bytes).is_err());
    }
}
