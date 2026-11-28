//! Read version strings directly from the image handle. Windows' path-based
//! version APIs can reopen the file and merge externally stored multilingual
//! user interface strings.

const MAX_RESOURCE_BYTES: usize = 4 * 1024 * 1024;
const RT_VERSION: u32 = 16;
const DIRECTORY: u32 = 1 << 31;

pub(crate) fn read_product_names(
    read_at: impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
) -> Option<Vec<String>> {
    version_values(read_at, version_strings)
}

pub(crate) fn read_file_version(
    read_at: impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
) -> Option<[u16; 4]> {
    let versions = version_values(read_at, fixed_file_version)?;
    let first = *versions.first()?;
    versions
        .iter()
        .all(|version| *version == first)
        .then_some(first)
}

fn fixed_file_version(buf: &[u8]) -> Option<Vec<[u16; 4]>> {
    let root = Block::read(buf)?;
    if !wide_eq(root.key, "VS_VERSION_INFO")
        || root.text
        || root.value.len() != 52
        || u32_at(root.value, 0)? != 0xfeef_04bd
    {
        return None;
    }
    // VS_FIXEDFILEINFO has separate file and product versions. Chrome's
    // sibling directory is named by the four components of the file version.
    Some(vec![[
        u16_at(root.value, 10)?,
        u16_at(root.value, 8)?,
        u16_at(root.value, 14)?,
        u16_at(root.value, 12)?,
    ]])
}

fn resource_table(
    read_at: &mut impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
) -> Option<(Vec<u8>, u32)> {
    let mut dos = [0; 64];
    read_at(0, &mut dos).ok()?;
    if &dos[..2] != b"MZ" {
        return None;
    }
    let pe_offset = u64::from(u32_at(&dos, 60)?);
    let mut pe = [0; 24];
    read_at(pe_offset, &mut pe).ok()?;
    if &pe[..4] != b"PE\0\0" {
        return None;
    }
    let sections = usize::from(u16_at(&pe, 6)?);
    // The PE loader limits images to 96 sections.
    if !(1..=96).contains(&sections) {
        return None;
    }
    let mut optional = vec![0; usize::from(u16_at(&pe, 20)?)];
    read_at(pe_offset + 24, &mut optional).ok()?;
    let directory = match u16_at(&optional, 0)? {
        0x10b => 96,  // PE32
        0x20b => 112, // PE32+
        _ => return None,
    };
    if u32_at(&optional, directory - 4)? < 5 {
        return None;
    }
    let header_size = u64::from(u32_at(&optional, 60)?);
    let rva = u32_at(&optional, directory + 16)?;
    let length = u32_at(&optional, directory + 20)?;
    // Unlike other data directories, the certificate uses a file offset, not
    // a relative virtual address. ProductName must be inside a hashed section
    // and outside the certificate table, which Authenticode does not hash.
    let cert_offset = u64::from(u32_at(&optional, directory + 32)?);
    let cert_size = u32_at(&optional, directory + 36)?;
    if rva == 0 || length as usize > MAX_RESOURCE_BYTES || length < 16 || cert_size < 8 {
        return None;
    }

    let section_offset = pe_offset + 24 + optional.len() as u64;
    let mut headers = vec![0; sections * 40];
    if section_offset + headers.len() as u64 > header_size {
        return None;
    }
    read_at(section_offset, &mut headers).ok()?;
    let mut found = None;
    for section in headers.as_chunks::<40>().0 {
        let va = u32_at(section, 12)?;
        let raw_size = u32_at(section, 16)?;
        let raw = u64::from(u32_at(section, 20)?);
        let Some(delta) = rva.checked_sub(va) else {
            continue;
        };
        if delta >= u32_at(section, 8)?.max(raw_size) {
            continue;
        }
        if found.is_some()
            || delta.checked_add(length)? > raw_size
            || raw < header_size
            || raw + u64::from(raw_size) > cert_offset
        {
            return None;
        }
        found = Some(raw + u64::from(delta));
    }
    let mut table = vec![0; length as usize];
    read_at(found?, &mut table).ok()?;
    Some((table, rva))
}

fn version_values<T>(
    mut read_at: impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
    mut values_in_resource: impl FnMut(&[u8]) -> Option<Vec<T>>,
) -> Option<Vec<T>> {
    let (table, rva) = resource_table(&mut read_at)?;
    let mut versions = directory_entries(&table, 0)?.filter(|&(id, _)| id == RT_VERSION);
    let version = versions.next()?.1;
    if versions.next().is_some() {
        return None;
    }
    let mut names = 0;
    let mut resources = 0;
    let mut values = Vec::new();
    for (_, name) in directory_entries(&table, directory_offset(version)?)? {
        names += 1;
        if names > 64 {
            return None;
        }
        for (_, lang) in directory_entries(&table, directory_offset(name)?)? {
            resources += 1;
            if resources > 64 || lang & DIRECTORY != 0 {
                return None;
            }
            let entry = lang as usize;
            let start = u32_at(&table, entry)?.checked_sub(rva)? as usize;
            let size = u32_at(&table, entry + 4)? as usize;
            values.extend(values_in_resource(
                table.get(start..start.checked_add(size)?)?,
            )?);
        }
    }
    (!values.is_empty()).then_some(values)
}

fn directory_offset(entry: u32) -> Option<usize> {
    (entry & DIRECTORY != 0).then_some((entry & !DIRECTORY) as usize)
}

fn directory_entries(table: &[u8], offset: usize) -> Option<impl Iterator<Item = (u32, u32)> + '_> {
    let count = usize::from(u16_at(table, offset + 12)?) + usize::from(u16_at(table, offset + 14)?);
    let start = offset + 16;
    Some(
        table
            .get(start..start.checked_add(count * 8)?)?
            .as_chunks::<8>()
            .0
            .iter()
            .map(|entry| {
                let (id, value) = entry.split_at(4);
                (
                    u32::from_le_bytes(id.try_into().unwrap()),
                    u32::from_le_bytes(value.try_into().unwrap()),
                )
            }),
    )
}

fn version_strings(buf: &[u8]) -> Option<Vec<String>> {
    let root = Block::read(buf)?;
    if !wide_eq(root.key, "VS_VERSION_INFO") {
        return None;
    }
    let mut products = Vec::new();
    for child in root.children() {
        let child = child?;
        if !wide_eq(child.key, "StringFileInfo") {
            continue;
        }
        for locale in child.children() {
            let mut product = None;
            for string in locale?.children() {
                let string = string?;
                if wide_eq(string.key, "ProductName") {
                    if product.is_some() || !string.text {
                        return None;
                    }
                    let text = string.value.strip_suffix(&[0, 0])?;
                    let units: Vec<u16> = text
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .copied()
                        .map(u16::from_le_bytes)
                        .collect();
                    product = Some(String::from_utf16(&units).ok()?);
                }
            }
            products.push(product?);
        }
    }
    (!products.is_empty()).then_some(products)
}

struct Block<'a> {
    len: usize,
    key: &'a [u8],
    text: bool,
    value: &'a [u8],
    rest: &'a [u8],
}

impl<'a> Block<'a> {
    fn read(buf: &'a [u8]) -> Option<Self> {
        let len = usize::from(u16_at(buf, 0)?);
        let buf = buf.get(..len)?;
        let value_len = usize::from(u16_at(buf, 2)?);
        let text = match u16_at(buf, 4)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let key_end = 6 + 2 * buf
            .get(6..)?
            .as_chunks::<2>()
            .0
            .iter()
            .position(|unit| *unit == [0, 0])?;
        let start = align4(key_end + 2).min(len);
        let end = start + if text { value_len * 2 } else { value_len };
        Some(Self {
            len,
            key: &buf[6..key_end],
            text,
            value: buf.get(start..end)?,
            rest: &buf[align4(end).min(len)..],
        })
    }

    fn children(&self) -> impl Iterator<Item = Option<Block<'a>>> {
        let mut rest = self.rest;
        std::iter::from_fn(move || {
            if rest.len() < 4 && rest.iter().all(|&b| b == 0) {
                return None;
            }
            let child = Block::read(rest);
            rest = child
                .as_ref()
                .map_or(&[], |block| &rest[align4(block.len).min(rest.len())..]);
            Some(child)
        })
    }
}

fn align4(offset: usize) -> usize {
    (offset + 3) & !3
}

fn wide_eq(bytes: &[u8], expected: &str) -> bool {
    bytes
        .iter()
        .copied()
        .eq(expected.encode_utf16().flat_map(u16::to_le_bytes))
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
pub(crate) mod tests;
