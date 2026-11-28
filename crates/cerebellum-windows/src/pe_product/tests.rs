use super::*;

fn block(key: &str, text: bool, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 6];
    b.extend(key.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    b.resize(align4(b.len()), 0);
    b.extend(value);
    for child in children {
        b.resize(align4(b.len()), 0);
        b.extend(child);
    }
    let len = b.len() as u16;
    b[0..2].copy_from_slice(&len.to_le_bytes());
    b[2..4].copy_from_slice(&((value.len() / if text { 2 } else { 1 }) as u16).to_le_bytes());
    b[4] = u8::from(text);
    b
}

fn product(name: &str) -> Vec<u8> {
    let value: Vec<u8> = name
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    block("ProductName", true, &value, &[])
}

fn version(products: &[Vec<u8>]) -> Vec<u8> {
    let table = block("040904b0", true, &[], products);
    let strings = block("StringFileInfo", true, &[], &[table]);
    let mut fixed = [0; 52];
    for (offset, value) in [
        (0, 0xfeef_04bdu32),
        (8, (143 << 16) | 1),
        (12, (55 << 16) | 706),
        (16, 123),
        (20, 456),
    ] {
        fixed[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    block("VS_VERSION_INFO", false, &fixed, &[strings])
}

#[test]
fn reads_product_name_without_normalizing_and_reports_ambiguous_metadata() {
    for name in [
        "Google Chrome",
        "Google Chrome Beta",
        "google chrome",
        "Google Chrome\0extra",
        "",
    ] {
        assert_eq!(
            version_strings(&version(&[product(name)])),
            Some(vec![name.to_owned()])
        );
    }
    let duplicate = version(&[product("Google Chrome"), product("Google Chrome")]);
    assert_eq!(version_strings(&duplicate), None);
}

pub(crate) fn fixture_versioned_image() -> Vec<u8> {
    fn set(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut image = vec![0; 0x608];
    let version = version(&[product("Google Chrome")]);
    let resource = &mut image[0x400..0x600];
    for (offset, id, value) in [
        (0, 16, DIRECTORY | 24),
        (24, 1, DIRECTORY | 48),
        (48, 1033, 72),
    ] {
        resource[offset + 14] = 1;
        set(resource, offset + 16, id);
        set(resource, offset + 20, value);
    }
    set(resource, 72, 0x1000 + 88);
    set(resource, 76, version.len() as u32);
    resource[88..88 + version.len()].copy_from_slice(&version);
    image[..2].copy_from_slice(b"MZ");
    set(&mut image, 60, 64);
    image[64..68].copy_from_slice(b"PE\0\0");
    image[70] = 1;
    image[84] = 0xf0;
    let optional = 88;
    set(&mut image, optional, 0x20b);
    set(&mut image, optional + 60, 0x400);
    set(&mut image, optional + 108, 16);
    set(&mut image, optional + 128, 0x1000);
    set(&mut image, optional + 132, 0x200);
    set(&mut image, optional + 144, 0x600);
    set(&mut image, optional + 148, 8);
    let section = optional + 0xf0;
    set(&mut image, section + 8, 0x200);
    set(&mut image, section + 12, 0x1000);
    set(&mut image, section + 16, 0x200);
    set(&mut image, section + 20, 0x400);
    image
}

fn read_image(image: &[u8]) -> impl FnMut(u64, &mut [u8]) -> std::io::Result<()> + '_ {
    |offset, buf| {
        let i = offset as usize;
        let bytes = image
            .get(i..i + buf.len())
            .ok_or(std::io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn reads_product_from_resource_section_not_certificate_table() {
    let mut image = fixture_versioned_image();
    let check = |image: &[u8]| read_product_names(read_image(image));
    assert_eq!(check(&image), Some(vec!["Google Chrome".into()]));
    assert_eq!(check(&image[..0x5ff]), None);
    image[232..236].copy_from_slice(&0x450u32.to_le_bytes());
    assert_eq!(check(&image), None);
}

#[test]
fn uses_the_fixed_file_version_not_the_product_version() {
    let mut image = fixture_versioned_image();
    assert_eq!(
        read_file_version(read_image(&image)),
        Some([143, 1, 55, 706])
    );
    image[0x400 + 88 + 40] ^= 1; // Corrupt the VS_FIXEDFILEINFO signature.
    assert_eq!(read_file_version(read_image(&image)), None);
}
