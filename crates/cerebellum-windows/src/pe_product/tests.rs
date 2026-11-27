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
    block("VS_VERSION_INFO", false, &[0; 52], &[strings])
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

#[test]
fn reads_product_from_resource_section_not_certificate_table() {
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
    let check = |image: &[u8]| {
        read_product_names(|offset, buf| {
            let i = offset as usize;
            let bytes = image
                .get(i..i + buf.len())
                .ok_or(std::io::ErrorKind::UnexpectedEof)?;
            buf.copy_from_slice(bytes);
            Ok(())
        })
    };
    assert_eq!(check(&image), Some(vec!["Google Chrome".into()]));
    assert_eq!(check(&image[..0x5ff]), None);
    set(&mut image, optional + 144, 0x450);
    assert_eq!(check(&image), None);
}
