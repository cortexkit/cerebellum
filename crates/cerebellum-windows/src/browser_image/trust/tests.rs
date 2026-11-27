use super::*;

#[test]
fn crypt32_reads_subject_common_name_and_organization() {
    // X.509 Name with the common name in UTF8String and organization in PrintableString.
    let encoded = b"\x30\x2a\x31\x13\x30\x11\x06\x03\x55\x04\x03\x0c\x0aGoogle LLC\x31\x13\x30\x11\x06\x03\x55\x04\x0a\x13\x0aGoogle LLC";
    let subject = read_distinguished_name(encoded).unwrap();
    assert_eq!(subject.common_names, ["Google LLC"]);
    assert_eq!(subject.organizations, ["Google LLC"]);
    let mut other = *encoded;
    other[13] = b'g';
    assert_eq!(
        read_distinguished_name(&other).unwrap().common_names,
        ["google LLC"]
    );
    other[31] = 0x0b; // The organization becomes an organizational unit.
    assert!(read_distinguished_name(&other)
        .unwrap()
        .organizations
        .is_empty());
    assert!(matches!(
        read_distinguished_name(&encoded[1..]),
        Err(ImageReadError::SubjectDecode(_))
    ));
}
