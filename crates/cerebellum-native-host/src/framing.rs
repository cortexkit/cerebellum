use std::io::{self, Read, Write};

// Chrome permits larger incoming messages, but frames on the local cerebellum
// socket have a 16 MiB limit. The browser extension and cerebellum split large
// action results into chunks; the host only translates framing.
pub(crate) const MAX_CHROME_TO_HOST_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_HOST_TO_CHROME_BYTES: usize = 1024 * 1024;

pub(crate) fn read_native_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    read_frame(reader, MAX_CHROME_TO_HOST_BYTES, u32::from_ne_bytes)
}

pub(crate) fn write_native_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    write_frame(writer, bytes, MAX_HOST_TO_CHROME_BYTES, u32::to_ne_bytes)
}

pub(crate) fn read_frame(
    reader: &mut impl Read,
    limit: usize,
    decode: fn([u8; 4]) -> u32,
) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0; 4];
    // EOF is clean only between frames, never partway through the prefix.
    loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut prefix[1..])?;
    let length = decode(prefix) as usize;
    if length == 0 || length > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame size"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

pub(crate) fn write_frame(
    writer: &mut impl Write,
    bytes: &[u8],
    limit: usize,
    encode: fn(u32) -> [u8; 4],
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame size"));
    }
    writer.write_all(&encode(bytes.len() as u32))?;
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn chrome_frame_uses_native_endian_and_preserves_bytes() {
        let json = br#" { "text": "hello", "value": 1 } "#;
        let mut wire = Vec::new();
        write_native_frame(&mut wire, json).unwrap();
        assert_eq!(&wire[..4], &(json.len() as u32).to_ne_bytes());
        assert_eq!(&wire[4..], json);
        let mut wire = Cursor::new(wire);
        assert_eq!(read_native_frame(&mut wire).unwrap().unwrap(), json);
        assert!(read_native_frame(&mut wire).unwrap().is_none());
    }

    #[test]
    fn partial_prefix_and_body_are_not_clean_eof() {
        for length in 1..4 {
            let bytes = [1, 0, 0, 0];
            assert_eq!(
                read_native_frame(&mut &bytes[..length]).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        assert_eq!(
            read_native_frame(&mut &4_u32.to_ne_bytes()[..])
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn invalid_sizes_are_rejected_before_body_allocation_or_writes() {
        for size in [0, MAX_CHROME_TO_HOST_BYTES as u32 + 1, u32::MAX] {
            assert_eq!(
                read_native_frame(&mut &size.to_ne_bytes()[..])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut output = Vec::new();
        assert!(write_native_frame(&mut output, &[]).is_err());
        assert!(write_native_frame(&mut output, &vec![0; MAX_HOST_TO_CHROME_BYTES + 1]).is_err());
        assert!(output.is_empty());
        write_native_frame(&mut output, &vec![0; MAX_HOST_TO_CHROME_BYTES]).unwrap();
        assert_eq!(output.len(), MAX_HOST_TO_CHROME_BYTES + 4);
    }
}
