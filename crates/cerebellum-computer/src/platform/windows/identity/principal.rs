//! The Windows grant principal is distinct from any particular live process.

use std::fmt::{self, Write};
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Principal {
    Signed {
        root: [u8; 32],
        cn: String,
        organization: String,
        program: String,
    },
    Packaged {
        family: String,
        application: String,
    },
    Unsigned {
        sha256: [u8; 32],
        image_name: String,
    },
}

impl Principal {
    pub fn executable(&self) -> Option<&str> {
        match self {
            Self::Signed { program, .. } => Some(program),
            Self::Unsigned { image_name, .. } => Some(image_name),
            Self::Packaged { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPrincipal;

impl fmt::Display for InvalidPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a canonical Windows principal")
    }
}

impl std::error::Error for InvalidPrincipal {}

fn field(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    for ch in value.chars() {
        if matches!(ch, '%' | '/' | '\\' | ':' | ';' | '!') || ch.is_control() {
            for byte in ch.encode_utf8(&mut [0; 4]).as_bytes() {
                write!(f, "%{byte:02X}")?;
            }
        } else {
            f.write_char(ch)?;
        }
    }
    Ok(())
}

fn hex(f: &mut fmt::Formatter<'_>, digest: &[u8; 32]) -> fmt::Result {
    for byte in digest {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed {
                root,
                cn,
                organization,
                program,
            } => {
                f.write_str("win-signed:")?;
                hex(f, root)?;
                f.write_str(":CN=")?;
                field(f, cn)?;
                f.write_str(";O=")?;
                field(f, organization)?;
                f.write_char('/')?;
                field(f, program)
            }
            Self::Packaged {
                family,
                application,
            } => {
                f.write_str("win-package:")?;
                field(f, family)?;
                f.write_char('!')?;
                field(f, application)
            }
            Self::Unsigned { sha256, image_name } => {
                f.write_str("win-unsigned:")?;
                hex(f, sha256)?;
                f.write_char('/')?;
                field(f, image_name)
            }
        }
    }
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn byte(pair: &[u8]) -> Option<u8> {
    let [hi, lo] = pair else { return None };
    Some(nibble(*hi)? * 16 + nibble(*lo)?)
}

fn digest(encoded: &str) -> Option<[u8; 32]> {
    let mut digest = [0; 32];
    if encoded.len() != 2 * digest.len() {
        return None;
    }
    for (dst, pair) in digest.iter_mut().zip(encoded.as_bytes().as_chunks::<2>().0) {
        *dst = byte(pair)?;
    }
    Some(digest)
}

fn unescape(encoded: &str) -> Option<String> {
    let mut input = encoded.as_bytes().iter();
    let mut output = Vec::new();
    while let Some(&ch) = input.next() {
        output.push(if ch == b'%' {
            byte(&[*input.next()?, *input.next()?])?
        } else {
            ch
        });
    }
    String::from_utf8(output).ok()
}

impl FromStr for Principal {
    type Err = InvalidPrincipal;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        fn parse(value: &str) -> Option<Principal> {
            let (tier, body) = value.split_once(':')?;
            Some(match tier {
                "win-signed" => {
                    let (root, rest) = body.split_once(":CN=")?;
                    let (subject, program) = rest.split_once('/')?;
                    let (cn, organization) = subject.split_once(";O=")?;
                    if (cn.is_empty() && organization.is_empty()) || program.is_empty() {
                        return None;
                    }
                    Principal::Signed {
                        root: digest(root)?,
                        cn: unescape(cn)?,
                        organization: unescape(organization)?,
                        program: unescape(program)?,
                    }
                }
                "win-package" => {
                    let (family, application) = body.split_once('!')?;
                    if family.is_empty() || application.is_empty() {
                        return None;
                    }
                    Principal::Packaged {
                        family: unescape(family)?,
                        application: unescape(application)?,
                    }
                }
                "win-unsigned" => {
                    let (sha256, image_name) = body.split_once('/')?;
                    if image_name.is_empty() {
                        return None;
                    }
                    Principal::Unsigned {
                        sha256: digest(sha256)?,
                        image_name: unescape(image_name)?,
                    }
                }
                _ => return None,
            })
        }

        let principal = parse(value).ok_or(InvalidPrincipal)?;
        (principal.to_string() == value)
            .then_some(principal)
            .ok_or(InvalidPrincipal)
    }
}

/// These image names are never principals even when the signature is valid.
pub fn shell_image(name: &str) -> bool {
    [
        "explorer.exe",
        "ApplicationFrameHost.exe",
        "StartMenuExperienceHost.exe",
        "ShellExperienceHost.exe",
    ]
    .iter()
    .any(|shell| name.eq_ignore_ascii_case(shell))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tiers_round_trip_encoded_fields() {
        let field = "Å%/\\:;!\n\u{85}".to_owned();
        for principal in [
            Principal::Signed {
                root: [0xaf; 32],
                cn: field.clone(),
                organization: field.clone(),
                program: field.clone(),
            },
            Principal::Packaged {
                family: field.clone(),
                application: field.clone(),
            },
            Principal::Unsigned {
                sha256: [0x10; 32],
                image_name: field,
            },
        ] {
            let encoded = principal.to_string();
            assert!(
                encoded.contains("Å%25%2F%5C%3A%3B%21%0A%C2%85"),
                "{encoded}"
            );
            assert_eq!(encoded.parse(), Ok(principal));
            assert!(encoded.replace("%2F", "%2f").parse::<Principal>().is_err());
            assert!(encoded.replace("%2F", "/").parse::<Principal>().is_err());
        }
    }
}
