use core::str;
use std::fmt::Write;

use base64::Engine;

/// escape all control char as octal `\777`, plus `\`, `"`, keep visible utf8 if keep_utf8
pub fn escape_char_octal(ch: char, mut w: impl Write, keep_utf8: bool) -> Result<(), std::fmt::Error> {
    let w = &mut w;
    if ch.is_ascii() {
        if ch.is_control() {
            let b = ch as u8;
            write!(w, "\\{b:03o}")?;
        } else if ch == '\\' || ch == '\"' {
            write!(w, "\\{}", ch)?;
        } else {
            write!(w, "{}", ch)?;
        }
    } else if keep_utf8 && !ch.is_control() {
        write!(w, "{}", ch)?;
    } else {
        for b in ch.to_string().as_bytes() {
            write!(w, "\\{b:03o}")?;
        }
    }
    Ok(())
}

/// escape all control char as octal `\777`, plus `\`, `"`, keep visible utf8 if keep_utf8
pub fn escape_bytes_octal(bytes: &[u8], mut w: impl Write, keep_utf8: bool) -> Result<(), std::fmt::Error> {
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            escape_char_octal(ch, &mut w, keep_utf8)?;
        }
        for byte in chunk.invalid() {
            write!(&mut w, "\\{:03o}", byte)?;
        }
    }
    Ok(())
}

/// 'xy' -> '7879'
pub fn escape_bytes_hex(bytes: &[u8], mut w: impl Write) -> Result<(), std::fmt::Error> {
    for b in bytes {
        write!(w, "{:02x}", b)?;
    }
    Ok(())
}

pub fn escape_bytes_base64<'a>(bytes: &'a [u8], mut w: impl Write) -> Result<(), std::fmt::Error> {
    use base64::{display::Base64Display, engine::general_purpose::STANDARD};

    write!(&mut w, "{}", Base64Display::new(bytes,  &STANDARD))
}

pub fn unescape(value: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;

    if value.starts_with("0s") || value.starts_with("0S") {
        STANDARD.decode(&value[2..]).ok()
    } else if value.starts_with("0x") || value.starts_with("0X") {
        unescape_hex(&value[2..]).ok()
    } else {
        // unescaped by shell
        Some(value.as_bytes().to_vec())
    }
}

fn unescape_octal(value: &str) -> Result<Vec<u8>, ()> {
    let mut out = vec![];
    let mut next = &value[0..];
    while let Some(pos) = next.find(r"\") {
        for b in next[..pos].as_bytes() {
            out.push(*b);
        }
        if &next[pos..pos+2] == r#"\""# {
            out.push('"' as u8);
            next = &next[pos+2..];
        } else if &next[pos..pos+2] == r#"\\"# {
            out.push('\\' as u8);
            next = &next[pos+2..];
        } else {
            let b = u8::from_str_radix(&next[pos+1..pos+4], 8).map_err(|_| ())?;
            out.push(b);
            next = &next[pos+4..];
        }
    }
    for b in next.as_bytes() {
        out.push(*b);
    }
    Ok(out)
}

fn unescape_hex(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 {
        return Err(());
    }
    let bytes = value.as_bytes();
    let pair_count = value.len() / 2;
    let mut out = Vec::with_capacity(pair_count);
    for i in 0..pair_count {
        let idx = i * 2;
        let p = &bytes[idx..idx+2];
        let s = str::from_utf8(p).map_err(|_| ())?;
        let b = u8::from_str_radix(s, 16).map_err(|_| ())?;
        out.push(b);
    }
    Ok(out)
}

#[test]
fn test_unescape() {
    let a = unescape("0x61625c745c6e1b24").unwrap();
    let b = unescape("0sYWJcdFxuGyQ=").unwrap();

    assert_eq!(a, b);
    
    let c = unescape(r#"ab\\t\\n\033$"#).unwrap();
    assert_eq!(a, c);
}

#[test]
fn test_escape() {
    let v = unescape("0x61625c745c6e1b24").unwrap();

    let mut repr = String::new();
    escape_bytes_hex(v.as_slice(), &mut repr).unwrap();
    assert_eq!("61625c745c6e1b24", repr);

    let mut repr = String::new();
    escape_bytes_base64(v.as_slice(), &mut repr).unwrap();
    assert_eq!("YWJcdFxuGyQ=", repr);

    let mut repr = String::new();
    escape_bytes_octal(v.as_slice(), &mut repr, false).unwrap();
    assert_eq!(r#"ab\\t\\n\033$"#, repr);
}
