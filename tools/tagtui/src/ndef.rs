//! NDEF messages and records (NFC Forum NDEF 1.0). Independent of the tag
//! type: a Type 2 tag stores the message in a TLV, an NTAG 424 DNA in its
//! NDEF file, and both hold the same bytes.

/// One record, with its header already taken apart.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// Type name format: 0 empty, 1 well-known, 2 MIME, 3 absolute URI,
    /// 4 external, 5 unknown, 6 unchanged (chunk continuation).
    pub tnf: u8,
    pub record_type: Vec<u8>,
    pub payload: Vec<u8>,
    /// ME flag: the last record of the message.
    pub last: bool,
    /// CF flag: the payload continues in the next record.
    pub chunked: bool,
}

/// Parse the record at the start of `msg`. Returns it and the number of
/// bytes it took, so the caller can step to the next one.
pub fn parse_record(msg: &[u8]) -> Result<(Record, usize), &'static str> {
    let &flags = msg.first().ok_or("empty message")?;
    let short = flags & 0x10 != 0;
    let has_id = flags & 0x08 != 0;
    let type_len = *msg.get(1).ok_or("no type length")? as usize;
    let (payload_len, mut p) = if short {
        (*msg.get(2).ok_or("no payload length")? as usize, 3)
    } else {
        let n = msg.get(2..6).ok_or("no payload length")?;
        (u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize, 6)
    };
    let id_len = if has_id {
        let n = *msg.get(p).ok_or("no id length")? as usize;
        p += 1;
        n
    } else {
        0
    };
    let record_type = msg.get(p..p + type_len).ok_or("type truncated")?.to_vec();
    p += type_len + id_len;
    let payload = msg
        .get(p..p + payload_len)
        .ok_or("payload truncated")?
        .to_vec();
    let record = Record {
        tnf: flags & 0x07,
        record_type,
        payload,
        last: flags & 0x40 != 0,
        chunked: flags & 0x20 != 0,
    };
    Ok((record, p + payload_len))
}

/// Every record of a message, in order, up to the one flagged last.
pub fn records(msg: &[u8]) -> Result<Vec<Record>, &'static str> {
    let mut out = Vec::new();
    let mut rest = msg;
    loop {
        let (r, used) = parse_record(rest)?;
        if r.chunked {
            return Err("chunked records are not supported");
        }
        let last = r.last;
        out.push(r);
        rest = &rest[used..];
        if last || rest.is_empty() {
            return Ok(out);
        }
    }
}

/// One line describing a record. Types without a decoder are named.
pub fn describe(r: &Record) -> String {
    let p = &r.payload;
    match (r.tnf, r.record_type.as_slice()) {
        (0x01, b"U") if !p.is_empty() => {
            format!("URL  {}{}", uri_prefix(p[0]), String::from_utf8_lossy(&p[1..]))
        }
        (0x01, b"T") if !p.is_empty() => text(p),
        _ => format!(
            "record TNF {}, type {:?}, {} bytes",
            r.tnf,
            String::from_utf8_lossy(&r.record_type),
            p.len()
        ),
    }
}

/// Text RTD: status byte (bit 7 UTF-16, bits 0-5 language code length),
/// the IANA language code, then the text.
fn text(p: &[u8]) -> String {
    let lang_len = (p[0] & 0x3F) as usize;
    let lang = String::from_utf8_lossy(p.get(1..1 + lang_len).unwrap_or(&[])).into_owned();
    let body = p.get(1 + lang_len..).unwrap_or(&[]);
    let text = if p[0] & 0x80 != 0 {
        utf16(body)
    } else {
        String::from_utf8_lossy(body).into_owned()
    };
    if lang.is_empty() {
        format!("text  {text}")
    } else {
        format!("text [{lang}]  {text}")
    }
}

/// UTF-16, big-endian unless a byte order mark says otherwise.
fn utf16(b: &[u8]) -> String {
    let (little, b) = match b {
        [0xFF, 0xFE, rest @ ..] => (true, rest),
        [0xFE, 0xFF, rest @ ..] => (false, rest),
        _ => (false, b),
    };
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| if little { u16::from_le_bytes(pair) } else { u16::from_be_bytes(pair) })
        .collect();
    String::from_utf16_lossy(&units)
}

/// NFC Forum URI record prefix codes (URI RTD, table 3). Codes past the
/// table are reserved and treated as "no prefix".
const URI_PREFIXES: [&str; 36] = [
    "",
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    "tel:",
    "mailto:",
    "ftp://anonymous:anonymous@",
    "ftp://ftp.",
    "ftps://",
    "sftp://",
    "smb://",
    "nfs://",
    "ftp://",
    "dav://",
    "news:",
    "telnet://",
    "imap:",
    "rtsp://",
    "urn:",
    "pop:",
    "sip:",
    "sips:",
    "tftp:",
    "btspp://",
    "btl2cap://",
    "btgoep://",
    "tcpobex://",
    "irdaobex://",
    "file://",
    "urn:epc:id:",
    "urn:epc:tag:",
    "urn:epc:pat:",
    "urn:epc:raw:",
    "urn:epc:",
    "urn:nfc:",
];

pub fn uri_prefix(code: u8) -> &'static str {
    URI_PREFIXES.get(code as usize).copied().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_record_header() {
        // MB|ME|SR, well-known, type "U", payload 04 "a.b"
        let msg = [0xD1, 0x01, 0x04, b'U', 0x04, b'a', b'.', b'b'];
        let (r, used) = parse_record(&msg).unwrap();
        assert_eq!(
            (r.tnf, r.record_type.as_slice(), r.last, used),
            (1, b"U".as_slice(), true, 8)
        );
        assert_eq!(r.payload, [0x04, b'a', b'.', b'b']);
    }

    #[test]
    fn long_record_and_id() {
        // MB|ME|IL (no SR): 4-byte payload length, then an id
        let msg = [
            0xC9, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, b'T', b'i', b'd', 0x42,
        ];
        let (r, used) = parse_record(&msg).unwrap();
        assert_eq!(
            (r.record_type.as_slice(), r.payload.as_slice(), used),
            (b"T".as_slice(), [0x42].as_slice(), 11)
        );
    }

    #[test]
    fn walks_every_record() {
        // URI record (MB), then a text record (ME)
        let msg = [
            0x91, 0x01, 0x04, b'U', 0x04, b'a', b'.', b'b', //
            0x51, 0x01, 0x04, b'T', 0x02, b'e', b'n', b'h',
        ];
        let lines: Vec<String> = records(&msg).unwrap().iter().map(describe).collect();
        assert_eq!(lines, ["URL  https://a.b", "text [en]  h"]);
    }

    #[test]
    fn chunked_records_are_refused() {
        assert_eq!(records(&[0xB1, 0x01, 0x01, b'U', 0x04]), Err("chunked records are not supported"));
    }

    #[test]
    fn text_encodings() {
        // UTF-8 with a language code: "koń" (ń = C5 84)
        assert_eq!(text(&[0x02, b'p', b'l', b'k', b'o', 0xC5, 0x84]), "text [pl]  ko\u{144}");
        // UTF-16 big-endian, no language code
        assert_eq!(text(&[0x80, 0x00, b'h', 0x00, b'i']), "text  hi");
        // UTF-16 with a little-endian byte order mark
        assert_eq!(text(&[0x82, b'e', b'n', 0xFF, 0xFE, 0x1F, 0x01]), "text [en]  \u{11F}");
    }

    #[test]
    fn uri_prefixes() {
        assert_eq!(uri_prefix(0x00), "");
        assert_eq!(uri_prefix(0x04), "https://");
        assert_eq!(uri_prefix(0x15), "sip:");
        assert_eq!(uri_prefix(0x23), "urn:nfc:");
        assert_eq!(uri_prefix(0x24), "", "reserved codes add nothing");
    }

    #[test]
    fn truncated() {
        assert_eq!(
            parse_record(&[0xD1, 0x01, 0x09, b'U', 0x04]),
            Err("payload truncated")
        );
        assert_eq!(parse_record(&[]), Err("empty message"));
    }
}
