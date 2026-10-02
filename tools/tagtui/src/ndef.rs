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
    };
    Ok((record, p + payload_len))
}

/// NFC Forum URI record prefix codes (the common ones).
pub fn uri_prefix(code: u8) -> &'static str {
    match code {
        0x01 => "http://www.",
        0x02 => "https://www.",
        0x03 => "http://",
        0x04 => "https://",
        0x05 => "tel:",
        0x06 => "mailto:",
        _ => "",
    }
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
    fn truncated() {
        assert_eq!(
            parse_record(&[0xD1, 0x01, 0x09, b'U', 0x04]),
            Err("payload truncated")
        );
        assert_eq!(parse_record(&[]), Err("empty message"));
    }
}
