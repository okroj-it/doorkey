//! NFC Forum Type 2 tags (NTAG21x, MIFARE Ultralight and their clones):
//! decoding what the read-only commands return. No reader access here, so
//! everything is unit-testable against real dumps.
//!
//! Memory is 4-byte pages. Pages 0-2 hold the UID, its check bytes and the
//! static lock bytes; page 3 is the capability container; user memory with
//! the TLVs (and the NDEF message) starts at page 4.

/// GET_VERSION (0x60), when the chip answers it. Genuine NTAG21x and
/// Ultralight EV1 do; the original Ultralight and many clones do not.
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    pub vendor: u8,
    pub product_type: u8,
    pub storage: u8,
}

impl Version {
    pub fn parse(b: &[u8]) -> Option<Self> {
        (b.len() >= 8 && b[0] == 0x00).then(|| Version {
            vendor: b[1],
            product_type: b[2],
            storage: b[6],
        })
    }

    pub fn model(&self) -> String {
        let name = match (self.product_type, self.storage) {
            (0x04, 0x0B) => "NTAG210",
            (0x04, 0x0E) => "NTAG212",
            (0x04, 0x0F) => "NTAG213",
            (0x04, 0x11) => "NTAG215",
            (0x04, 0x13) => "NTAG216",
            (0x03, 0x0B) => "MIFARE Ultralight EV1 (MF0UL11)",
            (0x03, 0x0E) => "MIFARE Ultralight EV1 (MF0UL21)",
            _ => {
                return format!(
                    "unknown (type {:02X}, storage {:02X})",
                    self.product_type, self.storage
                )
            }
        };
        name.to_string()
    }
}

/// Name for the ISO/IEC 7816-6 manufacturer code in UID byte 0. Only codes
/// we are sure of are named; anything else is shown as its hex value.
pub fn manufacturer(code: u8) -> String {
    match code {
        0x02 => "STMicroelectronics".into(),
        0x04 => "NXP".into(),
        0x05 => "Infineon".into(),
        0x07 => "Texas Instruments".into(),
        c => format!("{c:02X} (not NXP)"),
    }
}

/// The model implied by the capability container's size byte, for tags that
/// will not answer GET_VERSION.
pub fn model_from_capacity(bytes: usize) -> &'static str {
    match bytes {
        48 => "NTAG210 / Ultralight EV1 compatible",
        128 => "NTAG212 / Ultralight EV1 (MF0UL21) compatible",
        144 => "NTAG213 compatible",
        496 => "NTAG215 compatible",
        872 => "NTAG216 compatible",
        _ => "unknown size",
    }
}

/// Capability container, page 3.
#[derive(Debug, Clone, PartialEq)]
pub struct Cc {
    pub ndef_formatted: bool,
    pub version: (u8, u8),
    /// Bytes of user memory the CC advertises (size byte × 8).
    pub data_bytes: usize,
    pub readable: bool,
    /// Writable as far as the CC says. 0x0F means read-only.
    pub writable: bool,
}

impl Cc {
    pub fn parse(page3: &[u8]) -> Cc {
        Cc {
            ndef_formatted: page3[0] == 0xE1,
            version: (page3[1] >> 4, page3[1] & 0x0F),
            data_bytes: page3[2] as usize * 8,
            readable: page3[3] >> 4 == 0,
            writable: page3[3] & 0x0F == 0,
        }
    }
}

/// Static lock bytes (page 2, bytes 2-3): any set bit locks pages 3-15.
pub fn static_locks(page2: &[u8]) -> [u8; 2] {
    [page2[2], page2[3]]
}

#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// An NDEF TLV with a zero-length message: formatted but empty.
    Empty,
    Uri(String),
    Text(String),
    Other {
        tnf: u8,
        record_type: Vec<u8>,
        len: usize,
    },
    /// No NDEF TLV before the terminator / end of memory.
    NoNdef,
    Malformed(&'static str),
}

/// Walk the TLVs in user memory (from page 4) and decode the first NDEF
/// record. Lock and memory control TLVs are skipped.
pub fn content(user: &[u8]) -> Content {
    let mut i = 0;
    while i < user.len() {
        let t = user[i];
        match t {
            0x00 => i += 1, // NULL TLV
            0xFE => return Content::NoNdef,
            _ => {
                let Some((len, hdr)) = tlv_len(&user[i + 1..]) else {
                    return Content::Malformed("truncated TLV length");
                };
                let start = i + 1 + hdr;
                if start + len > user.len() {
                    return Content::Malformed("TLV runs past the end of memory");
                }
                if t == 0x03 {
                    return if len == 0 {
                        Content::Empty
                    } else {
                        record(&user[start..start + len])
                    };
                }
                i = start + len;
            }
        }
    }
    Content::NoNdef
}

/// TLV length: one byte, or 0xFF followed by two big-endian bytes.
fn tlv_len(b: &[u8]) -> Option<(usize, usize)> {
    match b.first()? {
        0xFF => Some(((*b.get(1)? as usize) << 8 | *b.get(2)? as usize, 3)),
        &n => Some((n as usize, 1)),
    }
}

/// The first record of an NDEF message.
fn record(msg: &[u8]) -> Content {
    let Some(&flags) = msg.first() else {
        return Content::Malformed("empty message");
    };
    let tnf = flags & 0x07;
    let short = flags & 0x10 != 0;
    let has_id = flags & 0x08 != 0;
    let Some(type_len) = msg.get(1).map(|&n| n as usize) else {
        return Content::Malformed("no type length");
    };
    let (payload_len, mut p) = if short {
        let Some(&n) = msg.get(2) else {
            return Content::Malformed("no payload length");
        };
        (n as usize, 3)
    } else {
        let Some(n) = msg.get(2..6) else {
            return Content::Malformed("no payload length");
        };
        (u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize, 6)
    };
    let id_len = if has_id {
        let Some(&n) = msg.get(p) else {
            return Content::Malformed("no id length");
        };
        p += 1;
        n as usize
    } else {
        0
    };
    let Some(record_type) = msg.get(p..p + type_len) else {
        return Content::Malformed("type truncated");
    };
    p += type_len + id_len;
    let Some(payload) = msg.get(p..p + payload_len) else {
        return Content::Malformed("payload truncated");
    };

    match (tnf, record_type) {
        (0x01, b"U") if !payload.is_empty() => Content::Uri(format!(
            "{}{}",
            uri_prefix(payload[0]),
            String::from_utf8_lossy(&payload[1..])
        )),
        (0x01, b"T") if !payload.is_empty() => {
            let lang = (payload[0] & 0x3F) as usize;
            Content::Text(
                String::from_utf8_lossy(payload.get(1 + lang..).unwrap_or(&[])).into_owned(),
            )
        }
        _ => Content::Other {
            tnf,
            record_type: record_type.to_vec(),
            len: payload_len,
        },
    }
}

/// NFC Forum URI record prefix codes (the common ones).
fn uri_prefix(code: u8) -> &'static str {
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

/// Labelled rows for the screen and for --probe.
pub struct Summary {
    pub identity: Vec<(&'static str, String)>,
    pub ndef: String,
    /// "page: 4 bytes × 4" rows, up to the last page that is not all zero.
    pub pages: Vec<String>,
}

pub fn summarise(uid: &[u8], version: Option<&[u8]>, header: &[u8; 16], user: &[u8]) -> Summary {
    let cc = Cc::parse(&header[12..16]);
    let ver = version.and_then(Version::parse);
    let model = match &ver {
        Some(v) => v.model(),
        None if cc.ndef_formatted => {
            format!("{} (no GET_VERSION)", model_from_capacity(cc.data_bytes))
        }
        None => "unknown (no GET_VERSION, not NDEF-formatted)".into(),
    };
    let maker = manufacturer(ver.as_ref().map_or(uid[0], |v| v.vendor));
    let format = if cc.ndef_formatted {
        let access = match (cc.readable, cc.writable) {
            (true, true) => "read/write",
            (true, false) => "READ-ONLY",
            _ => "restricted",
        };
        format!("NDEF {}.{}, {access}", cc.version.0, cc.version.1)
    } else {
        format!(
            "not NDEF-formatted (CC {})",
            hex::encode_upper(&header[12..16])
        )
    };
    let locks = match static_locks(&header[8..12]) {
        [0, 0] => "none".to_string(),
        l => format!(
            "{} — some of pages 3-15 are permanently read-only",
            hex::encode_upper(l)
        ),
    };
    let ndef = match content(user) {
        Content::Empty => "empty (formatted, no message)".into(),
        Content::Uri(u) => format!("URL  {u}"),
        Content::Text(t) => format!("text  {t}"),
        Content::Other {
            tnf,
            record_type,
            len,
        } => {
            format!(
                "record TNF {tnf}, type {:?}, {len} bytes",
                String::from_utf8_lossy(&record_type)
            )
        }
        Content::NoNdef => "no NDEF message".into(),
        Content::Malformed(why) => format!("malformed: {why}"),
    };

    let mut mem = header.to_vec();
    mem.extend_from_slice(user);
    let last = mem
        .chunks(4)
        .rposition(|p| p.iter().any(|&b| b != 0))
        .unwrap_or(3);
    let pages = mem
        .chunks(16)
        .enumerate()
        .take(last / 4 + 1)
        .map(|(i, row)| {
            let groups: Vec<String> = row.chunks(4).map(hex::encode_upper).collect();
            format!("{:>3}  {}", i * 4, groups.join(" "))
        })
        .collect();

    Summary {
        identity: vec![
            (
                "Type",
                "NFC Forum Type 2 (NTAG21x / Ultralight family)".into(),
            ),
            ("Model", model),
            ("Maker", maker),
            ("UID", hex::encode_upper(uid)),
            ("Capacity", format!("{} bytes", cc.data_bytes)),
            ("Format", format),
            ("Locks", locks),
        ],
        ndef,
        pages,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pages 0-15 of a blank NTAG213-compatible sticker (non-NXP clone).
    const BLANK: [u8; 64] = [
        0x1D, 0x4F, 0x4E, 0x94, 0x06, 0x0C, 0x10, 0x80, 0x9A, 0xC0, 0x00, 0x00, 0xE1, 0x10, 0x12,
        0x00, 0x01, 0x03, 0xA0, 0x0C, 0x34, 0x03, 0x00, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn blank_clone_sticker() {
        let cc = Cc::parse(&BLANK[12..16]);
        assert!(cc.ndef_formatted && cc.readable && cc.writable);
        assert_eq!((cc.version, cc.data_bytes), ((1, 0), 144));
        assert_eq!(model_from_capacity(cc.data_bytes), "NTAG213 compatible");
        assert_eq!(static_locks(&BLANK[8..12]), [0, 0]);
        // Lock control TLV first, then an empty NDEF TLV.
        assert_eq!(content(&BLANK[16..]), Content::Empty);
        assert_eq!(manufacturer(BLANK[0]), "1D (not NXP)");
    }

    #[test]
    fn uri_record() {
        // NDEF TLV with one short URI record: https:// + door.example.com/a/x?t=abc
        let body = b"door.example.com/a/x?t=abc";
        let mut rec = vec![0xD1, 0x01, (body.len() + 1) as u8, b'U', 0x04];
        rec.extend_from_slice(body);
        let mut user = vec![0x01, 0x03, 0xA0, 0x0C, 0x34, 0x03, rec.len() as u8];
        user.extend_from_slice(&rec);
        user.push(0xFE);
        assert_eq!(
            content(&user),
            Content::Uri("https://door.example.com/a/x?t=abc".into())
        );
    }

    #[test]
    fn text_and_other_records() {
        let text = [
            0x03, 0x08, 0xD1, 0x01, 0x04, b'T', 0x02, b'e', b'n', b'h', 0xFE,
        ];
        assert_eq!(content(&text), Content::Text("h".into()));
        let mime = [0x03, 0x06, 0xD2, 0x01, 0x02, b'x', 0xAA, 0xBB, 0xFE];
        assert_eq!(
            content(&mime),
            Content::Other {
                tnf: 2,
                record_type: b"x".to_vec(),
                len: 2
            }
        );
    }

    #[test]
    fn missing_and_broken() {
        assert_eq!(content(&[0x00, 0x00, 0xFE]), Content::NoNdef);
        assert_eq!(content(&[0u8; 8]), Content::NoNdef);
        assert_eq!(
            content(&[0x03, 0x20, 0xD1]),
            Content::Malformed("TLV runs past the end of memory")
        );
    }

    #[test]
    fn summary_of_the_blank_sticker() {
        let header: [u8; 16] = BLANK[..16].try_into().unwrap();
        let s = summarise(
            &[0x1D, 0x4F, 0x4E, 0x06, 0x0C, 0x10, 0x80],
            None,
            &header,
            &BLANK[16..],
        );
        let row = |k: &str| s.identity.iter().find(|(l, _)| *l == k).unwrap().1.clone();
        assert_eq!(row("Model"), "NTAG213 compatible (no GET_VERSION)");
        assert_eq!(row("Maker"), "1D (not NXP)");
        assert_eq!(row("Capacity"), "144 bytes");
        assert_eq!(row("Format"), "NDEF 1.0, read/write");
        assert_eq!(row("Locks"), "none");
        assert_eq!(s.ndef, "empty (formatted, no message)");
        // Pages 0-7 hold data; the all-zero rows after them are left out.
        assert_eq!(s.pages.len(), 2);
        assert_eq!(s.pages[1], "  4  0103A00C 340300FE 00000000 00000000");
    }

    #[test]
    fn version_decoding() {
        let ntag213 = Version::parse(&[0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03]).unwrap();
        assert_eq!(
            (manufacturer(ntag213.vendor), ntag213.model()),
            ("NXP".into(), "NTAG213".into())
        );
        assert_eq!(
            Version::parse(&[0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03])
                .unwrap()
                .model(),
            "NTAG216"
        );
        assert!(Version::parse(&[0x01, 0x02]).is_none());
    }
}
