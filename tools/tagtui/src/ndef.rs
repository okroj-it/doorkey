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
        (0x01, b"Sp") => smart_poster(p),
        (0x00, _) => "empty record".into(),
        (0x02, b"application/vnd.wfa.wsc") => wifi(p),
        (0x02, b"text/vcard" | b"text/x-vcard") => vcard(&String::from_utf8_lossy(p)),
        (0x02, b"application/vnd.bluetooth.ep.oob") => bluetooth_classic(p),
        (0x02, b"application/vnd.bluetooth.le.oob") => bluetooth_le(p),
        (0x02, t) => mime(&String::from_utf8_lossy(t), p),
        (0x03, t) => format!("URI  {}", String::from_utf8_lossy(t)),
        (0x04, b"android.com:pkg") => {
            format!("Android app  {}", String::from_utf8_lossy(p))
        }
        (0x04, t) => format!(
            "external type {}, {} bytes",
            String::from_utf8_lossy(t),
            p.len()
        ),
        (0x05, _) => format!("unknown-type record, {} bytes", p.len()),
        _ => format!(
            "record TNF {}, type {:?}, {} bytes",
            r.tnf,
            String::from_utf8_lossy(&r.record_type),
            p.len()
        ),
    }
}

/// Wi-Fi Simple Config attributes: 2-byte type, 2-byte length, value.
fn wsc_attrs(mut b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let t = u16::from_be_bytes([b[0], b[1]]);
        let n = u16::from_be_bytes([b[2], b[3]]) as usize;
        let Some(v) = b.get(4..4 + n) else { break };
        out.push((t, v));
        b = &b[4 + n..];
    }
    out
}

/// A Wi-Fi network as NFC Tools and Android write it. The key is never
/// shown, only its length: anyone holding the tag can read it anyway, but
/// it does not belong on a screen.
fn wifi(p: &[u8]) -> String {
    let top = wsc_attrs(p);
    // The fields usually sit inside a Credential (0x100E), but not always.
    let creds = top
        .iter()
        .find(|(t, _)| *t == 0x100E)
        .map_or(top.clone(), |(_, v)| wsc_attrs(v));
    let get = |t: u16| creds.iter().find(|(k, _)| *k == t).map(|(_, v)| *v);
    let word = |t: u16| get(t).filter(|v| v.len() == 2).map(|v| u16::from_be_bytes([v[0], v[1]]));

    let ssid = get(0x1045).map_or("?".into(), |v| String::from_utf8_lossy(v).into_owned());
    let auth = match word(0x1003) {
        Some(0x0001) => "open",
        Some(0x0002) => "WPA-Personal",
        Some(0x0004) => "shared",
        Some(0x0008) => "WPA-Enterprise",
        Some(0x0010) => "WPA2-Enterprise",
        Some(0x0020) => "WPA2-Personal",
        Some(0x0022) => "WPA/WPA2-Personal",
        Some(_) => "other auth",
        None => "auth ?",
    };
    let enc = match word(0x100F) {
        Some(0x0001) => "none",
        Some(0x0002) => "WEP",
        Some(0x0004) => "TKIP",
        Some(0x0008) => "AES",
        Some(0x000C) => "AES/TKIP",
        _ => "?",
    };
    let key = match get(0x1027) {
        Some(k) if !k.is_empty() => format!("key {} chars", k.len()),
        _ => "no key".into(),
    };
    let mac = match get(0x1020) {
        Some(m) if m.len() == 6 && m != [0xFF; 6] => format!("  MAC {}", hex::encode_upper(m)),
        _ => String::new(),
    };
    format!("Wi-Fi  \"{ssid}\"  {auth}/{enc}  {key}{mac}")
}

/// A contact card: name, phone numbers, emails, organisation and URL.
fn vcard(card: &str) -> String {
    // Unfold: a line starting with a space or tab continues the previous one.
    let mut lines: Vec<String> = Vec::new();
    for raw in card.lines() {
        match (raw.strip_prefix([' ', '\t']), lines.last_mut()) {
            (Some(rest), Some(prev)) => prev.push_str(rest),
            _ => lines.push(raw.to_string()),
        }
    }
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in &lines {
        let Some((key, value)) = line.split_once(':') else { continue };
        // "TEL;TYPE=CELL" -> "TEL"; "item1.EMAIL" -> "EMAIL"
        let name = key.split(';').next().unwrap_or("");
        let name = name.rsplit('.').next().unwrap_or("").to_ascii_uppercase();
        fields.push((name, value.trim().to_string()));
    }
    let all = |k: &str| fields.iter().filter(|(n, _)| n == k).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
    let name = all("FN")
        .first()
        .map(|s| s.to_string())
        .or_else(|| {
            // N is "family;given;additional;prefix;suffix"
            all("N").first().map(|n| {
                let parts: Vec<&str> = n.split(';').collect();
                let (family, given) = (parts.first().copied().unwrap_or(""), parts.get(1).copied().unwrap_or(""));
                format!("{given} {family}").trim().to_string()
            })
        })
        .unwrap_or_else(|| "?".into());
    let mut out = vec![format!("contact  {name}")];
    for k in ["TEL", "EMAIL", "ORG", "URL"] {
        out.extend(all(k).iter().filter(|v| !v.is_empty()).map(|v| v.replace(';', " ")));
    }
    out.join(" · ")
}

/// Bluetooth EIR / AD structures: length (covering type and data), type, data.
fn ad_structs(mut b: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let [len, rest @ ..] = b {
        let n = *len as usize;
        if n == 0 || rest.len() < n {
            break;
        }
        out.push((rest[0], &rest[1..n]));
        b = &rest[n..];
    }
    out
}

/// Bluetooth addresses are stored least significant byte first.
fn bd_addr(b: &[u8]) -> String {
    b.iter().rev().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

fn bt_name(ad: &[(u8, &[u8])]) -> String {
    // 0x09 complete local name, 0x08 shortened
    ad.iter()
        .find(|(t, _)| *t == 0x09)
        .or_else(|| ad.iter().find(|(t, _)| *t == 0x08))
        .map_or(String::new(), |(_, v)| format!("  \"{}\"", String::from_utf8_lossy(v)))
}

/// Classic (BR/EDR) pairing: OOB length (2, LE), address (6), then EIR data.
fn bluetooth_classic(p: &[u8]) -> String {
    let Some(addr) = p.get(2..8) else { return "Bluetooth, malformed".into() };
    let ad = ad_structs(&p[8..]);
    let class = ad
        .iter()
        .find(|(t, v)| *t == 0x0D && v.len() == 3)
        .map_or(String::new(), |(_, v)| format!("  class {:02X}{:02X}{:02X}", v[2], v[1], v[0]));
    format!("Bluetooth  {}{}{class}", bd_addr(addr), bt_name(&ad))
}

/// LE pairing: AD structures only, with the address in an 0x1B structure.
fn bluetooth_le(p: &[u8]) -> String {
    let ad = ad_structs(p);
    let addr = ad.iter().find(|(t, v)| *t == 0x1B && v.len() == 7).map_or("address ?".into(), |(_, v)| {
        format!("{} ({})", bd_addr(&v[..6]), if v[6] & 1 == 1 { "random" } else { "public" })
    });
    let role = match ad.iter().find(|(t, v)| *t == 0x1C && v.len() == 1).map(|(_, v)| v[0]) {
        Some(0x00) => "  peripheral",
        Some(0x01) => "  central",
        Some(0x02) => "  peripheral (central possible)",
        Some(0x03) => "  central (peripheral possible)",
        _ => "",
    };
    format!("Bluetooth LE  {addr}{}{role}", bt_name(&ad))
}

/// MIME-typed record. Text types are shown; anything else is named.
fn mime(media_type: &str, p: &[u8]) -> String {
    match std::str::from_utf8(p) {
        Ok(t) if media_type.starts_with("text/") && !t.contains('\0') => {
            format!("{media_type}  {}", t.trim())
        }
        _ => format!("{media_type}, {} bytes", p.len()),
    }
}

/// Text RTD: status byte (bit 7 UTF-16, bits 0-5 language code length),
/// the IANA language code, then the text.
fn text(p: &[u8]) -> String {
    let (lang, text) = text_parts(p);
    if lang.is_empty() {
        format!("text  {text}")
    } else {
        format!("text [{lang}]  {text}")
    }
}

/// (language, text) of a Text RTD payload.
fn text_parts(p: &[u8]) -> (String, String) {
    let Some(&status) = p.first() else { return (String::new(), String::new()) };
    let lang_len = (status & 0x3F) as usize;
    let lang = String::from_utf8_lossy(p.get(1..1 + lang_len).unwrap_or(&[])).into_owned();
    let body = p.get(1 + lang_len..).unwrap_or(&[]);
    let text = if status & 0x80 != 0 {
        utf16(body)
    } else {
        String::from_utf8_lossy(body).into_owned()
    };
    (lang, text)
}

/// Smart Poster: a nested message with the URI, titles and hints.
fn smart_poster(p: &[u8]) -> String {
    let Ok(inner) = records(p) else { return "smart poster, malformed".into() };
    let uri = inner
        .iter()
        .find(|r| r.tnf == 0x01 && r.record_type == b"U" && !r.payload.is_empty())
        .map_or("?".into(), |r| format!("{}{}", uri_prefix(r.payload[0]), String::from_utf8_lossy(&r.payload[1..])));
    let mut out = format!("smart poster  {uri}");
    for t in inner.iter().filter(|r| r.tnf == 0x01 && r.record_type == b"T") {
        let (lang, title) = text_parts(&t.payload);
        out += &if lang.is_empty() { format!("  \"{title}\"") } else { format!("  \"{title}\" [{lang}]") };
    }
    let local = |name: &[u8]| inner.iter().find(|r| r.tnf == 0x01 && r.record_type == name).map(|r| r.payload.as_slice());
    match local(b"act") {
        Some([0]) => out += "  action: open",
        Some([1]) => out += "  action: save",
        Some([2]) => out += "  action: edit",
        _ => {}
    }
    if let Some(&[a, b, c, d]) = local(b"s") {
        out += &format!("  size {} bytes", u32::from_be_bytes([a, b, c, d]));
    }
    if let Some(t) = local(b"t") {
        out += &format!("  type {}", String::from_utf8_lossy(t));
    }
    out
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

    fn rec(tnf: u8, record_type: &[u8], payload: &[u8]) -> Record {
        Record {
            tnf,
            record_type: record_type.to_vec(),
            payload: payload.to_vec(),
            last: true,
            chunked: false,
        }
    }

    #[test]
    fn record_kinds() {
        assert_eq!(describe(&rec(0, b"", b"")), "empty record");
        assert_eq!(describe(&rec(3, b"https://x.example/", b"")), "URI  https://x.example/");
        assert_eq!(describe(&rec(4, b"android.com:pkg", b"com.example.app")), "Android app  com.example.app");
        assert_eq!(describe(&rec(4, b"example.com:thing", b"abc")), "external type example.com:thing, 3 bytes");
        assert_eq!(describe(&rec(5, b"", b"ab")), "unknown-type record, 2 bytes");
        assert_eq!(describe(&rec(2, b"text/plain", b"hello\n")), "text/plain  hello");
        assert_eq!(describe(&rec(2, b"image/png", &[0x89, b'P'])), "image/png, 2 bytes");
    }

    /// A WSC attribute: type, length, value.
    fn attr(t: u16, v: &[u8]) -> Vec<u8> {
        let mut a = t.to_be_bytes().to_vec();
        a.extend_from_slice(&(v.len() as u16).to_be_bytes());
        a.extend_from_slice(v);
        a
    }

    #[test]
    fn wifi_credential() {
        let mut cred = attr(0x1026, &[1]);
        cred.extend(attr(0x1045, b"HomeNet"));
        cred.extend(attr(0x1003, &[0x00, 0x20]));
        cred.extend(attr(0x100F, &[0x00, 0x08]));
        cred.extend(attr(0x1027, b"correct horse"));
        cred.extend(attr(0x1020, &[0xFF; 6]));
        let mut payload = attr(0x104A, &[0x10]);
        payload.extend(attr(0x100E, &cred));
        let line = describe(&rec(2, b"application/vnd.wfa.wsc", &payload));
        assert_eq!(line, "Wi-Fi  \"HomeNet\"  WPA2-Personal/AES  key 13 chars");
        assert!(!line.contains("horse"), "the key is never shown");

        // Open network written without the Credential wrapper.
        let mut open = attr(0x1045, b"Cafe");
        open.extend(attr(0x1003, &[0x00, 0x01]));
        open.extend(attr(0x100F, &[0x00, 0x01]));
        assert_eq!(describe(&rec(2, b"application/vnd.wfa.wsc", &open)), "Wi-Fi  \"Cafe\"  open/none  no key");
    }

    #[test]
    fn contact_cards() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nN:Kowalska;Anna;;;\r\nFN:Anna Kowalska\r\n\
                    TEL;TYPE=CELL:+48 600 100 200\r\nitem1.EMAIL;TYPE=INTERNET:anna@exam\r\n ple.com\r\n\
                    ORG:Example;Lab\r\nEND:VCARD\r\n";
        assert_eq!(
            describe(&rec(2, b"text/vcard", card.as_bytes())),
            "contact  Anna Kowalska · +48 600 100 200 · anna@example.com · Example Lab"
        );
        // No FN: fall back to the structured name.
        let bare = "BEGIN:VCARD\nN:Doe;John\nEND:VCARD";
        assert_eq!(describe(&rec(2, b"text/x-vcard", bare.as_bytes())), "contact  John Doe");
    }

    #[test]
    fn bluetooth_pairing() {
        // Classic: length, address 00:1A:7D:DA:71:13 (stored reversed), name, class 240404
        let mut classic = vec![0x00, 0x00, 0x13, 0x71, 0xDA, 0x7D, 0x1A, 0x00];
        classic.extend([0x08, 0x09, b'S', b'p', b'e', b'a', b'k', b'e', b'r']);
        classic.extend([0x04, 0x0D, 0x04, 0x04, 0x24]);
        classic[0] = classic.len() as u8;
        assert_eq!(
            describe(&rec(2, b"application/vnd.bluetooth.ep.oob", &classic)),
            "Bluetooth  00:1A:7D:DA:71:13  \"Speaker\"  class 240404"
        );
        // LE: random address, peripheral, shortened name
        let le = [
            0x08, 0x1B, 0x66, 0x55, 0x44, 0x33, 0x22, 0xC1, 0x01, //
            0x02, 0x1C, 0x00, //
            0x04, 0x08, b'T', b'a', b'g',
        ];
        assert_eq!(
            describe(&rec(2, b"application/vnd.bluetooth.le.oob", &le)),
            "Bluetooth LE  C1:22:33:44:55:66 (random)  \"Tag\"  peripheral"
        );
    }

    #[test]
    fn smart_poster_record() {
        // Nested message: URI, two titles, action "save", size
        let inner = [
            0x91, 0x01, 0x0A, b'U', 0x04, b'x', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', //
            0x11, 0x01, 0x05, b'T', 0x02, b'e', b'n', b'H', b'i', //
            0x11, 0x01, 0x06, b'T', 0x02, b'p', b'l', b'C', b'z', b'e', //
            0x11, 0x03, 0x01, b'a', b'c', b't', 0x01, //
            0x51, 0x01, 0x04, b's', 0x00, 0x00, 0x04, 0x00,
        ];
        assert_eq!(
            describe(&rec(1, b"Sp", &inner)),
            "smart poster  https://x.example  \"Hi\" [en]  \"Cze\" [pl]  action: save  size 1024 bytes"
        );
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
