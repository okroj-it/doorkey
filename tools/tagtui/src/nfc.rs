//! Reader access via libnfc.
//!
//! EasyFraming + AutoIso144434 let the PN532 firmware handle ISO-DEP I-block
//! framing, so this layer only has to build APDUs. Without them we would be
//! toggling PCB bytes by hand.

use anyhow::{Result, anyhow, bail};
use nfc1::target_info::TargetInfo;
use nfc1::{BaudRate, Context, Device, Modulation, ModulationType, Property, Timeout};

use crate::ev2::{self, Session};

pub struct Tag {
    pub uid: Vec<u8>,
    pub sak: u8,
    pub ats: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TagKind {
    /// ISO 14443-4 (SAK bit 0x20): APDUs, as the NTAG 424 DNA speaks.
    IsoDep,
    /// SAK 0x00: NFC Forum Type 2 (NTAG21x, MIFARE Ultralight, clones).
    Type2,
    Other,
}

impl Tag {
    pub fn kind(&self) -> TagKind {
        if self.sak & 0x20 != 0 {
            TagKind::IsoDep
        } else if self.sak == 0x00 {
            TagKind::Type2
        } else {
            TagKind::Other
        }
    }
}

/// What the read-only Type 2 commands returned. Decoded by `type2`.
pub struct Type2Dump {
    /// GET_VERSION, if the chip answers it.
    pub version: Option<Vec<u8>>,
    /// Pages 0-3: UID, check bytes, static locks, capability container.
    pub header: [u8; 16],
    /// User memory from page 4, as much as the CC advertises.
    pub user: Vec<u8>,
}

/// Field order matters: Device must be dropped before Context.
pub struct Reader {
    dev: Device,
    _ctx: Context,
    pub name: String,
    /// The connstring actually opened - more useful on screen than the
    /// driver's own description ("user defined default device").
    pub port: String,
}

pub fn list_devices() -> Result<Vec<String>> {
    let mut ctx = Context::new().map_err(|e| anyhow!("libnfc init: {e:?}"))?;
    ctx.list_devices(8).map_err(|e| anyhow!("list devices: {e:?}"))
}

impl Reader {
    pub fn open(connstring: Option<&str>) -> Result<Self> {
        let mut ctx = Context::new().map_err(|e| anyhow!("libnfc init: {e:?}"))?;
        let mut dev = match connstring {
            Some(c) => ctx.open_with_connstring(c),
            None => ctx.open(),
        }
        .map_err(|e| anyhow!("open reader: {e:?}"))?;

        dev.initiator_init().map_err(|e| anyhow!("init: {e:?}"))?;
        // Let the PN532 firmware do ISO-DEP framing for us.
        dev.set_property_bool(Property::EasyFraming, true).ok();
        dev.set_property_bool(Property::AutoIso144434, true).ok();
        let name = dev.name().to_string();
        let port = connstring
            .map(|c| c.rsplit_once(':').map_or(c.to_string(), |(h, _)| h.to_string()))
            .unwrap_or_else(|| {
                std::env::var("LIBNFC_DEFAULT_DEVICE")
                    .ok()
                    .and_then(|v| v.rsplit_once(':').map(|(h, _)| h.to_string()))
                    .unwrap_or_else(|| name.clone())
            });
        Ok(Self { dev, _ctx: ctx, name, port })
    }

    /// Select whatever tag is on the reader now. Called per action, so the tag
    /// can be lifted and replaced between operations.
    pub fn select(&mut self) -> Result<Tag> {
        let modulation = Modulation {
            modulation_type: ModulationType::Iso14443a,
            baud_rate: BaudRate::Baud106,
        };
        // A tag that is still selected from a previous operation will not
        // re-select, which looks exactly like an empty reader. Drop any
        // existing target first, and re-init if even that is not enough.
        self.dev.initiator_deselect_target().ok();
        let target = match self.dev.initiator_select_passive_target(&modulation) {
            Ok(t) => t,
            Err(_) => {
                self.dev.initiator_init().ok();
                self.dev
                    .initiator_select_passive_target(&modulation)
                    .map_err(|_| anyhow!("no tag on the reader"))?
            }
        };

        match target.target_info {
            TargetInfo::Iso14443a(t) => Ok(Tag {
                uid: t.uid[..t.uid_len].to_vec(),
                sak: t.sak,
                ats: t.ats[..t.ats_len].to_vec(),
            }),
            _ => bail!("not an ISO14443-A target"),
        }
    }

    /// Select, and refuse anything that is not an ISO-DEP tag. Every DNA
    /// operation starts here, so a Type 2 sticker gets a clear message
    /// instead of a failed APDU.
    pub fn select_dna(&mut self) -> Result<Tag> {
        let t = self.select()?;
        match t.kind() {
            TagKind::IsoDep => Ok(t),
            TagKind::Type2 => bail!(
                "this is a Type 2 tag (NTAG21x/Ultralight), not an NTAG 424 DNA — read it with 'r'"
            ),
            TagKind::Other => bail!("SAK {:02X}: not an NTAG 424 DNA", t.sak),
        }
    }

    /// Type 2 READ (0x30): four pages from `page`, 16 bytes. Never writes.
    pub fn t2_read(&mut self, page: u8) -> Result<[u8; 16]> {
        let r = self
            .dev
            .initiator_transceive_bytes(&[0x30, page], 16, Timeout::Default)
            .map_err(|e| anyhow!("READ page {page}: {e:?}"))?;
        r.get(..16)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow!("READ page {page}: short response ({} bytes)", r.len()))
    }

    /// A Type 2 command as a raw frame (InCommunicateThru). The PN532 still
    /// adds and checks the CRC. Needed for the NTAG commands the firmware's
    /// InDataExchange misreads as MIFARE Classic ones.
    fn t2_raw(&mut self, cmd: &[u8], max_rx: usize) -> Result<Vec<u8>> {
        self.dev.set_property_bool(Property::EasyFraming, false).ok();
        let r = self.dev.initiator_transceive_bytes(cmd, max_rx, Timeout::Default);
        self.dev.set_property_bool(Property::EasyFraming, true).ok();
        r.map_err(|e| anyhow!("raw {:02X}: {e:?}", cmd.first().copied().unwrap_or(0)))
    }

    /// Type 2 GET_VERSION (0x60). None when the chip does not answer it, as
    /// the original Ultralight does not. The failed command halts the tag,
    /// so it is re-selected before returning.
    ///
    /// Sent as a raw frame: with easy framing the PN532 wraps it in
    /// InDataExchange, which takes 0x60 for a MIFARE Classic authentication
    /// and never sends it, so even a genuine NTAG21x looked silent.
    pub fn t2_version(&mut self) -> Option<Vec<u8>> {
        match self.t2_raw(&[0x60], 8) {
            Ok(v) if v.len() >= 8 => Some(v),
            _ => {
                self.select().ok();
                None
            }
        }
    }

    /// Type 2 PWD_AUTH (0x1B), as a raw frame. Returns the PACK the tag
    /// answers with. A wrong password gets no answer and halts the tag, so it
    /// is re-selected before the error is returned.
    pub fn t2_auth(&mut self, pwd: [u8; 4]) -> Result<[u8; 2]> {
        match self.t2_raw(&[0x1B, pwd[0], pwd[1], pwd[2], pwd[3]], 2) {
            Ok(r) if r.len() >= 2 => Ok([r[0], r[1]]),
            _ => {
                self.select().ok();
                bail!("PWD_AUTH refused")
            }
        }
    }

    /// Type 2 WRITE (0xA2): one page. The tag answers with a 4-bit ACK; a
    /// NAK (protected page, locked page, bad address) comes back as an error.
    pub fn t2_write(&mut self, page: u8, data: [u8; 4]) -> Result<()> {
        let cmd = [0xA2, page, data[0], data[1], data[2], data[3]];
        self.dev
            .initiator_transceive_bytes(&cmd, 1, Timeout::Default)
            .map(|_| ())
            .map_err(|e| {
                self.select().ok();
                anyhow!("WRITE page {page:#04X} refused: {e:?}")
            })
    }

    /// Everything a Type 2 tag shows without authentication or writes.
    pub fn read_type2(&mut self) -> Result<Type2Dump> {
        let version = self.t2_version();
        let header = self.t2_read(0)?;
        let cc = crate::type2::Cc::parse(&header[12..16]);
        // Unformatted tags advertise nothing; read a small window anyway.
        let bytes = if cc.ndef_formatted { cc.data_bytes.clamp(16, 1024) } else { 48 };
        let mut user = Vec::with_capacity(bytes + 16);
        let mut page = 4u8;
        while user.len() < bytes {
            user.extend_from_slice(&self.t2_read(page)?);
            page = page.checked_add(4).ok_or_else(|| anyhow!("page counter overflow"))?;
        }
        user.truncate(bytes);
        Ok(Type2Dump { version, header, user })
    }

    /// One APDU. Returns the body and the two status bytes separately.
    fn apdu(&mut self, data: &[u8]) -> Result<(Vec<u8>, [u8; 2])> {
        let r = self
            .dev
            .initiator_transceive_bytes(data, 512, Timeout::Default)
            .map_err(|e| anyhow!("transceive: {e:?}"))?;
        if r.len() < 2 {
            bail!("short response ({} bytes)", r.len());
        }
        let sw = [r[r.len() - 2], r[r.len() - 1]];
        Ok((r[..r.len() - 2].to_vec(), sw))
    }

    pub fn select_ndef_app(&mut self) -> Result<()> {
        let (_, sw) = self.apdu(&h("00A4040007D276000085010100"))?;
        if sw != [0x90, 0x00] {
            bail!("select NDEF app: {:02X}{:02X}", sw[0], sw[1]);
        }
        Ok(())
    }

    /// UID from GetVersion - three frames, no session needed.
    pub fn get_version_uid(&mut self) -> Result<[u8; 7]> {
        let (_, sw) = self.apdu(&h("9060000000"))?;
        if sw != [0x91, 0xAF] {
            bail!("GetVersion: {:02X}{:02X}", sw[0], sw[1]);
        }
        let (_, sw) = self.apdu(&h("90AF000000"))?;
        if sw != [0x91, 0xAF] {
            bail!("GetVersion frame 2: {:02X}{:02X}", sw[0], sw[1]);
        }
        let (body, sw) = self.apdu(&h("90AF000000"))?;
        if sw != [0x91, 0x00] || body.len() < 7 {
            bail!("GetVersion frame 3: {:02X}{:02X}", sw[0], sw[1]);
        }
        let mut uid = [0u8; 7];
        uid.copy_from_slice(&body[0..7]);
        Ok(uid)
    }

    pub fn file_settings(&mut self, file_no: u8) -> Result<Vec<u8>> {
        let (body, sw) = self.apdu(&[0x90, 0xF5, 0x00, 0x00, 0x01, file_no, 0x00])?;
        if sw != [0x91, 0x00] {
            bail!("GetFileSettings({file_no}): {:02X}{:02X}", sw[0], sw[1]);
        }
        Ok(body)
    }

    pub fn read_data(&mut self, file_no: u8, offset: u32, len: u32) -> Result<Vec<u8>> {
        let mut h = vec![file_no];
        h.extend_from_slice(&offset.to_le_bytes()[0..3]);
        h.extend_from_slice(&len.to_le_bytes()[0..3]);
        let mut apdu = vec![0x90, 0xAD, 0x00, 0x00, h.len() as u8];
        apdu.extend_from_slice(&h);
        apdu.push(0x00);
        let (body, sw) = self.apdu(&apdu)?;
        if sw != [0x91, 0x00] {
            bail!("ReadData: {:02X}{:02X}", sw[0], sw[1]);
        }
        Ok(body)
    }

    /// AuthenticateEV2First. Proves we hold the key without sending it, and
    /// checks the tag echoed our nonce before trusting the session.
    pub fn authenticate(&mut self, key_no: u8, key: &[u8]) -> Result<Session> {
        let (body, sw) = self.apdu(&[0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00])?;
        if sw != [0x91, 0xAF] {
            bail!("auth rejected: {:02X}{:02X}", sw[0], sw[1]);
        }
        let rnd_b = ev2::decrypt_challenge(key, &body)?;

        let mut rnd_a = [0u8; 16];
        getrandom(&mut rnd_a)?;
        let payload = ev2::challenge_response(key, &rnd_a, &rnd_b);

        let mut apdu = vec![0x90, 0xAF, 0x00, 0x00, payload.len() as u8];
        apdu.extend_from_slice(&payload);
        apdu.push(0x00);
        let (body, sw) = self.apdu(&apdu)?;
        if sw != [0x91, 0x00] {
            bail!("auth part 2 rejected: {:02X}{:02X}", sw[0], sw[1]);
        }

        let plain = ev2::cbc_decrypt(key, &[0u8; ev2::BLOCK], &body)?;
        if !ev2::check_echo(&rnd_a, &plain[4..20]) {
            bail!("RndA mismatch - tag did not echo our nonce");
        }
        let (k_enc, k_mac) = ev2::session_keys(key, &rnd_a, &rnd_b);
        let mut ti = [0u8; 4];
        ti.copy_from_slice(&plain[0..4]);
        Ok(Session { ti, k_enc, k_mac, cmd_ctr: 0 })
    }
}

fn getrandom(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)?;
    Ok(())
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("literal hex")
}

/// Everything below is the write path. It mirrors tools/provision.py, which was
/// proven on hardware first: K0 is the only key that may change keys, a wrong
/// old key fails closed with 911E, and K0 must therefore be changed last.
impl Reader {
    fn pad(plain: &[u8]) -> Vec<u8> {
        let mut v = plain.to_vec();
        v.push(0x80);
        while !v.len().is_multiple_of(ev2::BLOCK) {
            v.push(0x00);
        }
        v
    }

    fn truncate_mac(mac: &[u8; 16]) -> [u8; 8] {
        let mut out = [0u8; 8];
        for (i, s) in out.iter_mut().enumerate() {
            *s = mac[i * 2 + 1];
        }
        out
    }

    /// CommMode.FULL: encrypt the data, MAC the encrypted form, bump CmdCtr.
    pub fn send_full(
        &mut self,
        s: &mut Session,
        cmd: u8,
        header: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let enc = if plain.is_empty() {
            Vec::new()
        } else {
            let mut iv_src = vec![0xA5, 0x5A];
            iv_src.extend_from_slice(&s.ti);
            iv_src.extend_from_slice(&s.cmd_ctr.to_le_bytes());
            iv_src.extend_from_slice(&[0u8; 8]);
            let iv = ev2::cbc_encrypt(&s.k_enc, &[0u8; ev2::BLOCK], &iv_src);
            ev2::cbc_encrypt(&s.k_enc, &iv, &Self::pad(plain))
        };

        let mut mac_msg = vec![cmd];
        mac_msg.extend_from_slice(&s.cmd_ctr.to_le_bytes());
        mac_msg.extend_from_slice(&s.ti);
        mac_msg.extend_from_slice(header);
        mac_msg.extend_from_slice(&enc);
        let mac = Self::truncate_mac(&ev2::cmac_aes(&s.k_mac, &mac_msg));

        let mut body = header.to_vec();
        body.extend_from_slice(&enc);
        body.extend_from_slice(&mac);

        let mut apdu = vec![0x90, cmd, 0x00, 0x00, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu.push(0x00);

        let (resp, sw) = self.apdu(&apdu)?;
        s.cmd_ctr += 1;
        if sw != [0x91, 0x00] {
            bail!("cmd {cmd:#04X} rejected: {:02X}{:02X}", sw[0], sw[1]);
        }
        Ok(resp)
    }

    /// Plain write. File 2 is free-write from the factory, so no session.
    pub fn write_data(&mut self, file_no: u8, offset: u32, data: &[u8]) -> Result<()> {
        let mut body = vec![file_no];
        body.extend_from_slice(&offset.to_le_bytes()[0..3]);
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()[0..3]);
        body.extend_from_slice(data);
        let mut apdu = vec![0x90, 0x8D, 0x00, 0x00, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu.push(0x00);
        let (_, sw) = self.apdu(&apdu)?;
        if sw != [0x91, 0x00] {
            bail!("WriteData: {:02X}{:02X}", sw[0], sw[1]);
        }
        Ok(())
    }

    /// Whether this key slot opens with the given key. Read-only: a failed
    /// authentication changes nothing, so this is safe to probe with.
    pub fn key_opens(&mut self, key_no: u8, key: &[u8]) -> bool {
        if self.select().is_err() || self.select_ndef_app().is_err() {
            return false;
        }
        self.authenticate(key_no, key).is_ok()
    }

    pub fn change_key(
        &mut self,
        s: &mut Session,
        key_no: u8,
        new_key: &[u8],
        old_key: &[u8],
        same_as_auth: bool,
    ) -> Result<()> {
        let plain = if same_as_auth {
            let mut p = new_key.to_vec();
            p.push(0x00); // key version
            p
        } else {
            let mut p: Vec<u8> = new_key.iter().zip(old_key).map(|(a, b)| a ^ b).collect();
            p.push(0x00);
            p.extend_from_slice(&jam_crc32(new_key).to_le_bytes());
            p
        };
        self.send_full(s, 0xC4, &[key_no], &plain)?;
        Ok(())
    }

    /// ChangeFileSettings enabling SDM. `write_locked` sets the access rights
    /// so only K0 may rewrite the URL; free write is the factory default and
    /// lets anyone with a phone overwrite the tag.
    pub fn enable_sdm(
        &mut self,
        s: &mut Session,
        file_no: u8,
        picc_off: u32,
        mac_off: u32,
        write_locked: bool,
    ) -> Result<()> {
        let access: [u8; 2] = if write_locked {
            [0x00, 0xE0] // RW=none, Change=K0, Read=free, Write=K0
        } else {
            [0xE0, 0xEE] // factory: everything free
        };
        let mut data = vec![0x40]; // SDM enabled, plain comms
        data.extend_from_slice(&access);
        data.push(0xC1); // UID mirror + read counter + ASCII

        // SDMAccessRights nibbles are [RFU][SDMCtrRet][SDMMetaRead][SDMFileRead].
        // F1 21 therefore means FileRead = K1 - a key nobody provisions, left
        // at factory zeros, so every tap was signed with a zero key. It cannot
        // be caught before the keys differ, because while they are all zero any
        // slot verifies. FF 23 = counter retrieval disabled, meta read K2,
        // file read K3.
        data.extend_from_slice(&[0xFF, 0x23]);
        data.extend_from_slice(&picc_off.to_le_bytes()[0..3]);
        data.extend_from_slice(&mac_off.to_le_bytes()[0..3]); // MAC input offset
        data.extend_from_slice(&mac_off.to_le_bytes()[0..3]); // MAC offset
        self.send_full(s, 0x5F, &[file_no], &data)?;
        Ok(())
    }
}

/// CRC32 as ChangeKey wants it: reflected, init all ones, no final inversion.
fn jam_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    crc
}

/// Per-tag key from the offline master. Matches derive() in provision.py.
pub fn derive_key(master: &[u8], label: u8, uid: &[u8]) -> [u8; 16] {
    let mut msg = vec![label];
    msg.extend_from_slice(uid);
    ev2::cmac_aes(master, &msg)
}

/// Password and PACK for write-protecting a Type 2 tag, from the offline
/// master: every tag gets its own, nothing is stored, and only someone with
/// the master can unprotect it. Label 0x10 keeps it apart from the DNA keys.
pub fn tag_password(master: &[u8], uid: &[u8]) -> ([u8; 4], [u8; 2]) {
    let k = derive_key(master, 0x10, uid);
    ([k[0], k[1], k[2], k[3]], [k[4], k[5]])
}

/// The URL the chip emits, minus the https:// that NDEF abbreviates, for
/// doorkey's public origin in DOORKEY_ORIGIN. Every tag carries the same
/// /k/sun URL; whether a tap opens the keypad or an action is decided by
/// doorkey's database, not by the chip.
pub fn sdm_url_template() -> Result<String> {
    let origin = std::env::var("DOORKEY_ORIGIN").map_err(|_| {
        anyhow!("set DOORKEY_ORIGIN to doorkey's public origin, e.g. https://door.example.com")
    })?;
    sdm_template_for(&origin)
}

pub fn sdm_template_for(origin: &str) -> Result<String> {
    let host = origin
        .trim()
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("DOORKEY_ORIGIN must start with https://, got {origin}"))?;
    let host = host.strip_suffix('/').unwrap_or(host);
    if host.is_empty() || host.contains(['/', '?', '#']) {
        bail!("DOORKEY_ORIGIN must be just scheme and host, e.g. https://door.example.com");
    }
    let body = format!("{host}/k/sun?picc={}&cmac={}", "0".repeat(32), "0".repeat(16));
    if body.len() + 1 > 255 {
        bail!("origin too long for a short NDEF record");
    }
    Ok(body)
}

pub fn build_ndef(url_body: &str) -> Vec<u8> {
    let mut payload = vec![0x04]; // https:// prefix abbreviation
    payload.extend_from_slice(url_body.as_bytes());
    let mut record = vec![0xD1, 0x01, payload.len() as u8, 0x55];
    record.extend_from_slice(&payload);
    let mut out = (record.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&record);
    out
}

/// File offsets of the two placeholders that SDM overwrites on every read.
///
/// Searched over the BYTES. A lossy UTF-8 view would be wrong: the NDEF
/// header's 0xD1 is invalid UTF-8 and becomes a 3-byte replacement character,
/// inflating every later index by 2. That shifts both mirrors two bytes late,
/// so the PICC data overwrites the "&c" of "&cmac=" and the tag emits a bare
/// "mac=" with no cmac field at all.
fn find_after(hay: &[u8], needle: &[u8]) -> Option<u32> {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .map(|i| (i + needle.len()) as u32)
}

pub fn mirror_offsets(ndef: &[u8]) -> Result<(u32, u32)> {
    match (find_after(ndef, b"picc="), find_after(ndef, b"cmac=")) {
        (Some(p), Some(c)) => Ok((p, c)),
        _ => bail!("placeholders missing from template"),
    }
}

/// The URL text out of an NDEF file, taken from the raw bytes.
///
/// Layout: NLEN(2) D1 01 len 55 04 then the URL, where 04 abbreviates
/// "https://". Reading this out of a lossy UTF-8 string instead would shift
/// every offset, because D1 is not valid UTF-8.
pub fn url_from_ndef(data: &[u8]) -> String {
    const URL_START: usize = 7;
    if data.len() <= URL_START {
        return String::new();
    }
    let tail = &data[URL_START..];
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

/// The two SUN parameters a tap carries.
pub fn sun_params(url: &str) -> Result<(String, String)> {
    let picc = url
        .split("picc=")
        .nth(1)
        .and_then(|x| x.split('&').next())
        .ok_or_else(|| anyhow!("no picc= in the URL - is SDM enabled?"))?;
    let cmac = url
        .split("cmac=")
        .nth(1)
        .and_then(|x| x.split('&').next())
        .ok_or_else(|| anyhow!("no cmac= in the URL"))?;
    Ok((picc.to_string(), cmac.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: offsets must be byte offsets into the file. Computing them
    /// over a lossy UTF-8 view inflates both by 2 (the NDEF header's 0xD1
    /// becomes a 3-byte replacement char), which puts the PICC mirror over the
    /// "&c" of "&cmac=" and leaves the tag emitting no cmac field.
    #[test]
    fn mirror_offsets_are_byte_offsets() {
        let ndef = build_ndef(&sdm_template_for(ORIGIN).unwrap());
        let (picc, cmac) = mirror_offsets(&ndef).unwrap();
        assert_eq!((picc, cmac), (32, 70));

        // The placeholders must sit exactly where the offsets point, and be
        // the exact length of the data that replaces them.
        assert_eq!(&ndef[picc as usize..picc as usize + 32], b"0".repeat(32));
        assert_eq!(&ndef[cmac as usize..cmac as usize + 16], b"0".repeat(16));
        assert_eq!(&ndef[picc as usize + 32..cmac as usize], b"&cmac=");
    }

    #[test]
    fn url_from_ndef_skips_the_header() {
        let template = sdm_template_for(ORIGIN).unwrap();
        assert_eq!(url_from_ndef(&build_ndef(&template)), template);
    }

    /// Same length as the origin the 32/70 offsets above were measured on.
    const ORIGIN: &str = "https://door.test.xyz";

    #[test]
    fn tag_passwords_are_per_tag() {
        let master = [0x42u8; 16];
        let a = tag_password(&master, &[0x04, 0xB8, 0x5A, 0x11, 0xBB, 0x2A, 0x81]);
        let b = tag_password(&master, &[0x1D, 0x4F, 0x4E, 0x06, 0x0C, 0x10, 0x80]);
        assert_eq!(a, tag_password(&master, &[0x04, 0xB8, 0x5A, 0x11, 0xBB, 0x2A, 0x81]), "deterministic");
        assert_ne!(a, b, "different tags, different passwords");
        assert_ne!(a.0, [0xFF; 4], "never the factory password");
        // Not the K0 or K3 of the same tag
        let uid = [0x04, 0xB8, 0x5A, 0x11, 0xBB, 0x2A, 0x81];
        assert_ne!(&derive_key(&master, 0x00, &uid)[..4], &a.0);
        assert_ne!(&derive_key(&master, 0x03, &uid)[..4], &a.0);
    }

    #[test]
    fn template_from_origin() {
        assert_eq!(
            sdm_template_for("https://door.example.com/").unwrap(),
            format!("door.example.com/k/sun?picc={}&cmac={}", "0".repeat(32), "0".repeat(16)),
        );
        for bad in ["http://door.example.com", "https://door.example.com/k", "door.example.com", "https://"] {
            assert!(sdm_template_for(bad).is_err(), "{bad} should be rejected");
        }
    }
}
