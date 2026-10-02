//! tagtui - NTAG 424 DNA provisioning for doorkey.
//!
//! Dry runs are the default: reading and tapping never write. The two write
//! actions live behind an explicit confirmation, and the irreversible one
//! (changing keys) is ordered so a factory K0 session can still repair the tag
//! until the very last step.

mod db;
mod ev2;
mod nfc;
mod ui;

use anyhow::Result;

fn main() -> Result<()> {
    // libnfc will not probe serial ports unless told where to look, and there
    // is no /etc/nfc/libnfc.conf on this machine. Without this the reader is
    // simply invisible, which looks like a hardware fault.
    if std::env::var("LIBNFC_DEFAULT_DEVICE").is_err() {
        unsafe { std::env::set_var("LIBNFC_DEFAULT_DEVICE", "pn532_uart:/dev/ttyUSB0:115200") };
    }

    // Headless path: exercises the same reader and crypto code as the TUI,
    // which makes it usable over ssh and from a test run.
    if std::env::args().any(|a| a == "--probe") {
        return probe();
    }
    if std::env::args().any(|a| a == "--authcheck") {
        return authcheck();
    }
    if std::env::args().any(|a| a == "--fix-sdm") {
        return fix_sdm();
    }

    let terminal = ratatui::init();
    let result = ui::App::new().run(terminal);
    ratatui::restore();
    result
}

/// Read-only hardware check: enumerate, read the tag, verify a tap.
fn probe() -> Result<()> {
    let devices = nfc::list_devices()?;
    println!("  readers: {devices:?}");

    let mut r = nfc::Reader::open(devices.first().map(|s| s.as_str()))?;
    println!("  opened {}", r.name);

    let t = r.select()?;
    println!("  UID {}  SAK {:02X}", hex::encode_upper(&t.uid), t.sak);

    r.select_ndef_app()?;
    println!("  GetVersion UID {}", hex::encode_upper(r.get_version_uid()?));
    for f in 1u8..=3 {
        let s = r.file_settings(f)?;
        println!("  file {f}: sdm {}  access {}", if s[1] & 0x40 != 0 { "ON" } else { "off" },
                 hex::encode_upper(&s[2..4]));
    }

    let ndef_len = nfc::build_ndef(&nfc::sdm_url_template()?).len() as u32;
    println!("  expecting {ndef_len} bytes from our template");

    // Read well past the template so a longer or rewritten record is visible.
    let raw = r.read_data(2, 0, 160)?;
    println!("  raw file 2, first 160 bytes:");
    for (i, chunk) in raw.chunks(32).enumerate() {
        let hex = chunk.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("");
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        println!("    {:04X}  {hex}  |{ascii}|", i * 32);
    }

    let data = raw[..ndef_len as usize].to_vec();
    let url = nfc::url_from_ndef(&data);
    let (picc, cmac) = nfc::sun_params(&url)?;
    println!("  url  https://{url}");

    let zero = [0u8; 16];
    let p = ev2::decrypt_picc(&zero, &hex::decode(&picc)?)?;
    let ok = ev2::ct_eq(&ev2::sun_mac(&zero, &p, &[]), &hex::decode(&cmac)?);
    println!("  tap: uid {} ctr {} -> {}", hex::encode_upper(p.uid), p.read_counter,
             if ok { "VERIFIED (factory keys)" } else { "MISMATCH" });
    Ok(())
}

/// Which keys are actually installed. Read-only: a failed authentication
/// changes nothing on the chip.
fn authcheck() -> Result<()> {
    let zero = [0u8; 16];
    let meta = std::env::var("DOORKEY_TAG_META_KEY")
        .ok()
        .and_then(|h| hex::decode(h).ok());

    let mut candidates: Vec<(u8, &str, Vec<u8>)> = vec![
        (0, "factory zeros", zero.to_vec()),
        (2, "factory zeros", zero.to_vec()),
        (3, "factory zeros", zero.to_vec()),
    ];
    if let Some(m) = meta {
        candidates.push((2, "shared meta key", m.clone()));
        candidates.push((3, "shared meta key", m));
    }

    let mut r = nfc::Reader::open(None)?;
    for (no, name, key) in candidates {
        // Each attempt needs a fresh selection: a failed auth leaves the
        // session unusable.
        r.select()?;
        r.select_ndef_app()?;
        match r.authenticate(no, &key) {
            Ok(_) => println!("  key {no}: opens with {name}"),
            Err(_) => println!("  key {no}: NOT {name}"),
        }
    }
    Ok(())
}

/// Rewrite the URL and SDM configuration using a factory K0 session.
///
/// Usable on a tag whose K2/K3 were changed but whose K0 was not - which is
/// where the provisioning gate leaves a tag when the SUN check fails.
fn fix_sdm() -> Result<()> {
    let mut r = nfc::Reader::open(None)?;
    r.select()?;
    r.select_ndef_app()?;

    let ndef = nfc::build_ndef(&nfc::sdm_url_template()?);
    let (picc_off, mac_off) = nfc::mirror_offsets(&ndef)?;
    println!("  picc offset {picc_off}, cmac offset {mac_off}");

    r.write_data(2, 0, &ndef)?;
    println!("  URL template rewritten");

    let mut s = r.authenticate(0, &ev2::FACTORY_KEY)?;
    r.enable_sdm(&mut s, 2, picc_off, mac_off, false)?;
    println!("  SDM reconfigured: meta read K2, file read K3");

    let raw = r.read_data(2, 0, ndef.len() as u32)?;
    let url = nfc::url_from_ndef(&raw);
    let (picc, cmac) = nfc::sun_params(&url)?;
    println!("  tag now emits https://{url}");
    println!("  picc {picc}");
    println!("  cmac {cmac}");
    Ok(())
}
