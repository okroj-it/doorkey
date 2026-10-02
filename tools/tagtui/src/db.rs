//! Optional Postgres link, used only to enrol a provisioned tag.
//!
//! Nothing else in the app needs it: reading, tapping and writing a tag all
//! work with no database. When it is not connected the enrolment SQL is shown
//! instead, to paste by hand.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow};
use postgres::{Client, NoTls};

pub struct Db {
    pub client: Option<Client>,
    pub status: String,
}

impl Db {
    pub fn new() -> Self {
        Self { client: None, status: "not connected".into() }
    }

    pub fn connect(&mut self, url: &str) {
        match Client::connect(url, NoTls) {
            Ok(mut c) => match c.query_one("select version()", &[]) {
                Ok(row) => {
                    let v: String = row.get(0);
                    self.status = format!("connected - {}", v.split_whitespace().take(2)
                        .collect::<Vec<_>>().join(" "));
                    self.client = Some(c);
                }
                Err(e) => {
                    self.status = format!("connected but query failed: {e}");
                    self.client = None;
                }
            },
            Err(e) => {
                self.status = format!("failed: {e}");
                self.client = None;
            }
        }
    }

    pub fn enrol(&mut self, uid: &[u8], label: &str, mac_key_enc: &[u8]) -> Result<()> {
        let c = self.client.as_mut().ok_or_else(|| anyhow!("not connected"))?;
        c.execute(
            "insert into tags (uid, label, mac_key_enc) values ($1, $2, $3)
             on conflict (uid) do update set label = excluded.label,
                                             mac_key_enc = excluded.mac_key_enc",
            &[&uid, &label, &mac_key_enc],
        )?;
        Ok(())
    }
}

/// Wrap K3 for storage. Matches unwrapKey() in src/auth/kek.ts:
/// nonce(12) || ciphertext || tag(16).
pub fn wrap_key(kek: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| anyhow!("KEK must be 32 bytes"))?;
    let mut nonce_bytes = [0u8; 12];
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce_bytes)?;
    }
    let nonce = Nonce::try_from(&nonce_bytes[..]).expect("12-byte nonce");
    let ct = cipher.encrypt(&nonce, plain).map_err(|_| anyhow!("wrap failed"))?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn sql_for(uid: &[u8], label: &str, wrapped: &[u8]) -> String {
    format!(
        "insert into tags (uid, label, mac_key_enc) values ('\\x{}', '{}', '\\x{}');",
        hex::encode(uid),
        label,
        hex::encode(wrapped)
    )
}
