//! NTAG 424 DNA EV2 crypto, on RustCrypto primitives.
//!
//! The Python tool in ../provision.py hand-rolls AES-CMAC; here it comes from
//! the `cmac` crate instead. Values are cross-checked against that tool and
//! against the AN12196 vectors in ../../test/sun-crypto.test.ts.

use aes::Aes128;
use aes::cipher::KeyIvInit;
use anyhow::{Result, bail};
use cbc::{Decryptor, Encryptor};
use cmac::{Cmac, KeyInit, Mac};

pub const BLOCK: usize = 16;
pub const FACTORY_KEY: [u8; 16] = [0u8; 16];

pub fn cmac_aes(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut m = Cmac::<Aes128>::new_from_slice(key).expect("16-byte key");
    m.update(msg);
    m.finalize().into_bytes().into()
}

fn arr16(b: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    a
}

pub fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    use aes::cipher::block_padding::NoPadding;
    use cbc::cipher::BlockModeEncrypt;
    let (k, v) = (arr16(key), arr16(iv));
    let enc = Encryptor::<Aes128>::new(&k.into(), &v.into());
    enc.encrypt_padded_vec::<NoPadding>(data)
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::block_padding::NoPadding;
    use cbc::cipher::BlockModeDecrypt;
    let (k, v) = (arr16(key), arr16(iv));
    let dec = Decryptor::<Aes128>::new(&k.into(), &v.into());
    match dec.decrypt_padded_vec::<NoPadding>(data) {
        Ok(v) => Ok(v),
        Err(_) => bail!("CBC decrypt failed"),
    }
}

fn rotl(b: &[u8]) -> Vec<u8> {
    let mut v = b[1..].to_vec();
    v.push(b[0]);
    v
}

/// An authenticated EV2 session. Holds what every later command needs.
pub struct Session {
    pub ti: [u8; 4],
    pub k_enc: [u8; 16],
    pub k_mac: [u8; 16],
    pub cmd_ctr: u16,
}

/// Session keys from the two nonces (AN12196 s 3.2).
pub fn session_keys(key: &[u8], rnd_a: &[u8], rnd_b: &[u8]) -> ([u8; 16], [u8; 16]) {
    let xored: Vec<u8> = rnd_a[2..8]
        .iter()
        .zip(&rnd_b[0..6])
        .map(|(a, b)| a ^ b)
        .collect();

    let mut tail = Vec::with_capacity(26);
    tail.extend_from_slice(&rnd_a[0..2]);
    tail.extend_from_slice(&xored);
    tail.extend_from_slice(&rnd_b[6..16]);
    tail.extend_from_slice(&rnd_a[8..16]);

    let sv = |prefix: &[u8]| -> [u8; 16] {
        let mut m = prefix.to_vec();
        m.extend_from_slice(&tail);
        cmac_aes(key, &m)
    };
    (
        sv(&[0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]),
        sv(&[0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]),
    )
}

pub fn decrypt_challenge(key: &[u8], enc_rnd_b: &[u8]) -> Result<Vec<u8>> {
    cbc_decrypt(key, &[0u8; BLOCK], enc_rnd_b)
}

/// The second half of the handshake: E(key, RndA || RndB').
pub fn challenge_response(key: &[u8], rnd_a: &[u8], rnd_b: &[u8]) -> Vec<u8> {
    let mut plain = rnd_a.to_vec();
    plain.extend_from_slice(&rotl(rnd_b));
    cbc_encrypt(key, &[0u8; BLOCK], &plain)
}

/// Confirms the tag echoed our own nonce, so this is not a replayed session.
pub fn check_echo(rnd_a: &[u8], echoed: &[u8]) -> bool {
    rotl(rnd_a) == echoed
}

pub struct Picc {
    pub uid: [u8; 7],
    pub read_counter: u32,
}

pub fn decrypt_picc(meta_key: &[u8], picc_enc: &[u8]) -> Result<Picc> {
    if picc_enc.len() != 16 {
        bail!("picc must be 16 bytes");
    }
    let p = cbc_decrypt(meta_key, &[0u8; BLOCK], picc_enc)?;
    if p[0] & 0x80 == 0 {
        bail!("no UID in PICC data - SDMMetaRead key is wrong");
    }
    if p[0] & 0x40 == 0 {
        bail!("no read counter in PICC data");
    }
    let mut uid = [0u8; 7];
    uid.copy_from_slice(&p[1..8]);
    Ok(Picc {
        uid,
        read_counter: u32::from(p[8]) | u32::from(p[9]) << 8 | u32::from(p[10]) << 16,
    })
}

/// Session MAC key then the tap CMAC, of which the tag emits every other byte.
pub fn sun_mac(mac_key: &[u8], picc: &Picc, message: &[u8]) -> [u8; 8] {
    let mut sv2 = vec![0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80];
    sv2.extend_from_slice(&picc.uid);
    sv2.push((picc.read_counter & 0xff) as u8);
    sv2.push(((picc.read_counter >> 8) & 0xff) as u8);
    sv2.push(((picc.read_counter >> 16) & 0xff) as u8);

    let session = cmac_aes(mac_key, &sv2);
    let full = cmac_aes(&session, message);
    let mut out = [0u8; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = full[i * 2 + 1];
    }
    out
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn cmac_rfc4493() {
        let k = hx("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(hex::encode(cmac_aes(&k, &[])), "bb1d6929e95937287fa37d129b756746");
        assert_eq!(
            hex::encode(cmac_aes(&k, &hx("6bc1bee22e409f96e93d7e117393172a"))),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
    }

    /// AN12196 worked example, same vector as test/sun-crypto.test.ts.
    #[test]
    fn picc_and_mac_an12196() {
        let zero = [0u8; 16];
        let p = decrypt_picc(&zero, &hx("EF963FF7828658A599F3041510671E88")).unwrap();
        assert_eq!(hex::encode_upper(p.uid), "04DE5F1EACC040");
        assert_eq!(p.read_counter, 61);
        assert_eq!(hex::encode_upper(sun_mac(&zero, &p, &[])), "94EED9EE65337086");
    }

    /// The real tap captured from tag 1 while its keys were still factory.
    #[test]
    fn real_tap_from_tag_one() {
        let zero = [0u8; 16];
        let p = decrypt_picc(&zero, &hx("C4CE157FB365BE1FE77257E726C2D4C9")).unwrap();
        assert_eq!(hex::encode_upper(p.uid), "045891521F1E90");
        assert_eq!(p.read_counter, 1);
        assert!(ct_eq(&sun_mac(&zero, &p, &[]), &hx("7E8E89B295427FBF")));
    }
}
