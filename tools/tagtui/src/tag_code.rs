//! The tag code that enrols a provisioned tag without database access:
//! `dktag1.<uid hex>.<wrapped K3 hex>.<label base64url>`. Pasted into the
//! doorkey admin page (DNA tags) or `cli/doorkey.ts tag:add`. Must match
//! encodeTagCode in src/tag-code.ts - the test vector is shared.

/// base64url without padding (RFC 4648 §5).
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, &b| n << 8 | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn encode(uid: &[u8], wrapped: &[u8], label: &str) -> String {
    format!("dktag1.{}.{}.{}", hex::encode(uid), hex::encode(wrapped), base64url(label.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_shared_vector() {
        let uid = hex::decode("04de5f1eacc040").unwrap();
        let wrapped: Vec<u8> = (0..44).collect();
        assert_eq!(
            encode(&uid, &wrapped, "Front door"),
            "dktag1.04de5f1eacc040.000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b.RnJvbnQgZG9vcg"
        );
    }

    #[test]
    fn base64url_without_padding() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url("Garaż".as_bytes()), "R2FyYcW8");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }
}
