//! Writing to Type 2 tags: an NDEF message, and password write protection.
//! Every operation checks the tag before its first write and reads back
//! what it wrote.

use anyhow::{Result, bail};

use crate::nfc::{self, Reader, TagKind};
use crate::type2::{self, Cc};

/// What a write found and did, for the log.
pub struct Written {
    pub uid: Vec<u8>,
    pub bytes: usize,
    /// The tag was protected and the derived password opened it.
    pub authenticated: bool,
}

/// The tag on the reader, checked to be a writable Type 2 tag.
struct Target {
    uid: Vec<u8>,
    cc: Cc,
    user: Vec<u8>,
    config: Option<type2::ConfigPages>,
    protected: bool,
}

fn target(r: &mut Reader) -> Result<Target> {
    let t = r.select()?;
    if t.kind() != TagKind::Type2 {
        bail!("not a Type 2 tag (SAK {:02X})", t.sak);
    }
    let d = r.read_type2()?;
    let cc = Cc::parse(&d.header[12..16]);
    if !cc.ndef_formatted {
        bail!("not NDEF-formatted — format it first");
    }
    if !cc.writable {
        bail!("the capability container marks this tag read-only");
    }
    if type2::static_locks(&d.header[8..12]) != [0, 0] {
        bail!("static lock bits are set — part of the tag is permanently read-only");
    }
    let config = type2::config_pages(cc.data_bytes);
    let mut protected = false;
    if let Some(p) = config {
        // Dynamic lock bytes sit on the page before CFG0.
        let around = r.t2_read(p.cfg0 - 1)?;
        if around[..3] != [0, 0, 0] {
            bail!("dynamic lock bits are set — part of the tag is permanently read-only");
        }
        let cfg0: [u8; 4] = around[4..8].try_into().expect("4 bytes");
        protected = type2::write_protected(&cfg0, p);
    }
    Ok(Target {
        uid: t.uid,
        cc,
        user: d.user,
        config,
        protected,
    })
}

/// PWD_AUTH with the password derived from the master, checking the PACK.
fn unlock(r: &mut Reader, uid: &[u8], master: Option<&[u8]>) -> Result<()> {
    let Some(master) = master else {
        bail!("the tag is write-protected — load the master key to write it");
    };
    let (pwd, pack) = nfc::tag_password(master, uid);
    match r.t2_auth(pwd) {
        Ok(got) if got == pack => Ok(()),
        Ok(_) => bail!("the tag accepted the password but answered with another PACK"),
        Err(_) => bail!("the tag refused this master's password — protected by someone else?"),
    }
}

/// Make `msg` the tag's NDEF message. Authenticates first when the tag is
/// write-protected.
pub fn write_ndef(r: &mut Reader, msg: &[u8], master: Option<&[u8]>) -> Result<Written> {
    let t = target(r)?;
    let area = type2::user_area_for(&t.user, t.cc.data_bytes, msg).map_err(anyhow::Error::msg)?;
    if t.protected {
        unlock(r, &t.uid, master)?;
    }
    for (i, page) in area.chunks(4).enumerate() {
        r.t2_write(
            type2::PROTECT_FROM + i as u8,
            page.try_into().expect("whole pages"),
        )?;
    }
    // Read back what was written; READ returns four pages at a time.
    let mut back = Vec::with_capacity(area.len() + 16);
    while back.len() < area.len() {
        back.extend_from_slice(&r.t2_read(type2::PROTECT_FROM + (back.len() / 4) as u8)?);
    }
    if back[..area.len()] != area[..] {
        bail!("read-back does not match what was written");
    }
    Ok(Written {
        uid: t.uid,
        bytes: area.len(),
        authenticated: t.protected,
    })
}
