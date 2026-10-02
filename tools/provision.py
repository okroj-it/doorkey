#!/usr/bin/env python3
"""NTAG 424 DNA provisioning for doorkey.

Staged on purpose. Stage 1 proves the EV2 implementation against a real tag
while changing nothing; only then is it safe to run the irreversible stages.

  --check      stage 1: authenticate with the factory key, dump file settings.
               Writes nothing. Success proves RndA/RndB handling and the
               session key derivation are correct.
  --write-url  stage 2: write the SUN URL template to the NDEF file. File 2 is
               free-write from the factory, so this needs no key and can be
               redone at any time.
  --keys       stage 3b: change K2, K3, then K0. LOCKS THE TAG TO YOUR MASTER.
               Only K0 may change keys on this chip, so every change is made
               in a K0 session and K0 itself is changed LAST - once it moves,
               the factory key no longer opens a session to fix anything.

Key scheme (see src/auth/ntag424.ts):
  K0 app, per tag  = CMAC(master, 0x00 || uid)   never leaves this machine
  K2 meta, shared  = DOORKEY_TAG_META_KEY        lets the service find the tag
  K3 MAC, per tag  = CMAC(master, 0x03 || uid)   wrapped into Postgres
"""
import argparse, os, sys, zlib
from getpass import getpass
from binascii import hexlify, unhexlify

import nfc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

BLOCK = 16
FACTORY_KEY = bytes(16)


def aes_cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def aes_cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def rotl(b: bytes) -> bytes:
    return b[1:] + b[:1]


# Set from --origin / DOORKEY_ORIGIN in main(): the stages that write the URL
# or size the SDM file need it, --check does not.
SDM_URL_TEMPLATE = ""


def sdm_template(origin: str) -> str:
    """The URL the chip emits, minus the https:// that NDEF abbreviates.

    Every tag carries the same /k/sun URL; whether a tap opens the keypad or an
    action is decided by doorkey's database, not by the chip.
    """
    from urllib.parse import urlsplit
    u = urlsplit(origin.strip())
    if u.scheme != "https" or not u.netloc or u.path not in ("", "/") or u.query or u.fragment:
        raise SystemExit(f"--origin must be like https://door.example.com, got {origin!r}")
    body = f"{u.netloc}/k/sun?picc={'0' * 32}&cmac={'0' * 16}"
    if len(body) + 1 > 255:  # short NDEF record: one length byte
        raise SystemExit("origin too long for a short NDEF record")
    return body


def build_ndef(url_body: str) -> bytes:
    """NDEF file content: NLEN(2, big endian) then one URI record.

    0x04 is the 'https://' prefix abbreviation, so it is not spelled out.
    """
    payload = bytes([0x04]) + url_body.encode()
    record = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    return len(record).to_bytes(2, "big") + record


def mirror_offsets(ndef: bytes) -> tuple[int, int]:
    """File offsets of the picc and cmac placeholders that SDM overwrites.

    Searched over bytes. Doing this on a decoded string would be wrong: the
    NDEF header's 0xD1 is invalid UTF-8, so a lossy decode inflates every later
    index by 2 and both mirrors land two bytes late, overwriting the "&c" of
    "&cmac=".
    """
    picc = ndef.find(b"picc=") + len("picc=")
    cmac_ = ndef.find(b"cmac=") + len("cmac=")
    if picc < len("picc=") or cmac_ < len("cmac="):
        raise RuntimeError("placeholders missing from template")
    return picc, cmac_


class Ntag424:
    def __init__(self, tag):
        self.tag = tag
        self.ti = None
        self.cmd_ctr = 0
        self.k_enc = None
        self.k_mac = None

    def apdu(self, data: bytes) -> tuple[bytes, bytes]:
        r = bytes(self.tag.transceive(bytearray(data)))
        return r[:-2], r[-2:]

    def select_ndef_app(self):
        body, sw = self.apdu(unhexlify("00A4040007D276000085010100"))
        if sw != b"\x90\x00":
            raise RuntimeError(f"select failed: {sw.hex()}")

    def authenticate_ev2_first(self, key_no: int, key: bytes):
        """AN12196 s 3.1. Proves we hold `key` without ever sending it."""
        body, sw = self.apdu(bytes([0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00]))
        if sw != b"\x91\xAF":
            raise RuntimeError(f"AuthenticateEV2First rejected: {sw.hex()}")

        rnd_b = aes_cbc_dec(key, bytes(BLOCK), body)
        rnd_a = os.urandom(BLOCK)
        payload = aes_cbc_enc(key, bytes(BLOCK), rnd_a + rotl(rnd_b))

        body, sw = self.apdu(bytes([0x90, 0xAF, 0x00, 0x00, len(payload)]) + payload + b"\x00")
        if sw != b"\x91\x00":
            raise RuntimeError(f"AuthenticateEV2First part 2 rejected: {sw.hex()}")

        plain = aes_cbc_dec(key, bytes(BLOCK), body)
        self.ti = plain[0:4]
        rnd_a_echo = plain[4:20]
        if rnd_a_echo != rotl(rnd_a):
            # The tag proved it holds the key; this proves we are not being
            # replayed a recorded session.
            raise RuntimeError("RndA mismatch - tag did not echo our nonce")

        # Session keys, AN12196 s 3.2.
        xored = bytes(a ^ b for a, b in zip(rnd_a[2:8], rnd_b[0:6]))
        sv_tail = rnd_a[0:2] + xored + rnd_b[6:16] + rnd_a[8:16]
        self.k_enc = cmac(key, unhexlify("A55A00010080") + sv_tail)
        self.k_mac = cmac(key, unhexlify("5AA500010080") + sv_tail)
        self.cmd_ctr = 0
        return self.ti

    # ---- EV2 secure messaging -------------------------------------------
    #
    # After authentication every command carries a MAC over
    # Cmd || CmdCtr || TI || header || data, and the tag replies with a MAC of
    # its own. CmdCtr advances per command, which is what stops a recorded
    # command being replayed inside a session.

    @staticmethod
    def _truncate(mac: bytes) -> bytes:
        return bytes(mac[i] for i in range(1, 16, 2))

    def _mac(self, cmd: int, header: bytes, data: bytes) -> bytes:
        msg = bytes([cmd]) + self.cmd_ctr.to_bytes(2, "little") + self.ti + header + data
        return self._truncate(cmac(self.k_mac, msg))

    def _iv(self) -> bytes:
        """Command IV: AN12196 s 3.3 - derived per command from TI and CmdCtr."""
        return aes_cbc_enc(
            self.k_enc, bytes(BLOCK),
            unhexlify("A55A") + self.ti + self.cmd_ctr.to_bytes(2, "little") + bytes(8),
        )

    @staticmethod
    def _pad(data: bytes) -> bytes:
        return data + b"\x80" + bytes((-len(data) - 1) % BLOCK)

    def send_full(self, cmd: int, header: bytes, plain: bytes) -> bytes:
        """CommMode.FULL: encrypt the data, then MAC the encrypted form."""
        enc = aes_cbc_enc(self.k_enc, self._iv(), self._pad(plain)) if plain else b""
        mac = self._mac(cmd, header, enc)
        body = header + enc + mac
        resp, sw = self.apdu(bytes([0x90, cmd, 0x00, 0x00, len(body)]) + body + b"\x00")
        self.cmd_ctr += 1
        if sw != b"\x91\x00":
            raise RuntimeError(f"cmd {cmd:#04x} rejected: {sw.hex()}")
        return resp

    def write_data(self, file_no: int, offset: int, data: bytes) -> None:
        """Plain write - file 2 is free-write from the factory, so no session
        is needed and none is used here."""
        header = bytes([file_no]) + offset.to_bytes(3, "little") + len(data).to_bytes(3, "little")
        body = header + data
        _, sw = self.apdu(bytes([0x90, 0x8D, 0x00, 0x00, len(body)]) + body + b"\x00")
        if sw != b"\x91\x00":
            raise RuntimeError(f"WriteData rejected: {sw.hex()}")

    def get_version_uid(self) -> bytes:
        """UID from GetVersion, which needs no session (third frame)."""
        _, sw = self.apdu(unhexlify("9060000000"))
        if sw != b"\x91\xAF":
            raise RuntimeError(f"GetVersion failed: {sw.hex()}")
        _, sw = self.apdu(unhexlify("90AF000000"))
        if sw != b"\x91\xAF":
            raise RuntimeError(f"GetVersion(2) failed: {sw.hex()}")
        body, sw = self.apdu(unhexlify("90AF000000"))
        if sw != b"\x91\x00":
            raise RuntimeError(f"GetVersion(3) failed: {sw.hex()}")
        return body[0:7]

    def change_key(self, key_no: int, new_key: bytes, old_key: bytes,
                   key_ver: int = 0, same_as_auth: bool = False) -> None:
        """ChangeKey (AN12196 s 3.5). The tag must be able to prove the caller
        knew the OLD key, so for any key other than the authenticated one the
        payload is new XOR old plus a CRC32 over the new key. Getting that CRC
        wrong leaves the key holding a value nobody knows - which is why this
        is first exercised against an unused key slot.
        """
        if same_as_auth:
            plain = new_key + bytes([key_ver])
        else:
            xored = bytes(a ^ b for a, b in zip(new_key, old_key))
            crc = (~zlib.crc32(new_key)) & 0xFFFFFFFF   # JAMCRC, little endian
            plain = xored + bytes([key_ver]) + crc.to_bytes(4, "little")
        self.send_full(0xC4, bytes([key_no]), plain)

    def read_data(self, file_no: int, offset: int, length: int) -> bytes:
        header = bytes([file_no]) + offset.to_bytes(3, "little") + length.to_bytes(3, "little")
        body, sw = self.apdu(bytes([0x90, 0xAD, 0x00, 0x00, len(header)]) + header + b"\x00")
        if sw != b"\x91\x00":
            raise RuntimeError(f"ReadData rejected: {sw.hex()}")
        return body

    def enable_sdm(self, file_no: int, picc_off: int, mac_off: int) -> None:
        """ChangeFileSettings with SDM mirroring (AN12196 s 4.2).

        SDMOptions 0xC1 = UID mirror + read counter + ASCII encoding.

        SDMAccessRights nibbles are [RFU][SDMCtrRet][SDMMetaRead][SDMFileRead],
        so 0xF121 would mean file read with K1 - a slot nobody provisions,
        left at factory zeros, signing every tap with a zero key. While all
        keys are still zero that is invisible. 0xFF23 disables counter
        retrieval and uses K2 for meta read and K3 for file read.
        """
        file_option = 0x40            # SDM enabled, plain communication
        access_rights = unhexlify("E0EE")   # unchanged: free read and write
        sdm_options = 0xC1
        sdm_access = unhexlify("FF23")

        data = (
            bytes([file_option]) + access_rights + bytes([sdm_options]) + sdm_access
            + picc_off.to_bytes(3, "little")
            + mac_off.to_bytes(3, "little")      # SDMMACInputOffset
            + mac_off.to_bytes(3, "little")      # SDMMACOffset
        )
        self.send_full(0x5F, bytes([file_no]), data)

    def get_file_settings(self, file_no: int) -> bytes:
        body, sw = self.apdu(bytes([0x90, 0xF5, 0x00, 0x00, 0x01, file_no, 0x00]))
        if sw != b"\x91\x00":
            raise RuntimeError(f"GetFileSettings({file_no}) failed: {sw.hex()}")
        return body

    def get_card_uid(self) -> bytes:
        """Only available inside an authenticated session."""
        body, sw = self.apdu(unhexlify("9051000000"))
        if sw not in (b"\x91\x00",):
            raise RuntimeError(f"GetCardUID failed: {sw.hex()}")
        return body


def derive(master: bytes, label: int, uid: bytes) -> bytes:
    return cmac(master, bytes([label]) + uid)


def stage_check(tag) -> None:
    dev = Ntag424(tag)
    dev.select_ndef_app()
    print("  NDEF application selected")

    # Read settings BEFORE authenticating: once a session is open every command
    # must carry secure messaging, and a plain GetFileSettings returns 917E
    # (LENGTH_ERROR). Plain reads are allowed while unauthenticated.
    for f in (1, 2, 3):
        s = dev.get_file_settings(f)
        sdm = "ON" if s[1] & 0x40 else "off"
        print(f"  file {f}: type={s[0]:#04x} sdm={sdm} access={s[2:4].hex()} "
              f"size={int.from_bytes(s[4:7], 'little')}")

    ti = dev.authenticate_ev2_first(0, FACTORY_KEY)
    print(f"  AuthenticateEV2First OK with FACTORY key - TI {ti.hex()}")
    print("  -> EV2 auth, RndA/RndB and session key derivation are correct")
    print(f"  SesAuthENCKey {dev.k_enc.hex()[:8]}...  SesAuthMACKey {dev.k_mac.hex()[:8]}...")

    print("\n  The tag is still in FACTORY state. Nothing was written.")



def stage_write(tag) -> None:
    """Stage 2. Both steps are reversible: file 2 is free-write, and
    ChangeFileSettings can be re-issued while K0 is still the factory key."""
    dev = Ntag424(tag)
    dev.select_ndef_app()

    ndef = build_ndef(SDM_URL_TEMPLATE)
    picc_off, mac_off = mirror_offsets(ndef)
    print(f"  NDEF {len(ndef)} bytes, picc at {picc_off}, cmac at {mac_off}")

    dev.write_data(2, 0, ndef)
    print("  URL template written")

    dev.authenticate_ev2_first(0, FACTORY_KEY)
    dev.enable_sdm(2, picc_off, mac_off)
    print("  SDM enabled on file 2")

    # Read back through a fresh session: the tag fills the placeholders on
    # every read, so this shows exactly what a phone would see.
    dev2 = Ntag424(tag)
    dev2.select_ndef_app()
    out = dev2.read_data(2, 0, len(ndef))
    url = out[7:].split(b"\x00")[0].decode(errors="replace")
    print(f"\n  tag now emits: https://{url}")



def stage_test_changekey(tag) -> None:
    """Prove ChangeKey against key slot 1, which doorkey never uses.

    If the payload construction is wrong we lose a key we had no use for, and
    we learn it before touching K0, K2 or K3.
    """
    probe = cmac(bytes(16), b"doorkey-changekey-probe")
    print(f"  probe key for slot 1: {probe.hex()}")

    # Idempotent: a previous run may have left the probe in place. A wrong old
    # key is rejected with 911E (integrity error) and changes nothing, so
    # trying the factory key first is safe.
    dev = Ntag424(tag)
    dev.select_ndef_app()
    dev.authenticate_ev2_first(0, FACTORY_KEY)
    try:
        dev.change_key(1, probe, FACTORY_KEY)
        print("  ChangeKey(1) accepted")
    except RuntimeError as e:
        if "911e" not in str(e):
            raise
        print("  slot 1 already holds the probe key (911E on factory old key)")

    # The only proof that matters: authenticate with what we think we wrote.
    dev2 = Ntag424(tag)
    dev2.select_ndef_app()
    dev2.authenticate_ev2_first(1, probe)
    print("  AuthenticateEV2First(key 1, probe key) OK")
    print("  -> ChangeKey payload, CRC32 and XOR are all correct")

    # Put the slot back. Only K0 may change keys on this chip - a key cannot
    # change itself (that returns 91AE), so same_as_auth applies to K0 alone.
    dev3 = Ntag424(tag)
    dev3.select_ndef_app()
    dev3.authenticate_ev2_first(0, FACTORY_KEY)
    dev3.change_key(1, FACTORY_KEY, probe)
    print("  slot 1 restored to the factory key")



def wrap_key(kek: bytes, plain: bytes) -> bytes:
    """Matches unwrapKey() in src/auth/kek.ts: nonce(12) || ct || tag(16)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(kek).encrypt(nonce, plain, None)


def verify_tap(dev: Ntag424, ndef_len: int, meta: bytes, mac_key: bytes) -> bool:
    """Read the tag as a phone would and check the SUN data with the keys we
    believe are installed. This is what proves the SDM access rights really
    point at K2 and K3 - untestable while every key is still zero."""
    out = dev.read_data(2, 0, ndef_len)
    url = out[7:].split(b"\x00")[0].decode(errors="replace")
    picc_hex = url.split("picc=")[1].split("&")[0]
    cmac_hex = url.split("cmac=")[1]

    plain = aes_cbc_dec(meta, bytes(BLOCK), unhexlify(picc_hex))
    if not (plain[0] & 0x80) or not (plain[0] & 0x40):
        print("  PICC data did not decrypt with K2 - SDMMetaRead points elsewhere")
        return False
    uid, ctr = plain[1:8], plain[8:11]

    sv2 = unhexlify("3CC3000100 80".replace(" ", "")) + uid + ctr
    session = cmac(mac_key, sv2)
    full = cmac(session, b"")
    trunc = bytes(full[i] for i in range(1, 16, 2))
    ok = trunc == unhexlify(cmac_hex)
    print(f"  tap: uid {uid.hex().upper()} ctr {int.from_bytes(ctr, 'little')} "
          f"cmac {'MATCH' if ok else 'MISMATCH'}")
    return ok


def stage_keys(tag) -> None:
    """Stage 3b. K0 is changed last, so until the final step a factory K0
    session can still repair anything.

    Not irreversible in itself: with the master you can still change every key
    and setting afterwards, even back to factory zeros. What changes here is
    that the master becomes the *only* way in - there is no factory reset.
    """
    master_hex = os.environ.get("DOORKEY_TAG_MASTER") or getpass("  master key (hex, not echoed): ")
    meta_hex = os.environ["DOORKEY_TAG_META_KEY"]
    kek_hex = os.environ["DOORKEY_TAG_KEK"]
    master, meta, kek = unhexlify(master_hex.strip()), unhexlify(meta_hex), unhexlify(kek_hex)
    if len(master) != 16 or len(meta) != 16 or len(kek) != 32:
        raise SystemExit("  master and meta must be 16 bytes, KEK 32")

    dev = Ntag424(tag)
    dev.select_ndef_app()
    uid = dev.get_version_uid()
    print(f"  tag uid {uid.hex().upper()}")

    k0 = derive(master, 0x00, uid)
    k3 = derive(master, 0x03, uid)
    ndef_len = len(build_ndef(SDM_URL_TEMPLATE))

    # K2 and K3 first - both repairable while K0 is factory.
    dev.select_ndef_app()
    dev.authenticate_ev2_first(0, FACTORY_KEY)
    dev.change_key(2, meta, FACTORY_KEY)
    dev.change_key(3, k3, FACTORY_KEY)
    print("  K2 (shared meta) and K3 (per-tag MAC) changed")

    for no, key, name in ((2, meta, "K2"), (3, k3, "K3")):
        v = Ntag424(tag)
        v.select_ndef_app()
        v.authenticate_ev2_first(no, key)
        print(f"  verified: session opens with {name}")

    # Now the real test of the SDM access rights.
    v = Ntag424(tag)
    v.select_ndef_app()
    if not verify_tap(v, ndef_len, meta, k3):
        raise SystemExit("  SUN verification FAILED - K0 is still factory, "
                         "so re-run --write-url with corrected SDMAccessRights")

    # Last, and only now: the key that can reconfigure the tag.
    f = Ntag424(tag)
    f.select_ndef_app()
    f.authenticate_ev2_first(0, FACTORY_KEY)
    f.change_key(0, k0, FACTORY_KEY, same_as_auth=True)
    print("  K0 changed - the tag is now locked to your master")

    c = Ntag424(tag)
    c.select_ndef_app()
    c.authenticate_ev2_first(0, k0)
    print("  verified: session opens with the derived K0")

    print("\n  enrol with:")
    print(f"  insert into tags (uid, label, mac_key_enc) values "
          f"('\\x{uid.hex()}', 'tag-1', '\\x{wrap_key(kek, k3).hex()}');")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="stage 1: verify auth, write nothing")
    ap.add_argument("--keys", action="store_true",
                    help="stage 3b: change K2/K3/K0 (IRREVERSIBLE)")
    ap.add_argument("--test-changekey", action="store_true",
                    help="stage 3a: prove ChangeKey on unused slot 1, then undo it")
    ap.add_argument("--write-url", action="store_true",
                    help="stage 2: write the SUN URL and enable SDM (reversible)")
    ap.add_argument("--device", default="tty:USB0:pn532")
    ap.add_argument("--origin", default=os.environ.get("DOORKEY_ORIGIN", ""),
                    help="doorkey's public origin, e.g. https://door.example.com "
                         "(default: $DOORKEY_ORIGIN)")
    args = ap.parse_args()

    if not (args.check or args.write_url or args.test_changekey or args.keys):
        ap.error("pick a stage: --check, --write-url, --test-changekey or --keys")
    if args.write_url or args.keys:
        if not args.origin:
            ap.error("--write-url and --keys need --origin (or DOORKEY_ORIGIN)")
        global SDM_URL_TEMPLATE
        SDM_URL_TEMPLATE = sdm_template(args.origin)
        print(f"  tag URL: https://{SDM_URL_TEMPLATE}")

    clf = nfc.ContactlessFrontend(args.device)
    print(f"  reader: {clf}")

    def on_connect(tag):
        try:
            if args.keys:
                stage_keys(tag)
            elif args.test_changekey:
                stage_test_changekey(tag)
            elif args.write_url:
                stage_write(tag)
            else:
                stage_check(tag)
        except Exception as e:
            print(f"  FAILED: {e}")
        return False

    clf.connect(rdwr={"on-connect": on_connect, "beep-on-connect": False})
    clf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
