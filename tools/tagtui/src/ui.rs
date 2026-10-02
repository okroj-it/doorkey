//! The screen and the key handling.

use std::time::Duration;

use anyhow::Result;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Cell, List, ListItem, Padding, Paragraph, Row, Table, Tabs, Wrap,
};

/// One palette, used everywhere, so the screen reads as a single thing.
mod theme {
    use ratatui::style::Color;
    pub const ACCENT: Color = Color::Rgb(122, 162, 247);
    pub const GOOD: Color = Color::Rgb(158, 206, 106);
    pub const BAD: Color = Color::Rgb(247, 118, 142);
    pub const WARN: Color = Color::Rgb(224, 175, 104);
    pub const DIM: Color = Color::Rgb(86, 95, 137);
    pub const TEXT: Color = Color::Rgb(192, 202, 245);
    pub const FRAME: Color = Color::Rgb(61, 68, 102);
}

/// A bordered panel in the house style.
fn panel(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(theme::FRAME))
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            format!(" {title} "),
            Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
        ))
}

/// label:value, for the status row and the forms.
fn chip(label: &str, value: String, colour: Color) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!("{label} "), Style::new().fg(theme::DIM)),
        Span::styled(value, Style::new().fg(colour).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
    ]
}

fn key(k: &str, what: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!(" {k} "), Style::new().bg(theme::FRAME).fg(theme::TEXT)),
        Span::styled(format!(" {what}   "), Style::new().fg(theme::DIM)),
    ]
}

use crate::db::{self, Db};
use crate::ev2::{self, FACTORY_KEY};
use crate::nfc::{self, Reader};

const TABS: [&str; 5] = ["Reader", "Tag", "Tap", "Write", "Database"];

#[derive(PartialEq, Clone, Copy)]
enum Field {
    Master,
    Meta,
    Kek,
    DbUrl,
    Label,
}

impl Field {
    fn name(self) -> &'static str {
        match self {
            Field::Master => "master key (hex, 32 chars)",
            Field::Meta => "shared meta key K2 (hex, 32 chars)",
            Field::Kek => "KEK (hex, 64 chars)",
            Field::DbUrl => "postgres url",
            Field::Label => "tag label",
        }
    }
}

#[derive(Clone, Copy)]
enum Pending {
    WriteUrl,
    ChangeKeys,
}

pub struct App {
    tab: usize,
    devices: Vec<String>,
    dev_sel: usize,
    reader: Option<Reader>,
    log: Vec<Line<'static>>,
    tag_lines: Vec<Line<'static>>,
    tag_ident: Vec<Line<'static>>,
    /// file no, sdm on, access rights, size
    tag_files: Vec<(u8, bool, String, u32)>,
    tap_ok: Option<bool>,
    tap_lines: Vec<Line<'static>>,
    write_lines: Vec<Line<'static>>,
    master: String,
    meta: String,
    kek: String,
    db_url: String,
    label: String,
    editing: Option<Field>,
    pending: Option<Pending>,
    db: Db,
    last_uid: Option<Vec<u8>>,
    last_wrapped: Option<Vec<u8>>,
    started: std::time::Instant,
    quit: bool,
}

impl App {
    pub fn new() -> Self {
        let mut app = Self {
            tab: 0,
            devices: Vec::new(),
            dev_sel: 0,
            reader: None,
            log: Vec::new(),
            tag_lines: Vec::new(),
            tag_ident: Vec::new(),
            tag_files: Vec::new(),
            tap_ok: None,
            tap_lines: Vec::new(),
            write_lines: Vec::new(),
            master: String::new(),
            meta: std::env::var("DOORKEY_TAG_META_KEY").unwrap_or_default(),
            kek: std::env::var("DOORKEY_TAG_KEK").unwrap_or_default(),
            db_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            label: "tag-1".into(),
            editing: None,
            pending: None,
            db: Db::new(),
            last_uid: None,
            last_wrapped: None,
            started: std::time::Instant::now(),
            quit: false,
        };
        app.info("ready — reading and tapping never write; the two write actions ask first");
        app.enumerate();
        // Connect straight away when DATABASE_URL is set. Waiting for 'c' made
        // it easy to press 'i' while still offline, which only prints the SQL
        // and looks indistinguishable from having enrolled.
        if !app.db_url.is_empty() {
            let url = app.db_url.clone();
            app.db.connect(&url);
            let st = app.db.status.clone();
            if app.db.client.is_some() {
                app.ok(&format!("postgres {st}"));
            } else {
                app.err(&format!("postgres {st}"));
            }
        }
        app
    }

    // ---- logging --------------------------------------------------------

    fn push(&mut self, glyph: &'static str, s: String, colour: Color) {
        let t = self.started.elapsed().as_secs();
        self.log.push(Line::from(vec![
            Span::styled(format!("{:02}:{:02} ", t / 60, t % 60), Style::new().fg(theme::DIM)),
            Span::styled(format!("{glyph} "), Style::new().fg(colour)),
            Span::styled(s, Style::new().fg(theme::TEXT)),
        ]));
        if self.log.len() > 200 {
            self.log.remove(0);
        }
    }
    fn info(&mut self, s: &str) {
        self.push("·", s.to_string(), theme::DIM);
    }
    fn ok(&mut self, s: &str) {
        self.push("✓", s.to_string(), theme::GOOD);
    }
    fn err(&mut self, s: &str) {
        self.push("✗", s.to_string(), theme::BAD);
    }

    // ---- actions --------------------------------------------------------

    fn enumerate(&mut self) {
        match nfc::list_devices() {
            Ok(d) if d.is_empty() => self.err("no readers found"),
            Ok(d) => {
                self.ok(&format!("{} reader(s) found", d.len()));
                self.devices = d;
            }
            Err(e) => self.err(&format!("enumerate: {e}")),
        }
    }

    fn open_reader(&mut self) {
        let cs = self.devices.get(self.dev_sel).cloned();
        match Reader::open(cs.as_deref()) {
            Ok(r) => {
                let n = r.name.clone();
                self.reader = Some(r);
                self.ok(&format!("opened {n}"));
            }
            Err(e) => self.err(&format!("open: {e}")),
        }
    }

    /// Everything the tag will tell us without a single write.
    fn read_tag(&mut self) {
        let Some(r) = self.reader.as_mut() else {
            self.err("open a reader first (Reader tab, 'o')");
            return;
        };
        let mut ident = Vec::new();
        let mut files = Vec::new();
        let row = |k: &str, v: String| {
            Line::from(vec![
                Span::styled(format!("{k:<12}"), Style::new().fg(theme::DIM)),
                Span::styled(v, Style::new().fg(theme::TEXT)),
            ])
        };
        let res = (|| -> Result<Vec<u8>> {
            let t = r.select()?;
            ident.push(row("UID", hex::encode_upper(&t.uid)));
            ident.push(row("SAK", format!("{:02X}", t.sak)));
            ident.push(row("ATS", hex::encode_upper(&t.ats)));
            r.select_ndef_app()?;
            let vuid = r.get_version_uid()?;
            ident.push(row("GetVersion", hex::encode_upper(vuid)));
            for f in 1u8..=3 {
                let s = r.file_settings(f)?;
                let sdm = s.len() > 1 && s[1] & 0x40 != 0;
                let size = if s.len() >= 7 {
                    u32::from(s[4]) | u32::from(s[5]) << 8 | u32::from(s[6]) << 16
                } else {
                    0
                };
                files.push((f, sdm, hex::encode_upper(&s[2..4.min(s.len())]), size));
            }
            Ok(vuid.to_vec())
        })();

        match res {
            Ok(uid) => {
                self.last_uid = Some(uid);
                self.tag_ident = ident;
                self.tag_files = files;
                self.tag_lines = vec![Line::from("read")];
                self.ok("tag read — nothing written");
            }
            Err(e) => self.err(&format!("read: {e}")),
        }
    }

    /// Read the tag exactly as a phone would and verify the SUN data.
    fn simulate_tap(&mut self) {
        let master = self.master.clone();
        let meta_hex = self.meta.clone();
        let Some(r) = self.reader.as_mut() else {
            self.err("open a reader first (Reader tab, 'o')");
            return;
        };

        let mut out = Vec::new();
        let mut uid_seen: Option<Vec<u8>> = None;
        let res = (|| -> Result<bool> {
            r.select()?;
            r.select_ndef_app()?;
            let ndef_len = nfc::build_ndef(&nfc::sdm_url_template()?).len() as u32;
            let data = r.read_data(2, 0, ndef_len)?;

            let url = nfc::url_from_ndef(&data);
            out.push(Line::from(vec![
                Span::styled("https://", Style::new().fg(theme::DIM)),
                Span::styled(url.clone(), Style::new().fg(theme::TEXT)),
            ]));
            let (picc_hex, cmac_hex) = nfc::sun_params(&url)?;

            // Factory tags still hold zero keys; a provisioned tag needs the
            // shared meta key and a K3 derived from the master.
            let (meta_key, note) = if meta_hex.len() == 32 {
                (hex::decode(&meta_hex)?, "shared meta key")
            } else {
                (FACTORY_KEY.to_vec(), "factory zero key")
            };
            out.push(Line::from(format!("  decrypting PICC with the {note}")));

            let picc = ev2::decrypt_picc(&meta_key, &hex::decode(&picc_hex)?)?;
            uid_seen = Some(picc.uid.to_vec());
            out.push(Line::from(format!(
                "  UID {}   read counter {}",
                hex::encode_upper(picc.uid),
                picc.read_counter
            )));

            let mac_key = if master.len() == 32 {
                nfc::derive_key(&hex::decode(&master)?, 0x03, &picc.uid).to_vec()
            } else {
                FACTORY_KEY.to_vec()
            };
            let expect = ev2::sun_mac(&mac_key, &picc, &[]);
            let got = hex::decode(&cmac_hex)?;
            let ok = ev2::ct_eq(&expect, &got);
            out.push(Line::from(format!(
                "  CMAC {} vs {} on the tag",
                hex::encode_upper(expect),
                hex::encode_upper(&got)
            )));
            Ok(ok)
        })();

        match res {
            Ok(ok) => {
                self.tap_ok = Some(ok);
                if uid_seen.is_some() {
                    self.last_uid = uid_seen.clone();
                }
                self.tap_lines = out;
                if ok {
                    self.ok("tap verified — doorkey would accept this");
                } else {
                    self.err("tap did NOT verify — wrong keys, or SDM points elsewhere");
                }
            }
            Err(e) => {
                self.tap_ok = None;
                self.tap_lines = out;
                self.err(&format!("tap: {e}"));
            }
        }
    }

    /// Reversible: writes the URL template and turns SDM on.
    ///
    /// Authenticates with the derived K0 when a master is loaded, so this also
    /// works on an already-provisioned tag; falls back to the factory key for
    /// a fresh one.
    fn write_url(&mut self) {
        let master_hex = self.master.clone();
        let Some(r) = self.reader.as_mut() else {
            self.err("open a reader first");
            return;
        };
        let res = (|| -> Result<()> {
            r.select()?;
            r.select_ndef_app()?;
            let uid = r.get_version_uid()?;
            let ndef = nfc::build_ndef(&nfc::sdm_url_template()?);
            let (picc_off, mac_off) = nfc::mirror_offsets(&ndef)?;
            r.write_data(2, 0, &ndef)?;

            let k0 = if master_hex.len() == 32 {
                nfc::derive_key(&hex::decode(&master_hex)?, 0x00, &uid)
            } else {
                FACTORY_KEY
            };
            let mut s = r.authenticate(0, &k0)?;
            r.enable_sdm(&mut s, 2, picc_off, mac_off, false)?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                self.ok("URL written and SDM enabled (reversible)");
                self.write_lines = vec![Line::from(
                    "  URL template written, SDM on. Try the Tap tab now.",
                )];
            }
            Err(e) => self.err(&format!("write url: {e}")),
        }
    }

    /// Irreversible. K2 and K3 first, verified by a real tap, then K0 last.
    fn change_keys(&mut self) {
        let (master_hex, meta_hex, kek_hex) =
            (self.master.clone(), self.meta.clone(), self.kek.clone());
        if master_hex.len() != 32 || meta_hex.len() != 32 || kek_hex.len() != 64 {
            self.err("need master (32 hex), meta (32 hex) and KEK (64 hex)");
            return;
        }
        let Some(r) = self.reader.as_mut() else {
            self.err("open a reader first");
            return;
        };

        let mut out = Vec::new();
        let res = (|| -> Result<(Vec<u8>, Vec<u8>)> {
            let master = hex::decode(&master_hex)?;
            let meta = hex::decode(&meta_hex)?;
            let kek = hex::decode(&kek_hex)?;

            r.select()?;
            r.select_ndef_app()?;
            let uid = r.get_version_uid()?;
            let k0 = nfc::derive_key(&master, 0x00, &uid);
            let k3 = nfc::derive_key(&master, 0x03, &uid);
            out.push(Line::from(format!("  tag {}", hex::encode_upper(uid))));

            // Resumable: a tag can be part-provisioned already, because the
            // SUN gate below deliberately stops before K0 when something is
            // wrong. Probe what is installed rather than assuming factory.
            let need_k2 = !r.key_opens(2, &meta);
            let need_k3 = !r.key_opens(3, &k3);
            let need_k0 = !r.key_opens(0, &k0);
            let admin = if need_k0 { FACTORY_KEY } else { k0 };

            if need_k2 || need_k3 {
                r.select()?;
                r.select_ndef_app()?;
                let mut s = r.authenticate(0, &admin)?;
                if need_k2 {
                    r.change_key(&mut s, 2, &meta, &FACTORY_KEY, false)?;
                }
                if need_k3 {
                    r.change_key(&mut s, 3, &k3, &FACTORY_KEY, false)?;
                }
            }
            out.push(Line::from(format!(
                "  K2 {}   K3 {}",
                if need_k2 { "changed" } else { "already set" },
                if need_k3 { "changed" } else { "already set" },
            )));

            r.select()?;
            r.select_ndef_app()?;
            r.authenticate(2, &meta)?;
            r.select()?;
            r.select_ndef_app()?;
            r.authenticate(3, &k3)?;
            out.push(Line::from("  verified: sessions open with K2 and K3"));

            // Proves the SDM access rights really point at K2 and K3 - which
            // cannot be tested while every key is still zero, since any slot
            // then verifies. K0 is untouched here, so a failure is repairable.
            r.select()?;
            r.select_ndef_app()?;
            let ndef_len = nfc::build_ndef(&nfc::sdm_url_template()?).len() as u32;
            let data = r.read_data(2, 0, ndef_len)?;
            let (picc_hex, cmac_hex) = nfc::sun_params(&nfc::url_from_ndef(&data))?;
            let picc = ev2::decrypt_picc(&meta, &hex::decode(&picc_hex)?)?;
            if !ev2::ct_eq(&ev2::sun_mac(&k3, &picc, &[]), &hex::decode(&cmac_hex)?) {
                anyhow::bail!(
                    "SUN check failed - K0 is untouched, so press u to rewrite the URL and SDM"
                );
            }
            out.push(Line::from("  verified: a real tap checks out with the new keys"));

            if need_k0 {
                r.select()?;
                r.select_ndef_app()?;
                let mut s = r.authenticate(0, &FACTORY_KEY)?;
                r.change_key(&mut s, 0, &k0, &FACTORY_KEY, true)?;
                r.select()?;
                r.select_ndef_app()?;
                r.authenticate(0, &k0)?;
                out.push(Line::from("  K0 changed and verified — tag locked to your master"));
            } else {
                out.push(Line::from("  K0 already set to your derived key"));
            }

            Ok((uid.to_vec(), db::wrap_key(&kek, &k3)?))
        })();

        match res {
            Ok((uid, wrapped)) => {
                out.push(Line::from(Span::styled(
                    "  PROVISIONED",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                )));
                self.last_uid = Some(uid);
                self.last_wrapped = Some(wrapped);
                self.write_lines = out;
                self.ok("provisioned - enrol it on the Database tab");
            }
            Err(e) => {
                self.write_lines = out;
                self.err(&format!("provision: {e}"));
            }
        }
    }

    /// Enrol the tag on the reader.
    ///
    /// K3 is CMAC(master, 03 || UID), so it can be recomputed at any time from
    /// the tag itself - enrolment does not have to happen in the same session
    /// that provisioned it, and quitting the app loses nothing.
    fn enrol(&mut self) {
        let have = (self.last_uid.clone(), self.last_wrapped.clone());
        let (uid, wrapped) = match have {
            (Some(u), Some(w)) => (u, w),
            _ => match self.derive_for_tag_on_reader() {
                Ok(pair) => {
                    self.last_uid = Some(pair.0.clone());
                    self.last_wrapped = Some(pair.1.clone());
                    pair
                }
                Err(e) => {
                    self.err(&format!("enrol: {e}"));
                    return;
                }
            },
        };

        let label = self.label.clone();
        if self.db.client.is_none() {
            self.err("not connected — press c, or copy the SQL shown below");
            return;
        }
        match self.db.enrol(&uid, &label, &wrapped) {
            Ok(()) => self.ok(&format!("enrolled {} as '{label}'", hex::encode_upper(&uid))),
            Err(e) => self.err(&format!("enrol: {e}")),
        }
    }

    /// Read the UID off the reader and re-derive this tag's wrapped K3.
    fn derive_for_tag_on_reader(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.master.len() != 32 {
            anyhow::bail!("enter the master key (m) so K3 can be derived");
        }
        if self.kek.len() != 64 {
            anyhow::bail!("enter the KEK (e) so K3 can be wrapped");
        }
        let master = hex::decode(&self.master)?;
        let kek = hex::decode(&self.kek)?;
        let r = self
            .reader
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("open a reader first"))?;
        r.select()?;
        r.select_ndef_app()?;
        let uid = r.get_version_uid()?;
        let k3 = nfc::derive_key(&master, 0x03, &uid);
        Ok((uid.to_vec(), db::wrap_key(&kek, &k3)?))
    }

    // ---- event loop -----------------------------------------------------

    pub fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(200))?
                && let Event::Key(k) = event::read()?
                    && k.kind == KeyEventKind::Press {
                        self.on_key(k.code);
                    }
        }
        Ok(())
    }

    fn on_key(&mut self, code: KeyCode) {
        // Text entry swallows everything until Enter or Esc.
        if let Some(field) = self.editing {
            match code {
                KeyCode::Enter | KeyCode::Esc => self.editing = None,
                KeyCode::Backspace => {
                    self.field_mut(field).pop();
                }
                KeyCode::Char(c) => self.field_mut(field).push(c),
                _ => {}
            }
            return;
        }

        // A pending irreversible action waits for y/n.
        if let Some(p) = self.pending {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.pending = None;
                    match p {
                        Pending::WriteUrl => self.write_url(),
                        Pending::ChangeKeys => self.change_keys(),
                    }
                }
                _ => {
                    self.pending = None;
                    self.info("cancelled");
                }
            }
            return;
        }

        match code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Tab | KeyCode::Right => self.tab = (self.tab + 1) % TABS.len(),
            KeyCode::BackTab | KeyCode::Left => {
                self.tab = (self.tab + TABS.len() - 1) % TABS.len()
            }
            KeyCode::Char(c @ '1'..='5') => self.tab = c as usize - '1' as usize,
            _ => match self.tab {
                0 => match code {
                    KeyCode::Char('e') => self.enumerate(),
                    KeyCode::Char('o') => self.open_reader(),
                    KeyCode::Down | KeyCode::Char('j') => {
                        if self.dev_sel + 1 < self.devices.len() {
                            self.dev_sel += 1;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => self.dev_sel = self.dev_sel.saturating_sub(1),
                    _ => {}
                },
                1 => {
                    if code == KeyCode::Char('r') {
                        self.read_tag()
                    }
                }
                2 => {
                    if code == KeyCode::Char('t') {
                        self.simulate_tap()
                    }
                }
                3 => match code {
                    KeyCode::Char('m') => self.editing = Some(Field::Master),
                    KeyCode::Char('s') => self.editing = Some(Field::Meta),
                    KeyCode::Char('e') => self.editing = Some(Field::Kek),
                    KeyCode::Char('u') => self.pending = Some(Pending::WriteUrl),
                    KeyCode::Char('K') => self.pending = Some(Pending::ChangeKeys),
                    _ => {}
                },
                4 => match code {
                    KeyCode::Char('u') => self.editing = Some(Field::DbUrl),
                    KeyCode::Char('l') => self.editing = Some(Field::Label),
                    KeyCode::Char('c') => {
                        let url = self.db_url.clone();
                        self.db.connect(&url);
                        let st = self.db.status.clone();
                        if self.db.client.is_some() {
                            self.ok(&st)
                        } else {
                            self.err(&st)
                        }
                    }
                    KeyCode::Char('i') => self.enrol(),
                    _ => {}
                },
                _ => {}
            },
        }
    }

    fn field_mut(&mut self, f: Field) -> &mut String {
        match f {
            Field::Master => &mut self.master,
            Field::Meta => &mut self.meta,
            Field::Kek => &mut self.kek,
            Field::DbUrl => &mut self.db_url,
            Field::Label => &mut self.label,
        }
    }

    // ---- rendering ------------------------------------------------------

    fn draw(&mut self, f: &mut ratatui::Frame) {
        let [head, status, body, logs, foot] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .areas(f.area());

        self.draw_head(f, head);
        self.draw_status(f, status);

        match self.tab {
            0 => self.draw_reader(f, body),
            1 => self.draw_tag(f, body),
            2 => self.draw_tap(f, body),
            3 => self.draw_write(f, body),
            _ => self.draw_db(f, body),
        }

        // Last, so it is painted over whatever is underneath.
        if let Some(p) = self.pending {
            self.draw_confirm(f, body, p);
        }

        f.render_widget(
            Paragraph::new(self.log.clone())
                .block(panel("Log"))
                .wrap(Wrap { trim: false }),
            logs,
        );
        self.draw_foot(f, foot);
    }

    fn draw_head(&self, f: &mut ratatui::Frame, area: Rect) {
        let titles: Vec<Line> = TABS
            .iter()
            .enumerate()
            .map(|(i, t)| Line::from(format!(" {} {t} ", i + 1)))
            .collect();
        f.render_widget(
            Tabs::new(titles)
                .select(self.tab)
                .divider(symbols::DOT)
                .style(Style::new().fg(theme::DIM))
                .highlight_style(
                    Style::new()
                        .fg(Color::Black)
                        .bg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                )
                .block(
                    Block::bordered()
                        .border_type(BorderType::Rounded)
                        .border_style(Style::new().fg(theme::FRAME))
                        .title(Span::styled(
                            " tagtui ",
                            Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
                        ))
                        .title_top(
                            Line::from(Span::styled(
                                " NTAG 424 DNA · doorkey ",
                                Style::new().fg(theme::DIM),
                            ))
                            .right_aligned(),
                        ),
                ),
            area,
        );
    }

    /// One line that always says what state the hardware and database are in.
    fn draw_status(&self, f: &mut ratatui::Frame, area: Rect) {
        let mut spans = vec![Span::raw(" ")];
        match &self.reader {
            Some(r) => spans.extend(chip("reader", r.port.clone(), theme::GOOD)),
            None => spans.extend(chip("reader", "closed".into(), theme::BAD)),
        }
        match &self.last_uid {
            Some(u) => spans.extend(chip("tag", hex::encode_upper(u), theme::GOOD)),
            None => spans.extend(chip("tag", "none read".into(), theme::DIM)),
        }
        spans.extend(chip(
            "keys",
            if self.master.len() == 32 { "master loaded".into() } else { "factory".to_string() },
            if self.master.len() == 32 { theme::WARN } else { theme::DIM },
        ));
        spans.extend(chip(
            "db",
            if self.db.client.is_some() { "connected".into() } else { "offline".to_string() },
            if self.db.client.is_some() { theme::GOOD } else { theme::DIM },
        ));
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_foot(&self, f: &mut ratatui::Frame, area: Rect) {
        let spans = match self.editing {
            Some(fd) => vec![
                Span::styled(
                    format!(" {} ", fd.name()),
                    Style::new().bg(theme::WARN).fg(Color::Black).add_modifier(Modifier::BOLD),
                ),
                Span::styled("  Enter accept · Esc cancel", Style::new().fg(theme::DIM)),
            ],
            None => {
                let mut v = vec![Span::raw(" ")];
                v.extend(key("1-5", "tabs"));
                match self.tab {
                    0 => {
                        v.extend(key("e", "enumerate"));
                        v.extend(key("o", "open"));
                    }
                    1 => v.extend(key("r", "read tag")),
                    2 => v.extend(key("t", "simulate tap")),
                    3 => {
                        v.extend(key("m/s/e", "secrets"));
                        v.extend(key("u", "write url"));
                        v.extend(key("K", "change keys"));
                    }
                    _ => {
                        v.extend(key("c", "connect"));
                        v.extend(key("i", "enrol"));
                    }
                }
                v.extend(key("q", "quit"));
                v
            }
        };
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_reader(&self, f: &mut ratatui::Frame, area: Rect) {
        let items: Vec<ListItem> = if self.devices.is_empty() {
            vec![ListItem::new(Line::from(Span::styled(
                "no readers found — press e",
                Style::new().fg(theme::DIM),
            )))]
        } else {
            self.devices
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let selected = i == self.dev_sel;
                    let (marker, style) = if selected {
                        ("▸ ", Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD))
                    } else {
                        ("  ", Style::new().fg(theme::TEXT))
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(marker, style),
                        Span::styled(d.clone(), style),
                    ]))
                })
                .collect()
        };
        f.render_widget(List::new(items).block(panel("Readers")), area);
    }

    fn draw_tag(&self, f: &mut ratatui::Frame, area: Rect) {
        if self.tag_lines.is_empty() {
            f.render_widget(hint("press r to read the tag — this never writes"), area);
            return;
        }
        let [left, right] = Layout::horizontal([Constraint::Percentage(45), Constraint::Min(30)])
            .areas(area);
        f.render_widget(
            Paragraph::new(self.tag_ident.clone())
                .block(panel("Identity"))
                .wrap(Wrap { trim: false }),
            left,
        );

        let rows: Vec<Row> = self
            .tag_files
            .iter()
            .map(|(no, sdm, access, size)| {
                Row::new(vec![
                    Cell::from(format!("{no}")),
                    Cell::from(if *sdm { "on" } else { "—" }).style(Style::new().fg(
                        if *sdm { theme::GOOD } else { theme::DIM },
                    )),
                    Cell::from(access.clone()),
                    Cell::from(format!("{size}")),
                ])
            })
            .collect();
        f.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(5),
                    Constraint::Length(5),
                    Constraint::Length(8),
                    Constraint::Length(6),
                ],
            )
            .header(
                Row::new(vec!["file", "sdm", "access", "size"])
                    .style(Style::new().fg(theme::DIM).add_modifier(Modifier::BOLD)),
            )
            .column_spacing(2)
            .block(panel("Files")),
            right,
        );
    }

    fn draw_tap(&self, f: &mut ratatui::Frame, area: Rect) {
        if self.tap_lines.is_empty() {
            f.render_widget(hint("press t to read the tag as a phone would"), area);
            return;
        }
        let [banner, detail] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(4)]).areas(area);

        let (text, colour) = match self.tap_ok {
            Some(true) => ("TAP VERIFIED", theme::GOOD),
            Some(false) => ("CMAC MISMATCH", theme::BAD),
            None => ("—", theme::DIM),
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                text,
                Style::new().fg(Color::Black).bg(colour).add_modifier(Modifier::BOLD),
            )))
            .alignment(Alignment::Center)
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(colour)),
            ),
            banner,
        );
        f.render_widget(
            Paragraph::new(self.tap_lines.clone())
                .block(panel("What the tag emitted"))
                .wrap(Wrap { trim: false }),
            detail,
        );
    }

    fn mask(s: &str) -> Span<'static> {
        if s.is_empty() {
            Span::styled("not set", Style::new().fg(theme::DIM))
        } else {
            Span::styled(
                format!("{}  {} chars", "•".repeat(s.len().min(24)), s.len()),
                Style::new().fg(theme::GOOD),
            )
        }
    }

    fn draw_write(&self, f: &mut ratatui::Frame, area: Rect) {
        let [left, right] = Layout::horizontal([Constraint::Percentage(46), Constraint::Min(30)])
            .areas(area);

        let field = |k: &str, name: &str, val: Span<'static>| {
            Line::from(vec![
                Span::styled(format!(" {k} "), Style::new().bg(theme::FRAME).fg(theme::TEXT)),
                Span::styled(format!(" {name:<10}"), Style::new().fg(theme::DIM)),
                val,
            ])
        };
        let form = vec![
            field("m", "master", Self::mask(&self.master)),
            field("s", "meta K2", Self::mask(&self.meta)),
            field("e", "KEK", Self::mask(&self.kek)),
            Line::from(""),
            Line::from(vec![
                Span::styled(" u ", Style::new().bg(theme::FRAME).fg(theme::TEXT)),
                Span::styled(" write URL + SDM  ", Style::new().fg(theme::TEXT)),
                Span::styled("reversible", Style::new().fg(theme::GOOD)),
            ]),
            Line::from(vec![
                Span::styled(" K ", Style::new().bg(theme::BAD).fg(Color::Black)),
                Span::styled(" change K2, K3, K0  ", Style::new().fg(theme::TEXT)),
                Span::styled("locks to master", Style::new().fg(theme::BAD)),
            ]),
        ];
        f.render_widget(
            Paragraph::new(form).block(panel("Provision")).wrap(Wrap { trim: false }),
            left,
        );

        let steps = if self.write_lines.is_empty() {
            vec![Line::from(Span::styled(
                "K2 and K3 change first and are verified with a real tap, so a wrong setting is still repairable while K0 is factory. Afterwards everything stays changeable — keys, SDM config, the URL, even back to factory zeros — but only with the master. There is no factory reset without it.",
                Style::new().fg(theme::DIM),
            ))]
        } else {
            self.write_lines.clone()
        };
        f.render_widget(
            Paragraph::new(steps).block(panel("Progress")).wrap(Wrap { trim: false }),
            right,
        );
    }

    /// A centred modal. Always visible regardless of terminal height, which
    /// the inline version was not.
    fn draw_confirm(&self, f: &mut ratatui::Frame, area: Rect, p: Pending) {
        let (title, body, colour) = match p {
            Pending::WriteUrl => (
                " Write URL + SDM ",
                vec![
                    Line::from("Writes the URL template and turns SDM on."),
                    Line::from(Span::styled(
                        "Reversible — the keys are untouched.",
                        Style::new().fg(theme::GOOD),
                    )),
                ],
                theme::WARN,
            ),
            Pending::ChangeKeys => (
                " Change keys ",
                vec![
                    Line::from("Sets K2, K3 and then K0 on this tag."),
                    Line::from(Span::styled(
                        "From here your master is the only way back in.",
                        Style::new().fg(theme::BAD),
                    )),
                    Line::from(Span::styled(
                        "There is no factory reset.",
                        Style::new().fg(theme::BAD),
                    )),
                ],
                theme::BAD,
            ),
        };

        let h = (body.len() + 4) as u16;
        let w = 62u16.min(area.width.saturating_sub(4));
        let popup = Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + (area.height.saturating_sub(h)) / 2,
            width: w,
            height: h.min(area.height),
        };

        let mut lines = body;
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(" y ", Style::new().bg(colour).fg(Color::Black).add_modifier(Modifier::BOLD)),
            Span::styled(" go ahead     ", Style::new().fg(theme::DIM)),
            Span::styled(" n ", Style::new().bg(theme::FRAME).fg(theme::TEXT)),
            Span::styled(" cancel", Style::new().fg(theme::DIM)),
        ]));

        f.render_widget(ratatui::widgets::Clear, popup);
        f.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Center)
                .block(
                    Block::bordered()
                        .border_type(BorderType::Double)
                        .border_style(Style::new().fg(colour))
                        .padding(Padding::horizontal(1))
                        .title(Span::styled(
                            title,
                            Style::new().fg(colour).add_modifier(Modifier::BOLD),
                        )),
                )
                .wrap(Wrap { trim: true }),
            popup,
        );
    }

    fn draw_db(&self, f: &mut ratatui::Frame, area: Rect) {
        let connected = self.db.client.is_some();
        let [top, bottom] =
            Layout::vertical([Constraint::Length(7), Constraint::Min(3)]).areas(area);

        let lines = vec![
            Line::from(vec![
                Span::styled(" u ", Style::new().bg(theme::FRAME).fg(theme::TEXT)),
                Span::styled(" url        ", Style::new().fg(theme::DIM)),
                if self.db_url.is_empty() {
                    Span::styled("not set", Style::new().fg(theme::DIM))
                } else {
                    Span::styled("set", Style::new().fg(theme::GOOD))
                },
            ]),
            Line::from(vec![
                Span::styled(" l ", Style::new().bg(theme::FRAME).fg(theme::TEXT)),
                Span::styled(" label      ", Style::new().fg(theme::DIM)),
                Span::styled(self.label.clone(), Style::new().fg(theme::TEXT)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("   status     ", Style::new().fg(theme::DIM)),
                Span::styled(
                    self.db.status.clone(),
                    Style::new().fg(if connected { theme::GOOD } else { theme::BAD }),
                ),
            ]),
            Line::from(Span::styled(
                "   optional — only enrolment touches Postgres",
                Style::new().fg(theme::DIM),
            )),
        ];
        f.render_widget(Paragraph::new(lines).block(panel("Connection")), top);

        let sql = match (&self.last_uid, &self.last_wrapped) {
            (Some(uid), Some(w)) => Paragraph::new(Line::from(Span::styled(
                db::sql_for(uid, &self.label, w),
                Style::new().fg(theme::ACCENT),
            )))
            .wrap(Wrap { trim: false }),
            _ => Paragraph::new(Line::from(Span::styled(
                "provision a tag to get its enrolment SQL",
                Style::new().fg(theme::DIM),
            ))),
        };
        f.render_widget(sql.block(panel("Enrolment")), bottom);
    }
}

fn hint(msg: &str) -> Paragraph<'static> {
    Paragraph::new(Text::from(vec![
        Line::from(""),
        Line::from(Span::styled(msg.to_string(), Style::new().fg(theme::DIM))),
    ]))
    .alignment(Alignment::Center)
    .block(panel("—"))
}
