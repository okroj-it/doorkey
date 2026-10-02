# Changelog

Notable changes to doorkey. Versions follow [semantic versioning](https://semver.org);
each one is a [prebuilt image](README.md#prebuilt-images) `ghcr.io/okroj-it/doorkey:<version>`.

## [Unreleased]

The first tagged release, 0.1.0.

### Added

- Phone keypad for the front door, opened by an NFC tap: NTAG 424 DNA tags
  with SUN messages, or a static link.
- Guest codes with schedules, validity windows, "home only" and lockout after
  failed tries.
- Tap-gated Home Assistant actions: a tag tap plus a passkey (fingerprint)
  runs an allowlisted `script.*`, with roles deciding who may run what.
- Admin page: codes, tags, actions, users, passkeys and roles; English, and
  Polish chosen by browser language.
- MQTT discovery for the keypad entities in Home Assistant.
- PostgreSQL or a SQLite file, chosen by `DATABASE_URL`.
- Tag enrolment codes (`dktag1.…`) from `tagtui` or `provision.py`, pasted
  into the admin page or `doorkey tag:add`: no database access needed to
  provision a tag.
- Home Assistant app mode: settings from the app options, Home Assistant and
  MQTT through the Supervisor, admin in the sidebar via Ingress for Home
  Assistant administrators.
- Multi-arch release images (amd64, arm64) with build provenance.
- `tagtui`: reads and decodes NFC Type 2 tags and NDEF records, provisions
  DNA tags, writes password-protected URLs.

### Fixed

- PostgreSQL 18: deleting an action still linked to a tag answers 409, not 500.

[Unreleased]: https://github.com/okroj-it/doorkey/commits/master
