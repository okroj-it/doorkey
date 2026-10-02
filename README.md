<p align="center">
  <img src="docs/banner.svg" alt="doorkey — tap a tag, type a code, or touch the sensor" width="100%">
</p>

<p align="center">
  <img alt="Bun" src="https://img.shields.io/badge/runtime-Bun_1.x-f9f1e1?logo=bun&logoColor=black&style=flat-square">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white&style=flat-square">
  <img alt="Hono" src="https://img.shields.io/badge/Hono-4-e36002?logo=hono&logoColor=white&style=flat-square">
  <img alt="Svelte" src="https://img.shields.io/badge/Svelte-5-ff3e00?logo=svelte&logoColor=white&style=flat-square">
  <img alt="PostgreSQL" src="https://img.shields.io/badge/database-PostgreSQL-4169e1?logo=postgresql&logoColor=white&style=flat-square">
  <br>
  <img alt="NTAG 424 DNA" src="https://img.shields.io/badge/NFC-NTAG_424_DNA_SUN-6aa2ff?style=flat-square">
  <img alt="WebAuthn" src="https://img.shields.io/badge/auth-passkeys_only-4ade80?logo=webauthn&logoColor=black&style=flat-square">
  <img alt="Home Assistant" src="https://img.shields.io/badge/Home_Assistant-REST_+_MQTT-18bcf2?logo=homeassistant&logoColor=white&style=flat-square">
  <img alt="Docker, Podman or Kubernetes" src="https://img.shields.io/badge/runs_on-Docker_·_Podman_·_Kubernetes-2496ed?logo=docker&logoColor=white&style=flat-square">
  <img alt="English and Polish" src="https://img.shields.io/badge/UI-English_·_Polski-8a90a0?style=flat-square">
  <img alt="MIT license" src="https://img.shields.io/badge/license-MIT-eef1f7?style=flat-square">
</p>

<p align="center">
  <b>A keypad for the front door that lives on a phone instead of on the wall</b> —<br>
  and, from the same tags, a fingerprint-confirmed trigger for any allowlisted Home Assistant script.
</p>

<p align="center">
  <a href="#-how-it-works">How it works</a> ·
  <a href="#-security-model">Security model</a> ·
  <a href="#-tap-gated-actions">Tap-gated actions</a> ·
  <a href="#-admin">Admin</a> ·
  <a href="#-deploying">Deploying</a> ·
  <a href="#-development">Development</a> ·
  <a href="#-roadmap">Roadmap</a>
</p>

---

<table>
  <tr>
    <td align="center" width="33%"><img src="docs/screenshots/keypad.png" alt="The keypad, three digits entered" width="230"><br><sub><b>Tap the door tag</b> → keypad</sub></td>
    <td align="center" width="33%"><img src="docs/screenshots/confirm.png" alt="An action page asking for a fingerprint" width="230"><br><sub><b>Tap an action tag</b> → fingerprint</sub></td>
    <td align="center" width="33%"><img src="docs/screenshots/done.png" alt="The action ran" width="230"><br><sub><b>Script runs</b> in Home Assistant</sub></td>
  </tr>
</table>

## ✨ Features

| | |
|---|---|
| 🚪 **Phone keypad for the door** | Tap the NFC tag by the door, type a code, your Home Assistant lock toggles. No outdoor hardware to weatherproof, power or vandalise. |
| 🔁 **One code, both ways** | A valid entry locks an open door and opens a locked one. If the state can't be read it unlocks — being shut out by a flaky read is worse. |
| 🏷️ **Unclonable tags** | NTAG 424 DNA Secure Dynamic Messaging: every tap is a fresh, signed, counter-protected URL. A copied URL is dead after one use. |
| 🧑‍🤝‍🧑 **Guest codes with rules** | Expiry, max uses, weekly schedules (`mon,wed 07:00-09:00`), shown once and stored only as an HMAC. |
| 🛡️ **Harsh, global lockout** | 3 failures → 60 s, 4 → 24 h, for everyone. IP bans are theatre against a phone that can rotate its MAC. |
| 👆 **Tap-gated HA actions** | Tag tap + passkey with fingerprint → one allowlisted `script.*`. Role-based, one run per tap. |
| 🔑 **Passkeys only** | Admin and action sign-in are WebAuthn resident keys. No passwords, no fallback, unphishable. |
| 🖥️ **Admin UI** | Codes, lockouts, audit logs, actions, users, roles and passkeys — in a browser, behind a passkey. |
| 📡 **Home Assistant native** | MQTT discovery for keypad state, push notifications, scripts receive who ran them. |
| 🌍 **English and Polish** | The phone pages follow the browser language; adding one is a block in `web/src/i18n.js`. |
| 📦 **Self-hosted, small** | One container and Postgres — Docker, Podman or Kubernetes, behind any TLS reverse proxy. |

## 🧭 How it works

```mermaid
flowchart LR
    tag(["🏷️ NFC tag<br/>/k/sun?picc=…&cmac=…"])
    phone["📱 Phone browser"]
    tls["🔒 TLS<br/>reverse proxy · Cloudflare"]
    dk["🔐 doorkey<br/>Bun · Hono"]
    pg[("PostgreSQL<br/>codes · tags · passkeys · audit")]
    ha["🏠 Home Assistant<br/>lock · script · notify"]
    mq["📡 MQTT broker<br/>discovery"]

    tag -- tap --> phone -- https --> tls --> dk
    dk --> pg
    dk -- REST --> ha
    dk -- MQTT --> mq --> ha
```

Two things can sit behind a tap:

- **the keypad** (`/k/…`) — a guest code toggles the door;
- **an action** (`/a/<slug>`) — a passkey with fingerprint runs one allowlisted HA script. See [Tap-gated actions](#-tap-gated-actions).

Which one a DNA tag opens is decided in the database, not on the chip — every tag carries the same URL.

## 🛡️ Security model

Be clear about what each layer actually does.

> [!IMPORTANT]
> **The tag proves a tap, not a person.** In `sun` mode every tap emits a new URL signed by the chip with a per-tag key and a strictly increasing counter, so a copied URL is dead after one use and a cloned tag cannot be made without the key. It still proves only that *someone* is at the door — anyone can tap it.

**The code is the credential**, and the rate limiter is what protects it:

| failures | consequence |
|---------:|-------------|
| 1–2      | nothing |
| 3        | 60 s lockout |
| 4+       | 24 h lockout |

- **Counters are global, not per-IP.** A phone outside the door rotates its MAC and DHCP lease by toggling Wi-Fi, so IP bans are theatre. The global streak is the only counter an attacker cannot reset. A recognised code that keeps failing (e.g. outside its schedule) is additionally locked on its own after 5 failures, for 24 h.
- **That ladder allows roughly 15–20 attempts a day**, so a random six-digit code survives for tens of thousands of years. The limiter matters far more than the code length — which is why codes are generated, never chosen.
- **The lockout is deliberately harsh and has no reset button at the door.** The Companion app and the physical key both bypass this service, so locking the keypad costs the household nothing. If a guest locks themselves out, you get a notification and let them in from your phone (or clear it in `/admin`).
- **Every failure returns an identical response.** `bad_code`, `expired`, `out_of_schedule`, `exhausted`, `code_locked` and `system_locked` are all one 401 after a fixed 1 s floor; the real reason stays in `attempts.result`. Telling the caller is a free oracle, and tells an honest guest nothing useful. Every bad tap is likewise a plain 404, indistinguishable from a path that was never routed.
- **Codes are stored as `HMAC-SHA256(pepper, code)`** with the pepper in the environment, never in the database. That gives an O(1) indexed lookup, so identifying a code takes the same time whether or not it exists. The trade: somebody holding *both* the database and the pepper brute-forces six digits instantly. Argon2 would fix that but would mean verifying against every row in turn — seconds per attempt.

> [!CAUTION]
> **`src_ip` comes from `CF-Connecting-IP` (or `X-Forwarded-For`) and is untrusted.** Anyone who can reach the origin without going through your proxy can set those headers. For the door it is audit only; for actions it also feeds the optional `home_only` check, which is a convenience — never the thing standing between a stranger and a script. The passkey is.

## 🏷️ Tap modes

| mode | proof of a physical tap | replay-proof | needs |
|------|:-----------------------:|:------------:|-------|
| `sun` | ✅ | ✅ | NTAG 424 DNA, provisioned — **deployed** |
| `static` | ❌ | ❌ | any NTAG213 |
| `dev` | ❌ | ❌ | local only |

### NTAG 424 DNA (`sun`)

Secure Dynamic Messaging (NXP AN12196). The chip mirrors two values into the URL on every read: `picc` — its UID and read counter, AES-encrypted with **K2** — and `cmac`, a truncated AES-CMAC over them with **K3**.

```mermaid
flowchart TB
    master["🔒 master key<br/><i>offline · your password manager</i>"]
    k0["K0 app key — per tag<br/>CMAC(master, 00‖uid)<br/><i>never online · can reconfigure the chip</i>"]
    k3["K3 MAC key — per tag<br/>CMAC(master, 03‖uid)<br/><i>tags.mac_key_enc, wrapped with DOORKEY_TAG_KEK</i>"]
    k2["K2 meta key — shared<br/><i>DOORKEY_TAG_META_KEY</i>"]
    picc["picc = Enc(K2, uid ‖ counter)"]
    cmac["cmac = CMAC(K3, …)"]
    verify{{"doorkey: decrypt → look up UID →<br/>unwrap K3 → check MAC → counter strictly up"}}

    master --> k0
    master --> k3
    k2 --> picc
    k3 --> cmac
    picc --> verify
    cmac --> verify
```

- **K2 is shared** so one decrypt yields the UID and lookup is an index hit; leaking it exposes UIDs and counters, never the ability to forge.
- **A stolen database dump is useless without the KEK**, and the service can verify taps but can never reconfigure a tag.
- **The counter check is a single conditional `UPDATE`**, so two concurrent replays of one URL cannot both win.

**Provisioning** needs a PN532 reader. Two tools, same key scheme:

- **`tools/tagtui`** — Rust TUI. Dry runs by default; reading and tapping never write. Writing the URL and changing keys sit behind explicit confirmation, ordered so a factory-K0 session can repair the tag until the very last step. Enrols the tag (UID, label, wrapped K3) straight into Postgres. It also reads plain NFC Type 2 tags (NTAG21x, Ultralight and compatible clones) without writing — model, capacity and locks, and every record of the NDEF message decoded: URLs, text, Smart Posters, Wi-Fi networks (key masked), contacts, Bluetooth pairing, Android app records and the handover/signature types. DNA-only actions refuse them. It also writes URLs to them, optionally password write-protected (see below).
- **`tools/provision.py`** — a staged CLI: `--check` (auth only, writes nothing), `--write-url`, then `--keys` (irreversible: locks the tag to your master).

Both take your public origin (`--origin` or `DOORKEY_ORIGIN`, e.g. `https://door.example.com`) and write `<host>/k/sun?picc=…&cmac=…`. That one URL serves every tag.

### Plain tags (`static`, and action tokens)

Write the URL with `tagtui` and **write-protect it**. The password is derived from your offline master and the tag's UID, so every tag gets its own and there is nothing to remember: `tagtui` can rewrite or unprotect any tag you protected, and nobody without the master can. Reads stay open, so phones still see the URL.

```sh
export DOORKEY_TAG_MASTER=<32 hex, from your password manager>   # e.g. read -s, not in history
tagtui --write-url "https://door.example.com/a/garage?t=…" --protect
tagtui --unprotect                                              # back to factory password
```

The same is on the TUI's Write tab (`p` URL, `x` protect, `w` write, `R` remove protection). It works on NTAG210/212/213/215/216, Ultralight EV1 and NTAG213-compatible clones; every write is verified by reading back. NFC Tools works too (Other → Set password, leave `PROT=0`), or the static lock bytes make a tag permanently read-only.

> [!NOTE]
> NTAG21x passwords are 32 bits and travel in clear over the air: they stop a passer-by with a phone app, not someone sniffing the tag while you rewrite it.

> [!WARNING]
> An unprotected NTAG213 on the outside of your door can be rewritten by any passer-by in two seconds — point it at a lookalike domain, and the next person to tap types a valid code into someone else's page. The lockout ladder does nothing against that, because the code they capture is correct. (Passkeys are immune: they will not sign for a lookalike origin.)
>
> Nothing stops someone sticking their own tag over yours. Mount it where that would be noticed.

## 👆 Tap-gated actions

Home Assistant can lock the whole Companion app behind biometrics, but cannot ask for a fingerprint before one particular action. This does.

```mermaid
sequenceDiagram
    autonumber
    actor U as You
    participant T as 🏷️ Tag
    participant P as 📱 Phone
    participant D as 🔐 doorkey
    participant H as 🏠 Home Assistant

    U->>T: tap
    T-->>P: /a/garage?t=… (plain)  or  /k/sun?picc=…&cmac=… (DNA)
    P->>D: GET
    D->>D: verify tag · home_only? · DNA linked to this action?
    D-->>P: action page + 120 s session (this action only)
    U->>P: "Confirm with fingerprint" + 👆
    P->>D: WebAuthn assertion (user verification required)
    D->>D: passkey valid → user active → shares a role with the action → spend session
    D->>H: script.turn_on {tapgate_user, tapgate_action, tapgate_via}
    D-->>P: ✓ Done
    D--)H: notify (push)
```

- **The tag is presence, the passkey is identity.** Neither alone runs anything.
- **A DNA tag** linked to an action proves the phone is at the tag and opens only that action — never the door, never another action.
- **A plain tag** carries `?t=<128-bit token>` (only its HMAC is stored). Its URL can be copied and reopened from anywhere, so it proves nothing about location — fine for "confirm this deliberate action", wrong for doors. Mark such actions **home-only** to require a client IP in `DOORKEY_HOME_CIDRS`, or **DNA required** to refuse plain tags altogether.
- **Only `script.*`**, fixed per action server-side. The browser never names an entity. Put the real logic, and any extra conditions, in the script; it receives who ran it as variables.
- **One run per tap.** The session is spent when the script starts; running again means tapping again.
- **Action passkeys are not admin passkeys.** Separate users, separate table, separate WebAuthn user handle on the same RP id. An action passkey cannot sign in to `/admin`, an admin passkey cannot run an action, and the tap page only offers passkeys whose user may run that action.
- **RBAC:** users have roles, actions allow roles. Disabling a user, removing a role or disabling an action takes effect on the next tap.

Every attempt lands in `action_events` (`ran`, `not_allowed`, `bad_passkey`, `not_home`, `inactive`, `ha_error`), visible in `/admin`, and a successful run sends the usual `HA_NOTIFY_SERVICE` push.

> [!TIP]
> Removing an action never turns its tag back into a door key: the foreign key is `RESTRICT`, so the tag has to be unlinked first, on purpose — and the UI warns that unlinking makes it open the front door again.

### Setting one up

Everything below is also a click in the [Actions tab](#-admin):

```sh
dk() { docker exec doorkey bun cli/doorkey.ts "$@"; }   # or kubectl exec … / podman exec …

dk user:add alex
dk user:grant alex owner
dk user:enroll alex pixel            # single-use link, 15 min: open it on the phone

dk action:add garage script.garage_open --label "Open the garage"
dk action:allow garage owner

dk action:token garage                # plain tag: prints the URL to write, shown once
dk action:link-tag garage 04de5f1eacc040  # or: a provisioned DNA tag
```

<details>
<summary><b>All action, user and role commands</b></summary>

```
users                                  action users, roles, passkeys
user:add <name>
user:enroll <name> <device> [--minutes 15]
user:grant | user:ungrant <name> <role>
user:disable | user:enable <name>
user:reset <name>                      remove all of a user's passkeys
actions                                actions, roles, tags
action:add <slug> <script.x> [--label TEXT] [--sun] [--home-only]
action:allow | action:deny <slug> <role>
action:token <slug>                    (re)issue the plain-tag URL; the old one dies
action:untoken <slug>                  stop accepting plain tags
action:link-tag <slug> <uid>           a DNA tag opens this action, not the door
action:unlink-tag <uid>                back to the door
action:disable | action:enable <slug>
action:remove <slug>                   refused while a DNA tag is still linked
action:log [--tail 40]
```

</details>

## 🖥️ Admin

`/admin` is authenticated by a **passkey** — nothing else. No password, no shared secret, no fallback. That is the only reason a second authenticated surface on this service is defensible: a WebAuthn resident key cannot be guessed, never leaves the authenticator, and is bound to your hostname — so a phishing clone on a lookalike domain cannot use it even if someone types everything into it.

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/admin-door.png" alt="Admin, Door tab: status, codes and activity"></td>
    <td width="50%"><img src="docs/screenshots/admin-actions.png" alt="Admin, Actions tab: actions, users, roles and activity"></td>
  </tr>
  <tr>
    <td align="center"><sub><b>Door</b> — status, codes, door and admin activity, admin passkeys</sub></td>
    <td align="center"><sub><b>Actions</b> — actions, action users and their passkeys, roles, activity</sub></td>
  </tr>
</table>

**Door tab:** create codes (plaintext shown once), set or change expiry, cap uses, revoke, re-enable, regenerate and delete; clear a lockout; review the door and admin audit logs; manage the admin passkeys.

**Actions tab:** create actions from a live list of your HA scripts; toggle *DNA required*, *home-only* and *active*; issue or rotate a plain-tag URL (shown once, with copy); link or unlink provisioned DNA tags; allow roles. Create and disable action users, grant roles, mint single-use enrolment links, and see and remove each user's passkeys. Unused roles can be deleted. Every change is in the admin activity log.

> [!NOTE]
> An admin passkey can mint enrolment links for action users. That is no wider than admin already is — it can create door codes. Admin passkeys themselves are still only ever enrolled from the CLI, so `kubectl` remains the root of trust.

### Enrolling an admin passkey

There is no self-service path in. Links are minted from the CLI:

```sh
dk admin:enroll "Alex"
```

It prints a single-use link valid for 15 minutes. Open it, register the passkey (Bitwarden, a platform authenticator, a hardware key — anything WebAuthn), and you land on the dashboard already signed in. `admin:list` and `admin:revoke <id>` cover the rest. The UI refuses to remove the last remaining passkey, since that would lock you out with no way back except the CLI.

### Narrowing the blast radius

`/admin` sits on the same public hostname as the keypad. If you would rather it were not reachable from the internet at all, set `DOORKEY_ADMIN_HOST` to a LAN-only name, point that name at the same container through your proxy, and `/admin` becomes a 404 everywhere else. This holds as long as your public proxy only forwards your own public hostname, so a forged `Host` header never reaches doorkey.

> [!WARNING]
> Changing hostname means changing `DOORKEY_RP_ID` and `DOORKEY_ORIGIN` to match — and passkeys registered on the old origin, admin and action alike, stop working.

## 🔢 Managing codes

```sh
dk <command>     # dk() as defined above
```

```
add <label> [--schedule "tue 09:00-12:00"] [--from ISO] [--until ISO]
            [--max-uses N] [--digits 6]
list
revoke <id>
enable <id>
log [--tail 40]
```

The code is printed once, on creation. Only its HMAC is stored, so **a code cannot be read back** — there is no "show code" anywhere, by design. A guest who forgets theirs gets a new one (*new code* in the admin UI), which invalidates the old one immediately.

Schedules are `day[,day] HH:MM-HH:MM`, multiple windows separated by `;`, and windows may wrap midnight:

```
--schedule "mon,wed,fri 07:00-09:00; sat 10:00-14:00"
```

## 🏠 Home Assistant

- **MQTT discovery** on startup and on every broker reconnect gives a **Door Keypad** device with `locked_out`, `failed_today`, `last_entry` and `last_entry_at`. Useful automation: on `locked_out`, notify and turn on the porch light — someone standing outside guessing codes is exactly the event worth a camera snapshot.
- **The HA token** is used for `lock.*` on `HA_LOCK_ENTITY`, `notify.*`, `script.turn_on` for actions, and reading `script.*` states for the admin picker. HA tokens cannot be scoped, so it stays server-side; what limits actions is the allowlist in the `actions` table.
- **Scripts receive** `tapgate_user`, `tapgate_action` and `tapgate_via` (`sun` or `token`):

```yaml
alias: Open the garage
fields:
  tapgate_user: { description: who confirmed with their passkey }
sequence:
  - action: cover.open_cover
    target: { entity_id: cover.garage }
  - action: logbook.log
    data:
      name: Garage
      message: "opened by {{ tapgate_user }} ({{ tapgate_via }})"
```

## ⚙️ Configuration

Required: `DOORKEY_ORIGIN` (your public `https://` origin, scheme and host only), `DATABASE_URL`, `DOORKEY_PEPPER`, `DOORKEY_SESSION_SECRET`, `HA_URL`, `HA_TOKEN`, `HA_LOCK_ENTITY`. A commented template is in [`deploy/compose/.env.example`](deploy/compose/.env.example).

<details>
<summary><b>Every environment variable</b></summary>

| var | default | |
|-----|---------|--|
| `DATABASE_URL` | — | `postgres://user:pw@host:5432/doorkey`, or `sqlite:///data/doorkey.db` for a single file (WAL; back it up after `bun cli/doorkey.ts db:checkpoint`) |
| `PORT` | `8080` | |
| `DOORKEY_TAP_MODE` | `static` | `static` \| `sun` \| `dev` |
| `DOORKEY_TAG_KEK` | — | 64 hex; wraps K3 at rest. Required for `sun` |
| `DOORKEY_TAG_META_KEY` | — | 32 hex; shared K2. Required for `sun` |
| `DOORKEY_STATIC_PATH` | — | required when mode is `static` |
| `DOORKEY_SESSION_TTL_S` | `300` | how long the keypad stays usable after a tap |
| `DOORKEY_MIN_RESPONSE_MS` | `1000` | unlock response floor |
| `DOORKEY_LOCKOUT_SOFT_AFTER` / `_SECONDS` | `3` / `60` | |
| `DOORKEY_LOCKOUT_HARD_AFTER` / `_SECONDS` | `4` / `86400` | |
| `DOORKEY_CODE_FAILURES_BEFORE_LOCK` | `5` | per-code lockout |
| `DOORKEY_CODE_LOCK_SECONDS` | `86400` | |
| `DOORKEY_RP_ID` | the origin's host | WebAuthn relying party — the hostname passkeys bind to |
| `DOORKEY_RP_NAME` | `Front door` | shown by the authenticator |

| `DOORKEY_ADMIN_SESSION_TTL_S` | `3600` | |
| `DOORKEY_ADMIN_HOST` | — | when set, `/admin` is served only to this Host |
| `DOORKEY_ACTION_SESSION_TTL_S` | `120` | how long an action page stays usable after a tap |
| `DOORKEY_HOME_CIDRS` | — | e.g. `203.0.113.7/32,192.168.1.0/24` (WAN + LAN); empty: home-only actions refuse everyone |
| `HA_NOTIFY_SERVICE` | — | e.g. `mobile_app_pixel`; empty disables push |
| `MQTT_URL` | — | empty skips HA discovery |
| `MQTT_USERNAME` / `MQTT_PASSWORD` | — | if your broker requires them |
| `MQTT_DISCOVERY_PREFIX` | `homeassistant` | |
| `MQTT_NODE_ID` | `doorkey` | |
| `TZ` | `UTC` | schedules and log times are evaluated here |

</details>

## 🚀 Deploying

doorkey is one container. It needs:

- **a public `https://` origin** — passkeys only work in a secure context and bind to the hostname. Terminate TLS in a reverse proxy (Caddy, Traefik, nginx…) or use Cloudflare;
- **a database** — PostgreSQL (bundled in the compose stack, or any server you already run) or a SQLite file (`DATABASE_URL=sqlite:///data/doorkey.db`, nothing else to run);
- **Home Assistant's REST API** reachable from the container, and optionally your MQTT broker;
- **one replica** — WebAuthn challenges and spent action sessions are held in memory.

### Docker / Podman compose

[`deploy/compose/`](deploy/compose) has a stack with a bundled Postgres:

```sh
cd deploy/compose
cp .env.example .env        # fill in: origin, HA URL/token/lock, secrets, tag keys
docker compose up -d        # or: podman compose up -d
docker exec doorkey bun cli/doorkey.ts admin:enroll "Alex"   # first admin passkey
```

Already run Postgres? Delete the `db` service and `depends_on` from `compose.yaml`, create a database and role for doorkey, and set `DATABASE_URL` in `.env`. Tables are created and migrated on startup (`db/*.sql`, idempotent).

> [!TIP]
> Home Assistant on the same machine: `HA_URL=http://host.docker.internal:8123` (the stack maps it to the host gateway; Podman also has `host.containers.internal`). mDNS names like `homeassistant.local` usually do not resolve inside containers — use an IP or a DNS name.

### TLS in front

The container listens on plain HTTP `:8080`, bound to `127.0.0.1` by default. Point your proxy at it, e.g. Caddy:

```caddyfile
door.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

> [!WARNING]
> **Do not put SSO or forward-auth in front of doorkey.** A guest at the door has no account — the code they type, or the passkey, is the credential.
>
> **With Cloudflare**, prefer a **Cloudflare Tunnel** (no open port) or SSL mode **Full (strict)** with an origin certificate. *Flexible* mode works, but the hop from Cloudflare to your server is then plain HTTP across the internet.

### Kubernetes

[`deploy/kubernetes/doorkey.yaml`](deploy/kubernetes/doorkey.yaml) is a Deployment (one replica, `Recreate`), a Service and an HTTPRoute. Bring your own Postgres and put the secret settings in a Secret:

```sh
kubectl create namespace doorkey
kubectl create secret generic doorkey-secrets -n doorkey --from-env-file=doorkey.env
kubectl apply -f deploy/kubernetes/doorkey.yaml
```

### Building the image yourself

```sh
./scripts/publish.sh
```

Builds `linux/amd64`, tags it with the commit sha and pushes to `ghcr.io/<owner>/<repo>` of your GitHub remote (or `$DOORKEY_IMAGE`). It refuses a dirty working tree — "which build is guarding the front door" should have an answer, so pin the sha, not `:latest`.

### Home Assistant add-on

Planned — see the [roadmap](#-roadmap).

## 🧪 Development

```sh
bun install
cd web && bun install && bun run build && cd ..
bun run check                # tsc --noEmit
bun test                     # SUN crypto vectors (RFC 4493, AN12196), action policy, CIDRs

docker run -d --name dk-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=doorkey \
  -p 55432:5432 postgres:18-alpine

DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/doorkey \
DOORKEY_PEPPER=dev DOORKEY_SESSION_SECRET=dev DOORKEY_TAP_MODE=dev \
DOORKEY_ORIGIN=http://localhost:8080 \
HA_URL=http://127.0.0.1:18123 HA_TOKEN=dev HA_LOCK_ENTITY=lock.front_door \
  bun run dev
```

- In `dev` tap mode any `/k/<anything>` serves the keypad.
- `bun test/fake-ha.ts` stands in for Home Assistant on `:18123`: it records service calls at `GET /calls` and offers two scripts in `/api/states`.
- To exercise `sun` locally, use the AN12196 example: a `DOORKEY_TAG_META_KEY` of 32 zeros, a tag with UID `04de5f1eacc040` and an all-zero K3 (wrapped with your KEK), and `/k/sun?picc=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086` — its counter is 61, so reset `tags.last_counter` between taps.

<details>
<summary><b>Browser tests</b> — real Chrome, CDP virtual authenticators</summary>

All three need Chrome at `/usr/bin/google-chrome-stable` (or `CHROME_PATH`), and the server on `http://localhost:18080` with `DOORKEY_RP_ID=localhost` and `DOORKEY_ORIGIN=http://localhost:18080`, against an empty database.

**Admin passkey** — registration, sign-out, sign-in, expiry, refusals. Needs `DOORKEY_TAP_MODE=static`, `DOORKEY_STATIC_PATH=abc123secretpath`:

```sh
TOKEN=$(bun cli/doorkey.ts admin:enroll "Test" | grep -o 'enroll/[A-Za-z0-9_-]*' | cut -d/ -f2)
bun run test:passkey "$TOKEN"
```

**Actions** — enrolment, a run, one run per tap, a passkey without the role, admin/action separation. Needs the fake HA as `HA_URL`:

```sh
cli() { bun cli/doorkey.ts "$@"; }
cli user:add owner; cli user:grant owner owner
cli user:add guest; cli user:grant guest guests
cli action:add test script.tapgate_test; cli action:allow test owner
OT=$(cli user:enroll owner phone | grep -o 'enroll/[^ ]*' | cut -d/ -f2)
GT=$(cli user:enroll guest phone | grep -o 'enroll/[^ ]*' | cut -d/ -f2)
bun run test:actions "$OT" "$GT" "$(cli action:token test | grep -o 'http[^ ]*')"
```

**Admin Actions tab** — the whole UI: script picker, roles, tag URL, users, enrolment link, a run from a second phone, tightening and teardown, and the admin log. Needs the fake HA:

```sh
TOKEN=$(bun cli/doorkey.ts admin:enroll "Test" | grep -o 'enroll/[^ ]*' | cut -d/ -f2)
bun run test:admin-actions "$TOKEN"
```

</details>

<details>
<summary><b>Regenerating the screenshots</b></summary>

`scripts/screenshots.ts` seeds demo data through the admin API on a throwaway instance (static mode, fake HA, empty database) and writes `docs/screenshots/*.png`. Any DNA tag already in the database is linked to the demo action so its chip shows.

```sh
TOKEN=$(bun cli/doorkey.ts admin:enroll "Alex" | grep -o 'enroll/[^ ]*' | cut -d/ -f2)
DOORKEY_STATIC_PATH=<the server's static path> bun run screenshots "$TOKEN"
```

</details>

<details>
<summary><b>Repository layout</b></summary>

```
src/
  index.ts            routes: /k (keypad), /api/unlock, /admin, /a
  config.ts           every env var, validated at boot
  db.ts               all SQL (Bun.sql), migrations runner
  auth/               tap verification: SUN (ntag424, sun-crypto, kek), static path
  admin/              admin routes, session, passkeys
  actions/            tap-gated actions: routes, policy (pure), session, passkeys
  challenges.ts       WebAuthn challenge store shared by admin and actions
  codes.ts unlock.ts lockout.ts ha.ts mqtt.ts session.ts
db/                   001_init · 002_admin · 003_tags · 004_actions
web/src/              App (keypad) · Admin + ActionsTab · Action (tap page) · i18n
cli/doorkey.ts        codes, admin passkeys, actions, users, roles
tools/                tagtui (Rust TUI) · provision.py
test/                 unit tests · browser tests · fake HA
scripts/              publish.sh · screenshots.ts
deploy/               compose (with Postgres) · kubernetes
```

</details>

## 🗺️ Roadmap

- [ ] **Home Assistant add-on** — install from an add-on repository; HA access through the Supervisor (no long-lived token), MQTT credentials from the MQTT integration, settings as add-on options, admin in the HA sidebar via Ingress using HA's own login, multi-arch images (amd64 · aarch64).
- [ ] **SQLite** — a zero-dependency database for the add-on and small compose installs, next to PostgreSQL.
- [ ] **More languages** for the phone pages — strings live in [`web/src/i18n.js`](web/src/i18n.js).

## 📄 License

[MIT](LICENSE)
