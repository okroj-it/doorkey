<script>
  import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
  import ActionsTab from './ActionsTab.svelte';

  // Everything up to and including /admin: the page is at /admin on its own
  // host and under /api/hassio_ingress/<token>/admin in Home Assistant.
  const BASE = location.pathname.slice(0, location.pathname.indexOf('/admin') + '/admin'.length);
  const enrollToken = location.pathname.slice(BASE.length).match(/^\/enroll\/(.+)$/)?.[1] ?? null;

  let view = $state('loading');   // loading | enroll | login | dashboard
  // door | actions, kept in the hash so /admin#actions deep-links.
  let tab = $state(location.hash === '#actions' ? 'actions' : 'door');
  $effect(() => { history.replaceState(null, '', tab === 'door' ? location.pathname : '#actions'); });
  let label = $state('');
  // Signed in through Home Assistant (the app's Ingress): HA owns sign-out.
  let viaHa = $state(false);
  let error = $state('');
  let busy = $state(false);

  let codes = $state([]);
  let status = $state(null);
  let attempts = $state([]);
  let events = $state([]);
  let credentials = $state([]);
  let tags = $state([]);
  let tagForm = $state({ code: '', label: '' });
  let tagNote = $state('');

  // Shown once, right after creation — the only time the plaintext exists.
  let freshCode = $state(null);

  let form = $state({ label: '', validUntil: '', maxUses: '', digits: 6 });

  async function api(path, options = {}) {
    const res = await fetch(`${BASE}/api${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error ?? `${res.status}`);
    }
    return res.status === 204 ? null : res.json();
  }

  async function refresh() {
    const [c, s, l, k, t] = await Promise.all([
      api('/codes'), api('/status'), api('/log?limit=40'), api('/credentials'), api('/tags'),
    ]);
    codes = c; status = s; attempts = l.attempts; events = l.events; credentials = k; tags = t;
  }

  async function boot() {
    if (enrollToken) { view = 'enroll'; return; }
    try {
      const s = await api('/session');
      label = s.label;
      viaHa = s.via === 'home-assistant';
      await refresh();
      view = 'dashboard';
    } catch {
      view = 'login';
    }
  }

  async function signIn() {
    busy = true; error = '';
    try {
      const { key, options } = await api('/auth/options', { method: 'POST' });
      const response = await startAuthentication({ optionsJSON: options });
      const out = await api('/auth/verify', {
        method: 'POST',
        body: JSON.stringify({ key, response }),
      });
      label = out.label;
      await refresh();
      view = 'dashboard';
    } catch (e) {
      error = e.message === 'no passkeys enrolled'
        ? 'No passkey enrolled yet — mint a link with: doorkey admin:enroll'
        : 'Sign-in failed.';
    } finally { busy = false; }
  }

  async function enroll() {
    busy = true; error = '';
    try {
      const options = await api(`/enroll/${enrollToken}/options`, { method: 'POST' });
      const response = await startRegistration({ optionsJSON: options });
      const out = await api(`/enroll/${enrollToken}/verify`, {
        method: 'POST',
        body: JSON.stringify(response),
      });
      label = out.label;
      history.replaceState(null, '', BASE);
      await refresh();
      view = 'dashboard';
    } catch (e) {
      error = e.message === 'invalid or expired'
        ? 'That enrolment link is expired or already used.'
        : 'Registration failed.';
    } finally { busy = false; }
  }

  async function createCode(event) {
    event.preventDefault();
    busy = true; error = ''; freshCode = null;
    try {
      const out = await api('/codes', {
        method: 'POST',
        body: JSON.stringify({
          label: form.label,
          validUntil: form.validUntil ? new Date(form.validUntil).toISOString() : null,
          maxUses: form.maxUses ? Number(form.maxUses) : null,
          digits: Number(form.digits),
        }),
      });
      freshCode = out;
      form = { label: '', validUntil: '', maxUses: '', digits: 6 };
      await refresh();
    } catch (e) { error = e.message; } finally { busy = false; }
  }

  async function enrolTag(event) {
    event.preventDefault();
    busy = true; error = ''; tagNote = '';
    try {
      const t = await api('/tags', {
        method: 'POST',
        body: JSON.stringify({ code: tagForm.code, label: tagForm.label || undefined }),
      });
      tagNote = `${t.label} ${t.replaced ? 're-enrolled' : 'enrolled'} — it opens the door until linked to an action.`;
      tagForm = { code: '', label: '' };
      await refresh();
    } catch (e) { error = e.message; } finally { busy = false; }
  }

  async function setTagActive(uid, active) {
    busy = true;
    try {
      await api(`/tags/${uid}`, { method: 'PATCH', body: JSON.stringify({ active }) });
      await refresh();
    } catch (e) { error = e.message; } finally { busy = false; }
  }

  async function patchCode(id, body) {
    busy = true;
    try {
      await api(`/codes/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
      await refresh();
    } catch (e) { error = e.message; } finally { busy = false; }
  }

  async function regenerate(id, name) {
    if (!confirm(`Issue a new code for ${name}? The old one stops working immediately.`)) return;
    busy = true; error = ''; freshCode = null;
    try {
      freshCode = await api(`/codes/${id}/regenerate`, { method: 'POST' });
      await refresh();
    } catch (e) { error = e.message; } finally { busy = false; }
  }

  async function removeCode(id, name) {
    if (!confirm(`Delete the code for ${name}? The audit log keeps its history.`)) return;
    busy = true;
    try {
      await api(`/codes/${id}`, { method: 'DELETE' });
      await refresh();
    } catch (e) { error = e.message; } finally { busy = false; }
  }

  async function setExpiry(id, current) {
    const value = prompt('Expires at (YYYY-MM-DD HH:MM, blank for never)',
      current ? new Date(current).toISOString().slice(0, 16).replace('T', ' ') : '');
    if (value === null) return;
    const iso = value.trim() ? new Date(value.trim().replace(' ', 'T')).toISOString() : null;
    await patchCode(id, { validUntil: iso });
  }

  async function clearLockout() {
    busy = true;
    try { await api('/lockout/clear', { method: 'POST' }); await refresh(); }
    catch (e) { error = e.message; } finally { busy = false; }
  }

  async function removePasskey(id) {
    if (!confirm('Remove this passkey?')) return;
    busy = true;
    try { await api(`/credentials/${id}`, { method: 'DELETE' }); await refresh(); }
    catch (e) { error = e.message; } finally { busy = false; }
  }

  async function signOut() {
    await api('/logout', { method: 'POST' });
    location.reload();
  }

  function codeState(c) {
    if (!c.active) return 'revoked';
    if (c.locked_until && new Date(c.locked_until) > new Date()) return 'locked';
    if (c.valid_until && new Date(c.valid_until) < new Date()) return 'expired';
    if (c.max_uses !== null && c.use_count >= c.max_uses) return 'used up';
    return 'active';
  }

  const fmt = (v) => v ? new Date(v).toLocaleString('sv-SE').slice(0, 16) : '—';

  boot();
</script>

<main>
  {#if view === 'loading'}
    <p class="muted">…</p>

  {:else if view === 'enroll'}
    <section class="gate">
      <h1>Register a passkey</h1>
      <p class="muted">This link works once. Your authenticator will prompt you.</p>
      <button class="primary" onclick={enroll} disabled={busy}>
        {busy ? 'Waiting for authenticator…' : 'Register passkey'}
      </button>
      {#if error}<p class="bad">{error}</p>{/if}
    </section>

  {:else if view === 'login'}
    <section class="gate">
      <h1>doorkey</h1>
      <p class="muted">Admin access requires an enrolled passkey.</p>
      <button class="primary" onclick={signIn} disabled={busy}>
        {busy ? 'Waiting for authenticator…' : 'Sign in with passkey'}
      </button>
      {#if error}<p class="bad">{error}</p>{/if}
    </section>

  {:else}
    <header>
      <h1>doorkey</h1>
      <div class="who">
        <span class="muted">{label}</span>
        {#if !viaHa}<button class="link" onclick={signOut}>sign out</button>{/if}
      </div>
    </header>

    <nav class="tabs" aria-label="Sections">
      <button class:on={tab === 'door'} aria-current={tab === 'door' ? 'page' : undefined}
              onclick={() => (tab = 'door')}>Door</button>
      <button class:on={tab === 'actions'} aria-current={tab === 'actions' ? 'page' : undefined}
              onclick={() => (tab = 'actions')}>Actions</button>
    </nav>

    {#if error}<p class="bad banner">{error}</p>{/if}

    {#if tab === 'actions'}
      <ActionsTab {api} {fmt} />
    {:else}
    {#if status}
      <section class="status">
        <div class="stat">
          <span class="k">Front door</span>
          <span class="v" class:ok={status.door === 'locked'} class:bad={status.door === 'unlocked'}>
            {status.door === 'unknown' ? 'unreachable' : status.door}
          </span>
        </div>
        <div class="stat">
          <span class="k">Keypad</span>
          {#if status.lockedUntil}
            <span class="v bad">locked out until {fmt(status.lockedUntil)}</span>
            <button class="link" onclick={clearLockout} disabled={busy}>clear</button>
          {:else}
            <span class="v ok">accepting codes</span>
          {/if}
        </div>
        <div class="stat">
          <span class="k">Failed today</span>
          <span class="v">{status.failedToday}</span>
          <span class="muted">streak {status.streak}/{status.hardAfter}</span>
        </div>
        <div class="stat">
          <span class="k">Last entry</span>
          <span class="v">
            {status.lastEntry ? `${status.lastEntry.label} · ${fmt(status.lastEntry.ts)}` : 'never'}
          </span>
        </div>
      </section>
    {/if}

    {#if freshCode}
      <section class="fresh">
        <div>
          <span class="muted">Code for {freshCode.label} — shown once</span>
          <strong>{freshCode.code}</strong>
        </div>
        <button class="link" onclick={() => (freshCode = null)}>dismiss</button>
      </section>
    {/if}

    <section>
      <h2>New code</h2>
      <form onsubmit={createCode}>
        <label>Who <input bind:value={form.label} placeholder="Cleaner" required /></label>
        <label>Expires <input type="datetime-local" bind:value={form.validUntil} /></label>
        <label>Max uses <input type="number" min="1" bind:value={form.maxUses} placeholder="∞" /></label>
        <label>Digits <input type="number" min="4" max="12" bind:value={form.digits} /></label>
        <button class="primary" disabled={busy}>Create</button>
      </form>
    </section>

    <section>
      <h2>Codes</h2>
      <table>
        <thead>
          <tr><th>Who</th><th>State</th><th>Uses</th><th>Expires</th><th>Last used</th><th></th></tr>
        </thead>
        <tbody>
          {#each codes as c (c.id)}
            <tr class:dim={codeState(c) !== 'active'}>
              <td>{c.label}</td>
              <td><span class="pill {codeState(c)}">{codeState(c)}</span></td>
              <td>{c.use_count}{c.max_uses ? `/${c.max_uses}` : ''}</td>
              <td>
                <button class="link" onclick={() => setExpiry(c.id, c.valid_until)}>
                  {c.valid_until ? fmt(c.valid_until) : 'never'}
                </button>
              </td>
              <td class="muted">{fmt(c.last_used_at)}</td>
              <td>
                <div class="actions">
                  <button class="link" onclick={() => regenerate(c.id, c.label)}>new code</button>
                  {#if c.active}
                    <button class="link" onclick={() => patchCode(c.id, { active: false })}>revoke</button>
                  {:else}
                    <button class="link" onclick={() => patchCode(c.id, { active: true })}>enable</button>
                  {/if}
                  <button class="link bad" onclick={() => removeCode(c.id, c.label)}>delete</button>
                </div>
              </td>
            </tr>
          {:else}
            <tr><td colspan="6" class="muted">No codes yet.</td></tr>
          {/each}
        </tbody>
      </table>
    </section>

    <section>
      <h2>DNA tags</h2>
      <table>
        <thead>
          <tr><th>Tag</th><th>Opens</th><th>State</th><th>Last used</th><th></th></tr>
        </thead>
        <tbody>
          {#each tags as t (t.uid)}
            <tr class:dim={!t.active}>
              <td>{t.label} <span class="muted mono small">{t.uid}</span></td>
              <td>{t.action ? `action ${t.action}` : 'the door'}</td>
              <td><span class="pill {t.active ? 'active' : 'revoked'}">{t.active ? 'active' : 'disabled'}</span></td>
              <td class="muted">{fmt(t.last_used_at)}</td>
              <td>
                <div class="actions">
                  <button class="link" class:bad={t.active} onclick={() => setTagActive(t.uid, !t.active)} disabled={busy}>
                    {t.active ? 'disable' : 'enable'}
                  </button>
                </div>
              </td>
            </tr>
          {:else}
            <tr><td colspan="5" class="muted">No tags yet.</td></tr>
          {/each}
        </tbody>
      </table>
      <form onsubmit={enrolTag} aria-label="Enrol tag" class="tag-form">
        <label class="wide">Tag code <input bind:value={tagForm.code} placeholder="dktag1.…" required /></label>
        <label>Label <input bind:value={tagForm.label} placeholder="from the code" /></label>
        <button class="primary" disabled={busy}>Enrol</button>
      </form>
      {#if tagNote}<p class="ok small">{tagNote}</p>{/if}
      <p class="muted small">
        tagtui and <code>provision.py</code> print a tag code after provisioning. It holds the tag's key only
        wrapped with your KEK, and is refused unless this server's KEK opens it.
      </p>
    </section>

    <section>
      <h2>Door activity</h2>
      <table>
        <tbody>
          {#each attempts as a}
            <tr>
              <td class="muted mono">{fmt(a.ts)}</td>
              <td><span class="pill {a.result === 'granted' ? 'active' : 'revoked'}">{a.result}</span></td>
              <td>{a.label ?? ''}</td>
              <td class="muted mono">{a.src_ip ?? ''}</td>
            </tr>
          {:else}
            <tr><td class="muted">Nothing yet.</td></tr>
          {/each}
        </tbody>
      </table>
    </section>

    <section>
      <h2>Admin activity</h2>
      <table>
        <tbody>
          {#each events as e}
            <tr>
              <td class="muted mono">{fmt(e.ts)}</td>
              <td>{e.event}</td>
              <td class="muted">{e.detail ?? ''}</td>
            </tr>
          {:else}
            <tr><td class="muted">Nothing yet.</td></tr>
          {/each}
        </tbody>
      </table>
    </section>

    <section>
      <h2>Admin passkeys</h2>
      <table>
        <tbody>
          {#each credentials as k}
            <tr>
              <td>{k.label}</td>
              <td class="muted mono">added {fmt(k.created_at)}</td>
              <td class="muted mono">last used {fmt(k.last_used_at)}</td>
              <td>
                <div class="actions">
                  {#if credentials.length > 1}
                    <button class="link bad" onclick={() => removePasskey(k.id)}>remove</button>
                  {:else}
                    <span class="muted small">only key</span>
                  {/if}
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="muted small">
        Codes are stored as an HMAC and cannot be shown again — a forgotten code
        is replaced with <em>new code</em>, never recovered.
      </p>
      <p class="muted small">
        New passkeys are minted from the CLI only:
        <code>doorkey admin:enroll &lt;label&gt;</code>
      </p>
    </section>
    {/if}
  {/if}
</main>

<style>
  :global(:root) {
    --bg: #12141a; --panel: #171a22; --fg: #eef1f7; --dim: #878da0;
    --line: #252a36; --ok: #4ade80; --bad: #f87171; --accent: #6aa2ff;
    color-scheme: dark;
  }
  :global(body) {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.5 system-ui, -apple-system, 'Segoe UI', sans-serif;
  }
  main { max-width: 60rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; }

  header { display: flex; align-items: baseline; justify-content: space-between;
           border-bottom: 1px solid var(--line); padding-bottom: 1rem; margin-bottom: 1.5rem; }
  .who { display: flex; gap: .75rem; align-items: baseline; }

  .tabs { display: flex; gap: .25rem; margin: -0.5rem 0 1.5rem; border-bottom: 1px solid var(--line); }
  .tabs button { background: none; border: none; color: var(--dim); padding: .55rem .9rem;
                 border-bottom: 2px solid transparent; margin-bottom: -1px; font-weight: 500; }
  .tabs button.on { color: var(--fg); border-bottom-color: var(--accent); }
  .tabs button:hover:not(.on) { color: var(--fg); }
  h1 { font-size: 1.25rem; margin: 0; letter-spacing: .02em; }
  h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .09em;
       color: var(--dim); font-weight: 600; margin: 2rem 0 .75rem; }

  .gate { max-width: 22rem; margin: 18vh auto 0; text-align: center; }
  .gate h1 { margin-bottom: .5rem; }
  .gate .primary { margin-top: 1.5rem; width: 100%; }

  .status { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
            gap: .75rem; }
  .stat { background: var(--panel); border: 1px solid var(--line); border-radius: .6rem;
          padding: .8rem .9rem; display: flex; flex-wrap: wrap; gap: .5rem; align-items: baseline; }
  .stat .k { color: var(--dim); font-size: .8rem; width: 100%; }
  .stat .v { font-variant-numeric: tabular-nums; }

  .fresh { margin-top: 1rem; background: #16251b; border: 1px solid #2c5138;
           border-radius: .6rem; padding: .9rem; display: flex; justify-content: space-between;
           align-items: center; gap: 1rem; flex-wrap: wrap; }
  .fresh strong { display: block; font-size: 2rem; letter-spacing: .22em;
                  font-variant-numeric: tabular-nums; }

  form { display: flex; flex-wrap: wrap; gap: .75rem; align-items: flex-end; }
  label { display: flex; flex-direction: column; gap: .3rem; font-size: .8rem; color: var(--dim); }
  input { background: var(--panel); border: 1px solid var(--line); color: var(--fg);
          border-radius: .4rem; padding: .5rem .6rem; font: inherit; font-size: .9rem; }
  input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }

  button { font: inherit; cursor: pointer; }
  .primary { background: var(--accent); color: #08101f; border: none; font-weight: 600;
             border-radius: .4rem; padding: .55rem 1.1rem; }
  .primary:disabled { opacity: .5; cursor: default; }
  .link { background: none; border: none; color: var(--accent); padding: 0; font-size: .85rem; }
  .link.bad { color: var(--bad); }
  .link:disabled { opacity: .5; cursor: default; }

  table { width: 100%; border-collapse: collapse; font-size: .88rem; }
  th { text-align: left; font-weight: 500; color: var(--dim); font-size: .75rem;
       text-transform: uppercase; letter-spacing: .06em; padding: .4rem .6rem; }
  td { padding: .5rem .6rem; border-top: 1px solid var(--line); vertical-align: middle; }
  tr.dim td { opacity: .55; }
  td .actions { display: flex; gap: .75rem; justify-content: flex-end; }

  .pill { font-size: .72rem; padding: .12rem .5rem; border-radius: 1rem;
          border: 1px solid var(--line); text-transform: uppercase; letter-spacing: .05em; }
  .pill.active { color: var(--ok); border-color: #2c5138; }
  .pill.revoked, .pill.expired, .pill.locked { color: var(--bad); border-color: #5a2b2b; }

  .muted { color: var(--dim); }
  .tag-form { margin-top: 1rem; }
  .tag-form .wide { flex: 1; min-width: min(100%, 24rem); }
  .tag-form .wide input { width: 100%; box-sizing: border-box; font-variant-numeric: tabular-nums; }
  .small { font-size: .8rem; }
  .mono { font-variant-numeric: tabular-nums; }
  .ok { color: var(--ok); }
  .bad { color: var(--bad); }
  .banner { background: #241a1a; border: 1px solid #5a2b2b; border-radius: .5rem; padding: .6rem .8rem; }
  code { background: var(--panel); padding: .1rem .35rem; border-radius: .25rem; }

  @media (max-width: 560px) {
    td .actions { justify-content: flex-start; }
    form label { flex: 1 1 8rem; }
  }
</style>
