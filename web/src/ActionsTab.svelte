<script>
  // Tap-gated actions: actions, action users with their passkeys, and roles.
  // Everything here is the same operation as a CLI command, logged the same.
  let { api, fmt } = $props();

  let data = $state({ actions: [], users: [], roles: [], tags: [], events: [] });
  let scripts = $state(null);   // null while loading, [] if HA is unreachable
  let error = $state('');
  let busy = $state(false);

  // A tag URL or enrolment link, shown once right after it is minted.
  let secret = $state(null);    // { title, url, note }
  let copied = $state(false);

  let newAction = $state({ label: '', slug: '', script: '', requireSun: false, homeOnly: false });
  let slugTouched = $state(false);
  let newUser = $state('');
  let roleDraft = $state({});   // `a<id>` / `u<id>` -> text in that card's role input

  const roleNames = $derived(data.roles.map((r) => r.name));

  async function load() {
    data = await api('/actions?limit=60');
  }

  async function loadScripts() {
    try { scripts = await api('/ha/scripts'); } catch { scripts = []; }
  }

  async function run(fn) {
    busy = true; error = '';
    try { await fn(); await load(); }
    catch (e) { error = e.message; }
    finally { busy = false; }
  }

  const send = (path, method, body) =>
    api(path, { method, body: body === undefined ? undefined : JSON.stringify(body) });

  const slugify = (s) =>
    s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);

  function pickScript(entity) {
    newAction.script = entity;
    const script = scripts?.find((s) => s.entity_id === entity);
    if (!newAction.label && script) newAction.label = script.name;
    if (!slugTouched) newAction.slug = slugify(entity.replace(/^script\./, ''));
  }

  function show(title, url, note) {
    secret = { title, url, note };
    copied = false;
  }

  async function copy() {
    try { await navigator.clipboard.writeText(secret.url); copied = true; }
    catch { copied = false; }
  }

  // --- actions --------------------------------------------------------------

  const createAction = (event) => {
    event.preventDefault();
    return run(async () => {
      await send('/actions', 'POST', newAction);
      newAction = { label: '', slug: '', script: '', requireSun: false, homeOnly: false };
      slugTouched = false;
    });
  };

  const patchAction = (a, patch) => run(() => send(`/actions/${a.id}`, 'PATCH', patch));

  function renameAction(a) {
    const label = prompt('Label shown on the tap page', a.label);
    if (label && label.trim() && label !== a.label) patchAction(a, { label });
  }

  function deleteAction(a) {
    if (!confirm(`Delete ${a.label}? Its tag URL stops working. The log keeps its history.`)) return;
    run(() => send(`/actions/${a.id}`, 'DELETE'));
  }

  function issueToken(a) {
    if (a.has_token && !confirm(`Issue a new tag URL for ${a.label}? The current one stops working immediately — rewrite the tag.`)) return;
    run(async () => {
      const { url } = await send(`/actions/${a.id}/token`, 'POST');
      show(`Tag URL for ${a.label}`, url, 'Shown once. Write it to the NFC tag as a URL record, then write-protect the tag.');
    });
  }

  function removeToken(a) {
    if (!confirm(`Stop accepting the plain tag for ${a.label}?`)) return;
    run(() => send(`/actions/${a.id}/token`, 'DELETE'));
  }

  function addRole(kind, id) {
    const key = `${kind}${id}`;
    const name = (roleDraft[key] ?? '').trim().toLowerCase();
    if (!name) return;
    run(async () => {
      await send(kind === 'a' ? `/actions/${id}/roles/${name}` : `/action-users/${id}/roles/${name}`, 'PUT');
      roleDraft[key] = '';
    });
  }

  const removeRole = (kind, id, name) =>
    run(() => send(kind === 'a' ? `/actions/${id}/roles/${name}` : `/action-users/${id}/roles/${name}`, 'DELETE'));

  function where(tag) {
    if (tag.action_id === null) return 'opens the door';
    const a = data.actions.find((x) => x.id === tag.action_id);
    return a ? `opens ${a.label}` : 'linked';
  }

  function linkTag(a, uid) {
    const tag = data.tags.find((t) => t.uid === uid);
    if (!tag) return;
    if (!confirm(`Tag “${tag.label}” currently ${where(tag)}. Make it open ${a.label} instead?`)) return;
    run(() => send(`/tags/${uid}/action`, 'PUT', { actionId: a.id }));
  }

  function unlinkTag(a, label) {
    const tag = data.tags.find((t) => t.label === label && t.action_id === a.id);
    if (!tag) return;
    if (!confirm(`Unlink “${tag.label}”? It will open the FRONT DOOR keypad again.`)) return;
    run(() => send(`/tags/${tag.uid}/action`, 'PUT', { actionId: null }));
  }

  // --- users ----------------------------------------------------------------

  const createUser = (event) => {
    event.preventDefault();
    return run(async () => { await send('/action-users', 'POST', { name: newUser }); newUser = ''; });
  };

  const setUserActive = (u, active) => run(() => send(`/action-users/${u.id}`, 'PATCH', { active }));

  function enrollLink(u) {
    const device = prompt(`Which device will ${u.name} register? (shown next to the passkey)`, 'phone');
    if (device === null) return;
    run(async () => {
      const { url, expiresAt } = await send(`/action-users/${u.id}/enroll`, 'POST', { device });
      show(
        `Enrolment link for ${u.name} · ${device || 'phone'}`,
        url,
        `Single use, valid until ${fmt(expiresAt).slice(11)}. Open it on that device.`,
      );
    });
  }

  function removePasskey(u, k) {
    if (!confirm(`Remove ${u.name}'s passkey “${k.label}”? That device can no longer confirm actions.`)) return;
    run(() => send(`/action-credentials/${k.id}`, 'DELETE'));
  }

  const deleteRole = (r) => run(() => send(`/roles/${r.name}`, 'DELETE'));

  run(load);
  loadScripts();
</script>

<datalist id="roles">
  {#each roleNames as r}<option value={r}></option>{/each}
</datalist>

{#if error}<p class="bad banner">{error}</p>{/if}

{#if secret}
  <section class="fresh">
    <div class="grow">
      <span class="muted">{secret.title} — shown once</span>
      <code class="url">{secret.url}</code>
      <span class="muted small">{secret.note}</span>
    </div>
    <div class="row">
      <button class="primary" onclick={copy}>{copied ? 'Copied ✓' : 'Copy'}</button>
      <button class="link" onclick={() => (secret = null)}>dismiss</button>
    </div>
  </section>
{/if}

<!-- actions ------------------------------------------------------------- -->

<section>
  <h2>Actions</h2>
  <div class="cards">
    {#each data.actions as a (a.id)}
      <article class="card" class:dim={!a.active}>
        <header>
          <div>
            <strong>{a.label}</strong>
            <span class="muted mono small">/a/{a.slug}</span>
          </div>
          <span class="pill {a.active ? 'active' : 'revoked'}">{a.active ? 'active' : 'disabled'}</span>
        </header>

        <dl>
          <dt>Runs</dt>
          <dd class="mono">{a.script_entity}</dd>

          <dt>Last run</dt>
          <dd class="muted">{fmt(a.last_run_at)}</dd>

          <dt>Plain tag</dt>
          <dd>
            {#if a.require_sun}
              <span class="muted">refused — DNA tag required</span>
            {:else}
              <span class:muted={!a.has_token}>{a.has_token ? 'URL issued' : 'none'}</span>
              <button class="link" onclick={() => issueToken(a)} disabled={busy}>
                {a.has_token ? 'rotate' : 'issue URL'}
              </button>
              {#if a.has_token}
                <button class="link bad" onclick={() => removeToken(a)} disabled={busy}>remove</button>
              {/if}
            {/if}
          </dd>

          <dt>DNA tags</dt>
          <dd>
            <div class="chips">
              {#each a.tags as t}
                <span class="chip">{t}<button aria-label="unlink {t}" onclick={() => unlinkTag(a, t)} disabled={busy}>×</button></span>
              {/each}
              {#if data.tags.some((t) => t.action_id !== a.id && t.active)}
                <select aria-label="Link a DNA tag" disabled={busy}
                        onchange={(e) => { linkTag(a, e.currentTarget.value); e.currentTarget.value = ''; }}>
                  <option value="">link a tag…</option>
                  {#each data.tags.filter((t) => t.action_id !== a.id && t.active) as t}
                    <option value={t.uid}>{t.label} ({where(t)})</option>
                  {/each}
                </select>
              {:else if a.tags.length === 0}
                <span class="muted small">no provisioned tags to link</span>
              {/if}
            </div>
          </dd>

          <dt>Roles</dt>
          <dd>
            <div class="chips">
              {#each a.roles as r}
                <span class="chip">{r}<button aria-label="remove role {r}" onclick={() => removeRole('a', a.id, r)} disabled={busy}>×</button></span>
              {:else}
                <span class="bad small">nobody may run it</span>
              {/each}
              <form class="inline" onsubmit={(e) => { e.preventDefault(); addRole('a', a.id); }}>
                <input list="roles" placeholder="add role" bind:value={roleDraft[`a${a.id}`]} />
              </form>
            </div>
          </dd>
        </dl>

        <footer>
          <div class="toggles">
            <label class="check"><input type="checkbox" checked={a.require_sun} disabled={busy}
                   onchange={(e) => patchAction(a, { requireSun: e.currentTarget.checked })} /> DNA tag required</label>
            <label class="check"><input type="checkbox" checked={a.home_only} disabled={busy}
                   onchange={(e) => patchAction(a, { homeOnly: e.currentTarget.checked })} /> home network only</label>
          </div>
          <div class="links">
          <button class="link" onclick={() => renameAction(a)} disabled={busy}>rename</button>
          <button class="link" onclick={() => patchAction(a, { active: !a.active })} disabled={busy}>
            {a.active ? 'disable' : 'enable'}
          </button>
          <button class="link bad" onclick={() => deleteAction(a)} disabled={busy || a.tags.length > 0}
                  title={a.tags.length > 0 ? 'Unlink its DNA tags first' : ''}>delete</button>
          </div>
        </footer>
      </article>
    {:else}
      <p class="muted">No actions yet.</p>
    {/each}
  </div>
</section>

<section>
  <h2>New action</h2>
  <form onsubmit={createAction} aria-label="New action">
    <label class="wide">Script
      {#if scripts === null}
        <input disabled placeholder="loading scripts from Home Assistant…" />
      {:else if scripts.length}
        <select required value={newAction.script} onchange={(e) => pickScript(e.currentTarget.value)}>
          <option value="" disabled>pick a script…</option>
          {#each scripts as s}<option value={s.entity_id}>{s.name} · {s.entity_id}</option>{/each}
        </select>
      {:else}
        <input required pattern={'script\\.[a-z0-9_]+'} placeholder="script.something (HA unreachable)"
               bind:value={newAction.script} />
      {/if}
    </label>
    <label>Label <input required bind:value={newAction.label} placeholder="Open the garage" /></label>
    <label>Slug
      <input required pattern="[a-z0-9][a-z0-9\-]{'{'}0,62{'}'}" bind:value={newAction.slug}
             oninput={() => (slugTouched = true)} placeholder="garage" />
    </label>
    <div class="opts">
      <label class="check"><input type="checkbox" bind:checked={newAction.requireSun} /> DNA tag required</label>
      <label class="check"><input type="checkbox" bind:checked={newAction.homeOnly} /> home network only</label>
      <button class="primary" disabled={busy}>Create</button>
    </div>
  </form>
  <p class="muted small">
    The script receives <code>tapgate_user</code>, <code>tapgate_action</code> and
    <code>tapgate_via</code>. Allow a role, then issue a tag URL or link a DNA tag.
  </p>
</section>

<!-- users --------------------------------------------------------------- -->

<section>
  <h2>Action users</h2>
  <div class="cards">
    {#each data.users as u (u.id)}
      <article class="card" class:dim={!u.active}>
        <header>
          <strong>{u.name}</strong>
          <span class="pill {u.active ? 'active' : 'revoked'}">{u.active ? 'active' : 'disabled'}</span>
        </header>

        <dl>
          <dt>Roles</dt>
          <dd>
            <div class="chips">
              {#each u.roles as r}
                <span class="chip">{r}<button aria-label="remove role {r}" onclick={() => removeRole('u', u.id, r)} disabled={busy}>×</button></span>
              {:else}
                <span class="muted small">no roles</span>
              {/each}
              <form class="inline" onsubmit={(e) => { e.preventDefault(); addRole('u', u.id); }}>
                <input list="roles" placeholder="add role" bind:value={roleDraft[`u${u.id}`]} />
              </form>
            </div>
          </dd>

          <dt>Passkeys</dt>
          <dd>
            {#each u.credentials as k}
              <div class="passkey">
                <span>{k.label}</span>
                <span class="muted small">added {fmt(k.created_at)} · used {fmt(k.last_used_at)}</span>
                <button class="link bad" onclick={() => removePasskey(u, k)} disabled={busy}>remove</button>
              </div>
            {:else}
              <span class="muted small">none yet</span>
            {/each}
          </dd>
        </dl>

        <footer>
          <button class="link" onclick={() => enrollLink(u)} disabled={busy || !u.active}>new enrolment link</button>
          <span class="spacer"></span>
          <button class="link" class:bad={u.active} onclick={() => setUserActive(u, !u.active)} disabled={busy}>
            {u.active ? 'disable' : 'enable'}
          </button>
        </footer>
      </article>
    {:else}
      <p class="muted">No action users yet.</p>
    {/each}
  </div>

  <form onsubmit={createUser} class="add" aria-label="New user">
    <label>New user <input required maxlength="64" bind:value={newUser} placeholder="Ola" /></label>
    <button class="primary" disabled={busy}>Add</button>
  </form>
  <p class="muted small">
    Action passkeys are separate from admin passkeys: they cannot sign in here, and
    the tap page only offers passkeys whose user may run that action.
  </p>
</section>

<!-- roles --------------------------------------------------------------- -->

<section>
  <h2>Roles</h2>
  <table>
    <thead><tr><th>Role</th><th>Users</th><th>Actions</th><th></th></tr></thead>
    <tbody>
      {#each data.roles as r}
        <tr>
          <td>{r.name}</td>
          <td class="mono">{r.users}</td>
          <td class="mono">{r.actions}</td>
          <td>
            <div class="actions">
              {#if r.users === 0 && r.actions === 0}
                <button class="link bad" onclick={() => deleteRole(r)} disabled={busy}>delete</button>
              {:else}
                <span class="muted small">in use</span>
              {/if}
            </div>
          </td>
        </tr>
      {:else}
        <tr><td class="muted">Roles appear when you grant one to a user or an action.</td></tr>
      {/each}
    </tbody>
  </table>
</section>

<!-- log ----------------------------------------------------------------- -->

<section>
  <h2>Action activity</h2>
  <table>
    <tbody>
      {#each data.events as e}
        <tr>
          <td class="muted mono">{fmt(e.ts)}</td>
          <td><span class="pill {e.result === 'ran' ? 'active' : 'revoked'}">{e.result}</span></td>
          <td>{e.action ?? ''}</td>
          <td>{e.user ?? ''}</td>
          <td class="muted small">{e.via === 'sun' ? `DNA ${e.tag ?? ''}` : e.via === 'token' ? 'plain tag' : ''}</td>
          <td class="muted mono">{e.src_ip ?? ''}</td>
        </tr>
      {:else}
        <tr><td class="muted">Nothing yet.</td></tr>
      {/each}
    </tbody>
  </table>
</section>

<style>
  /* Component styles are scoped, so the shared look is repeated from Admin.svelte. */
  h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .09em;
       color: var(--dim); font-weight: 600; margin: 2rem 0 .75rem; }

  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 27rem), 1fr)); gap: .75rem; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: .6rem;
          padding: .9rem 1rem; display: flex; flex-direction: column; gap: .7rem; min-width: 0; }
  .card.dim { opacity: .6; }
  .card header { display: flex; justify-content: space-between; align-items: baseline; gap: .75rem; }
  .card header strong { font-size: 1.02rem; margin-right: .4rem; }
  .card footer { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: center;
                 justify-content: space-between; border-top: 1px solid var(--line);
                 padding-top: .7rem; margin-top: auto; }
  .toggles, .links { display: flex; flex-wrap: wrap; gap: .4rem 1rem; align-items: center; }
  .links { margin-left: auto; }
  .opts { display: flex; flex-wrap: wrap; gap: .75rem 1.25rem; align-items: center; flex-basis: 100%; }
  .spacer { flex: 1; }

  dl { display: grid; grid-template-columns: 6.5rem 1fr; gap: .45rem .75rem; margin: 0; font-size: .88rem; }
  dt { color: var(--dim); font-size: .78rem; padding-top: .15rem; }
  dd { margin: 0; display: flex; flex-wrap: wrap; gap: .3rem .75rem; align-items: center; min-width: 0; }

  .chips { display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; }
  .chip { display: inline-flex; align-items: center; gap: .2rem; font-size: .8rem;
          background: var(--bg); border: 1px solid var(--line); border-radius: 1rem;
          padding: .1rem .2rem .1rem .6rem; }
  .chip button { background: none; border: none; color: var(--dim); font-size: .95rem;
                 line-height: 1; padding: 0 .3rem; cursor: pointer; border-radius: 1rem; }
  .chip button:hover:not(:disabled) { color: var(--bad); }

  .passkey { display: flex; flex-wrap: wrap; gap: .2rem .75rem; align-items: baseline; width: 100%; }

  .fresh { margin-top: 1rem; background: #16251b; border: 1px solid #2c5138;
           border-radius: .6rem; padding: .9rem; display: flex; justify-content: space-between;
           align-items: center; gap: 1rem; flex-wrap: wrap; }
  .fresh .grow { display: flex; flex-direction: column; gap: .35rem; min-width: 0; flex: 1; }
  .url { display: block; font-size: .85rem; overflow-wrap: anywhere; user-select: all; padding: .35rem .5rem; }
  .row { display: flex; gap: .75rem; align-items: center; }

  form { display: flex; flex-wrap: wrap; gap: .75rem; align-items: flex-end; }
  form.inline { display: inline-flex; }
  form.inline input { width: 7rem; padding: .15rem .5rem; font-size: .8rem; border-radius: 1rem; }
  form.add { margin-top: 1rem; }
  label { display: flex; flex-direction: column; gap: .3rem; font-size: .8rem; color: var(--dim); }
  label.wide { min-width: min(100%, 20rem); }
  label.check { flex-direction: row; align-items: center; gap: .4rem; color: var(--fg); font-size: .85rem; }
  input, select { background: var(--panel); border: 1px solid var(--line); color: var(--fg);
                  border-radius: .4rem; padding: .5rem .6rem; font: inherit; font-size: .9rem; }
  .card select { padding: .15rem .4rem; font-size: .8rem; background: var(--bg); }
  input:focus, select:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
  input[type='checkbox'] { accent-color: var(--accent); width: 1rem; height: 1rem; }

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
  td .actions { display: flex; gap: .75rem; justify-content: flex-end; }

  .pill { font-size: .72rem; padding: .12rem .5rem; border-radius: 1rem;
          border: 1px solid var(--line); text-transform: uppercase; letter-spacing: .05em; white-space: nowrap; }
  .pill.active { color: var(--ok); border-color: #2c5138; }
  .pill.revoked { color: var(--bad); border-color: #5a2b2b; }

  .muted { color: var(--dim); }
  .small { font-size: .8rem; }
  .mono { font-variant-numeric: tabular-nums; }
  .bad { color: var(--bad); }
  .banner { background: #2a1717; border: 1px solid #5a2b2b; border-radius: .5rem; padding: .6rem .8rem; }
  code { background: var(--bg); padding: .1rem .35rem; border-radius: .25rem; }

  @media (max-width: 30rem) {
    dl { grid-template-columns: 1fr; }
    dt { padding-top: .3rem; }
  }
</style>
