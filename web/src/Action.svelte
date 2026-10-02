<script>
  import { onMount } from 'svelte';
  import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
  import { t } from './i18n.js';

  // /a/enroll/<token> registers a passkey; anything else is a tapped action.
  const enrollToken = location.pathname.match(/^\/a\/enroll\/([^/]+)$/)?.[1] ?? null;

  // Options are fetched on load so the button can call WebAuthn straight from
  // the tap gesture; refetched if they are getting close to the server's 120 s.
  const OPTIONS_MAX_AGE_MS = 90_000;

  let phase = $state('loading'); // loading | ready | busy | done | failed
  let title = $state('');
  let detail = $state('');
  let message = $state('');
  let options = null;
  let fetchedAt = 0;

  async function post(path, body) {
    const res = await fetch(`/a/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    });
    return { res, body: await res.json().catch(() => ({})) };
  }

  function explain(status, error) {
    if (status === 401 && error === 'expired') return t.expired;
    if (status === 403 && error === 'nobody allowed') return t.nobodyAllowed;
    if (status === 403 && error === 'not allowed') return t.notAllowed;
    if (status === 403 && error === 'not home') return t.notHome;
    if (status === 401) return t.notVerified;
    if (status === 404) return t.invalidLink;
    if (status === 429) return t.tooMany;
    if (status === 502) return t.haDown;
    return t.failed;
  }

  async function load() {
    const { res, body } = enrollToken
      ? await post(`/enroll/${enrollToken}/options`)
      : await post('/begin');
    if (body.label) title = body.label;
    if (!res.ok) {
      phase = 'failed';
      message = explain(res.status, body.error);
      return false;
    }
    if (enrollToken) {
      title = t.newPasskey;
      detail = `${body.user} · ${body.device}`;
    }
    options = body.options;
    fetchedAt = Date.now();
    phase = 'ready';
    return true;
  }

  async function confirm() {
    phase = 'busy';
    message = '';
    try {
      if (Date.now() - fetchedAt > OPTIONS_MAX_AGE_MS && !(await load())) return;
      phase = 'busy';

      const { res, body } = enrollToken
        ? await post(`/enroll/${enrollToken}/verify`, await startRegistration({ optionsJSON: options }))
        : await post('/run', { response: await startAuthentication({ optionsJSON: options }) });

      if (res.ok) {
        phase = 'done';
        message = enrollToken ? t.saved : t.done;
        navigator.vibrate?.([20, 60, 20]);
      } else {
        const why = explain(res.status, body.error);
        navigator.vibrate?.(120);
        // A rejected passkey leaves the tap session usable: offer another try
        // (e.g. with a different passkey). Expired or invalid links do not.
        const retry = !enrollToken && (res.status === 401 || res.status === 403) && body.error !== 'expired';
        if (retry && (await load())) {
          message = why;
        } else {
          phase = 'failed';
          message = why;
        }
      }
    } catch (err) {
      // NotAllowedError: the prompt was dismissed or timed out. The challenge
      // was not used, so the same options can be tried again.
      if (err?.name === 'NotAllowedError') {
        phase = 'ready';
        message = t.cancelled;
      } else {
        phase = 'failed';
        message = t.failed;
      }
    }
  }

  onMount(() => {
    load().catch(() => {
      phase = 'failed';
      message = t.offline;
    });
  });
</script>

<main>
  <div class="head">
    <h1>{enrollToken ? t.passkey : t.action}</h1>
    <p class="title">{title || ' '}</p>
    {#if detail}<p class="detail">{detail}</p>{/if}
  </div>

  <div class="foot">
    <p class="msg" class:ok={phase === 'done'} class:bad={phase === 'failed'}>
      {phase === 'busy' ? t.checking : message || ' '}
    </p>
    {#if phase === 'ready' || phase === 'busy'}
      <button onclick={confirm} disabled={phase === 'busy'}>
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 3a8 8 0 0 0-8 8M12 3a8 8 0 0 1 8 8v1M8.5 20.5A12 12 0 0 0 9 11a3 3 0 0 1 6 0 16 16 0 0 1-1 6M12 11v2a20 20 0 0 1-2 8.5M17.5 19a24 24 0 0 0 .5-6" />
        </svg>
        {enrollToken ? t.register : t.confirm}
      </button>
    {/if}
    {#if phase === 'done'}<div class="check" aria-hidden="true">✓</div>{/if}
  </div>
</main>

<style>
  :global(:root) {
    --bg: #12141a;
    --fg: #eef1f7;
    --dim: #8a90a0;
    --key: #1e222c;
    --key-press: #2c323f;
    --accent: #6aa2ff;
    --ok: #4ade80;
    --bad: #f87171;
    color-scheme: dark;
  }
  :global(body) {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font: 16px/1.4 system-ui, -apple-system, 'Segoe UI', sans-serif;
    -webkit-tap-highlight-color: transparent;
  }

  main {
    min-height: 100svh;
    max-width: 22rem;
    margin: 0 auto;
    padding: max(1.5rem, env(safe-area-inset-top)) 1.25rem
             max(2rem, env(safe-area-inset-bottom));
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 2rem;
    box-sizing: border-box;
  }

  .head { text-align: center; padding-top: 2rem; }
  h1 { font-size: 1.1rem; font-weight: 500; letter-spacing: .08em;
       text-transform: uppercase; color: var(--dim); margin: 0 0 2rem; }
  .title { font-size: 1.6rem; font-weight: 600; margin: 0; overflow-wrap: anywhere; }
  .detail { color: var(--dim); margin: .5rem 0 0; }

  .foot { display: flex; flex-direction: column; gap: 1rem; align-items: stretch; }
  .msg { min-height: 1.4em; margin: 0; text-align: center; font-size: .95rem; color: var(--dim); }
  .msg.ok { color: var(--ok); }
  .msg.bad { color: var(--bad); }

  button {
    display: flex; align-items: center; justify-content: center; gap: .6rem;
    font: inherit; font-size: 1.1rem; font-weight: 600;
    color: #08101f; background: var(--accent);
    border: none; border-radius: 1rem; padding: 1.1rem 1rem;
    cursor: pointer; transition: transform .06s, opacity .1s;
  }
  button:active:not(:disabled) { transform: scale(.97); }
  button:disabled { opacity: .5; cursor: default; }
  svg { width: 1.5rem; height: 1.5rem; fill: none; stroke: currentColor;
        stroke-width: 1.8; stroke-linecap: round; }

  .check { text-align: center; font-size: 4rem; color: var(--ok); line-height: 1; }

  @media (prefers-reduced-motion: reduce) {
    button { transition: none; }
  }
</style>
