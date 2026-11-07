<script>
  import { onMount } from 'svelte';
  import { startAuthentication } from '@simplewebauthn/browser';
  import { t } from './i18n.js';

  const LENGTH = 6;

  let entered = $state('');
  let busy = $state(false);
  let status = $state('idle'); // idle | granted | denied | unavailable | error
  let action = $state(null);   // 'locked' | 'unlocked'

  // The door action, when the tap opened it too (see doorActionCookie on the
  // server): open with a fingerprint instead of a code. Options are fetched on
  // load so the button can call WebAuthn straight from the tap gesture, and
  // again once they get close to the server's 120 s.
  const OPTIONS_MAX_AGE_MS = 90_000;
  let fingerprint = $state('loading'); // loading | ready | none
  let fpOptions = null;
  let fpFetchedAt = 0;
  let fpMessage = $state('');
  // A phone that has opened the door by fingerprint before starts with it.
  const prefersFingerprint = document.cookie.split('; ').includes('doorkey_fp=1');
  let view = $state(prefersFingerprint ? 'fingerprint' : 'keypad'); // keypad | fingerprint

  async function loadFingerprint() {
    try {
      const res = await fetch('/a/api/begin', { method: 'POST' });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.options) throw new Error('not offered');
      fpOptions = body.options;
      fpFetchedAt = Date.now();
      fingerprint = 'ready';
      return true;
    } catch {
      fpOptions = null;
      fingerprint = 'none';
      view = 'keypad';
      return false;
    }
  }

  onMount(loadFingerprint);

  function fingerprintRefusal(status, error) {
    if (status === 403 && error === 'not allowed') return t.doorNotAllowed;
    if (status === 429) return t.fingerprintPaused;
    if (status === 502) return t.lockUnreachable;
    if (status === 401 && error === 'expired') return t.expired;
    return t.notVerified;
  }

  async function openWithFingerprint() {
    if (busy || fingerprint !== 'ready') return;
    busy = true;
    status = 'idle';
    fpMessage = '';
    entered = '';
    try {
      if (Date.now() - fpFetchedAt > OPTIONS_MAX_AGE_MS && !(await loadFingerprint())) return;
      const response = await startAuthentication({ optionsJSON: fpOptions });
      const res = await fetch('/a/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ response }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.ok) {
        // One run per tap: the session is spent.
        fingerprint = 'none';
        action = 'unlocked';
        status = 'granted';
        navigator.vibrate?.([20, 60, 20]);
        return;
      }
      fpMessage = fingerprintRefusal(res.status, body.error);
      navigator.vibrate?.(120);
      // A rejected passkey leaves the tap usable: offer another try.
      await loadFingerprint();
    } catch {
      // The prompt was dismissed or timed out; the options are still good.
      fpMessage = t.cancelled;
    } finally {
      busy = false;
      if (status !== 'granted') view = 'keypad';
    }
  }

  const message = $derived(
    status === 'granted'     ? (action === 'locked' ? t.locked : t.unlocked)
    : status === 'denied'      ? t.wrongCode
    : status === 'unavailable' ? t.lockUnreachable
    : status === 'error'       ? t.tryAgain
    : fpMessage
  );

  function press(digit) {
    if (busy || entered.length >= LENGTH) return;
    if (status !== 'idle') status = 'idle';
    fpMessage = '';
    navigator.vibrate?.(8);
    entered += digit;
    if (entered.length === LENGTH) submit();
  }

  function clear() {
    if (busy) return;
    navigator.vibrate?.(8);
    entered = '';
    status = 'idle';
    fpMessage = '';
  }

  async function submit() {
    busy = true;
    const code = entered;
    try {
      const res = await fetch('/api/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const body = await res.json().catch(() => ({}));
      action = body.action ?? null;
      status = res.ok ? 'granted' : body.lock === 'unavailable' ? 'unavailable' : 'denied';
    } catch {
      status = 'error';
    } finally {
      busy = false;
      entered = '';
      navigator.vibrate?.(status === 'granted' ? [20, 60, 20] : 120);
    }
  }
</script>

<main>
  <div class="head">
    <h1>{t.entry}</h1>
    {#if view === 'keypad'}
      <div class="dots" class:shake={status === 'denied'}>
        {#each { length: LENGTH } as _, i}
          <span class="dot" class:on={i < entered.length}></span>
        {/each}
      </div>
    {/if}
    <p class="msg" class:ok={status === 'granted'} class:bad={status === 'denied' || !!fpMessage}>
      {busy ? t.checking : message || ' '}
    </p>
  </div>

  {#snippet fingerprintIcon()}
    <svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" fill="none"
         stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
      <path d="M6.5 6.2A7.5 7.5 0 0 1 19.5 11v1.5" />
      <path d="M4.5 9.5A7.5 7.5 0 0 0 4.5 13" />
      <path d="M8 18.5c1-1.8 1.5-3.8 1.5-6a2.5 2.5 0 0 1 5 0c0 2.6-.4 5-1.4 7" />
      <path d="M12 12.5c0 3.2-.8 6-2.3 8" />
      <path d="M17 15.5c-.2 1.8-.7 3.4-1.4 4.8" />
      <path d="M6.6 16.4c.6-1.2.9-2.5.9-3.9a4.5 4.5 0 0 1 9 0" />
    </svg>
  {/snippet}

  {#if view === 'fingerprint'}
    <div class="fp">
      <button class="fp-main" onclick={openWithFingerprint}
              disabled={busy || fingerprint !== 'ready' || status === 'granted'}>
        <span class="fp-icon">{@render fingerprintIcon()}</span>
        {t.openFingerprint}
      </button>
      <button class="link" onclick={() => (view = 'keypad')} disabled={busy}>{t.useCode}</button>
    </div>
  {:else}

  <div class="pad">
    {#each [1, 2, 3, 4, 5, 6, 7, 8, 9] as n}
      <button onclick={() => press(String(n))} disabled={busy}>{n}</button>
    {/each}
    <button class="ghost" onclick={clear} disabled={busy} aria-label={t.clear}>✕</button>
    <button onclick={() => press('0')} disabled={busy}>0</button>
    {#if fingerprint === 'ready'}
      <button class="ghost fp-key" onclick={openWithFingerprint} disabled={busy}
              aria-label={t.openFingerprint} title={t.openFingerprint}>{@render fingerprintIcon()}</button>
    {:else}
      <span></span>
    {/if}
  </div>
  {/if}
</main>

<style>
  :global(:root) {
    --bg: #12141a;
    --fg: #eef1f7;
    --dim: #8a90a0;
    --key: #1e222c;
    --key-press: #2c323f;
    --ok: #4ade80;
    --bad: #f87171;
    color-scheme: dark;
  }
  :global(body) {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font: 16px/1.4 system-ui, -apple-system, 'Segoe UI', sans-serif;
    -webkit-user-select: none;
    user-select: none;
    -webkit-tap-highlight-color: transparent;
  }

  main {
    min-height: 100svh;
    max-width: 22rem;
    margin: 0 auto;
    padding: max(1.5rem, env(safe-area-inset-top)) 1.25rem
             max(1.5rem, env(safe-area-inset-bottom));
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 2rem;
    box-sizing: border-box;
  }

  .head { text-align: center; padding-top: 2rem; }
  h1 { font-size: 1.1rem; font-weight: 500; letter-spacing: .08em;
       text-transform: uppercase; color: var(--dim); margin: 0 0 2rem; }

  .dots { display: flex; justify-content: center; gap: .85rem; }
  .dot {
    width: .8rem; height: .8rem; border-radius: 50%;
    border: 1.5px solid var(--dim);
    transition: background-color .12s, transform .12s, border-color .12s;
  }
  .dot.on { background: var(--fg); border-color: var(--fg); transform: scale(1.12); }

  .msg { min-height: 1.4em; margin: 1.5rem 0 0; font-size: .95rem; color: var(--dim); }
  .msg.ok { color: var(--ok); }
  .msg.bad { color: var(--bad); }

  .pad {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: .75rem;
  }
  button {
    aspect-ratio: 1;
    font: inherit;
    font-size: 1.65rem;
    color: var(--fg);
    background: var(--key);
    border: none;
    border-radius: 50%;
    cursor: pointer;
    transition: background-color .1s, transform .06s;
  }
  button:active:not(:disabled) { background: var(--key-press); transform: scale(.94); }
  button:disabled { opacity: .45; cursor: default; }
  .ghost { background: transparent; font-size: 1.3rem; color: var(--dim); }

  .fp-key { font-size: 1.9rem; color: var(--ok); }

  .fp { display: flex; flex-direction: column; align-items: center; gap: 1.25rem;
        padding-bottom: 2rem; }
  .fp-main {
    aspect-ratio: auto;
    width: 100%;
    display: flex; flex-direction: column; align-items: center; gap: .9rem;
    padding: 2.25rem 1rem;
    border-radius: 1.5rem;
    font-size: 1.05rem;
  }
  .fp-main:active:not(:disabled) { transform: scale(.98); }
  .fp-icon { font-size: 3.5rem; line-height: 0; color: var(--ok); }
  .link {
    aspect-ratio: auto;
    background: transparent;
    border-radius: .5rem;
    padding: .5rem 1rem;
    font-size: .95rem;
    color: var(--dim);
    text-decoration: underline;
    text-underline-offset: .2em;
  }

  .shake { animation: shake .35s; }
  @keyframes shake {
    10%, 90% { transform: translateX(-2px); }
    30%, 70% { transform: translateX(4px); }
    50%      { transform: translateX(-4px); }
  }
  @media (prefers-reduced-motion: reduce) {
    .shake { animation: none; }
    .dot, button { transition: none; }
  }
</style>
