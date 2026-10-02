<script>
  import { t } from './i18n.js';

  const LENGTH = 6;

  let entered = $state('');
  let busy = $state(false);
  let status = $state('idle'); // idle | granted | denied | unavailable | error
  let action = $state(null);   // 'locked' | 'unlocked'

  const message = $derived(
    status === 'granted'     ? (action === 'locked' ? t.locked : t.unlocked)
    : status === 'denied'      ? t.wrongCode
    : status === 'unavailable' ? t.lockUnreachable
    : status === 'error'       ? t.tryAgain
    : ''
  );

  function press(digit) {
    if (busy || entered.length >= LENGTH) return;
    if (status !== 'idle') status = 'idle';
    navigator.vibrate?.(8);
    entered += digit;
    if (entered.length === LENGTH) submit();
  }

  function clear() {
    if (busy) return;
    navigator.vibrate?.(8);
    entered = '';
    status = 'idle';
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
    <div class="dots" class:shake={status === 'denied'}>
      {#each { length: LENGTH } as _, i}
        <span class="dot" class:on={i < entered.length}></span>
      {/each}
    </div>
    <p class="msg" class:ok={status === 'granted'} class:bad={status === 'denied'}>
      {busy ? t.checking : message || ' '}
    </p>
  </div>

  <div class="pad">
    {#each [1, 2, 3, 4, 5, 6, 7, 8, 9] as n}
      <button onclick={() => press(String(n))} disabled={busy}>{n}</button>
    {/each}
    <button class="ghost" onclick={clear} disabled={busy} aria-label={t.clear}>✕</button>
    <button onclick={() => press('0')} disabled={busy}>0</button>
    <span></span>
  </div>
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
