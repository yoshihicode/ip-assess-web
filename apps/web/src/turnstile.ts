// Turnstile のウィジェット（画面側）
//   普段は表示されず（interaction-only）、Bot の疑いがあるときだけ確認画面が出る

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      execute: (widgetId: string) => void;
      reset: (widgetId: string) => void;
    };
  }
}

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

let scriptPromise: Promise<void> | null = null;
function loadScript(): Promise<void> {
  scriptPromise ??= new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = SCRIPT_URL;
    s.async = true;
    s.onload = () => resolve();
    s.onerror = () => { scriptPromise = null; reject(new Error('turnstile_load_failed')); };
    document.head.appendChild(s);
  });
  return scriptPromise;
}

let widgetId: string | null = null;
let pending: { resolve: (t: string) => void; reject: (e: Error) => void } | null = null;

/** ウィジェットを配置する（ページ表示時に 1 回） */
export async function mountTurnstile(container: HTMLElement, siteKey: string, lang: string): Promise<void> {
  await loadScript();
  if (widgetId !== null || !window.turnstile) return;
  widgetId = window.turnstile.render(container, {
    sitekey: siteKey,
    execution: 'execute',
    appearance: 'interaction-only',
    language: lang,
    callback: (token: string) => { pending?.resolve(token); pending = null; },
    'error-callback': () => { pending?.reject(new Error('bot_check_failed')); pending = null; },
    'expired-callback': () => { pending?.reject(new Error('bot_check_failed')); pending = null; },
  });
}

/** トークンを 1 つ取得する（トークンは 1 回しか使えないため、取得のたびにリセットする） */
export function getTurnstileToken(timeoutMs = 120_000): Promise<string> {
  const ts = window.turnstile;
  if (!ts || widgetId === null) return Promise.reject(new Error('bot_check_failed'));
  ts.reset(widgetId);
  return new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => { pending = null; reject(new Error('bot_check_failed')); }, timeoutMs);
    pending = {
      resolve: (t) => { clearTimeout(timer); resolve(t); },
      reject: (e) => { clearTimeout(timer); reject(e); },
    };
    ts.execute(widgetId!);
  });
}
