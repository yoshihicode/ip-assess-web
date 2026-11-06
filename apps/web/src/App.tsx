import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { detectLang, dictionaries, I18nContext, type Lang } from './i18n';
import { useAssessment } from './useAssessment';
import { initBotCheck } from './session';
import {
  AiSection, ContactsSection, ExposureSection, HistorySection, Indicators, LocationSection,
  NetworkSection, Progress, SourcesSection, Summary,
} from './components/Report';

// URL: ?ip=<IP> で調査を実行、?id=<ID> で保存済みの結果を表示
function readUrl() {
  const q = new URLSearchParams(location.search);
  return { ip: q.get('ip'), id: q.get('id') };
}

export function App() {
  const [lang, setLangState] = useState<Lang>(detectLang);
  const t = dictionaries[lang];
  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try { localStorage.setItem('lang', l); } catch { /* 無視 */ }
  }, []);
  useEffect(() => { document.documentElement.lang = lang; }, [lang]);
  const i18n = useMemo(() => ({ lang, t, setLang }), [lang, t, setLang]);

  const { state, run, load } = useAssessment();

  // Turnstile のウィジェット（普段は表示されず、確認が必要なときだけ表示される）
  const botCheckRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (botCheckRef.current) initBotCheck(botCheckRef.current, lang);
    // 言語はウィジェットの初回配置時のみ反映する
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [input, setInput] = useState(() => readUrl().ip ?? '');

  const go = useCallback((params: Record<string, string>) => {
    const url = `${location.pathname}?${new URLSearchParams(params)}`;
    history.pushState(null, '', url);
  }, []);

  // 初回表示とブラウザの戻る・進む
  useEffect(() => {
    const apply = () => {
      const { ip, id } = readUrl();
      if (id) void load(id);
      else if (ip) { setInput(ip); void run(ip); }
    };
    apply();
    addEventListener('popstate', apply);
    return () => removeEventListener('popstate', apply);
  }, [load, run]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const ip = input.trim();
    if (!ip) return;
    go({ ip });
    void run(ip);
  };

  const openStored = (id: string) => {
    go({ id });
    void load(id);
  };

  const a = state.result?.assessment ?? null;
  const started = state.ip !== null;

  return (
    <I18nContext.Provider value={i18n}>
      <header className="header">
        <div className="brand">
          <h1>{t.title}</h1>
          <span className="muted">{t.tagline}</span>
        </div>
        <button type="button" className="link" onClick={() => setLang(lang === 'ja' ? 'en' : 'ja')}>{t.lang}</button>
      </header>

      <main className="main">
        <form className="search" onSubmit={onSubmit}>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={t.placeholder}
            aria-label={t.placeholder}
            autoComplete="off"
            spellCheck={false}
            inputMode="text"
          />
          <button type="submit">{t.submit}</button>
        </form>
        <div ref={botCheckRef} className="bot-check" />

        {state.error && <p className="error" role="alert">{(t.errors as Record<string, string>)[state.error] ?? t.errors.generic}</p>}

        {started && (
          <>
            <div className="target">
              <span className="target-ip">{state.ip}</span>
              {a && <span className="muted small">{new Date(a.assessedAt).toLocaleString(lang === 'ja' ? 'ja-JP' : 'en-US', { timeZone: 'Asia/Tokyo', hour12: false })} JST</span>}
            </div>
            <Progress checkState={state.checkState} assessing={state.assessing} />
            {a && <Summary a={a} />}
            <NetworkSection c={state.checks} ip={state.ip!} />
            <LocationSection c={state.checks} a={a} />
            <ContactsSection c={state.checks} />
            <ExposureSection c={state.checks} />
            {a && <Indicators a={a} />}
            {state.result && <AiSection ai={state.result.ai} />}
            {state.result && <HistorySection h={state.result.history} currentId={state.result.id} onOpen={openStored} />}
            <SourcesSection c={state.checks} />
          </>
        )}
      </main>

      <footer className="footer">
        <h2>{t.disclaimer.heading}</h2>
        <ul>
          {t.disclaimer.items.map((x, i) => <li key={i}>{x}</li>)}
        </ul>
      </footer>
    </I18nContext.Provider>
  );
}
