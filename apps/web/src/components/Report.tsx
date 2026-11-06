import type { ReactNode } from 'react';
import { CHECK_IDS, type Assessment, type CheckResults, type Indicator, type IndicatorState } from '@ip-assess/core';
import { fmt, indicatorEvidence, indicatorLabel, useI18n } from '../i18n';
import type { AiState, HistorySummary } from '../api';
import type { CheckState } from '../useAssessment';

// ---------------- 共通部品 ----------------

const MARK: Record<IndicatorState, string> = { hit: '🔴', safe: '🟢', info: '🔵', none: '⚪', unknown: '❔', na: '➖' };

function Section({ title, children, loading }: { title: string; children?: ReactNode; loading?: boolean }) {
  const { t } = useI18n();
  return (
    <section className="section">
      <h2>{title}</h2>
      {loading ? <p className="muted"><span className="spinner" aria-hidden /> {t.pending}</p> : children}
    </section>
  );
}

function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k} className="kv-row">
          <dt>{k}</dt>
          <dd>{v === null || v === undefined || v === '' ? '-' : v}</dd>
        </div>
      ))}
    </dl>
  );
}

function daysAgo(iso: string | null, tpl: string): string {
  if (!iso) return '';
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400_000);
  return Number.isFinite(d) ? ` (${fmt(tpl, { n: d })})` : '';
}

const fmtDateTime = (iso: string, lang: string) =>
  new Date(iso).toLocaleString(lang === 'ja' ? 'ja-JP' : 'en-US', { timeZone: 'Asia/Tokyo', hour12: false }) + ' JST';

// ---------------- 進行状況 ----------------

export function Progress({ checkState, assessing }: { checkState: Partial<Record<string, CheckState>>; assessing: boolean }) {
  const { t } = useI18n();
  return (
    <section className="progress" aria-live="polite">
      <h2 className="visually-hidden">{t.progress}</h2>
      <ul>
        {CHECK_IDS.map((id) => {
          const s = checkState[id] ?? 'pending';
          return (
            <li key={id} className={`chip chip-${s}`}>
              {s === 'pending' ? <span className="spinner" aria-hidden /> : <span aria-hidden>{s === 'done' ? '✓' : '!'}</span>}
              {t.checks[id]}
              <span className="visually-hidden">: {s === 'pending' ? t.pending : s === 'done' ? t.done : t.failed}</span>
            </li>
          );
        })}
        {assessing && <li className="chip chip-pending"><span className="spinner" aria-hidden />{t.assessing}</li>}
      </ul>
    </section>
  );
}

// ---------------- 結論 ----------------

export function Summary({ a }: { a: Assessment }) {
  const { t } = useI18n();
  const s = t.summary;
  const priorityMark = a.priority === 'HIGH' ? '🔴' : a.priority === 'MEDIUM' ? '🟡' : '🟢';
  const threat =
    a.threat.level === 'DETECTED'
      ? fmt(s.threatDetected, { list: a.indicators.filter((i) => i.axis === 'threat' && i.state === 'hit').map((i) => indicatorLabel(i, t)).join(', ') })
    : a.threat.level === 'UNKNOWN' ? s.threatUnknown : s.threatNone;
  const threatMark = a.threat.level === 'DETECTED' ? '🔴' : a.threat.level === 'UNKNOWN' ? '❔' : '⚪';
  return (
    <section className={`summary summary-${a.priority.toLowerCase()}`}>
      <h2 className="visually-hidden">{s.heading}</h2>
      <div className="summary-priority">
        <span className="summary-label">{s.priority}</span>
        <span className="summary-value">{priorityMark} {a.priority}</span>
      </div>
      <KV rows={[
        [s.infra, `${t.infraClass[a.infraClass]}  (${s.score} ${a.infraScore > 0 ? '+' : ''}${a.infraScore})`],
        [s.threat, `${threatMark} ${threat}`],
        [s.confidence, a.confidence === 'FULL' ? `🟢 ${s.full}` : `🟡 ${fmt(s.partial, { list: a.unavailable.join(', ') })}`],
      ]} />
      {a.note && <p className="note">🔵 {s.notes[a.note]}</p>}
    </section>
  );
}

// ---------------- 判定項目の一覧 ----------------

function IndicatorTable({ items }: { items: Indicator[] }) {
  const { t } = useI18n();
  return (
    <table className="indicators">
      <tbody>
        {items.map((ind) => (
          <tr key={`${ind.id}:${ind.key ?? ''}`} className={`ind-${ind.state}`}>
            <td className="ind-mark" title={t.legend[ind.state]}>{MARK[ind.state]}</td>
            <td className="ind-points">{ind.points ? (ind.points > 0 ? `+${ind.points}` : ind.points) : ''}</td>
            <td className="ind-name">{indicatorLabel(ind, t)}</td>
            <td className="ind-evidence">{indicatorEvidence(ind, t)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Indicators({ a }: { a: Assessment }) {
  const { t } = useI18n();
  return (
    <>
      <Section title={t.sections.infra}><IndicatorTable items={a.indicators.filter((i) => i.axis === 'infra')} /></Section>
      <Section title={t.sections.threat}><IndicatorTable items={a.indicators.filter((i) => i.axis === 'threat')} /></Section>
      <p className="legend">
        {(Object.keys(MARK) as IndicatorState[]).map((k) => <span key={k}>{MARK[k]} {t.legend[k]}</span>)}
      </p>
    </>
  );
}

// ---------------- 各チェックの詳細 ----------------

export function NetworkSection({ c, ip }: { c: Partial<CheckResults>; ip: string }) {
  const { t, lang } = useI18n();
  const f = t.fields;
  const v = t.values;
  const { rdap, asn, dns } = c;
  const ptrText = () => {
    if (!dns) return null;
    if (dns.ptrStatus !== 'found') return v.ptrStatus[dns.ptrStatus];
    const more = dns.ptrNames.filter((n) => n !== dns.ptr);
    return `${dns.ptr}${more.length ? ` (${fmt(v.moreNames, { n: more.length })}: ${more.join(', ')})` : ''}`;
  };
  const asnText = () => {
    if (!asn) return null;
    if (asn.status === 'not_announced') return lang === 'ja' ? '経路広告なし' : 'Not announced (no BGP route)';
    if (asn.status === 'failed') return `${v.unknown} (${asn.error ?? ''})`;
    return `AS${asn.asn}${asn.otherAsns.length ? ` (+ ${asn.otherAsns.map((a) => `AS${a}`).join(', ')})` : ''}`;
  };
  return (
    <Section title={t.sections.network} loading={!rdap && !asn && !dns}>
      <KV rows={[
        [f.networkName, rdap ? (rdap.status === 'failed' ? `${v.unknown} (${rdap.error ?? ''})` : rdap.name) : t.pending],
        [f.handle, rdap?.handle],
        [f.range, rdap?.range ? `${rdap.range.start} - ${rdap.range.end}` : null],
        [f.cidr, rdap?.cidrs.join(', ')],
        [f.type, rdap?.type],
        [f.registered, rdap?.registered ? rdap.registered + daysAgo(rdap.registered, v.daysAgo) : null],
        [f.lastChanged, rdap?.lastChanged ? rdap.lastChanged + daysAgo(rdap.lastChanged, v.daysAgo) : null],
        [f.rir, rdap ? `${rdap.rir.id}${rdap.rir.country ? ` (${rdap.rir.country})` : ''}` : null],
        [f.remarks, rdap?.remarks.length ? rdap.remarks.slice(0, 3).join(' ') : null],
        [f.asn, asn ? asnText() : t.pending],
        [f.asName, asn?.name],
        [f.bgpPrefix, asn?.prefix],
        [f.asnCountry, asn?.country],
        [f.prefixAllocated, asn?.allocated],
        [f.ptr, dns ? ptrText() : t.pending],
        [f.fcrdns, dns ? fmt(v.fcrdns[dns.fcrdns], { name: dns.ptr ?? '', ip }) : null],
      ]} />
    </Section>
  );
}

export function LocationSection({ c, a }: { c: Partial<CheckResults>; a: Assessment | null }) {
  const { t } = useI18n();
  const f = t.fields;
  const v = t.values;
  const { rdap, geofeed } = c;
  const geoText = () => {
    if (!geofeed) return t.pending;
    if (geofeed.status !== 'found') return v.geofeed[geofeed.status];
    const parts = [geofeed.country, geofeed.region, geofeed.city].filter(Boolean).join(' / ');
    return `${parts} (${geofeed.prefix}, ${v.geofeed.selfDeclared})`;
  };
  const check = a
    ? a.location === 'differ'
      ? `🟡 ${fmt(v.location.differ, { rdap: rdap?.country ?? '-', geo: geofeed?.country ?? '-' })}`
      : `❔ ${v.location[a.location]}`
    : null;
  return (
    <Section title={t.sections.location} loading={!rdap}>
      <KV rows={[
        [f.registeredCountry, rdap?.country],
        [f.geofeed, geoText()],
        [f.holderAddress, rdap?.holder ? `${rdap.holder.address}  [${rdap.holder.kind}: ${rdap.holder.name} / ${rdap.holder.roles.join(', ')}]` : null],
        [f.holderCountry, rdap?.holder?.country],
        [f.latency, v.latencyNa],
        [f.locationCheck, check],
      ]} />
    </Section>
  );
}

export function ContactsSection({ c }: { c: Partial<CheckResults> }) {
  const { t } = useI18n();
  const f = t.fields;
  const rdap = c.rdap;
  const list = (items: ReactNode[]) =>
    items.length ? <ul className="plain">{items.map((x, i) => <li key={i}>{x}</li>)}</ul> : <span className="muted">{t.values.notFoundInRdap}</span>;
  return (
    <Section title={t.sections.contacts} loading={!rdap}>
      {rdap && (
        <KV rows={[
          [f.addresses, list(rdap.addresses.map((a) => (
            <>
              <span className="muted">[{a.kind}] {a.name} ({a.roles.join(', ') || '-'}) [{a.handle}]</span><br />
              {a.address}{a.country ? `  (${a.country})` : ''}
            </>
          )))],
          [f.abuse, list(rdap.abuseContacts.map((x) => `${x.emails.join(', ') || '(no email)'}  [${x.name} / ${x.handle}]`))],
          [f.entities, list(rdap.entities)],
          [f.emails, list(rdap.emails.map((e) => `${e}  [${e.split('@')[1]}]`))],
        ]} />
      )}
    </Section>
  );
}

export function ExposureSection({ c }: { c: Partial<CheckResults> }) {
  const { t } = useI18n();
  const f = t.fields;
  const idb = c.internetdb;
  const none = t.values.none;
  return (
    <Section title={t.sections.exposure} loading={!idb}>
      {idb && (
        <KV rows={[
          [f.status, t.values.idb[idb.status]],
          ...(idb.status === 'found'
            ? ([
                [f.ports, idb.ports.join(', ') || none],
                [f.tags, idb.tags.join(', ') || none],
                [f.vulns, idb.vulns.length ? `${idb.vulns.length}: ${idb.vulns.join(' ')}` : none],
                [f.cpes, idb.cpes.join(' ') || none],
                [f.hostnames, idb.hostnames.join(' ') || none],
              ] as [string, ReactNode][])
            : []),
        ]} />
      )}
    </Section>
  );
}

// ---------------- AI 評価 ----------------

export function AiSection({ ai }: { ai: AiState }) {
  const { t } = useI18n();
  const a = t.ai;
  const r = ai.result;
  return (
    <Section title={t.sections.ai}>
      {ai.status === 'done' && r ? (
        <div className="ai">
          <p className={`ai-verdict verdict-${r.verdict}`}>
            {a.verdict[r.verdict]} <span className="muted">({a.confidence}: {r.confidence})</span>
          </p>
          <p>{r.summary}</p>
          {r.key_points.length > 0 && <><h3>{a.keyPoints}</h3><ul>{r.key_points.map((x, i) => <li key={i}>{x}</li>)}</ul></>}
          {r.recommended_actions.length > 0 && <><h3>{a.actions}</h3><ul>{r.recommended_actions.map((x, i) => <li key={i}>{x}</li>)}</ul></>}
          {r.caveats.length > 0 && <><h3>{a.caveats}</h3><ul>{r.caveats.map((x, i) => <li key={i}>{x}</li>)}</ul></>}
          <p className="muted small">{a.disclaimer}{ai.model ? ` (${a.model}: ${ai.model})` : ''}</p>
        </div>
      ) : (
        <p className="muted">
          {ai.status === 'queued' && <span className="spinner" aria-hidden />} {a[ai.status === 'done' ? 'failed' : ai.status]}
        </p>
      )}
    </Section>
  );
}

// ---------------- 問い合わせ状況 ----------------

export function HistorySection({ h, currentId, onOpen }: { h: HistorySummary; currentId: string; onOpen: (id: string) => void }) {
  const { t, lang } = useI18n();
  const x = t.history;
  return (
    <Section title={t.sections.history}>
      {h.total <= 1 ? (
        <p className="muted">{x.firstTime}</p>
      ) : (
        <>
          <div className="stats">
            <div><span>{x.total}</span><strong>{h.total}</strong></div>
            <div><span>{x.last24h}</span><strong>{h.last24h}</strong></div>
            <div><span>{x.last7d}</span><strong>{h.last7d}</strong></div>
            <div><span>{x.last30d}</span><strong>{h.last30d}</strong></div>
          </div>
          {h.first && <p className="muted small">{x.first}: {fmtDateTime(h.first, lang)}</p>}
          <h3>{x.recent}</h3>
          <ul className="history">
            {h.recent.map((r) => (
              <li key={r.id} className={r.id === currentId ? 'current' : ''}>
                <button type="button" className="link" onClick={() => onOpen(r.id)} disabled={r.id === currentId}>
                  {fmtDateTime(r.createdAt, lang)}
                </button>
                <span className={`badge badge-${r.priority.toLowerCase()}`}>{r.priority}</span>
                {r.threatLevel === 'DETECTED' && <span className="badge badge-threat">THREAT</span>}
              </li>
            ))}
          </ul>
        </>
      )}
    </Section>
  );
}

// ---------------- データソース ----------------

export function SourcesSection({ c }: { c: Partial<CheckResults> }) {
  const { t } = useI18n();
  const rows: [string, ReactNode][] = CHECK_IDS.flatMap((id) => {
    const r = c[id];
    if (!r) return [];
    const src = id === 'geofeed' ? (c.geofeed?.url ?? t.values.geofeed.not_published) : r.source;
    return [[t.checks[id], <>{src}<span className="muted small"> ({r.fetchedAt})</span></>] as [string, ReactNode]];
  });
  // Spamhaus DROP の利用条件: © 表記と日付をデータとともに表示する
  if (c.drop?.copyright) {
    rows.push(['Spamhaus DROP ©', `${c.drop.copyright} / ${c.drop.listUpdated ?? '-'} / ${c.drop.terms ?? ''}`]);
  }
  if (c.asndrop?.copyright) {
    rows.push(['Spamhaus ASN-DROP ©', `${c.asndrop.copyright} / ${c.asndrop.listUpdated ?? '-'} / ${c.asndrop.terms ?? ''}`]);
  }
  if (c.dns) rows.push([t.fields.resolver, c.dns.resolver]);
  return <Section title={t.sections.sources}><KV rows={rows} /></Section>;
}
