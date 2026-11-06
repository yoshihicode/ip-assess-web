// RDAP 応答の解析（ip-assess.sh の awk による解析を移植）

import type { RdapAbuseContact, RdapAddress, RdapResult, RirId } from './types';

type Json = unknown;
type Obj = Record<string, Json>;

const isObj = (v: Json): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: Json): string | null => (typeof v === 'string' && v.trim() !== '' ? v : null);
const squeeze = (s: string) => s.replace(/\s+/g, ' ').trim();

interface VcardProp { name: string; params: Obj; value: Json }

function vcardProps(entity: Obj): VcardProp[] {
  const arr = entity.vcardArray;
  if (!Array.isArray(arr) || !Array.isArray(arr[1])) return [];
  return (arr[1] as Json[]).flatMap((p) => {
    if (!Array.isArray(p) || typeof p[0] !== 'string') return [];
    return [{ name: p[0].toLowerCase(), params: isObj(p[1]) ? p[1] : {}, value: p[3] }];
  });
}

function vcardText(props: VcardProp[], name: string): string | null {
  for (const p of props) if (p.name === name && typeof p.value === 'string' && p.value.trim()) return squeeze(p.value);
  return null;
}

/** ネストしたエンティティ（ARIN 等）も含めて、親から順にすべて列挙する */
function walkEntities(root: Obj): Obj[] {
  const out: Obj[] = [];
  const visit = (o: Obj) => {
    const ents = o.entities;
    if (!Array.isArray(ents)) return;
    for (const e of ents) if (isObj(e)) { out.push(e); visit(e); }
  };
  visit(root);
  return out;
}

function rolesOf(e: Obj): string[] {
  return Array.isArray(e.roles) ? e.roles.filter((r): r is string => typeof r === 'string') : [];
}

function addressesOf(e: Obj): RdapAddress[] {
  const props = vcardProps(e);
  const kind = vcardText(props, 'kind') ?? 'unknown';
  const name = vcardText(props, 'fn') ?? '-';
  const roles = rolesOf(e);
  const handle = str(e.handle) ?? '-';
  const out: RdapAddress[] = [];
  for (const p of props) {
    if (p.name !== 'adr') continue;
    // 書式付きの label を優先し、なければ構造化された要素から組み立てる
    let address = typeof p.params.label === 'string' ? squeeze(p.params.label) : '';
    const comps = Array.isArray(p.value) ? p.value : [];
    if (!address) {
      address = comps
        .map((c) => squeeze(Array.isArray(c) ? c.filter((x) => typeof x === 'string').join(' ') : typeof c === 'string' ? c : ''))
        .filter(Boolean)
        .join(', ');
    }
    if (!address) continue;
    const cc = typeof p.params.cc === 'string' ? p.params.cc.toUpperCase() : (typeof comps[6] === 'string' ? squeeze(comps[6]) : '');
    out.push({ kind, name, roles, handle, address, country: cc });
  }
  return out;
}

function eventDate(root: Obj, action: string): string | null {
  if (!Array.isArray(root.events)) return null;
  for (const ev of root.events) {
    if (isObj(ev) && ev.eventAction === action && typeof ev.eventDate === 'string') return ev.eventDate;
  }
  return null;
}

/** 代表の住所: 登録組織（registrant かつ org）→ 組織 → 登録者 → 最初の住所 */
function pickHolder(addresses: RdapAddress[]): RdapAddress | null {
  let best: RdapAddress | null = null;
  let bestScore = 0;
  for (const a of addresses) {
    const reg = a.roles.includes('registrant');
    const s = a.kind === 'org' && reg ? 4 : a.kind === 'org' ? 3 : reg ? 2 : 1;
    if (s > bestScore) { best = a; bestScore = s; }
  }
  return best;
}

export function detectRir(port43: string | null, sourceUrl: string): { id: RirId; country: string | null } {
  const p = (port43 ?? '').toLowerCase();
  const u = sourceUrl.toLowerCase();
  const has = (k: string) => p.includes(k) || (!p && u.includes(k));
  if (p.includes('nic.ad.jp')) return { id: 'JPNIC', country: 'JP' };
  if (has('apnic')) return { id: 'APNIC', country: 'AU' };
  if (has('ripe')) return { id: 'RIPE', country: 'NL' };
  if (has('arin')) return { id: 'ARIN', country: 'US' };
  if (has('lacnic')) return { id: 'LACNIC', country: 'UY' };
  if (has('afrinic')) return { id: 'AFRINIC', country: 'MU' };
  return { id: 'UNKNOWN', country: null };
}

// 外部（RDAP 登録者）が書いた値なので、https の URL 以外は使わない
const GEOFEED_URL_RE = /^https:\/\/[A-Za-z0-9._~:/?#@!&()*+,;=%-]+$/;

function findGeofeedUrl(root: Obj, remarks: string[]): string | null {
  let url: string | null = null;
  if (Array.isArray(root.links)) {
    for (const l of root.links) if (isObj(l) && l.rel === 'geofeed' && typeof l.href === 'string') { url = l.href; break; }
  }
  if (!url) {
    for (const r of remarks) {
      const m = /Geofeed:?\s+(https:\/\/\S+)/i.exec(r);
      if (m) { url = m[1]!; break; }
    }
  }
  return url && GEOFEED_URL_RE.test(url) ? url : null;
}

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

export function parseRdap(raw: string, sourceUrl: string, fetchedAt: string): RdapResult {
  const root = JSON.parse(raw) as Json;
  if (!isObj(root)) throw new Error('RDAP response is not an object');

  const port43 = str(root.port43);
  const start = str(root.startAddress);
  const end = str(root.endAddress);
  const cidrs = Array.isArray(root.cidr0_cidrs)
    ? root.cidr0_cidrs.flatMap((c) => {
        if (!isObj(c)) return [];
        const pfx = str(c.v4prefix) ?? str(c.v6prefix);
        return pfx && typeof c.length === 'number' ? [`${pfx}/${c.length}`] : [];
      })
    : [];

  // 備考: ネットワーク自身の remarks のみ（notices の利用規約文などは除外）
  const remarks = Array.isArray(root.remarks)
    ? root.remarks.flatMap((r) => (isObj(r) && Array.isArray(r.description) ? r.description.filter((d): d is string => typeof d === 'string') : []))
    : [];

  const entities = walkEntities(root);
  const addresses = entities.flatMap(addressesOf);

  const abuseContacts: RdapAbuseContact[] = entities
    .filter((e) => rolesOf(e).includes('abuse'))
    .map((e) => {
      const props = vcardProps(e);
      const emails = [...new Set(props.filter((p) => p.name === 'email' && typeof p.value === 'string').map((p) => (p.value as string).trim()))];
      return { emails, name: vcardText(props, 'fn') ?? '-', handle: str(e.handle) ?? '-' };
    });

  const fns = [...new Set(entities.map((e) => vcardText(vcardProps(e), 'fn')).filter((v): v is string => !!v))].sort();
  const emails = [...new Set((raw.match(EMAIL_RE) ?? []).map((e) => e.toLowerCase()))].sort();
  const domains = [...new Set(emails.map((e) => e.split('@')[1]!))].sort();

  return {
    status: 'found',
    fetchedAt,
    source: sourceUrl,
    name: str(root.name),
    handle: str(root.handle),
    country: str(root.country)?.toUpperCase() ?? null,
    type: str(root.type),
    port43,
    range: start && end ? { start, end } : null,
    cidrs,
    registered: eventDate(root, 'registration'),
    lastChanged: eventDate(root, 'last changed'),
    rir: detectRir(port43, sourceUrl),
    addresses,
    holder: pickHolder(addresses),
    remarks,
    abuseContacts,
    entities: fns,
    emails,
    domains,
    geofeedUrl: findGeofeedUrl(root, remarks),
  };
}

export function emptyRdap(source: string, fetchedAt: string, error: string): RdapResult {
  return {
    status: 'failed', fetchedAt, source, error,
    name: null, handle: null, country: null, type: null, port43: null, range: null, cidrs: [],
    registered: null, lastChanged: null, rir: { id: 'UNKNOWN', country: null }, addresses: [], holder: null,
    remarks: [], abuseContacts: [], entities: [], emails: [], domains: [], geofeedUrl: null,
  };
}
