// Spamhaus DROP（Don't Route Or Peer）の解析
//   https://www.spamhaus.org/drop/drop_v4.json / drop_v6.json（1 行 1 JSON、最終行がメタデータ）
//   利用条件: 無料・事業規模や業種を問わず利用可。製品で使う場合は Spamhaus Project の表示と、
//   日付・© 表記をデータとともに残すこと（https://www.spamhaus.org/drop/terms/）

import { parsePrefix, prefixContains, type ParsedIp, type ParsedPrefix } from './ip';
import type { AsnDropEntry } from './types';

export interface DropEntry {
  cidr: string;
  prefix: ParsedPrefix;
  sblid: string | null;
}

export interface DropList {
  entries: DropEntry[];
  /** メタデータの timestamp（ISO 8601） */
  updated: string | null;
  copyright: string | null;
  terms: string | null;
}

export function parseDrop(text: string): DropList {
  const list: DropList = { entries: [], updated: null, copyright: null, terms: null };
  let sawMetadata = false;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (o.type === 'metadata') {
      sawMetadata = true;
      if (typeof o.timestamp === 'number') list.updated = new Date(o.timestamp * 1000).toISOString();
      if (typeof o.copyright === 'string') list.copyright = o.copyright;
      if (typeof o.terms === 'string') list.terms = o.terms;
      continue;
    }
    if (typeof o.cidr !== 'string') continue;
    const prefix = parsePrefix(o.cidr);
    if (prefix) list.entries.push({ cidr: o.cidr, prefix, sblid: typeof o.sblid === 'string' ? o.sblid : null });
  }
  // 取得途中で切れたファイルを「未掲載」と誤判定しないよう、メタデータ行がなければ不正とする
  if (!sawMetadata) throw new Error('DROP list has no metadata line');
  return list;
}

/** 対象 IP を含むエントリ（最も細かいもの） */
export function matchDrop(list: DropList, ip: ParsedIp): DropEntry | null {
  let best: DropEntry | null = null;
  for (const e of list.entries) {
    if (prefixContains(e.prefix, ip) && (!best || e.prefix.length > best.prefix.length)) best = e;
  }
  return best;
}

// ---------------- ASN-DROP ----------------
//   https://www.spamhaus.org/drop/asndrop.json（1 行 1 JSON、最終行がメタデータ。利用条件は DROP と同じ）

export interface AsnDropList {
  entries: Map<number, AsnDropEntry>;
  updated: string | null;
  copyright: string | null;
  terms: string | null;
}

export function parseAsnDrop(text: string): AsnDropList {
  const list: AsnDropList = { entries: new Map(), updated: null, copyright: null, terms: null };
  let sawMetadata = false;
  const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v : null);
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (o.type === 'metadata') {
      sawMetadata = true;
      if (typeof o.timestamp === 'number') list.updated = new Date(o.timestamp * 1000).toISOString();
      list.copyright = str(o.copyright);
      list.terms = str(o.terms);
      continue;
    }
    if (typeof o.asn !== 'number') continue;
    list.entries.set(o.asn, { asn: o.asn, asname: str(o.asname), cc: str(o.cc), domain: str(o.domain) });
  }
  // 取得途中で切れたファイルを「未掲載」と誤判定しないよう、メタデータ行がなければ不正とする
  if (!sawMetadata) throw new Error('ASN-DROP list has no metadata line');
  return list;
}

export function matchAsnDrop(list: AsnDropList, asns: number[]): AsnDropEntry[] {
  return asns.flatMap((a) => (list.entries.has(a) ? [list.entries.get(a)!] : []));
}
