// Geofeed（RFC 8805 / RFC 9632。運営者が自己申告する利用地）の解析
//   対象 IP を含む最も細かいプレフィックスの行を採用する
//   数万行あるファイルもあるため、先頭のオクテット（IPv6 は先頭 16 ビット）が一致しない行は
//   BigInt での解析を省く（Workers 無料枠の CPU 時間対策）

import { parsePrefix, prefixContains, type ParsedIp } from './ip';

export interface GeofeedMatch {
  prefix: string;
  country: string | null;
  region: string | null;
  city: string | null;
}

/** 行の先頭部分だけで、対象 IP を含む可能性があるかを判定する */
function mayContain(line: string, ip: ParsedIp, head: number): boolean {
  const comma = line.indexOf(',');
  const pfx = (comma < 0 ? line : line.slice(0, comma)).trim();
  const slash = pfx.indexOf('/');
  const len = slash < 0 ? (ip.version === 4 ? 32 : 128) : Number(pfx.slice(slash + 1));
  if (ip.version === 4) {
    if (pfx.includes(':')) return false;
    return len < 8 || Number(pfx.slice(0, pfx.indexOf('.'))) === head;
  }
  if (!pfx.includes(':')) return false;
  if (len < 16) return true;
  const first = pfx.startsWith('::') ? 0 : parseInt(pfx.slice(0, pfx.indexOf(':')), 16);
  return first === head;
}

export function matchGeofeed(csv: string, ip: ParsedIp): GeofeedMatch | null {
  const head = ip.version === 4 ? Number(ip.value >> 24n) : Number(ip.value >> 112n);
  let best: GeofeedMatch | null = null;
  let bestLen = -1;
  for (const rawLine of csv.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (/^\s*(#|$)/.test(line) || !mayContain(line, ip, head)) continue;
    const cols = line.split(',').map((c) => c.trim());
    const pfx = parsePrefix(cols[0] ?? '');
    if (!pfx || !prefixContains(pfx, ip) || pfx.length <= bestLen) continue;
    bestLen = pfx.length;
    best = {
      prefix: cols[0]!,
      country: cols[1] ? cols[1].toUpperCase() : null,
      region: cols[2] || null,
      city: cols[3] || null,
    };
  }
  return best;
}
