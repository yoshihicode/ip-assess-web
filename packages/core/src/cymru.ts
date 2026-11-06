// Team Cymru IP to ASN Mapping（DNS の TXT レコード）の解析
//   <逆順IP>.origin.asn.cymru.com / origin6.asn.cymru.com -> "ASN | BGP Prefix | CC | Registry | Allocated"
//   AS<番号>.asn.cymru.com                                  -> "ASN | CC | Registry | Allocated | AS Name"

export interface CymruOrigin {
  asn: number | null;
  otherAsns: number[];
  prefix: string | null;
  country: string | null;
  allocated: string | null;
}

const field = (line: string, i: number) => (line.split('|')[i] ?? '').trim();

export function parseCymruOrigin(records: string[]): CymruOrigin | null {
  const rows = records.map((r) => r.replace(/^"|"$/g, '')).filter((r) => r.includes('|'));
  if (rows.length === 0) return null;
  // 複数オリジン（MOAS）の場合は最も細かいプレフィックスを採用
  const len = (r: string) => Number(field(r, 1).split('/')[1] ?? 0);
  const best = [...rows].sort((a, b) => len(b) - len(a))[0]!;
  const asns = (r: string) => field(r, 0).split(/\s+/).filter((a) => /^\d+$/.test(a)).map(Number);
  const asn = asns(best)[0] ?? null;
  // 同一 AS の包含プレフィックスは除き、異なるオリジン AS のみを数える
  const otherAsns = [...new Set(rows.flatMap(asns))].filter((a) => a !== asn).sort((a, b) => a - b);
  return {
    asn,
    otherAsns,
    prefix: field(best, 1) || null,
    country: field(best, 2) || null,
    allocated: field(best, 4) || null,
  };
}

export function parseCymruAsName(records: string[]): string | null {
  const row = records.map((r) => r.replace(/^"|"$/g, '')).find((r) => r.includes('|'));
  return row ? field(row, 4) || null : null;
}
