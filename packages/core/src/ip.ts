// IPv4 / IPv6 の解析・正規化・プレフィックス判定
//   外部の URL や DNS 名に埋め込むため、ここを通った値だけを使う

export type IpVersion = 4 | 6;

export interface ParsedIp {
  version: IpVersion;
  /** 正規化済みの表記（IPv6 は RFC 5952 の短縮形・小文字） */
  address: string;
  value: bigint;
}

const V4_RE = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;

function parseV4(s: string): bigint | null {
  if (!V4_RE.test(s)) return null;
  return s.split('.').reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n);
}

function parseV6(s: string): bigint | null {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.length > 45) return null;
  const dbl = s.split('::');
  if (dbl.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (part === '') return [];
    const groups: number[] = [];
    const items = part.split(':');
    for (let i = 0; i < items.length; i++) {
      const g = items[i]!;
      // 末尾のみ IPv4 埋め込み表記（::ffff:192.0.2.1）を許可
      if (i === items.length - 1 && g.includes('.')) {
        const v4 = parseV4(g);
        if (v4 === null) return null;
        groups.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      groups.push(parseInt(g, 16));
    }
    return groups;
  };

  const head = parseGroups(dbl[0]!);
  const tail = dbl.length === 2 ? parseGroups(dbl[1]!) : [];
  if (!head || !tail) return null;
  let groups: number[];
  if (dbl.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<number>(missing).fill(0), ...tail];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

export function formatIp(value: bigint, version: IpVersion): string {
  if (version === 4) {
    return [24n, 16n, 8n, 0n].map((s) => ((value >> s) & 0xffn).toString()).join('.');
  }
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  // RFC 5952: 最長（2個以上）の 0 の連続を :: に短縮。同じ長さなら先頭側
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

/** 入力を解析する。IPv4 射影アドレス（::ffff:a.b.c.d）は IPv4 として扱う */
export function parseIp(input: string): ParsedIp | null {
  const s = input.trim();
  const v4 = parseV4(s);
  if (v4 !== null) return { version: 4, address: formatIp(v4, 4), value: v4 };
  const v6 = parseV6(s);
  if (v6 === null) return null;
  if (v6 >> 32n === 0xffffn) {
    const inner = v6 & 0xffffffffn;
    return { version: 4, address: formatIp(inner, 4), value: inner };
  }
  return { version: 6, address: formatIp(v6, 6), value: v6 };
}

export interface ParsedPrefix {
  version: IpVersion;
  network: bigint;
  length: number;
}

export function parsePrefix(s: string): ParsedPrefix | null {
  const [addr, len, ...rest] = s.trim().split('/');
  if (rest.length > 0 || !addr) return null;
  const ip = parseV4(addr) !== null ? { version: 4 as const, value: parseV4(addr)! } : (() => {
    const v = parseV6(addr);
    return v === null ? null : { version: 6 as const, value: v };
  })();
  if (!ip) return null;
  const bits = ip.version === 4 ? 32 : 128;
  const length = len === undefined ? bits : /^\d{1,3}$/.test(len) ? Number(len) : NaN;
  if (!Number.isInteger(length) || length < 0 || length > bits) return null;
  return { version: ip.version, network: ip.value >> BigInt(bits - length), length };
}

export function prefixContains(prefix: ParsedPrefix, ip: ParsedIp): boolean {
  if (prefix.version !== ip.version) return false;
  const bits = ip.version === 4 ? 32 : 128;
  return ip.value >> BigInt(bits - prefix.length) === prefix.network;
}

/** 32桁の16進（IPv6 のニブル表記用） */
function hex32(value: bigint): string {
  return value.toString(16).padStart(32, '0');
}

/** DNSBL・Team Cymru 用の逆順表記（in-addr.arpa / ip6.arpa の接尾辞なし） */
export function reverseLabel(ip: ParsedIp): string {
  if (ip.version === 4) return ip.address.split('.').reverse().join('.');
  return hex32(ip.value).split('').reverse().join('.');
}

/** 逆引き（PTR）の問い合わせ名 */
export function reverseDnsName(ip: ParsedIp): string {
  return `${reverseLabel(ip)}.${ip.version === 4 ? 'in-addr.arpa' : 'ip6.arpa'}`;
}

// 調査対象にならないアドレス（プライベート・予約・文書用など）
const NON_GLOBAL_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
].map((p) => parsePrefix(p)!);
const NON_GLOBAL_V6 = ['2001:db8::/32', '2001::/23', '3fff::/20'].map((p) => parsePrefix(p)!);
const GLOBAL_UNICAST_V6 = parsePrefix('2000::/3')!;

/** グローバルに到達可能なユニキャストアドレスか */
export function isGlobalUnicast(ip: ParsedIp): boolean {
  if (ip.version === 4) return !NON_GLOBAL_V4.some((p) => prefixContains(p, ip));
  if (!prefixContains(GLOBAL_UNICAST_V6, ip)) return false;
  // 2001::/23 は特殊用途（Teredo 等）だが、2001:200::/23 以降は通常の割り当て
  return !NON_GLOBAL_V6.some((p) => prefixContains(p, ip));
}
