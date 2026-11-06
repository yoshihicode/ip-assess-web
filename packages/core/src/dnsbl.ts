// DNSBL の定義と応答の解釈
//   脅威シグナルになるリスト（threat）と、迷惑メール専用で情報表示のみのリスト（spam）を分ける
//   各リストは RFC 5782 のテスト用アドレス（127.0.0.2 / ::FFFF:7F00:2）で健全性を確認する

export interface DnsblDefinition {
  id: string;
  label: string;
  zone: string;
  kind: 'threat' | 'spam';
  ipv6: boolean;
  /** false: 利用に必要なキーが未設定のため問い合わせない */
  configured: boolean;
  /** 応答コード -> カテゴリ名 */
  categorize: (code: string) => string | null;
  /** 脅威とみなさないカテゴリ */
  policyCategories?: string[];
  /** 拒否・エラーを示す応答 */
  isRefusal?: (code: string) => boolean;
}

// Spamhaus ZEN
//   127.0.0.2 SBL / 127.0.0.3 CSS / 127.0.0.4-7 XBL / 127.0.0.9 DROP / 127.0.0.10-11 PBL / 127.255.255.x エラー
const spamhausCategory = (code: string): string | null => {
  const last = Number(code.split('.')[3]);
  if (!code.startsWith('127.0.0.')) return null;
  if (last === 2) return 'SBL';
  if (last === 3) return 'CSS';
  if (last >= 4 && last <= 7) return 'XBL';
  if (last === 9) return 'DROP';
  if (last === 10 || last === 11) return 'PBL';
  return null;
};

// DroneBL の種別（https://dronebl.org/classes）※番号と名称は公開情報に基づく。変更があれば更新すること
const DRONEBL_CLASSES: Record<number, string> = {
  1: 'Testing', 2: 'Sample', 3: 'IRC drone', 5: 'Bottler', 6: 'Unknown spambot or drone',
  7: 'DDoS drone', 8: 'SOCKS proxy', 9: 'HTTP proxy', 10: 'ProxyChain', 11: 'Web page proxy',
  12: 'Open DNS resolver', 13: 'Brute force attackers', 14: 'Open Wingate proxy', 15: 'Compromised router / gateway',
  16: 'Autorooting worms', 17: 'Automatically determined botnet IPs', 18: 'DNS/MX type hostname detected on IRC',
  19: 'Abused VPN service', 255: 'Uncategorized threat',
};

export function buildDnsblDefinitions(opts: { spamhausDqsKey?: string } = {}): DnsblDefinition[] {
  const spamhausZone = opts.spamhausDqsKey ? `${opts.spamhausDqsKey}.zen.dq.spamhaus.net` : 'zen.spamhaus.org';
  return [
    {
      id: 'spamhaus',
      label: 'Spamhaus ZEN',
      zone: spamhausZone,
      kind: 'threat',
      ipv6: true,
      // 公開ミラー（zen.spamhaus.org）は公開リゾルバ経由を拒否し、利用条件も非商用・小規模に限られるため、
      // DQS キーがある場合のみ使う
      configured: !!opts.spamhausDqsKey,
      categorize: spamhausCategory,
      policyCategories: ['PBL'],
      isRefusal: (c) => c.startsWith('127.255.255.'),
    },
    {
      id: 'dronebl',
      label: 'DroneBL',
      zone: 'dnsbl.dronebl.org',
      kind: 'threat',
      ipv6: true,
      configured: true,
      categorize: (c) => (c.startsWith('127.0.0.') ? DRONEBL_CLASSES[Number(c.split('.')[3])] ?? `Code ${c}` : null),
    },
    {
      id: 'spamcop',
      label: 'SpamCop',
      zone: 'bl.spamcop.net',
      kind: 'spam',
      ipv6: false,
      configured: true,
      categorize: (c) => (c === '127.0.0.2' ? 'Spam source' : null),
    },
    {
      id: 'psbl',
      label: 'PSBL',
      zone: 'psbl.surriel.com',
      kind: 'spam',
      ipv6: false,
      configured: true,
      categorize: (c) => (c === '127.0.0.2' ? 'Spam trap hit' : null),
    },
  ];
}

/** 公開されている（キーを含まない）ゾーン名。証跡表示用 */
export function publicZone(zone: string): string {
  return zone.endsWith('.zen.dq.spamhaus.net') ? 'zen.dq.spamhaus.net (DQS)' : zone;
}
