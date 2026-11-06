// 各チェックの結果の型
//   取得に失敗した場合も例外にせず status: 'failed' として返す（判定不能を「Clean」と誤表示しないため）

import type { IpVersion } from './ip';

export const CHECK_IDS = ['rdap', 'dns', 'asn', 'dnsbl', 'drop', 'asndrop', 'tor', 'ipsum', 'internetdb', 'geofeed'] as const;
export type CheckId = (typeof CHECK_IDS)[number];

export interface CheckMeta {
  /** 取得日時（ISO 8601） */
  fetchedAt: string;
  /** 取得元（証跡用） */
  source: string;
  /** 失敗時の理由（利用者への表示用、英語の短文） */
  error?: string;
}

export interface RdapAddress {
  kind: string;
  name: string;
  roles: string[];
  handle: string;
  address: string;
  country: string;
}

export interface RdapAbuseContact {
  emails: string[];
  name: string;
  handle: string;
}

export interface RdapResult extends CheckMeta {
  status: 'found' | 'failed';
  name: string | null;
  handle: string | null;
  country: string | null;
  type: string | null;
  port43: string | null;
  range: { start: string; end: string } | null;
  cidrs: string[];
  registered: string | null;
  lastChanged: string | null;
  rir: { id: RirId; country: string | null };
  addresses: RdapAddress[];
  holder: RdapAddress | null;
  remarks: string[];
  abuseContacts: RdapAbuseContact[];
  /** 全エンティティの登録名（fn） */
  entities: string[];
  /** 応答全体に含まれるメールアドレス */
  emails: string[];
  /** メールアドレスのドメイン（運営者ドメイン） */
  domains: string[];
  geofeedUrl: string | null;
}

export type RirId = 'JPNIC' | 'APNIC' | 'RIPE' | 'ARIN' | 'LACNIC' | 'AFRINIC' | 'UNKNOWN';

export interface DnsResult extends CheckMeta {
  /** found: 取得 / none: 登録なし / broken: 相手側が SERVFAIL / failed: 実行側の失敗 */
  ptrStatus: 'found' | 'none' | 'broken' | 'failed';
  ptrNames: string[];
  /** 表示用の代表 PTR（FCrDNS 検証済みのものを優先） */
  ptr: string | null;
  /** verified / not_verified / not_verified_servfail（相手側の正引き不調）/ unknown（実行側の失敗）/ na（PTR なし） */
  fcrdns: 'verified' | 'not_verified' | 'not_verified_servfail' | 'unknown' | 'na';
  resolver: string;
}

export interface AsnResult extends CheckMeta {
  status: 'found' | 'not_announced' | 'failed';
  asn: number | null;
  /** 同じアドレスを広告している別のオリジン AS（MOAS） */
  otherAsns: number[];
  name: string | null;
  prefix: string | null;
  country: string | null;
  allocated: string | null;
}

export type DnsblKind = 'threat' | 'spam';

export interface DnsblListResult {
  id: string;
  label: string;
  zone: string;
  /** threat: 脅威シグナル / spam: 迷惑メール専用（情報表示のみ） */
  kind: DnsblKind;
  /**
   * listed / clean / refused（公開リゾルバ経由・超過等で拒否）/ unhealthy（テスト用アドレスに応答しない）
   * / failed（問い合わせ失敗）/ unsupported（IPv6 非対応）/ not_configured（利用に必要なキーが未設定）
   */
  status: 'listed' | 'clean' | 'refused' | 'unhealthy' | 'failed' | 'unsupported' | 'not_configured';
  codes: string[];
  /** 応答コードの意味（例: SBL, XBL, PBL, SOCKS proxy） */
  categories: string[];
  /** 脅威とみなさないカテゴリのみの掲載（Spamhaus PBL など） */
  policyOnly: boolean;
}

export interface DnsblResult extends CheckMeta {
  lists: DnsblListResult[];
}

// Spamhaus DROP（犯罪者が管理するネットワーク。無料・業務利用可。表示時は © 表記と日付を残す）
export interface DropResult extends CheckMeta {
  status: 'listed' | 'not_listed' | 'failed';
  cidr: string | null;
  sblid: string | null;
  /** リストの更新日時（ISO 8601） */
  listUpdated: string | null;
  /** リストに付いている著作権表記（例: "(c) 2026 The Spamhaus Project SLU"） */
  copyright: string | null;
  terms: string | null;
}

// Spamhaus ASN-DROP（犯罪者が運営する ASN。利用条件は DROP と同じ）
export interface AsnDropEntry {
  asn: number;
  asname: string | null;
  cc: string | null;
  domain: string | null;
}

export interface AsnDropResult extends CheckMeta {
  /** no_asn: 経路が広告されておらず照合する ASN がない */
  status: 'listed' | 'not_listed' | 'no_asn' | 'failed';
  /** 照合した ASN（オリジン AS と、同じアドレスを広告している別の AS） */
  checkedAsns: number[];
  /** 掲載されていた ASN */
  matches: AsnDropEntry[];
  listUpdated: string | null;
  copyright: string | null;
  terms: string | null;
}

export interface TorResult extends CheckMeta {
  status: 'listed' | 'not_listed' | 'failed';
}

export interface IpsumResult extends CheckMeta {
  /** unsupported: IPv6（IPsum は IPv4 のみ） */
  status: 'ok' | 'failed' | 'unsupported';
  count: number;
  updated: string | null;
}

export interface InternetDbResult extends CheckMeta {
  status: 'found' | 'no_data' | 'failed';
  ports: number[];
  tags: string[];
  vulns: string[];
  cpes: string[];
  hostnames: string[];
}

export interface GeofeedResult extends CheckMeta {
  status: 'not_published' | 'found' | 'not_listed' | 'failed';
  url: string | null;
  prefix: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
}

export interface CheckResults {
  rdap: RdapResult;
  dns: DnsResult;
  asn: AsnResult;
  dnsbl: DnsblResult;
  drop: DropResult;
  asndrop: AsnDropResult;
  tor: TorResult;
  ipsum: IpsumResult;
  internetdb: InternetDbResult;
  geofeed: GeofeedResult;
}

// ---------------- 判定結果 ----------------

/** hit: 該当（リスク）/ safe: 該当（安全側）/ info: 参考情報 / none: 該当なし / unknown: 確認できず / na: 対象外 */
export type IndicatorState = 'hit' | 'safe' | 'info' | 'none' | 'unknown' | 'na';

export type InfraIndicatorId =
  | 'consumer_isp' | 'sase' | 'verified_crawler' | 'datacenter' | 'sublease'
  | 'pobox' | 'vpn' | 'virtual_location' | 'pa' | 'no_ptr';

export type ThreatIndicatorId =
  | 'dnsbl' | 'drop' | 'asn_drop' | 'ipsum' | 'compromised' | 'proxy' | 'tor' | 'spoofed_crawler';

export interface Indicator {
  axis: 'infra' | 'threat';
  id: InfraIndicatorId | ThreatIndicatorId;
  /** DNSBL のように同じ id が複数ある場合の識別子 */
  key?: string;
  state: IndicatorState;
  points: number;
  /** UI で文言を組み立てるための値（言語に依存しない） */
  params: Record<string, string | number | string[]>;
}

export type Priority = 'HIGH' | 'MEDIUM' | 'LOW';

export type InfraClass =
  | 'tor' | 'crawler' | 'sase' | 'mixed' | 'consumer_isp' | 'datacenter' | 'unclassified';

export type LocationCheck = 'differ' | 'not_verified' | 'unknown';

export interface Assessment {
  ip: string;
  version: IpVersion;
  assessedAt: string;
  priority: Priority;
  infraClass: InfraClass;
  infraScore: number;
  threat: { level: 'DETECTED' | 'UNKNOWN' | 'NONE_FOUND'; signals: string[] };
  confidence: 'FULL' | 'PARTIAL';
  /** 完了できなかったチェック（表示名） */
  unavailable: string[];
  note: 'low_not_safe' | 'verified_crawler' | null;
  location: LocationCheck;
  indicators: Indicator[];
}
