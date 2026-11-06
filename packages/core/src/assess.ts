// 判定ロジック（ip-assess.sh v1.6.0 の [3] Analysis / [4] Report Summary を移植）
//   - 回線種別（インフラ属性）: 加点・減点でスコア化
//   - 脅威の評判: 検出の有無のみ（回線属性の減点で打ち消さない）
//   - 判定できなかった項目は Unknown とし、加点しない
//   Web 版の差分: Ping が打てないため「仮想ロケーション」は判定対象外（na）

import type {
  Assessment, CheckResults, Indicator, InfraClass, LocationCheck, Priority,
} from './types';
import type { ParsedIp } from './ip';

// 一般家庭向けの国内 ISP・モバイルキャリアの ASN
//   ※AS2914（NTT の国際基幹網）や IIJ（AS2497、法人・データセンター事業を含む）は一般向けとみなさない
export const CONSUMER_ISP_ASNS = new Set([4713, 2516, 17676, 9605, 138384, 2527, 2518, 4685, 17511, 18126, 9824]);
const ISP_PTR_RE = /(ocn\.ne\.jp|kddi\.ne\.jp|bbtec\.net|mesh\.ad\.jp|plala\.or\.jp|so-net\.ne\.jp|eonet\.ne\.jp|flets|spmode\.ne\.jp|au-net\.ne\.jp|rmobile\.jp|panda-world|nuro\.jp|biglobe\.ne\.jp|iij\.ad\.jp|iijmio|zaq\.ne\.jp|asahi-net|commufa\.jp|bbiq\.jp|megaegg\.ne\.jp|pikara\.ne\.jp|dion\.ne\.jp|vectant|ucom|open-cgn)/i;
const ISP_ORG_RE = /(ntt communications|kddi corporation|softbank corp|rakuten mobile|internet initiative japan|biglobe)/i;

const SASE_RE = /(cato networks|zscaler|cloudflare|netskope|prisma access|palo alto networks|cisco umbrella|iboss|skyhigh|menlo security|forcepoint)/i;

// 検索エンジンの正規クローラー（googleusercontent.com は GCP の利用者 VM も含むため対象外）
const CRAWLER_RE = /(\.googlebot\.com|\.google\.com|\.search\.msn\.com|\.applebot\.apple\.com|\.yandex\.(ru|net|com)|\.baidu\.(com|jp))$/i;

// ホスティング事業者の ASN（Cloudflare 13335 は SASE/WARP の切り分けが必要なため含めない）
export const HOSTING_ASNS = new Set([16509, 14618, 8075, 396982, 31898, 45102, 132203, 14061, 63949, 20473, 16276, 24940, 51167, 60781, 28753, 9009, 7684, 9370, 9371, 7506]);
const DC_SRC = '(hydra|zare|arisk|m-square|digitalocean|linode|vultr|choopa|ovh|equinix|hetzner|leaseweb|contabo|hostinger|sakura|conoha|gmo internet|xserver|amazon|aws|microsoft|azure|google cloud|alicloud|alibaba|tencent|hosting|cloud|datacenter|server|colocation|vps)';
const DC_PTR_RE = /(compute\.amazonaws|googleusercontent|cloudapp\.net|vultrusercontent)/i;

const BOX_RE = /(suite\s+\d+|ste\.?\s+\d+|p\.?\s*o\.?\s*box\s*\d*|private\s*box)/i;

// プロキシ用のポート（SOCKS / Squid / Privoxy / Tor SOCKS）と、乗っ取りを示す Shodan のタグ
const PROXY_PORTS = new Set([1080, 3128, 8118, 9050]);
const COMPROMISED_TAGS = new Set(['compromised', 'malware', 'c2', 'doublepulsar', 'botnet']);

export const IPSUM_THRESHOLD = 3;

/** 完了できなかったチェックの表示名 */
export function unavailableChecks(r: CheckResults): string[] {
  const out: string[] = [];
  if (r.rdap.status === 'failed') out.push('RDAP');
  if (r.dns.ptrStatus === 'failed') out.push('Reverse DNS (PTR)');
  else if (r.dns.fcrdns === 'unknown') out.push('FCrDNS');
  if (r.asn.status === 'failed') out.push('ASN Lookup (Team Cymru)');
  for (const l of r.dnsbl.lists) {
    if (l.status === 'failed' || l.status === 'refused' || l.status === 'unhealthy') out.push(`DNSBL (${l.label})`);
  }
  if (r.drop.status === 'failed') out.push('Spamhaus DROP');
  if (r.tor.status === 'failed') out.push('Tor Exit Node');
  if (r.ipsum.status === 'failed') out.push('IPsum');
  if (r.internetdb.status === 'failed') out.push('Shodan InternetDB');
  if (r.geofeed.status === 'failed') out.push('Geofeed');
  return out;
}

export function assess(ip: ParsedIp, r: CheckResults, now = new Date()): Assessment {
  const { rdap, dns, asn, dnsbl, drop, tor, ipsum, internetdb: idb, geofeed } = r;
  const indicators: Indicator[] = [];
  let score = 0;
  const add = (ind: Indicator) => { indicators.push(ind); score += ind.points; };

  const asnNum = asn.status === 'found' ? asn.asn : null;
  const asName = asn.name ?? '';
  const ptrLower = dns.ptrStatus === 'found' && dns.ptr ? dns.ptr.toLowerCase() : '';
  // 減点（安全側）の判定には、なりすまし防止のため FCrDNS 検証済みの PTR のみを使う
  const ptrTrusted = dns.fcrdns === 'verified' ? ptrLower : '';
  const metadata = [rdap.name ?? '', ...rdap.entities, ...rdap.remarks.slice(0, 3), ...rdap.domains, ...rdap.addresses.map((a) => a.address)]
    .join(' ').toLowerCase();

  // ---------------- 検索エンジンクローラー ----------------
  let verifiedCrawler = false;
  let spoofedCrawler = false;
  if (CRAWLER_RE.test(ptrLower)) {
    if (dns.fcrdns === 'verified') verifiedCrawler = true;
    else if (dns.fcrdns === 'not_verified' || dns.fcrdns === 'not_verified_servfail') spoofedCrawler = true;
  }

  // ---------------- A. 国内一般回線 ----------------
  //   1. FCrDNS 検証済み PTR → 2. ASN → 3. ASN が取れない場合のみ組織名（備考欄は使わない）
  let ispEvidence: Record<string, string> | null = null;
  const orgText = [rdap.name ?? '', ...rdap.entities].join(' ').toLowerCase();
  if (ptrTrusted && ISP_PTR_RE.test(ptrTrusted)) ispEvidence = { kind: 'ptr', value: dns.ptr! };
  else if (asnNum !== null && CONSUMER_ISP_ASNS.has(asnNum)) ispEvidence = { kind: 'asn', value: `AS${asnNum}`, name: asName };
  else if (asnNum === null && ISP_ORG_RE.test(orgText)) ispEvidence = { kind: 'org', value: ISP_ORG_RE.exec(orgText)![1]! };
  const ispNameInMeta = ISP_ORG_RE.exec(metadata)?.[1] ?? null;
  if (ispEvidence) {
    add({ axis: 'infra', id: 'consumer_isp', state: 'safe', points: -5, params: ispEvidence });
  } else if (ispNameInMeta && asnNum !== null) {
    // ISP 名は登録情報に出てくるが、経路は一般向け ISP のものではない（転売・法人・中継の帯域に多い）
    add({ axis: 'infra', id: 'consumer_isp', state: 'info', points: 0, params: { name: ispNameInMeta, asn: `AS${asnNum}`, asName } });
  } else {
    add({ axis: 'infra', id: 'consumer_isp', state: asnNum === null && asn.status === 'failed' && rdap.status === 'failed' ? 'unknown' : 'none', points: 0, params: {} });
  }

  // ---------------- B. 企業向け SASE ----------------
  const sase = SASE_RE.exec(metadata)?.[1] ?? SASE_RE.exec(ptrTrusted)?.[1] ?? null;
  add(sase
    ? { axis: 'infra', id: 'sase', state: 'safe', points: -5, params: { vendor: sase } }
    : { axis: 'infra', id: 'sase', state: 'none', points: 0, params: {} });

  // ---------------- 検証済みクローラー ----------------
  add(verifiedCrawler
    ? { axis: 'infra', id: 'verified_crawler', state: 'safe', points: -5, params: { ptr: dns.ptr ?? '' } }
    : { axis: 'infra', id: 'verified_crawler', state: dns.ptrStatus === 'failed' ? 'unknown' : 'none', points: 0, params: {} });

  // ---------------- データセンター (+3) ----------------
  const dcAsn = asnNum !== null && HOSTING_ASNS.has(asnNum);
  // 根拠1: 既知のホスティング ASN / 根拠2: 登録情報のキーワード、またはクラウド事業者の PTR
  const dcKeywordHit = new RegExp(DC_SRC, 'i').test(metadata) || DC_PTR_RE.test(ptrLower);
  const dcKeywords = [...new Set([...`${metadata} ${ptrLower}`.matchAll(new RegExp(DC_SRC, 'gi'))].map((m) => m[1]!.toLowerCase()))].sort();
  const dcHit = dcAsn || dcKeywordHit;
  add(dcHit
    ? {
        axis: 'infra', id: 'datacenter', state: 'hit', points: 3,
        params: { ...(dcAsn ? { asn: `AS${asnNum}`, asName } : {}), ...(dcKeywordHit ? { keywords: dcKeywords } : {}) },
      }
    : { axis: 'infra', id: 'datacenter', state: 'none', points: 0, params: {} });

  // ---------------- IP 転貸 (+3) ----------------
  const subleaseHit = rdap.domains.length >= 2;
  add({
    axis: 'infra', id: 'sublease', state: subleaseHit ? 'hit' : rdap.status === 'failed' ? 'unknown' : 'none',
    points: subleaseHit ? 3 : 0, params: { domains: rdap.domains },
  });

  // ---------------- 私書箱 / バーチャルオフィス (+2) ----------------
  //   加点するのは組織等の住所が該当した場合のみ。個人の連絡先だけなら Info
  const boxHits = rdap.addresses.filter((a) => BOX_RE.test(a.address));
  const boxOrgHits = boxHits.filter((a) => a.kind !== 'individual');
  const boxParams = {
    matches: boxHits.map((a) => `[${a.kind}] ${a.name}: ${a.address} (${BOX_RE.exec(a.address)?.[1] ?? ''})`),
  };
  if (boxOrgHits.length > 0) add({ axis: 'infra', id: 'pobox', state: 'hit', points: 2, params: boxParams });
  else if (boxHits.length > 0) add({ axis: 'infra', id: 'pobox', state: 'info', points: 0, params: boxParams });
  else add({ axis: 'infra', id: 'pobox', state: rdap.status === 'failed' ? 'unknown' : 'none', points: 0, params: {} });

  // ---------------- 匿名化 VPN (+3) ----------------
  const tagsLower = idb.tags.map((t) => t.toLowerCase());
  const vpnHit = tagsLower.includes('vpn');
  add(vpnHit
    ? { axis: 'infra', id: 'vpn', state: 'hit', points: 3, params: { tags: idb.tags, ports: idb.ports.map(String) } }
    : { axis: 'infra', id: 'vpn', state: idb.status === 'failed' ? 'unknown' : 'none', points: 0, params: {} });

  // ---------------- 仮想ロケーション: Web 版では遅延を測れないため対象外 ----------------
  add({ axis: 'infra', id: 'virtual_location', state: 'na', points: 0, params: {} });

  // ---------------- PA 割り当て (+1) ----------------
  const paHit = !!rdap.type && /PA/i.test(rdap.type);
  add({ axis: 'infra', id: 'pa', state: paHit ? 'hit' : 'none', points: paHit ? 1 : 0, params: { type: rdap.type ?? '' } });

  // ---------------- 使える逆引きなし (+1)（他のリスク要因がある場合のみ） ----------------
  const noPtr = dns.ptrStatus === 'none' || dns.ptrStatus === 'broken';
  if (noPtr && score > 0) add({ axis: 'infra', id: 'no_ptr', state: 'hit', points: 1, params: { ptrStatus: dns.ptrStatus } });
  else if (noPtr) add({ axis: 'infra', id: 'no_ptr', state: 'info', points: 0, params: { ptrStatus: dns.ptrStatus } });
  else if (dns.ptrStatus === 'failed') add({ axis: 'infra', id: 'no_ptr', state: 'unknown', points: 0, params: {} });
  else add({ axis: 'infra', id: 'no_ptr', state: 'none', points: 0, params: {} });

  // ================= 脅威の評判 =================
  const signals: string[] = [];
  const threat = (ind: Omit<Indicator, 'axis' | 'points'>, signal?: string) => {
    indicators.push({ axis: 'threat', points: 0, ...ind });
    if (ind.state === 'hit' && signal) signals.push(signal);
  };

  for (const l of dnsbl.lists) {
    const params = { label: l.label, zone: l.zone, codes: l.codes, categories: l.categories, kind: l.kind, status: l.status };
    if (l.status === 'listed' && l.kind === 'threat' && !l.policyOnly) {
      const cats = l.categories.filter((c) => !(l.id === 'spamhaus' && c === 'PBL'));
      threat({ id: 'dnsbl', key: l.id, state: 'hit', params }, `${l.label}${cats.length ? ` ${cats.join(' ')}` : ''}`);
    } else if (l.status === 'listed') {
      threat({ id: 'dnsbl', key: l.id, state: 'info', params });
    } else if (l.status === 'clean') {
      threat({ id: 'dnsbl', key: l.id, state: 'none', params });
    } else if (l.status === 'unsupported' || l.status === 'not_configured') {
      threat({ id: 'dnsbl', key: l.id, state: 'na', params });
    } else {
      threat({ id: 'dnsbl', key: l.id, state: 'unknown', params });
    }
  }

  const dropParams = { cidr: drop.cidr ?? '', sblid: drop.sblid ?? '', copyright: drop.copyright ?? '', listUpdated: drop.listUpdated ?? '' };
  if (drop.status === 'listed') threat({ id: 'drop', state: 'hit', params: dropParams }, `Spamhaus DROP${drop.sblid ? ` ${drop.sblid}` : ''}`);
  else threat({ id: 'drop', state: drop.status === 'failed' ? 'unknown' : 'none', params: dropParams });

  if (ipsum.status === 'ok' && ipsum.count >= IPSUM_THRESHOLD) threat({ id: 'ipsum', state: 'hit', params: { count: ipsum.count } }, `IPsum ${ipsum.count} lists`);
  else if (ipsum.status === 'ok' && ipsum.count >= 1) threat({ id: 'ipsum', state: 'info', params: { count: ipsum.count } });
  else threat({ id: 'ipsum', state: ipsum.status === 'failed' ? 'unknown' : ipsum.status === 'unsupported' ? 'na' : 'none', params: { count: 0 } });

  const compromised = tagsLower.filter((t) => COMPROMISED_TAGS.has(t));
  if (compromised.length) threat({ id: 'compromised', state: 'hit', params: { tags: compromised } }, `Shodan: ${compromised.join(' ')}`);
  else threat({ id: 'compromised', state: idb.status === 'failed' ? 'unknown' : 'none', params: {} });

  const proxyPorts = idb.ports.filter((p) => PROXY_PORTS.has(p)).map(String);
  const proxyTag = tagsLower.includes('proxy');
  if (proxyPorts.length || proxyTag) threat({ id: 'proxy', state: 'hit', params: { ports: proxyPorts, tag: proxyTag ? 'proxy' : '' } }, 'Proxy service exposed');
  else threat({ id: 'proxy', state: idb.status === 'failed' ? 'unknown' : 'none', params: {} });

  if (tor.status === 'listed') threat({ id: 'tor', state: 'hit', params: {} }, 'Tor Exit Node');
  else threat({ id: 'tor', state: tor.status === 'failed' ? 'unknown' : 'none', params: {} });

  if (spoofedCrawler) threat({ id: 'spoofed_crawler', state: 'hit', params: { ptr: dns.ptr ?? '' } }, 'Spoofed crawler PTR');
  else threat({ id: 'spoofed_crawler', state: dns.ptrStatus === 'failed' || dns.fcrdns === 'unknown' ? 'unknown' : 'none', params: {} });

  // ---------------- 回線種別 ----------------
  const ispHit = !!ispEvidence;
  let infraClass: InfraClass = 'unclassified';
  if (tor.status === 'listed') infraClass = 'tor';
  else if (verifiedCrawler) infraClass = 'crawler';
  else if (sase) infraClass = 'sase';
  else if (ispHit && dcHit) infraClass = 'mixed';
  else if (ispHit) infraClass = 'consumer_isp';
  else if (dcHit) infraClass = 'datacenter';

  // ---------------- 脅威の評判のまとめ ----------------
  const unavailable = unavailableChecks(r);
  const reputationIncomplete =
    tor.status === 'failed' || ipsum.status === 'failed' || drop.status === 'failed' ||
    dnsbl.lists.some((l) => l.kind === 'threat' && ['failed', 'refused', 'unhealthy'].includes(l.status));
  const threatLevel = signals.length > 0 ? 'DETECTED' : reputationIncomplete ? 'UNKNOWN' : 'NONE_FOUND';

  // ---------------- 調査優先度 ----------------
  //   脅威シグナルがあれば回線種別に関係なく HIGH
  let priority: Priority;
  let note: Assessment['note'] = null;
  if (threatLevel === 'DETECTED') priority = 'HIGH';
  else if (verifiedCrawler && score <= 0) { priority = 'LOW'; note = 'verified_crawler'; }
  else if (score >= 4) priority = 'HIGH';
  else if (score >= 1) priority = 'MEDIUM';
  else { priority = 'LOW'; note = 'low_not_safe'; }

  // ---------------- 所在地の整合性（遅延がないため、申告どうしの比較のみ） ----------------
  let location: LocationCheck = 'not_verified';
  if (geofeed.country && rdap.country && geofeed.country !== rdap.country) location = 'differ';
  else if (rdap.status === 'failed' && geofeed.status === 'failed') location = 'unknown';

  return {
    ip: ip.address,
    version: ip.version,
    assessedAt: now.toISOString(),
    priority,
    infraClass,
    infraScore: score,
    threat: { level: threatLevel, signals },
    confidence: unavailable.length ? 'PARTIAL' : 'FULL',
    unavailable,
    note,
    location,
    indicators,
  };
}
