import { createContext, useContext } from 'react';
import type { CheckId, Indicator, InfraClass } from '@ip-assess/core';

export type Lang = 'ja' | 'en';

const ja = {
  title: 'ip-assess',
  tagline: 'アクセス元 IP アドレスの一次調査用ツール',
  placeholder: 'IPv4 / IPv6 アドレス（例: 203.0.113.10）',
  submit: '調査する',
  errors: {
    invalid_ip: 'IP アドレスの形式が正しくありません。',
    not_global: 'プライベート・予約済みなど、調査対象外のアドレスです。',
    rate_limited: '短時間に問い合わせが集中しています。少し待ってから再度お試しください。',
    network: '通信に失敗しました。',
    not_found: '指定された結果が見つかりません。',
    generic: 'エラーが発生しました。',
  },
  checks: {
    rdap: '登録情報（RDAP）',
    dns: '逆引き・FCrDNS',
    asn: 'ASN（Team Cymru）',
    dnsbl: 'DNSBL',
    drop: 'Spamhaus DROP',
    tor: 'Tor 出口ノード',
    ipsum: 'IPsum',
    internetdb: 'Shodan InternetDB',
    geofeed: 'Geofeed',
  } satisfies Record<CheckId, string>,
  progress: '調査の進行状況',
  pending: '取得中…',
  done: '完了',
  failed: '取得できず',
  assessing: '判定中…',
  summary: {
    heading: '結論',
    priority: '調査優先度',
    infra: '回線種別',
    score: 'スコア',
    threat: '脅威の評判',
    confidence: '確実性',
    full: 'FULL（すべてのチェックが完了）',
    partial: 'PARTIAL（完了できなかったチェック: {list}）',
    threatDetected: '検出（{list}）',
    threatUnknown: '不明（一部の評判チェックが完了できず）',
    threatNone: '未検出（確認したデータソースの範囲のみ）',
    notes: {
      low_not_safe: 'LOW は「安全」という意味ではありません。乗っ取られた家庭の端末や住宅用プロキシも同じように見えます。',
      verified_crawler: '検証済みの検索エンジンクローラーです。遮断すると検索結果に影響する可能性があります。',
    },
  },
  infraClass: {
    tor: '匿名化ネットワーク（Tor）',
    crawler: '検索エンジンクローラー（検証済み）',
    sase: '企業向け SASE / ゼロトラスト',
    mixed: '混在（国内 ISP とホスティングの特徴）',
    consumer_isp: '国内一般回線（ISP・モバイル）',
    datacenter: 'データセンター・ホスティング・クラウド',
    unclassified: '分類できず',
  } satisfies Record<InfraClass, string>,
  sections: {
    network: 'ネットワーク',
    location: '所在地',
    contacts: '連絡先・登録情報',
    exposure: '公開サービス（Shodan InternetDB・週 1 回更新）',
    infra: '回線種別（点数）',
    threat: '脅威の評判',
    ai: 'AI による評価',
    history: 'このIPの問い合わせ状況',
    sources: 'データソース',
  },
  fields: {
    networkName: 'ネットワーク名', handle: 'ハンドル', range: '割当範囲', cidr: '割当 CIDR', type: '割当種別',
    registered: '登録日', lastChanged: '最終更新日', rir: 'RIR', remarks: '備考', asn: 'ASN', asName: 'AS 名',
    bgpPrefix: 'BGP プレフィックス', asnCountry: 'ASN の国', prefixAllocated: '割当日（RIR）', ptr: '逆引き（PTR）',
    fcrdns: 'FCrDNS', registeredCountry: '登録国', geofeed: '申告所在地（Geofeed）', holderAddress: '登録者の住所',
    holderCountry: '登録者の国', latency: '遅延', locationCheck: '整合性', addresses: '登録住所', abuse: 'Abuse 窓口',
    entities: '関係組織', emails: 'メール・運営者ドメイン', status: '状態', ports: '公開ポート', tags: 'タグ',
    vulns: '既知の脆弱性', cpes: 'CPE', hostnames: 'ホスト名', resolver: 'DNS リゾルバ',
  },
  values: {
    none: 'なし', unknown: '不明', daysAgo: '{n} 日前', moreNames: '他 {n} 件',
    latencyNa: '測定対象外（Web 版では Ping を実行できません）',
    ptrStatus: { found: '', none: 'なし（登録なし）', broken: 'なし（相手側の逆引きが SERVFAIL）', failed: '不明（問い合わせに失敗）' },
    fcrdns: {
      verified: '検証済み（{name} → {ip}）', not_verified: '未検証（正引きが {ip} を返さない）',
      not_verified_servfail: '未検証（相手側の正引きが SERVFAIL）', unknown: '不明（正引きに失敗）', na: '対象外（PTR なし）',
    },
    geofeed: { not_published: '公開されていない', not_listed: '該当プレフィックスなし', failed: '不明（取得に失敗）', selfDeclared: '運営者の自己申告' },
    location: {
      differ: '申告が一致しない（RDAP: {rdap} / Geofeed: {geo}）',
      not_verified: '未検証（遅延を測定できないため、申告の比較のみ）',
      unknown: '不明',
    },
    idb: { found: 'データあり', no_data: 'データなし（Shodan のスキャンで何も観測されていない）', failed: '不明（取得に失敗）' },
    notFoundInRdap: 'RDAP の応答に含まれていない',
  },
  legend: { hit: 'リスク', safe: '安全側', info: '参考', none: '該当なし', unknown: '確認できず', na: '対象外' },
  indicators: {
    consumer_isp: '国内一般回線', sase: '企業向け SASE', verified_crawler: '検証済みクローラー',
    datacenter: 'データセンター・クラウド', sublease: 'IP 転貸（ドメイン不一致）', pobox: '私書箱・バーチャルオフィス',
    vpn: '匿名化 VPN', virtual_location: '仮想ロケーション', pa: 'PA 割り当て', no_ptr: '使える逆引きなし',
    dnsbl: 'DNSBL', drop: 'Spamhaus DROP（犯罪者が管理するネットワーク）', ipsum: 'IPsum 集約ブラックリスト', compromised: '乗っ取られた機器（Shodan）',
    proxy: '公開プロキシ（Shodan）', tor: 'Tor 出口ノード', spoofed_crawler: 'クローラーを装った逆引き',
  } as Record<string, string>,
  evidence: {
    ispPtr: 'FCrDNS 検証済みの PTR: {v}', ispAsn: '一般向け ISP の ASN: {v} ({name})', ispOrg: '組織名のみ（ASN 取得不可）: {v}',
    ispInfo: '登録情報に「{name}」があるが、経路は {asn}（一般向け ISP ではない）',
    keywords: 'キーワード: {v}', domains: '{v}', individualOnly: '個人の連絡先のみ（加点なし）: {v}',
    virtualNa: 'Web 版では遅延を測定できないため判定しない', notScoredNoPtr: '他にリスク要因がないため加点なし',
    ipsumBelow: '{n} 件（しきい値 3 未満）', ipsumHit: '{n} 件のリストに掲載',
    spamOnly: '迷惑メール専用リスト（参考情報）', policyOnly: 'PBL のみ（一般回線の範囲。脅威ではない）',
    refused: '問い合わせが拒否された（公開リゾルバ経由など）', unhealthy: 'テスト用アドレスに応答しない（リストの不調）',
    unsupported: 'IPv6 に非対応', failed: '問い合わせに失敗', ipv4Only: 'IPv6 に非対応', notListed: '掲載なし',
    not_configured: 'DQS キー未設定のため対象外（公開ミラーは公開リゾルバ経由を拒否するため）',
    dropListed: '{cidr} に掲載（{sblid}）', dropCredit: 'データ: {copyright}（リスト更新: {date}）',
  },
  ai: {
    none: 'AI 評価は行われていません。',
    queued: 'AI が評価しています…',
    deferred: '本日の AI 評価の上限に達したため、翌日（日本時間 0 時以降）に評価します。',
    failed: 'AI 評価に失敗しました。',
    verdict: { likely_malicious: '悪意の可能性が高い', suspicious: '要注意', likely_benign: '問題ない可能性が高い', inconclusive: '判断できない' },
    confidence: '確度', keyPoints: '根拠', actions: '推奨する対応', caveats: '注意点',
    disclaimer: 'AI の評価は参考情報です。最終的な判断は根拠となる各項目を確認して行ってください。',
    model: 'モデル',
  },
  history: {
    total: '累計', last24h: '24 時間', last7d: '7 日', last30d: '30 日', first: '初回', recent: '最近の問い合わせ',
    firstTime: 'このIPの問い合わせは今回が初めてです。',
  },
  disclaimer: {
    heading: '免責事項',
    items: [
      '本サービスの結果は、アクセス元 IP アドレスの一次調査のための参考情報です。安全・危険を判定するものではなく、「LOW」や「未検出」は安全であることを意味しません。',
      '結果は第三者のデータソース（RDAP、DNS、Shodan InternetDB、Spamhaus DROP、IPsum、Tor Project など）に基づきます。これらの情報の正確性・完全性・最新性は保証されず、登録情報や申告所在地は誤っている場合があります。',
      'AI による評価は自動生成された参考情報であり、誤りを含む可能性があります。',
      '遮断・通報などの対応は、本サービスの結果だけで判断せず、アクセスログなどの根拠を確認したうえで、利用者の責任で行ってください。本サービスの利用によって生じた損害について、提供者は責任を負いません。',
      '調査のため、入力した IP アドレスは外部のデータソース（RDAP・DNS リゾルバ・DNSBL の運営者・Shodan など）に送信されます。また、問い合わせ内容と結果は問い合わせ状況の集計のために記録されます。',
      '各データソースの権利はそれぞれの提供者に帰属します。Spamhaus DROP: © The Spamhaus Project SLU。',
    ],
  },
  lang: 'English',
};

type Dict = typeof ja;

const en: Dict = {
  title: 'ip-assess',
  tagline: 'A first-line investigation tool for source IP addresses',
  placeholder: 'IPv4 / IPv6 address (e.g. 203.0.113.10)',
  submit: 'Assess',
  errors: {
    invalid_ip: 'Invalid IP address.',
    not_global: 'This address is private or reserved and cannot be assessed.',
    rate_limited: 'Too many requests. Please wait a moment and try again.',
    network: 'Network error.',
    not_found: 'Result not found.',
    generic: 'An error occurred.',
  },
  checks: {
    rdap: 'Registration (RDAP)', dns: 'Reverse DNS / FCrDNS', asn: 'ASN (Team Cymru)', dnsbl: 'DNSBL',
    drop: 'Spamhaus DROP', tor: 'Tor exit node', ipsum: 'IPsum', internetdb: 'Shodan InternetDB', geofeed: 'Geofeed',
  },
  progress: 'Progress',
  pending: 'Fetching…',
  done: 'Done',
  failed: 'Unavailable',
  assessing: 'Assessing…',
  summary: {
    heading: 'Summary',
    priority: 'Investigation priority',
    infra: 'Infrastructure',
    score: 'score',
    threat: 'Threat reputation',
    confidence: 'Confidence',
    full: 'FULL - all checks completed',
    partial: 'PARTIAL - could not complete: {list}',
    threatDetected: 'DETECTED ({list})',
    threatUnknown: 'UNKNOWN (some reputation checks could not be completed)',
    threatNone: 'NONE FOUND (in the checked sources only)',
    notes: {
      low_not_safe: 'LOW does not mean safe. Compromised end-user devices and residential proxies look the same.',
      verified_crawler: 'Verified search engine crawler. Blocking may affect search indexing.',
    },
  },
  infraClass: {
    tor: 'Anonymization network (Tor)', crawler: 'Search engine crawler (verified)', sase: 'Enterprise SASE / Zero Trust',
    mixed: 'Mixed (domestic ISP and hosting traits)', consumer_isp: 'Domestic consumer ISP / mobile',
    datacenter: 'Datacenter / hosting / cloud', unclassified: 'Unclassified',
  },
  sections: {
    network: 'Network', location: 'Location', contacts: 'Contacts', exposure: 'Exposure (Shodan InternetDB, updated weekly)',
    infra: 'Infrastructure attributes (points)', threat: 'Threat reputation', ai: 'AI evaluation',
    history: 'Inquiries for this IP', sources: 'Data sources',
  },
  fields: {
    networkName: 'Network name', handle: 'Handle', range: 'Allocated range', cidr: 'Allocated CIDR', type: 'Allocation type',
    registered: 'Registered', lastChanged: 'Last changed', rir: 'RIR', remarks: 'Remarks', asn: 'ASN', asName: 'AS name',
    bgpPrefix: 'BGP prefix', asnCountry: 'ASN country', prefixAllocated: 'Prefix allocated', ptr: 'Reverse DNS (PTR)',
    fcrdns: 'FCrDNS', registeredCountry: 'Registered country', geofeed: 'Declared (Geofeed)', holderAddress: 'Holder address',
    holderCountry: 'Holder country', latency: 'Latency', locationCheck: 'Check', addresses: 'Registered addresses', abuse: 'Abuse contact',
    entities: 'Entities', emails: 'Emails / operator domains', status: 'Status', ports: 'Open ports', tags: 'Tags',
    vulns: 'Known vulns', cpes: 'CPEs', hostnames: 'Hostnames', resolver: 'DNS resolver',
  },
  values: {
    none: 'none', unknown: 'Unknown', daysAgo: '{n} days ago', moreNames: '+{n} more',
    latencyNa: 'Not measured (ping is not available in the web version)',
    ptrStatus: { found: '', none: 'None (no record)', broken: 'None (remote reverse DNS returned SERVFAIL)', failed: 'Unknown (query failed)' },
    fcrdns: {
      verified: 'Verified ({name} -> {ip})', not_verified: 'Not verified (forward lookup does not return {ip})',
      not_verified_servfail: 'Not verified (remote forward lookup returned SERVFAIL)', unknown: 'Unknown (forward lookup failed)', na: 'N/A (no PTR)',
    },
    geofeed: { not_published: 'Not published', not_listed: 'Prefix not listed', failed: 'Unknown (failed to fetch)', selfDeclared: 'self-declared by operator' },
    location: {
      differ: 'Declarations differ (RDAP: {rdap} / Geofeed: {geo})',
      not_verified: 'Not verified (no latency measurement; declarations compared only)',
      unknown: 'Unknown',
    },
    idb: { found: 'Found', no_data: 'No data (nothing observed by Shodan scans)', failed: 'Unknown (failed to fetch)' },
    notFoundInRdap: 'Not found in RDAP response',
  },
  legend: { hit: 'risk', safe: 'safe', info: 'info', none: 'not detected', unknown: 'could not check', na: 'not applicable' },
  indicators: {
    consumer_isp: 'Domestic consumer ISP', sase: 'Enterprise SASE', verified_crawler: 'Verified search engine crawler',
    datacenter: 'Datacenter / hosting / cloud', sublease: 'IP sub-leasing (domain mismatch)', pobox: 'PO box / virtual office',
    vpn: 'Anonymizing VPN service', virtual_location: 'Virtual location', pa: 'PA allocation', no_ptr: 'No usable reverse DNS',
    dnsbl: 'DNSBL', drop: 'Spamhaus DROP (criminal-controlled networks)', ipsum: 'IPsum aggregated blocklists', compromised: 'Compromised host (Shodan)',
    proxy: 'Exposed proxy service (Shodan)', tor: 'Tor exit node', spoofed_crawler: 'Spoofed crawler PTR',
  },
  evidence: {
    ispPtr: 'FCrDNS-verified PTR: {v}', ispAsn: 'Consumer ISP ASN: {v} ({name})', ispOrg: 'Organization name only (ASN unavailable): {v}',
    ispInfo: "'{name}' in records, but routed by {asn} (not a consumer ISP)",
    keywords: 'keywords: {v}', domains: '{v}', individualOnly: 'individual contact only (not scored): {v}',
    virtualNa: 'Not evaluated: latency cannot be measured in the web version', notScoredNoPtr: 'not scored (no other risk indicators)',
    ipsumBelow: '{n} list(s) - below threshold of 3', ipsumHit: 'listed on {n} blocklists',
    spamOnly: 'spam-only list (informational)', policyOnly: 'PBL only (end-user range, not a threat)',
    refused: 'query refused (e.g. via public resolver)', unhealthy: 'list did not answer its test address (list malfunction)',
    unsupported: 'IPv6 not supported', failed: 'query failed', ipv4Only: 'IPv6 not supported', notListed: 'not listed',
    not_configured: 'Not used: no DQS key configured (the public mirror refuses queries via public resolvers)',
    dropListed: 'listed as {cidr} ({sblid})', dropCredit: 'Data: {copyright} (list updated: {date})',
  },
  ai: {
    none: 'No AI evaluation.',
    queued: 'AI is evaluating…',
    deferred: "Today's AI evaluation limit has been reached. It will be evaluated after midnight (JST).",
    failed: 'AI evaluation failed.',
    verdict: { likely_malicious: 'Likely malicious', suspicious: 'Suspicious', likely_benign: 'Likely benign', inconclusive: 'Inconclusive' },
    confidence: 'Confidence', keyPoints: 'Key points', actions: 'Recommended actions', caveats: 'Caveats',
    disclaimer: 'The AI evaluation is for reference only. Verify the underlying indicators before deciding.',
    model: 'Model',
  },
  history: {
    total: 'Total', last24h: '24h', last7d: '7 days', last30d: '30 days', first: 'First seen', recent: 'Recent inquiries',
    firstTime: 'This is the first inquiry for this IP.',
  },
  disclaimer: {
    heading: 'Disclaimer',
    items: [
      'Results are reference information for the first-line investigation of a source IP address. They are not a verdict on whether an address is safe or malicious; "LOW" or "not detected" does not mean safe.',
      'Results are based on third-party data sources (RDAP, DNS, Shodan InternetDB, Spamhaus DROP, IPsum, the Tor Project, etc.). Their accuracy, completeness and timeliness are not guaranteed; registration data and declared locations may be wrong.',
      'The AI evaluation is automatically generated and may contain errors.',
      'Do not block, report or take other action based solely on these results. Verify the evidence, such as access logs, and act at your own responsibility. The provider accepts no liability for any damage arising from the use of this service.',
      'To perform the checks, the entered IP address is sent to external data sources (RDAP, DNS resolver, DNSBL operators, Shodan, etc.). Queries and results are recorded to show inquiry statistics.',
      'Each data source remains the property of its provider. Spamhaus DROP: © The Spamhaus Project SLU.',
    ],
  },
  lang: '日本語',
};

export const dictionaries: Record<Lang, Dict> = { ja, en };

export const I18nContext = createContext<{ lang: Lang; t: Dict; setLang: (l: Lang) => void }>({
  lang: 'ja', t: ja, setLang: () => {},
});

export const useI18n = () => useContext(I18nContext);

/** {name} 形式の差し込み */
export function fmt(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, k: string) => String(vars[k] ?? ''));
}

const join = (v: unknown) => (Array.isArray(v) ? v.join(', ') : String(v ?? ''));

/** 判定項目の根拠を文章にする */
export function indicatorEvidence(ind: Indicator, t: Dict): string {
  const p = ind.params;
  const e = t.evidence;
  switch (ind.id) {
    case 'consumer_isp':
      if (ind.state === 'info') return fmt(e.ispInfo, { name: join(p.name), asn: join(p.asn) });
      if (ind.state !== 'safe') return '';
      if (p.kind === 'ptr') return fmt(e.ispPtr, { v: join(p.value) });
      if (p.kind === 'asn') return fmt(e.ispAsn, { v: join(p.value), name: join(p.name) });
      return fmt(e.ispOrg, { v: join(p.value) });
    case 'sase': return ind.state === 'safe' ? join(p.vendor) : '';
    case 'verified_crawler': return ind.state === 'safe' ? join(p.ptr) : '';
    case 'datacenter': {
      if (ind.state !== 'hit') return '';
      const parts: string[] = [];
      if (p.asn) parts.push(`${join(p.asn)} (${join(p.asName)})`);
      if (p.keywords) parts.push(fmt(e.keywords, { v: join(p.keywords) }));
      return parts.join(' / ');
    }
    case 'sublease': return join(p.domains);
    case 'pobox':
      if (ind.state === 'info') return fmt(e.individualOnly, { v: join(p.matches) });
      return ind.state === 'hit' ? join(p.matches) : '';
    case 'vpn': return ind.state === 'hit' ? `tags: ${join(p.tags)}` : '';
    case 'virtual_location': return e.virtualNa;
    case 'pa': return join(p.type);
    case 'no_ptr': return ind.state === 'info' ? e.notScoredNoPtr : '';
    case 'dnsbl': {
      if (p.status === 'listed') {
        const detail = `${join(p.categories) || join(p.codes)}`;
        if (ind.state === 'info') return `${detail} - ${p.kind === 'spam' ? e.spamOnly : e.policyOnly}`;
        return `${detail} (${join(p.codes)})`;
      }
      const s = String(p.status);
      return s === 'clean' ? e.notListed : (e as Record<string, string>)[s] ?? s;
    }
    case 'drop': {
      const credit = p.copyright ? fmt(e.dropCredit, { copyright: join(p.copyright), date: join(p.listUpdated) }) : '';
      if (ind.state === 'hit') return `${fmt(e.dropListed, { cidr: join(p.cidr), sblid: join(p.sblid) || '-' })} - ${credit}`;
      if (ind.state === 'unknown') return e.failed;
      return [e.notListed, credit].filter(Boolean).join(' - ');
    }
    case 'ipsum':
      if (ind.state === 'hit') return fmt(e.ipsumHit, { n: Number(p.count) });
      if (ind.state === 'info') return fmt(e.ipsumBelow, { n: Number(p.count) });
      if (ind.state === 'na') return e.ipv4Only;
      return '';
    case 'compromised': return ind.state === 'hit' ? `tags: ${join(p.tags)}` : '';
    case 'proxy': {
      if (ind.state !== 'hit') return '';
      const parts: string[] = [];
      if (Array.isArray(p.ports) && p.ports.length) parts.push(`ports: ${join(p.ports)}`);
      if (p.tag) parts.push(`tag: ${join(p.tag)}`);
      return parts.join(' / ');
    }
    case 'spoofed_crawler': return ind.state === 'hit' ? join(p.ptr) : '';
    default: return '';
  }
}

export function indicatorLabel(ind: Indicator, t: Dict): string {
  if (ind.id === 'dnsbl') return `${t.indicators.dnsbl}: ${String(ind.params.label)}`;
  return t.indicators[ind.id] ?? ind.id;
}

export function detectLang(): Lang {
  try {
    const saved = localStorage.getItem('lang');
    if (saved === 'ja' || saved === 'en') return saved;
  } catch {
    // 無視
  }
  return navigator.language?.toLowerCase().startsWith('ja') ? 'ja' : 'en';
}
