// DNS over HTTPS（JSON 形式）の問い合わせ
//   Workers では dig / host を実行できないため DoH を使う

export const DNS_TYPE = { A: 1, PTR: 12, TXT: 16, AAAA: 28 } as const;
export type DnsType = keyof typeof DNS_TYPE;

/** ok: 取得 / nxdomain: 該当なし（NOERROR で回答なしを含む）/ servfail / error: 問い合わせ失敗（タイムアウト等） */
export type DnsOutcome =
  | { kind: 'ok'; records: string[] }
  | { kind: 'nxdomain' }
  | { kind: 'servfail' }
  | { kind: 'error'; message: string };

interface DohJson {
  Status: number;
  Answer?: { name: string; type: number; data: string }[];
}

export async function dnsQuery(endpoint: string, name: string, type: DnsType, timeoutMs = 5000): Promise<DnsOutcome> {
  const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
  let body: DohJson;
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { kind: 'error', message: `DoH HTTP ${res.status}` };
    body = await res.json<DohJson>();
  } catch (e) {
    return { kind: 'error', message: e instanceof Error ? e.message : String(e) };
  }
  switch (body.Status) {
    case 0: {
      const want = DNS_TYPE[type];
      const records = (body.Answer ?? [])
        .filter((a) => a.type === want)
        .map((a) => (type === 'TXT' ? a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '') : a.data.replace(/\.$/, '')));
      return records.length ? { kind: 'ok', records } : { kind: 'nxdomain' };
    }
    case 3:
      return { kind: 'nxdomain' };
    case 2:
      return { kind: 'servfail' };
    default:
      return { kind: 'error', message: `DNS status ${body.Status}` };
  }
}

/** DoH の名前（証跡表示用） */
export function resolverLabel(endpoint: string): string {
  try {
    return `DoH ${new URL(endpoint).host}`;
  } catch {
    return endpoint;
  }
}
