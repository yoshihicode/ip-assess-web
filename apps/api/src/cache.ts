// チェック結果のキャッシュ
//   1. isolate 内のメモリ（同じ isolate への連続した呼び出しで再利用）
//   2. Workers Cache（Cache API。データセンター単位。*.workers.dev では無効のため、その場合は 1 のみ）
//   失敗した結果はキャッシュしない（一時的な障害を固定化しないため）

const memory = new Map<string, { expires: number; value: unknown }>();
const MEMORY_MAX = 500;

function cacheRequest(key: string): Request {
  return new Request(`https://cache.ip-assess.internal/${encodeURIComponent(key)}`);
}

export async function cached<T>(
  key: string,
  ttlSeconds: number,
  compute: () => Promise<T>,
  shouldCache: (value: T) => boolean = () => true,
): Promise<T> {
  const now = Date.now();
  const hit = memory.get(key);
  if (hit && hit.expires > now) return hit.value as T;

  const cache = typeof caches !== 'undefined' ? caches.default : undefined;
  if (cache) {
    try {
      const res = await cache.match(cacheRequest(key));
      if (res) {
        const value = await res.json<T>();
        remember(key, value, ttlSeconds);
        return value;
      }
    } catch {
      // キャッシュの障害は無視して取得し直す
    }
  }

  const value = await compute();
  if (shouldCache(value)) {
    remember(key, value, ttlSeconds);
    if (cache) {
      try {
        await cache.put(
          cacheRequest(key),
          new Response(JSON.stringify(value), {
            headers: { 'content-type': 'application/json', 'cache-control': `max-age=${ttlSeconds}` },
          }),
        );
      } catch {
        // 無視
      }
    }
  }
  return value;
}

function remember(key: string, value: unknown, ttlSeconds: number) {
  if (memory.size >= MEMORY_MAX) {
    const first = memory.keys().next().value;
    if (first !== undefined) memory.delete(first);
  }
  memory.set(key, { expires: Date.now() + ttlSeconds * 1000, value });
}

/** 大きな一覧（Tor・IPsum）を isolate 内に保持する */
export async function cachedText(url: string, ttlSeconds: number, validate: (text: string) => boolean): Promise<string> {
  const key = `text:${url}`;
  const hit = memory.get(key);
  if (hit && hit.expires > Date.now()) return hit.value as string;
  const res = await fetch(url, {
    // サブリクエストを Cloudflare のエッジにキャッシュさせる
    cf: { cacheTtl: ttlSeconds, cacheEverything: true },
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (!validate(text)) throw new Error('unexpected content');
  remember(key, text, ttlSeconds);
  return text;
}
