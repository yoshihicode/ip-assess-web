// 静的アセット（React SPA）を配信し、/api/* と /auth/* は Service Binding で api Worker に渡す

interface Env {
  ASSETS: Fetcher;
  API: Fetcher;
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname.startsWith('/api/') || pathname.startsWith('/auth/')) {
      return env.API.fetch(request);
    }
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
