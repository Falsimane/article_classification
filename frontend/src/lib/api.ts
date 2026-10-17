import type { ActorProfile, ActorRow, ArticleGraph, ArticleSummary, IocRow, Stats } from "../types";

async function get<T>(path: string, params: Record<string, string | undefined> = {}): Promise<T> {
  const query = new URLSearchParams(Object.entries(params).filter((e): e is [string, string] => !!e[1])).toString();
  const res = await fetch(query ? `${path}?${query}` : path);
  if (!res.ok) throw new Error(`${path} : HTTP ${res.status}`);
  return res.json();
}

export const api = {
  stats: () => get<Stats>("/api/stats"),
  articles: () => get<{ articles: ArticleSummary[] }>("/api/articles").then((r) => r.articles),
  graph: (articleId: number, filters: { type?: string; search?: string; dual_use_only?: string } = {}) =>
    get<ArticleGraph>("/api/graph", { article_id: String(articleId), ...filters }),
  iocs: (articleId: number) => get<{ iocs: IocRow[] }>("/api/iocs", { article_id: String(articleId) }).then((r) => r.iocs),
  actors: () => get<{ actors: ActorRow[] }>("/api/actors").then((r) => r.actors),
  actor: (id: string) => get<ActorProfile>(`/api/actors/${encodeURIComponent(id)}`),
};
