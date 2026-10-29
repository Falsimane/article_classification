import type { ActorProfile, ActorRow, ArticleGraph, ArticleSummary, ArticleText, IocRow, RuleRow, Stats } from "../types";

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
  rules: (articleId: number) => get<{ rules: RuleRow[] }>("/api/rules", { article_id: String(articleId) }).then((r) => r.rules),
  article: (articleId: number) => get<ArticleText>("/api/article", { article_id: String(articleId) }),
  /** Bundle STIX 2.1 écrit par l'extraction ; `matchesGraph` est faux s'il ne couvre plus le graphe de Neo4j (ré-extraction en --dry-run). */
  bundle: async (articleId: number) => {
    const res = await fetch(`/api/bundle?article_id=${articleId}`);
    if (!res.ok) throw new Error((await res.json().catch(() => null))?.error ?? `/api/bundle : HTTP ${res.status}`);
    return { blob: await res.blob(), matchesGraph: res.headers.get("X-Bundle-Matches-Graph") !== "0" };
  },
  /** Supprime l'article du graphe (et ce qu'aucun autre article n'étaye) ; `cti-extract` ne le reprendra plus. */
  deleteArticle: async (articleId: number) => {
    const res = await fetch(`/api/articles/${articleId}`, { method: "DELETE" });
    if (!res.ok) throw new Error((await res.json().catch(() => null))?.error ?? `/api/articles : HTTP ${res.status}`);
    return res.json() as Promise<{ nodes_deleted: number; edges_deleted: number }>;
  },
  actors: () => get<{ actors: ActorRow[] }>("/api/actors").then((r) => r.actors),
  actor: (id: string) => get<ActorProfile>(`/api/actors/${encodeURIComponent(id)}`),
};
