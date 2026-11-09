import type { Family, KgEdge, KnowledgeGraph } from "../types";

/** Filtres du graphe global. `period` : mois inclus (« 2025-03 »), `isolated` : ensemble de travail (« Isoler »). */
export interface KgFilters {
  families: Set<Family>;
  minSources: number;
  minConfidence: number;
  period: [string, string] | null;
  isolated: Set<string> | null;
}

export const monthOf = (date: string | null | undefined) => (date && /^\d{4}-\d{2}/.test(date) ? date.slice(0, 7) : null);

/** Nœuds et arêtes visibles. Avec une période, seuls comptent les articles publiés dans la période : un nœud ou une arête
 * qu'aucun d'eux n'étaye disparaît, et le seuil de sources se compte sur eux. */
export function visible(kg: KnowledgeGraph, f: KgFilters): { nodes: Set<string>; edges: Set<string> } {
  let inPeriod: ((ids: number[]) => number[]) | null = null;
  if (f.period) {
    const [from, to] = f.period;
    const kept = new Set(kg.articles.filter((a) => { const m = monthOf(a.published); return m != null && m >= from && m <= to; }).map((a) => a.id));
    inPeriod = (ids) => ids.filter((id) => kept.has(id));
  }
  const sources = (ids: number[]) => (inPeriod ? inPeriod(ids) : ids).length;
  const nodes = new Set(
    kg.nodes
      .filter((n) => f.families.has(n.family) && sources(n.article_ids) >= Math.max(f.minSources, inPeriod ? 1 : 0) && (!f.isolated || f.isolated.has(n.id)))
      .map((n) => n.id),
  );
  const edges = new Set(
    kg.edges
      .filter((e) => nodes.has(e.source) && nodes.has(e.target) && (e.confidence == null || e.confidence >= f.minConfidence) && (!inPeriod || sources(e.article_ids) > 0))
      .map((e) => e.id),
  );
  return { nodes, edges };
}

/** Voisins d'un nœud par type de relation (« Explorer autour »), relations les plus fournies d'abord. */
export function aroundByRelation(edges: KgEdge[], id: string): [string, string[]][] {
  const out = new Map<string, Set<string>>();
  for (const e of edges) {
    const other = e.source === id ? e.target : e.target === id ? e.source : null;
    if (other == null || other === id) continue;
    if (!out.has(e.type)) out.set(e.type, new Set());
    out.get(e.type)!.add(other);
  }
  return [...out.entries()].map(([k, v]): [string, string[]] => [k, [...v]]).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
}

/** Nombre d'articles publiés par mois, du premier au dernier mois connus, mois vides compris. */
export function histogram(kg: KnowledgeGraph): { month: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const a of kg.articles) { const m = monthOf(a.published); if (m) counts.set(m, (counts.get(m) ?? 0) + 1); }
  if (counts.size === 0) return [];
  const keys = [...counts.keys()].sort();
  const out: { month: string; count: number }[] = [];
  let [y, m] = keys[0].split("-").map(Number);
  const last = keys[keys.length - 1];
  for (;;) {
    const key = `${y}-${String(m).padStart(2, "0")}`;
    out.push({ month: key, count: counts.get(key) ?? 0 });
    if (key >= last) break;
    if (++m > 12) { m = 1; y++; }
  }
  return out;
}

/** Texte d'une réponse de l'assistant découpé en morceaux de texte et en citations `[[E3]]`. */
export function splitCitations(text: string): ({ text: string } | { handle: string })[] {
  return text.split(/(\[\[E\d+\]\])/).filter(Boolean).map((part) => { const m = /^\[\[(E\d+)\]\]$/.exec(part); return m ? { handle: m[1] } : { text: part }; });
}
