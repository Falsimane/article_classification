import type { ReactNode } from "react";
import { iconOf } from "../lib/icons";
import { FAMILY, relationLabel, typeLabel } from "../lib/theme";
import type { GraphEdge, GraphNode } from "../types";

const Section = ({ title, children }: { title: string; children: ReactNode }) => (
  <section className="border-b border-line px-4 py-3">
    <h3 className="mb-2 text-xs font-semibold text-muted">{title}</h3>
    {children}
  </section>
);

export function Inspector({ node, nodes, edges, onSelect }: { node: GraphNode | null; nodes: GraphNode[]; edges: GraphEdge[]; onSelect: (id: string) => void }) {
  if (!node) return <p className="p-4 text-sm text-faint">Sélectionnez un nœud pour afficher ses attributs, ses relations et leurs preuves.</p>;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const related = edges.filter((e) => e.source === node.id || e.target === node.id);
  return (
    <div className="overflow-y-auto">
      <header className="border-b border-line px-4 py-3">
        <div className="mb-1 flex items-center gap-2 text-xs font-semibold text-muted">
          {(() => { const Icon = iconOf(node.type); return <Icon size={14} color={FAMILY[node.family].color} strokeWidth={1.75} />; })()}
          {typeLabel(node.type)}
        </div>
        <h2 className="break-words text-lg font-semibold leading-6">{node.label}</h2>
      </header>

      <Section title="Attributs">
        <dl className="grid grid-cols-[96px_1fr] gap-y-1 text-sm">
          {node.aliases.length > 0 && (<><dt className="text-faint">Alias</dt><dd>{node.aliases.join(", ")}</dd></>)}
          {node.references.length > 0 && (<><dt className="text-faint">Références</dt><dd className="font-mono">{node.references.map((r) => r.id).join(", ")}</dd></>)}
          {node.tactics.length > 0 && (<><dt className="text-faint">Tactiques</dt><dd>{node.tactics.join(", ")}</dd></>)}
          {node.sectors.length > 0 && (<><dt className="text-faint">Secteurs</dt><dd>{node.sectors.join(", ")}</dd></>)}
          {node.identity_class && (<><dt className="text-faint">Classe</dt><dd>{node.identity_class}</dd></>)}
          {node.is_dual_use && (<><dt className="text-faint">Usage</dt><dd className="text-warn">Outil légitime détourné</dd></>)}
          <dt className="text-faint">Articles</dt><dd className="font-mono">{node.article_ids.join(", ") || "—"}</dd>
        </dl>
      </Section>

      <Section title={`Relations (${related.length})`}>
        {related.length === 0 && <p className="text-sm text-faint">Aucune relation.</p>}
        <ul className="space-y-3">
          {related.map((e) => {
            const outgoing = e.source === node.id;
            const other = byId.get(outgoing ? e.target : e.source);
            return (
              <li key={e.id} className="text-sm">
                <div className="flex flex-wrap items-baseline gap-x-1.5">
                  <span className="font-mono text-xs text-faint">{outgoing ? "→" : "←"} {relationLabel(e.type)}</span>
                  {other && <button className="text-left font-medium text-accent hover:underline" onClick={() => onSelect(other.id)}>{other.label}</button>}
                  {e.confidence != null && <span className="ml-auto font-mono text-xs text-faint">{e.confidence}</span>}
                </div>
                {e.tactic && <div className="text-xs text-faint">{e.tactic}</div>}
                {e.evidence[0]?.procedure && <div className="mt-1 text-xs text-ink">{e.evidence[0].procedure}</div>}
                {e.evidence.map((ev, i) => (
                  <blockquote key={i} className="mt-1 border-l-2 border-line-strong pl-2 text-xs italic text-muted">{ev.quote}</blockquote>
                ))}
              </li>
            );
          })}
        </ul>
      </Section>
    </div>
  );
}
