import clsx from "clsx";
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import type { ArticleSummary, Family } from "../types";
import { FamilyFilter } from "./FamilyFilter";
import { GraphCanvas } from "./GraphCanvas";
import { Inspector } from "./Inspector";

const Empty = ({ children }: { children: string }) => <div className="flex h-full items-center justify-center p-8 text-sm text-faint">{children}</div>;

export function ReportsView({ articles }: { articles: ArticleSummary[] }) {
  const [articleId, setArticleId] = useState<number | null>(articles[0]?.id ?? null);
  const [family, setFamily] = useState<Family | "all">("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => { setSelected(null); }, [articleId]);
  const graph = useAsync(() => (articleId == null ? Promise.resolve(null) : api.graph(articleId, { type: family === "all" ? undefined : family, search: search || undefined })), [articleId, family, search]);
  const current = graph.data;
  const node = useMemo(() => current?.nodes.find((n) => n.id === selected) ?? null, [current, selected]);

  if (articles.length === 0) return <Empty>Aucun article extrait. Lancez : uv run cti-extractor --limit 10</Empty>;
  return (
    <div className="grid h-full grid-cols-[300px_1fr_360px]">
      <aside className="overflow-y-auto border-r border-line bg-panel">
        <h2 className="border-b border-line px-4 py-2 font-mono text-[10px] uppercase tracking-widest text-faint">Rapports ({articles.length})</h2>
        <ul>
          {articles.map((a) => (
            <li key={a.id}>
              <button onClick={() => setArticleId(a.id)} className={clsx("block w-full border-b border-line px-4 py-2.5 text-left", a.id === articleId ? "bg-raised" : "hover:bg-raised/50")}>
                <div className="line-clamp-2 text-sm leading-5">{a.title}</div>
                <div className="mt-1 flex gap-3 font-mono text-[10px] uppercase tracking-wide text-faint">
                  <span>{a.site_name ?? "—"}</span><span>{a.publication_date ?? ""}</span>
                  <span className="ml-auto">{a.entities_count} ent · {a.relations_count} rel</span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      </aside>

      <section className="flex min-w-0 flex-col">
        <div className="flex flex-wrap items-center gap-3 border-b border-line bg-panel px-4 py-2">
          <FamilyFilter value={family} onChange={setFamily} />
          <input
            value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Rechercher une entité ou un alias"
            className="ml-auto w-64 border border-line bg-bg px-2 py-1 text-sm placeholder:text-faint focus:border-accent focus:outline-none"
          />
        </div>
        <div className="relative min-h-0 flex-1">
          {graph.error && <Empty>{graph.error}</Empty>}
          {current && current.nodes.length === 0 && !graph.error && <Empty>Aucune entité ne correspond à ces filtres.</Empty>}
          {current && current.nodes.length > 0 && <GraphCanvas nodes={current.nodes} edges={current.edges} selectedId={selected} onSelect={setSelected} />}
          {current?.article && (
            <a href={current.article.url} target="_blank" rel="noreferrer noopener" className="absolute left-3 top-3 max-w-[60%] truncate border border-line bg-panel px-2 py-1 text-xs text-muted hover:text-ink">
              {current.article.site_name} · {current.article.title}
            </a>
          )}
        </div>
      </section>

      <aside className="min-h-0 overflow-hidden border-l border-line bg-panel">
        <Inspector node={node} nodes={current?.nodes ?? []} edges={current?.edges ?? []} onSelect={setSelected} />
      </aside>
    </div>
  );
}
