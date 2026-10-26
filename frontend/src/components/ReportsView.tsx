import clsx from "clsx";
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import type { ArticleSummary, Family } from "../types";
import { FamilyFilter } from "./FamilyFilter";
import { GraphCanvas } from "./GraphCanvas";
import { IocTable } from "./IocTable";
import { Inspector } from "./Inspector";
import { RuleTable } from "./RuleTable";

const Empty = ({ children }: { children: string }) => <div className="flex h-full items-center justify-center p-8 text-sm text-faint">{children}</div>;

export function ReportsView({ articles }: { articles: ArticleSummary[] }) {
  const [articleId, setArticleId] = useState<number | null>(articles[0]?.id ?? null);
  const [family, setFamily] = useState<Family | "all">("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [panel, setPanel] = useState<"graph" | "iocs" | "rules">("graph");

  useEffect(() => { setSelected(null); }, [articleId]);
  const graph = useAsync(() => (articleId == null ? Promise.resolve(null) : api.graph(articleId, { type: family === "all" ? undefined : family, search: search || undefined })), [articleId, family, search]);
  const iocs = useAsync(() => (articleId == null ? Promise.resolve([]) : api.iocs(articleId)), [articleId]);
  const rules = useAsync(() => (articleId == null ? Promise.resolve([]) : api.rules(articleId)), [articleId]);
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
        <nav className="flex border-b border-line bg-panel px-3">
          {([["graph", "Graphe"], ["iocs", "Indicateurs"], ["rules", "Détection"]] as const).map(([id, label]) => (
            <button key={id} onClick={() => setPanel(id)} className={clsx("border-b-2 px-4 py-2 text-sm", panel === id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink")}>
              {label}
              {id !== "graph" && <span className="ml-1.5 font-mono text-xs text-faint">{(id === "iocs" ? iocs : rules).data?.length ?? 0}</span>}
            </button>
          ))}
        </nav>
        {panel === "rules" ? (
          <div className="min-h-0 flex-1 overflow-y-auto">
            {rules.error ? <Empty>{rules.error}</Empty> : <RuleTable rows={rules.data ?? []} empty="Aucune règle YARA ou Sigma valide dans cet article." />}
          </div>
        ) : panel === "iocs" ? (
          <div className="min-h-0 flex-1 overflow-y-auto">
            {iocs.error ? <Empty>{iocs.error}</Empty> : <IocTable rows={iocs.data ?? []} empty="Aucun indicateur malveillant retenu dans cet article." />}
          </div>
        ) : (<>
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
        </>)}
      </section>

      <aside className="min-h-0 overflow-hidden border-l border-line bg-panel">
        <Inspector node={node} nodes={current?.nodes ?? []} edges={current?.edges ?? []} onSelect={setSelected} />
      </aside>
    </div>
  );
}
