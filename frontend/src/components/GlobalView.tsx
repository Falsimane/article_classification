import clsx from "clsx";
import { ChevronDown, Search, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { glyphOf } from "../lib/icons";
import { aroundByRelation, histogram, visible, type KgFilters } from "../lib/kg";
import { FAMILY, STATE, captionOf, relationLabel } from "../lib/theme";
import { useAsync } from "../lib/useAsync";
import type { Family, KgNode } from "../types";
import { AskPanel } from "./AskPanel";
import { IocTable } from "./IocTable";
import { Inspector } from "./Inspector";
import { KgCanvas } from "./KgCanvas";
import { Timeline } from "./Timeline";

const Empty = ({ children }: { children: string }) => <div className="flex h-full items-center justify-center p-8 text-sm text-faint">{children}</div>;
const FAMILIES = Object.keys(FAMILY) as Family[];

/** Graphe global : toutes les entités de tous les articles, filtrables, et interrogeables par l'assistant. */
export function GlobalView() {
  const data = useAsync(api.kg, []);
  const [families, setFamilies] = useState(new Set<Family>(FAMILIES.filter((f) => f !== "detection")));
  const [minSources, setMinSources] = useState(1);
  const [minConfidence, setMinConfidence] = useState(0);
  const [period, setPeriod] = useState<[string, string] | null>(null);
  const [isolated, setIsolated] = useState<Set<string> | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [cited, setCited] = useState(new Set<string>());
  const [hovered, setHovered] = useState<string | null>(null);
  const [details, setDetails] = useState(false);
  const [iocs, setIocs] = useState(false);

  const kg = data.data?.graph;
  const byId = useMemo(() => new Map((kg?.nodes ?? []).map((n) => [n.id, n])), [kg]);
  const filters: KgFilters = { families, minSources, minConfidence, period, isolated };
  const shown = useMemo(() => (kg ? visible(kg, filters) : { nodes: new Set<string>(), edges: new Set<string>() }), [kg, families, minSources, minConfidence, period, isolated]); // eslint-disable-line react-hooks/exhaustive-deps
  const bins = useMemo(() => (kg ? histogram(kg) : []), [kg]);
  const counts = useMemo(() => {
    const out = new Map<Family, number>();
    for (const n of kg?.nodes ?? []) out.set(n.family, (out.get(n.family) ?? 0) + 1);
    return out;
  }, [kg]);
  const node = selected ? byId.get(selected) ?? null : null;
  useEffect(() => { if (!selected) { setDetails(false); setIocs(false); } }, [selected]);

  if (data.error) return <Empty>{data.error}</Empty>;
  if (!kg) return <Empty>Chargement du graphe…</Empty>;
  if (kg.nodes.length === 0) return <Empty>Le graphe est vide. Lancez : uv run cti-extract --limit 10</Empty>;

  const toggle = (f: Family) => setFamilies((s) => { const n = new Set(s); if (n.has(f)) n.delete(f); else n.add(f); return n; });
  const isolate = (ids: Iterable<string>) => setIsolated((cur) => new Set([...(cur ?? []), ...ids]));

  return (
    <div className="grid h-full grid-cols-[232px_minmax(0,1fr)_380px]">
      <aside className="flex min-h-0 flex-col gap-5 overflow-y-auto border-r border-line bg-panel py-4">
        <section className="px-4">
          <h2 className="mb-2 font-display text-sm font-semibold">Calques</h2>
          {FAMILIES.map((f) => (
            <label key={f} className={clsx("flex h-8 cursor-pointer items-center gap-2.5 text-sm", !counts.get(f) && "text-faint")}>
              <input type="checkbox" checked={families.has(f)} onChange={() => toggle(f)} className="accent-accent" />
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: FAMILY[f].color }} />
              <span className="flex-1">{FAMILY[f].label}</span>
              <span className="tabular-nums text-muted">{counts.get(f) ?? 0}</span>
            </label>
          ))}
        </section>
        <section className="space-y-4 border-t border-line px-4 pt-4">
          <h2 className="font-display text-sm font-semibold">Fiabilité</h2>
          <label className="block space-y-1 text-sm">
            <span className="flex justify-between"><span>Articles sources, au moins</span><span className="tabular-nums">{minSources}</span></span>
            <input type="range" min={1} max={10} value={minSources} onChange={(e) => setMinSources(+e.target.value)} className="w-full accent-accent" />
          </label>
          <label className="block space-y-1 text-sm">
            <span className="flex justify-between"><span>Confiance des relations, au moins</span><span className="tabular-nums">{minConfidence}</span></span>
            <input type="range" min={0} max={100} step={5} value={minConfidence} onChange={(e) => setMinConfidence(+e.target.value)} className="w-full accent-accent" />
          </label>
        </section>
        <section className="mt-auto space-y-2 border-t border-line px-4 pt-4 text-sm text-muted">
          <h2 className="font-display text-sm font-semibold text-ink">Légende des états</h2>
          <div className="flex items-center gap-2.5"><span className="h-3.5 w-3.5 rounded-full" style={{ boxShadow: `0 0 0 2px ${STATE.select}` }} />Votre sélection</div>
          <div className="flex items-center gap-2.5"><span className="h-3.5 w-3.5 rounded-full" style={{ boxShadow: `0 0 0 2px ${STATE.cited}` }} />Cité par l'assistant</div>
          <div className="flex items-center gap-2.5"><span className="mx-0.5 h-2.5 w-2.5 rotate-45 bg-warn" />Outil légitime détourné</div>
          <div className="flex items-center gap-2.5"><span className="h-3.5 w-3.5 rounded-[3px] border-2 border-[#e76a6e]" />Acteur (tuile carrée)</div>
          <div className="flex items-center gap-2.5"><span className="h-[3px] w-3.5 bg-[#4a5a6e]" />Trait épais : attribution, appartenance</div>
        </section>
      </aside>

      <section className="flex min-w-0 flex-col">
        <Toolbar nodes={kg.nodes} shown={shown} isolated={!!isolated} onPick={setSelected} onShowAll={() => setIsolated(null)} />
        <div className="relative min-h-0 flex-1 overflow-hidden">
          <KgCanvas kg={kg} revision={data.data!.revision} visibleNodes={shown.nodes} visibleEdges={shown.edges} selectedId={selected} cited={cited} hovered={hovered} onSelect={setSelected} />
          {node && (
            <SelectionCard
              node={node} around={aroundByRelation(kg.edges, node.id)} byId={byId} onClose={() => setSelected(null)} onDetails={() => setDetails(true)} onIocs={() => setIocs(true)}
              onIsolate={(ids) => isolate([node.id, ...ids])}
            />
          )}
          {node && iocs && <IocPanel node={node} onClose={() => setIocs(false)} />}
          {node && details && <DetailsDrawer id={node.id} onSelect={setSelected} onClose={() => setDetails(false)} />}
        </div>
        <Timeline bins={bins} period={period} onPeriod={setPeriod} />
      </section>

      <aside className="min-h-0 border-l border-line bg-panel">
        <AskPanel selected={node} onCited={setCited} onHover={setHovered} onPick={setSelected} onIsolate={(ids) => setIsolated(new Set(ids))} />
      </aside>
    </div>
  );
}

function Toolbar({ nodes, shown, isolated, onPick, onShowAll }: { nodes: KgNode[]; shown: { nodes: Set<string>; edges: Set<string> }; isolated: boolean; onPick: (id: string) => void; onShowAll: () => void }) {
  const [q, setQ] = useState("");
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); input.current?.focus(); } };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, []);
  const hits = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (s.length < 2) return [];
    return nodes.filter((n) => n.label.toLowerCase().includes(s) || n.aliases?.some((a) => a.toLowerCase().includes(s))).sort((a, b) => b.article_ids.length - a.article_ids.length).slice(0, 8);
  }, [q, nodes]);
  const pick = (id: string) => { onPick(id); setQ(""); input.current?.blur(); };
  return (
    <div className="relative flex items-center gap-3 border-b border-line bg-panel px-4 py-2">
      <label className="flex h-8 w-80 items-center gap-2 rounded border border-line bg-bg px-2.5 text-muted focus-within:border-accent">
        <Search size={15} />
        <input
          ref={input} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && hits[0]) pick(hits[0].id); if (e.key === "Escape") setQ(""); }}
          placeholder="Rechercher une entité ou un alias" aria-label="Rechercher une entité" className="min-w-0 flex-1 bg-transparent text-sm text-ink placeholder:text-faint focus:outline-none"
        />
        <kbd className="rounded-sm border border-line px-1 font-mono text-[11px]">Ctrl K</kbd>
      </label>
      {hits.length > 0 && (
        <ul className="absolute left-4 top-11 z-20 w-80 overflow-hidden rounded border border-line-strong bg-panel">
          {hits.map((n) => {
            const Icon = glyphOf(n);
            return (
              <li key={n.id}>
                <button onMouseDown={(e) => { e.preventDefault(); pick(n.id); }} className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm hover:bg-raised">
                  <Icon size={15} color={FAMILY[n.family].color} />
                  <span className="min-w-0 flex-1 truncate">{n.label}</span>
                  <span className="text-xs text-muted">{captionOf(n)}</span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <span className="text-sm text-muted">{shown.nodes.size} entités et {shown.edges.size} relations affichées</span>
      {isolated && <button onClick={onShowAll} className="ml-auto rounded border border-line px-2.5 py-1 text-xs hover:border-line-strong">Tout afficher</button>}
    </div>
  );
}

function SelectionCard({ node, around, byId, onClose, onDetails, onIocs, onIsolate }: {
  node: KgNode; around: [string, string[]][]; byId: Map<string, KgNode>; onClose: () => void; onDetails: () => void; onIocs: () => void; onIsolate: (ids: string[]) => void;
}) {
  const [menu, setMenu] = useState(false);
  useEffect(() => setMenu(false), [node.id]);
  const Icon = glyphOf(node);
  const relations = around.reduce((s, [, ids]) => s + ids.length, 0);
  return (
    <div className="absolute left-4 top-4 z-10 w-72 rounded border border-line-strong border-t-2 border-t-select bg-panel">
      <div className="flex items-start gap-2.5 px-3 pb-2 pt-2.5">
        <Icon size={20} color={FAMILY[node.family].color} className="mt-0.5 shrink-0" />
        <div className="min-w-0 flex-1">
          <div className="break-words font-display text-base font-semibold leading-5">{node.label}</div>
          <div className="text-xs text-muted">{captionOf(node)}. Cité par {node.article_ids.length} article{node.article_ids.length > 1 ? "s" : ""}, {relations} voisin{relations > 1 ? "s" : ""}.</div>
        </div>
        <button aria-label="Fermer la fiche" onClick={onClose} className="-mr-1 flex h-7 w-7 items-center justify-center text-muted hover:text-ink"><X size={14} /></button>
      </div>
      <div className="flex gap-1.5 px-3 pb-3">
        <button onClick={() => setMenu((m) => !m)} aria-expanded={menu} disabled={around.length === 0} className="flex h-8 flex-1 items-center justify-center gap-1.5 rounded border border-line-strong bg-raised text-sm disabled:opacity-40">
          Explorer autour <ChevronDown size={13} />
        </button>
        <button onClick={() => onIsolate(around.flatMap(([, ids]) => ids))} className="h-8 rounded border border-line-strong px-2.5 text-sm hover:bg-raised">Isoler</button>
        <button onClick={onDetails} className="h-8 rounded border border-line-strong px-2.5 text-sm hover:bg-raised">Détails</button>
      </div>
      {!!node.ioc_count && (
        <div className="px-3 pb-3">
          <button onClick={onIocs} className="h-8 w-full rounded border border-line-strong px-2.5 text-sm hover:bg-raised">Indicateurs (IOC) : {node.ioc_count}</button>
        </div>
      )}
      {menu && (
        <ul className="max-h-64 overflow-y-auto border-t border-line py-1">
          {around.map(([rel, ids]) => (
            <li key={rel}>
              <button onClick={() => { onIsolate(ids); setMenu(false); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-raised" title={ids.map((id) => byId.get(id)?.label ?? id).join(", ")}>
                <span className="flex-1">{relationLabel(rel)}</span><span className="tabular-nums text-muted">{ids.length}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Les IOC que désigne l'entité, en tableau : ils ne sont pas des nœuds du graphe (des centaines de feuilles le rendraient illisible). */
function IocPanel({ node, onClose }: { node: KgNode; onClose: () => void }) {
  const detail = useAsync(() => api.kgNode(node.id), [node.id]);
  return (
    <div className="absolute inset-4 z-20 flex flex-col border border-line-strong bg-panel">
      <div className="flex items-center justify-between border-b border-line px-6 py-2">
        <span className="font-display text-sm font-semibold">Indicateurs de {node.label}</span>
        <button aria-label="Fermer les indicateurs" onClick={onClose} className="flex h-7 w-7 items-center justify-center text-muted hover:text-ink"><X size={14} /></button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {detail.error ? <p className="p-4 text-sm text-danger">{detail.error}</p>
          : detail.data ? <IocTable rows={detail.data.iocs} empty="Aucun indicateur ne désigne cette entité." />
          : <p className="p-4 text-sm text-faint">Chargement…</p>}
      </div>
    </div>
  );
}

function DetailsDrawer({ id, onSelect, onClose }: { id: string; onSelect: (id: string) => void; onClose: () => void }) {
  const detail = useAsync(() => api.kgNode(id), [id]);
  return (
    <div className="absolute inset-y-0 right-0 z-10 flex w-[360px] flex-col border-l border-line-strong bg-panel">
      <div className="flex items-center justify-between border-b border-line px-4 py-2">
        <span className="font-display text-sm font-semibold">Détails et preuves</span>
        <button aria-label="Fermer les détails" onClick={onClose} className="flex h-7 w-7 items-center justify-center text-muted hover:text-ink"><X size={14} /></button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {detail.error ? <p className="p-4 text-sm text-danger">{detail.error}</p>
          : detail.data ? <Inspector node={detail.data.node} nodes={detail.data.nodes} edges={detail.data.edges} onSelect={onSelect} />
          : <p className="p-4 text-sm text-faint">Chargement…</p>}
      </div>
    </div>
  );
}
