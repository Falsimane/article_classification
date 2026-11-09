import clsx from "clsx";
import type { ReactNode } from "react";
import type { Stats } from "../types";

export type View = "reports" | "actors" | "graph";
const NAV: { id: View; label: string }[] = [
  { id: "reports", label: "Rapports" },
  { id: "actors", label: "Acteurs" },
  { id: "graph", label: "Graphe global" },
];

export function Shell({ view, onView, stats, children }: { view: View; onView: (v: View) => void; stats: Stats | null; children: ReactNode }) {
  return (
    <div className="flex h-full flex-col">
      <header className="flex h-11 shrink-0 items-center gap-6 border-b border-line bg-panel px-4">
        <div className="font-display text-[15px] font-semibold">CTI Knowledge Graph</div>
        <nav className="flex h-full">
          {NAV.map((n) => (
            <button
              key={n.id} onClick={() => onView(n.id)}
              className={clsx("h-full border-b-2 px-4 text-sm", view === n.id ? "border-accent font-medium text-ink" : "border-transparent text-muted hover:text-ink")} aria-current={view === n.id ? "page" : undefined}
            >{n.label}</button>
          ))}
        </nav>
        {stats && (
          <dl className="ml-auto flex gap-5 text-sm text-muted">
            {([["Articles", stats.articles_count], ["Entités", stats.entities_count], ["Relations", stats.relations_count], ["IOC", stats.iocs_count]] as const).map(([k, v]) => (
              <div key={k} className="flex gap-1.5"><dt>{k}</dt><dd className="tabular-nums text-ink">{v}</dd></div>
            ))}
          </dl>
        )}
      </header>
      <main className="min-h-0 flex-1">{children}</main>
    </div>
  );
}
