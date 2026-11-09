import { iconOf } from "../lib/icons";
import { FAMILY, relationLabel } from "../lib/theme";
import type { ProfileEntry } from "../types";

export function EntryTable({ entries, empty }: { entries: ProfileEntry[]; empty: string }) {
  if (entries.length === 0) return <p className="px-6 py-8 text-sm text-faint">{empty}</p>;
  return (
    <ul>
      {entries.map((e) => {
        const Icon = iconOf(e.node.type);
        return (
          <li key={e.node.id} className="border-b border-line px-6 py-3">
            <div className="flex items-center gap-3">
              <Icon size={16} color={FAMILY[e.node.family].color} strokeWidth={1.75} className="shrink-0" />
              <span className="text-sm font-medium">{e.node.label}</span>
              {e.node.references.length > 0 && <span className="font-mono text-xs text-faint">{e.node.references.map((r) => r.id).join(" ")}</span>}
              {e.node.is_dual_use && <span className="border border-warn px-1 text-xs text-warn">double usage</span>}
              <span className="ml-auto font-mono text-xs text-faint">{relationLabel(e.relation)}{e.confidence != null && ` · ${e.confidence}`}</span>
            </div>
            {[...new Set(e.evidence.map((ev) => ev.procedure).filter(Boolean))].map((p) => (
              <div key={p} className="ml-7 mt-1.5 text-xs text-ink">{p}</div>
            ))}
            {e.evidence.map((ev, i) => (
              <blockquote key={i} className="ml-7 mt-1.5 border-l-2 border-line-strong pl-3 text-xs italic text-muted">
                {ev.quote}{ev.article != null && <span className="ml-2 not-italic text-faint">art. {ev.article}</span>}
              </blockquote>
            ))}
          </li>
        );
      })}
    </ul>
  );
}
