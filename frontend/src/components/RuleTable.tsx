import clsx from "clsx";
import { Copy } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { RULE_KIND_LABEL, filterRules, joinSources } from "../lib/rules";
import type { RuleKind, RuleRow } from "../types";

const copy = (text: string) => navigator.clipboard?.writeText(text).catch(() => undefined);

export function RuleTable({ rows, empty = "Aucune règle de détection." }: { rows: RuleRow[]; empty?: string }) {
  const [kind, setKind] = useState<RuleKind | "all">("all");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const shown = useMemo(() => filterRules(rows, { kind, search }), [rows, kind, search]);
  if (rows.length === 0) return <p className="px-6 py-8 text-sm text-faint">{empty}</p>;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-6 py-2">
        <div className="flex">
          {(["all", "yara", "sigma"] as const).map((k) => (
            <button key={k} onClick={() => setKind(k)} className={clsx("border px-2 py-0.5 text-xs [&:not(:first-child)]:-ml-px", kind === k ? "border-accent text-ink" : "border-line text-muted hover:text-ink")}>
              {k === "all" ? "Toutes" : RULE_KIND_LABEL[k]}
              <span className="ml-1.5 font-mono text-faint">{k === "all" ? rows.length : rows.filter((r) => r.kind === k).length}</span>
            </button>
          ))}
        </div>
        <input
          value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Nom, entité ou contenu"
          className="ml-auto w-56 border border-line bg-bg px-2 py-1 text-sm placeholder:text-faint focus:border-accent focus:outline-none"
        />
        <button className="flex items-center gap-1.5 border border-line px-2 py-1 text-xs text-muted hover:border-line-strong hover:text-ink" onClick={() => copy(joinSources(shown))} title="Copier le texte des règles affichées">
          <Copy size={12} /> Copier ({shown.length})
        </button>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line text-left font-mono text-[10px] uppercase tracking-widest text-faint">
            {["Règle", "Langage", "Détecte", "Confiance"].map((h) => (<th key={h} className="px-3 py-2 font-normal first:pl-6">{h}</th>))}
          </tr>
        </thead>
        <tbody>
          {shown.map((r) => (
            <Fragment key={r.id}>
              <tr onClick={() => setOpen(open === r.id ? null : r.id)} className="cursor-pointer border-b border-line hover:bg-raised/50">
                <td className="max-w-[420px] px-3 py-2 pl-6">
                  <div className="break-all font-mono text-xs">{r.name}</div>
                  {r.description && <div className="mt-0.5 line-clamp-1 text-xs text-muted">{r.description}</div>}
                </td>
                <td className="px-3 py-2"><span className="border border-line-strong px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-muted">{RULE_KIND_LABEL[r.kind] ?? r.kind}</span></td>
                <td className="px-3 py-2 text-muted">{r.detects.map((t) => t.name).join(", ") || "—"}</td>
                <td className="px-3 py-2 font-mono text-xs text-muted">{r.confidence ?? "—"}</td>
              </tr>
              {open === r.id && (
                <tr className="border-b border-line bg-panel">
                  <td colSpan={4} className="px-6 py-3">
                    {r.description && <p className="mb-2 text-xs text-muted">{r.description}</p>}
                    <div className="relative">
                      <button className="absolute right-2 top-2 flex items-center gap-1 border border-line bg-panel px-1.5 py-0.5 text-[10px] text-muted hover:text-ink" onClick={() => copy(r.source)} title="Copier la règle">
                        <Copy size={11} /> Copier
                      </button>
                      <pre className="max-h-[480px] overflow-auto border border-line bg-bg p-3 font-mono text-xs leading-5">{r.source}</pre>
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
      {shown.length === 0 && <p className="px-6 py-6 text-sm text-faint">Aucune règle ne correspond à ce filtre.</p>}
      <p className="px-6 py-3 text-xs text-faint">
        Texte exact de l'article, retenu seulement s'il est valide (compilé par libyara pour YARA, YAML avec title, logsource et detection.condition pour Sigma) ;
        jamais réparé ni réécrit. Le modèle choisit seulement l'entité détectée, parmi celles que nomment la règle ou sa section.
      </p>
    </div>
  );
}
