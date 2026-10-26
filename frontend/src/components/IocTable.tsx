import clsx from "clsx";
import { Copy } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { KIND_LABEL, ROLE_LABEL, STATUS, countByStatus, filterIocs } from "../lib/ioc";
import type { IocRow, IocStatus } from "../types";

const STATUS_STYLE: Record<IocStatus, string> = {
  active: "border-ok text-ok",
  aging: "border-warn text-warn",
  stale: "border-line-strong text-faint",
  unknown: "border-line-strong text-faint border-dashed",
};

const copy = (text: string) => navigator.clipboard?.writeText(text).catch(() => undefined);

export function IocTable({ rows, empty = "Aucun indicateur." }: { rows: IocRow[]; empty?: string }) {
  const [activeOnly, setActiveOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const shown = useMemo(() => filterIocs(rows, { activeOnly, search }), [rows, activeOnly, search]);
  const counts = useMemo(() => countByStatus(rows), [rows]);
  if (rows.length === 0) return <p className="px-6 py-8 text-sm text-faint">{empty}</p>;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-6 py-2">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={activeOnly} onChange={(e) => setActiveOnly(e.target.checked)} className="accent-accent" />
          Actifs seulement <span className="font-mono text-xs text-faint">{counts.active}</span>
        </label>
        <span className="font-mono text-xs text-faint">
          {counts.aging} vieillissants · {counts.stale} périmés · {counts.unknown} sans date
        </span>
        <input
          value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Valeur, rôle ou entité"
          className="ml-auto w-56 border border-line bg-bg px-2 py-1 text-sm placeholder:text-faint focus:border-accent focus:outline-none"
        />
        <button className="flex items-center gap-1.5 border border-line px-2 py-1 text-xs text-muted hover:border-line-strong hover:text-ink" onClick={() => copy(shown.map((r) => r.value).join("\n"))} title="Copier les valeurs affichées, une par ligne">
          <Copy size={12} /> Copier ({shown.length})
        </button>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line text-left font-mono text-[10px] uppercase tracking-widest text-faint">
            {["Valeur", "Type", "Rôle", "Rattaché à", "Première obs.", "Dernière obs.", "Sources", "Statut"].map((h) => (<th key={h} className="px-3 py-2 font-normal first:pl-6">{h}</th>))}
          </tr>
        </thead>
        <tbody>
          {shown.map((r) => (
            <Fragment key={r.id}>
              <tr onClick={() => setOpen(open === r.id ? null : r.id)} className="cursor-pointer border-b border-line hover:bg-raised/50">
                <td className="max-w-[320px] break-all px-3 py-2 pl-6 font-mono text-xs">
                  {r.name && <div className="font-sans text-sm text-ink">{r.name}</div>}
                  {r.value}
                  <button className="ml-2 align-middle text-faint hover:text-ink" title="Copier" onClick={(e) => { e.stopPropagation(); copy(r.value); }}><Copy size={11} /></button>
                </td>
                <td className="px-3 py-2 text-muted">{KIND_LABEL[r.kind] ?? r.kind}{r.algo && <span className="ml-1 font-mono text-[10px] text-faint">{r.algo}</span>}</td>
                <td className="px-3 py-2">{ROLE_LABEL[r.role] ?? r.role}</td>
                <td className="px-3 py-2 text-muted">{r.attached_to.map((t) => t.name).join(", ") || "—"}</td>
                <td className="px-3 py-2 font-mono text-xs text-muted">{r.first_seen ?? "—"}</td>
                <td className="px-3 py-2 font-mono text-xs text-muted">{r.last_seen ?? "—"}</td>
                <td className="px-3 py-2 font-mono text-xs text-muted" title={`Articles : ${r.article_ids.join(", ")}`}>{r.sources}</td>
                <td className="px-3 py-2"><span title={STATUS[r.status].hint} className={clsx("border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide", STATUS_STYLE[r.status])}>{STATUS[r.status].label}</span></td>
              </tr>
              {open === r.id && (
                <tr className="border-b border-line bg-panel">
                  <td colSpan={8} className="px-6 py-3">
                    {Object.keys(r.hashes ?? {}).length > 1 && (
                      <dl className="mb-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-xs">
                        {Object.entries(r.hashes ?? {}).map(([algo, digest]) => (
                          <Fragment key={algo}><dt className="text-faint">{algo}</dt><dd className="break-all">{digest}<button className="ml-2 align-middle text-faint hover:text-ink" title="Copier" onClick={() => copy(digest)}><Copy size={11} /></button></dd></Fragment>
                        ))}
                      </dl>
                    )}
                    {r.evidence.length === 0 && <p className="text-xs text-faint">Aucune phrase de preuve.</p>}
                    {r.evidence.map((ev, i) => (
                      <blockquote key={i} className="mb-1.5 border-l-2 border-line-strong pl-3 text-xs italic text-muted">
                        {ev.quote}{ev.article != null && <span className="ml-2 not-italic text-faint">art. {ev.article}</span>}
                      </blockquote>
                    ))}
                    {r.confidence != null && <p className="mt-1 font-mono text-[10px] uppercase tracking-wide text-faint">confiance {r.confidence}</p>}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
      {shown.length === 0 && <p className="px-6 py-6 text-sm text-faint">Aucun indicateur ne correspond à ce filtre.</p>}
      <p className="px-6 py-3 text-xs text-faint">
        Le statut est calculé à l'affichage depuis la dernière observation et une durée de vie par type d'indicateur (valeurs indicatives, non calibrées). Il
        ne prouve pas qu'un indicateur est encore actif.
      </p>
    </div>
  );
}
