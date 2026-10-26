import type { RuleKind, RuleRow } from "../types";

export const RULE_KIND_LABEL: Record<RuleKind, string> = { yara: "YARA", sigma: "Sigma" };

export interface RuleFilter { kind: RuleKind | "all"; search: string }

/** Filtre par langage et recherche dans le nom, la description, l'entité détectée et le texte de la règle. */
export function filterRules(rows: RuleRow[], { kind, search }: RuleFilter): RuleRow[] {
  const q = search.trim().toLowerCase();
  return rows.filter((r) => {
    if (kind !== "all" && r.kind !== kind) return false;
    return !q || [r.name, r.description ?? "", r.source, ...r.detects.map((t) => t.name)].some((s) => s.toLowerCase().includes(q));
  });
}

/** Texte à copier : les règles telles quelles, séparées par une ligne vide (un fichier .yar ou un flux YAML multi-document). */
export function joinSources(rows: RuleRow[]): string {
  const sep = rows.every((r) => r.kind === "sigma") ? "---\n" : "\n";
  return rows.map((r) => r.source.trimEnd() + "\n").join(sep);
}
