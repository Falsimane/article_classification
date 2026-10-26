import type { IocRow, IocStatus } from "../types";

export const ROLE_LABEL: Record<string, string> = {
  c2: "Commande et contrôle",
  "payload-delivery": "Distribution de la charge",
  exfiltration: "Exfiltration",
  phishing: "Hameçonnage",
  "staging-or-proxy": "Relais / intermédiaire",
  "malware-sample": "Échantillon de malware",
  "other-malicious": "Malveillant (rôle non précisé)",
  unknown: "Rôle inconnu",
};

export const KIND_LABEL: Record<string, string> = {
  "ipv4-addr": "IPv4", "ipv6-addr": "IPv6", "domain-name": "Domaine", url: "URL", "email-addr": "Courriel", file: "Fichier",
};

export const STATUS: Record<IocStatus, { label: string; hint: string }> = {
  active: { label: "Actif probable", hint: "Observé récemment par rapport à la durée de vie habituelle de ce type d'indicateur" },
  aging: { label: "Vieillissant", hint: "Dernière observation ancienne pour ce type d'indicateur" },
  stale: { label: "Périmé", hint: "Dernière observation très ancienne pour ce type d'indicateur" },
  unknown: { label: "Date inconnue", hint: "Aucune observation datée : l'ancienneté ne peut pas être évaluée" },
};

export const STATUS_ORDER: IocStatus[] = ["active", "aging", "stale", "unknown"];

export interface IocFilter { activeOnly: boolean; search: string }

/** Filtre « actifs seulement » (un statut inconnu n'est PAS actif) et recherche par valeur, rôle ou entité rattachée. */
export function filterIocs(rows: IocRow[], { activeOnly, search }: IocFilter): IocRow[] {
  const q = search.trim().toLowerCase();
  return rows.filter((r) => {
    if (activeOnly && r.status !== "active") return false;
    const values = [r.value, r.name ?? "", ...Object.values(r.hashes ?? {})].map((v) => v.toLowerCase());
    return !q || values.some((v) => v.includes(q)) || r.role.includes(q) || r.attached_to.some((t) => t.name.toLowerCase().includes(q));
  });
}

export function countByStatus(rows: IocRow[]): Record<IocStatus, number> {
  const counts: Record<IocStatus, number> = { active: 0, aging: 0, stale: 0, unknown: 0 };
  for (const r of rows) counts[r.status]++;
  return counts;
}
