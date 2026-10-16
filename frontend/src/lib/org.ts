import type { ActorProfile, OrgProfile, ProfileEntry } from "../types";

export type Tab = "org" | "arsenal" | "techniques" | "infrastructure" | "targets" | "references";

export interface OrgBox {
  id: string;
  level: 0 | 1 | 2 | 3;
  title: string;
  caption: string;
  type: string;
  lines: string[];
  tab?: Tab;
  empty?: boolean;
}
export interface OrgChartData { boxes: OrgBox[]; links: [string, string][] }

export const BOX_W = 232;
export const BOX_H = 92;
const GAP_X = 36;
const GAP_Y = 76;

const names = (entries: ProfileEntry[]) => entries.map((e) => e.node.label);
const preview = (items: string[], max = 3) => (items.length === 0 ? ["Aucun élément connu"] : [...items.slice(0, max), ...(items.length > max ? [`+ ${items.length - max} autres`] : [])]);
export const techniqueCount = (p: OrgProfile) => Object.values(p.techniques).reduce((n, l) => n + l.length, 0);

/** Organigramme d'un acteur : identité et pays en haut, l'acteur, ses divisions, puis une case par domaine (renvoie à un onglet). */
export function buildOrg(data: ActorProfile): OrgChartData {
  const { actor, profile: p } = data;
  const boxes: OrgBox[] = [];
  const links: [string, string][] = [];
  const top = [
    ...p.sponsors.map((e) => ({ e, caption: "Sponsor / organisation" })),
    ...p.origin.map((e) => ({ e, caption: "Pays d'origine" })),
    ...p.parents.map((e) => ({ e, caption: "Rattaché à" })),
  ];
  if (top.length === 0) boxes.push({ id: "origin:none", level: 0, title: "Origine non établie", caption: "Pays / sponsor", type: "location", lines: ["Aucun article ne l'atteste"], empty: true });
  for (const { e, caption } of top) boxes.push({ id: `top:${e.node.id}`, level: 0, title: e.node.label, caption, type: e.node.type, lines: e.evidence.slice(0, 1).map((x) => x.quote) });
  boxes.forEach((b) => links.push([b.id, "actor"]));

  boxes.push({ id: "actor", level: 1, title: actor.label, caption: actor.aliases.length ? `Alias : ${actor.aliases.join(", ")}` : "Acteur", type: actor.type, lines: [] });
  for (const e of p.divisions) {
    boxes.push({ id: `div:${e.node.id}`, level: 2, title: e.node.label, caption: "Division / campagne", type: e.node.type, lines: [] });
    links.push(["actor", `div:${e.node.id}`]);
  }
  const domains: [string, string, string, string[], Tab][] = [
    ["arsenal", "Arsenal", "malware", [...names(p.malware), ...names(p.tools)], "arsenal"],
    ["techniques", "Techniques ATT&CK", "attack-pattern", Object.values(p.techniques).flat().map((e) => e.node.label), "techniques"],
    ["infrastructure", "Infrastructure", "infrastructure", names(p.infrastructure), "infrastructure"],
    ["targets", "Cibles", "identity", [...names(p.targets), ...names(p.vulnerabilities)], "targets"],
  ];
  for (const [id, title, type, items, tab] of domains) {
    boxes.push({ id: `domain:${id}`, level: 3, title: `${title} (${items.length})`, caption: "", type, lines: preview(items), tab, empty: items.length === 0 });
    links.push(["actor", `domain:${id}`]);
  }
  return { boxes, links };
}

/** Positions (coin haut-gauche) : chaque niveau est centré horizontalement. Déterministe, sans simulation. */
export function orgPositions(boxes: OrgBox[]): Record<string, { x: number; y: number }> {
  const rows = new Map<number, OrgBox[]>();
  for (const b of boxes) rows.set(b.level, [...(rows.get(b.level) ?? []), b]);
  const out: Record<string, { x: number; y: number }> = {};
  for (const [level, row] of rows) {
    const width = row.length * BOX_W + (row.length - 1) * GAP_X;
    row.forEach((b, i) => { out[b.id] = { x: -width / 2 + i * (BOX_W + GAP_X), y: level * (BOX_H + GAP_Y) }; });
  }
  return out;
}
