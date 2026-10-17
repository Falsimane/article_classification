import { describe, expect, it } from "vitest";
import { buildOrg, orgPositions } from "./org";
import type { ActorProfile, GraphNode, OrgProfile, ProfileEntry } from "../types";

const node = (id: string, type: string): GraphNode => ({ id, label: id, type, family: "target", aliases: [], references: [], tactics: [], sectors: [], identity_class: null, is_family: null, labels: [], is_dual_use: false, article_ids: [1], degree: 1 });
const entry = (id: string, type: string): ProfileEntry => ({ node: node(id, type), relation: "uses", confidence: 80, evidence: [{ article: 1, quote: `preuve ${id}` }] });
const empty: OrgProfile = { origin: [], sponsors: [], parents: [], divisions: [], malware: [], tools: [], infrastructure: [], targets: [], vulnerabilities: [], techniques: {} };
const data = (p: Partial<OrgProfile>, iocs: ActorProfile["iocs"] = []): ActorProfile => ({ actor: node("APT29", "intrusion-set"), profile: { ...empty, ...p }, iocs, nodes: [], edges: [], reports: [] });

describe("organigramme", () => {
  it("n'invente pas d'origine : une case « non établie » est affichée", () => {
    const { boxes } = buildOrg(data({}));
    expect(boxes.filter((b) => b.level === 0).map((b) => b.title)).toEqual(["Origine non établie"]);
    expect(boxes.filter((b) => b.level === 3).every((b) => b.empty)).toBe(true);
  });
  it("place identité en haut, acteur, divisions, puis domaines", () => {
    const org = buildOrg(data({ origin: [entry("Russie", "location")], divisions: [entry("SolarStorm", "campaign")], malware: [entry("WellMess", "malware")] }));
    const level = (t: string) => org.boxes.find((b) => b.title.startsWith(t))!.level;
    expect([level("Russie"), level("APT29"), level("SolarStorm"), level("Arsenal")]).toEqual([0, 1, 2, 3]);
    expect(org.links).toContainEqual(["actor", "domain:arsenal"]);
    expect(org.links).toContainEqual(["top:Russie", "actor"]);
  });
  it("renvoie chaque domaine vers son onglet et résume les éléments", () => {
    const org = buildOrg(data({ tools: [entry("a", "tool"), entry("b", "tool"), entry("c", "tool"), entry("d", "tool")] }));
    const arsenal = org.boxes.find((b) => b.id === "domain:arsenal")!;
    expect(arsenal.tab).toBe("arsenal");
    expect(arsenal.lines).toEqual(["a", "b", "c", "+ 1 autres"]);
  });
  it("résume les indicateurs dans la case Infrastructure, et ne la déclare pas vide s'il y en a", () => {
    const ioc = (status: "active" | "stale") => ({ status }) as ActorProfile["iocs"][number];
    const box = buildOrg(data({}, [ioc("active"), ioc("stale"), ioc("stale")])).boxes.find((b) => b.id === "domain:infrastructure")!;
    expect(box.empty).toBe(false);
    expect(box.lines).toContain("3 indicateurs, 1 actifs");
  });
  it("centre chaque niveau et ne superpose pas deux cases", () => {
    const org = buildOrg(data({ divisions: [entry("x", "campaign"), entry("y", "campaign")] }));
    const pos = orgPositions(org.boxes);
    const xs = org.boxes.filter((b) => b.level === 3).map((b) => pos[b.id].x).sort((a, b) => a - b);
    for (let i = 1; i < xs.length; i++) expect(xs[i] - xs[i - 1]).toBeGreaterThanOrEqual(232);
    expect(pos.actor.x).toBe(-232 / 2);
  });
});
