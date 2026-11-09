import { describe, expect, it } from "vitest";
import { forceLayout } from "./layout";
import type { GraphEdge, GraphNode } from "../types";

const node = (id: string): GraphNode => ({ id, label: id, type: "malware", family: "malware", aliases: [], references: [], tactics: [], sectors: [], identity_class: null, is_family: null, labels: [], is_dual_use: false, kinds: [], country: null, article_ids: [1], degree: 1 });
const edge = (s: string, t: string): GraphEdge => ({ id: `${s}-${t}`, source: s, target: t, type: "uses", confidence: 80, tactic: "", evidence: [], article_ids: [1] });
const nodes = ["a", "b", "c", "d"].map(node);
const edges = [edge("a", "b"), edge("a", "c"), edge("c", "d")];

describe("layout", () => {
  it("est déterministe", () => {
    expect(forceLayout(nodes, edges)).toEqual(forceLayout([...nodes].reverse(), edges));
  });
  it("ne superpose pas deux nœuds", () => {
    const pos = Object.values(forceLayout(nodes, edges));
    for (let i = 0; i < pos.length; i++)
      for (let j = i + 1; j < pos.length; j++) expect(Math.hypot(pos[i].x - pos[j].x, pos[i].y - pos[j].y)).toBeGreaterThan(80);
  });
  it("ignore les arêtes vers des nœuds filtrés", () => {
    expect(() => forceLayout(nodes, [...edges, edge("a", "absent")])).not.toThrow();
  });
});
