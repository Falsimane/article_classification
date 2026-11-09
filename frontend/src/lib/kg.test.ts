import { describe, expect, it } from "vitest";
import type { Family, KnowledgeGraph } from "../types";
import { aroundByRelation, histogram, splitCitations, visible, type KgFilters } from "./kg";

const kg: KnowledgeGraph = {
  nodes: [
    { id: "a", label: "A", type: "intrusion-set", family: "actor", article_ids: [1, 2] },
    { id: "m", label: "M", type: "malware", family: "malware", article_ids: [1] },
    { id: "t", label: "T", type: "attack-pattern", family: "technique", article_ids: [2] },
  ],
  edges: [
    { id: "e1", source: "a", target: "m", type: "uses", confidence: 80, article_ids: [1] },
    { id: "e2", source: "a", target: "t", type: "uses", confidence: 30, article_ids: [2] },
  ],
  articles: [{ id: 1, title: "x", published: "2025-01-10" }, { id: 2, title: "y", published: "2025-04-02" }],
};
const all: KgFilters = { families: new Set<Family>(["actor", "malware", "technique"]), minSources: 0, minConfidence: 0, period: null, isolated: null };

describe("graphe global", () => {
  it("filtre par famille, sources, confiance et ensemble isolé", () => {
    expect(visible(kg, all).edges.size).toBe(2);
    expect([...visible(kg, { ...all, minSources: 2 }).nodes]).toEqual(["a"]);
    expect([...visible(kg, { ...all, minConfidence: 50 }).edges]).toEqual(["e1"]);
    expect(visible(kg, { ...all, isolated: new Set(["a", "t"]) }).edges).toEqual(new Set(["e2"]));
  });
  it("ne garde dans une période que ce que ses articles étayent", () => {
    const v = visible(kg, { ...all, period: ["2025-01", "2025-02"] });
    expect(v.nodes).toEqual(new Set(["a", "m"]));
    expect(v.edges).toEqual(new Set(["e1"]));
  });
  it("histogramme continu, mois vides compris", () => {
    expect(histogram(kg).map((b) => b.count)).toEqual([1, 0, 0, 1]);
  });
  it("voisins par relation et citations", () => {
    expect(aroundByRelation(kg.edges, "a")).toEqual([["uses", ["m", "t"]]]);
    expect(splitCitations("x [[E2]], y")).toEqual([{ text: "x " }, { handle: "E2" }, { text: ", y" }]);
  });
});
