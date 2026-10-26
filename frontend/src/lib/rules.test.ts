import { describe, expect, it } from "vitest";
import { filterRules, joinSources } from "./rules";
import type { RuleRow } from "../types";

const rule = (kind: RuleRow["kind"], name: string, source: string, detects = ""): RuleRow => ({
  id: name, kind, name, description: null, source, confidence: 75, article_ids: [1], detects: detects ? [{ id: "x", name: detects, type: "malware" }] : [],
});
const rows = [rule("yara", "Bumble_ISO", "rule Bumble_ISO {\n condition: true\n}\n", "BumbleBee"), rule("sigma", "Rundll32", "title: Rundll32\n")];

describe("règles de détection", () => {
  it("filtre par langage et cherche dans le nom, l'entité détectée et le texte", () => {
    expect(filterRules(rows, { kind: "sigma", search: "" }).map((r) => r.name)).toEqual(["Rundll32"]);
    expect(filterRules(rows, { kind: "all", search: "bumblebee" })).toHaveLength(1);
    expect(filterRules(rows, { kind: "all", search: "condition" })).toHaveLength(1);
  });
  it("copie le texte exact ; des règles Sigma forment un flux YAML multi-document", () => {
    expect(joinSources(rows.slice(1).concat(rows.slice(1)))).toBe("title: Rundll32\n---\ntitle: Rundll32\n");
    expect(joinSources(rows.slice(0, 1))).toBe(rows[0].source);
  });
});
