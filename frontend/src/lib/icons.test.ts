import { describe, expect, it } from "vitest";
import { TYPE_LABEL } from "./theme";
import { TYPE_ICON, isRectangular } from "./icons";

describe("icônes", () => {
  it("chaque type STIX libellé a sa propre icône", () => {
    for (const type of Object.keys(TYPE_LABEL)) expect(TYPE_ICON[type], type).toBeDefined();
    const icons = Object.values(TYPE_ICON);
    expect(new Set(icons).size).toBe(icons.length);
  });
  it("seuls les acteurs sont rectangulaires", () => {
    expect(["threat-actor", "intrusion-set", "campaign"].every(isRectangular)).toBe(true);
    expect(["malware", "tool", "identity", "location", "incident"].some(isRectangular)).toBe(false);
  });
});
