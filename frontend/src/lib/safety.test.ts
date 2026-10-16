import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const files = (dir: string): string[] => readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : [join(dir, f)]));

describe("texte venu des articles", () => {
  it("n'est jamais injecté comme HTML", () => {
    const offenders = files("src").filter((f) => /\.(tsx?|jsx?)$/.test(f) && !f.endsWith(".test.ts") && /dangerouslySetInnerHTML|innerHTML/.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });
});
