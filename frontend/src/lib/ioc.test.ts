import { describe, expect, it } from "vitest";
import { countByStatus, filterIocs } from "./ioc";
import type { IocRow, IocStatus } from "../types";

const row = (value: string, status: IocStatus, role = "c2", target = "Qakbot"): IocRow => ({
  id: value, kind: "ipv4-addr", value, algo: null, role, roles: [role], confidence: 75, first_seen: "2026-04-22", last_seen: "2026-04-22",
  status, sources: 1, article_ids: [1], attached_to: [{ id: "x", name: target, type: "malware" }], evidence: [],
});
const rows = [row("8.8.4.4", "active"), row("9.9.9.9", "stale", "phishing", "APT29"), row("1.1.1.1", "unknown")];

describe("filtre des IOC", () => {
  it("« actifs seulement » exclut les statuts inconnus : une date manquante n'est jamais un IOC actif", () => {
    expect(filterIocs(rows, { activeOnly: true, search: "" }).map((r) => r.value)).toEqual(["8.8.4.4"]);
  });
  it("cherche dans la valeur, le rôle et l'entité rattachée", () => {
    expect(filterIocs(rows, { activeOnly: false, search: "8.8" })).toHaveLength(1);
    expect(filterIocs(rows, { activeOnly: false, search: "phishing" })).toHaveLength(1);
    expect(filterIocs(rows, { activeOnly: false, search: "apt29" })).toHaveLength(1);
  });
  it("compte par statut", () => {
    expect(countByStatus(rows)).toEqual({ active: 1, aging: 0, stale: 1, unknown: 1 });
  });
});
