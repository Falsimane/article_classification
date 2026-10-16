import { Bug, Building2, Crosshair, Fingerprint, Flag, MapPin, Server, ShieldAlert, ShieldCheck, Skull, TriangleAlert, Users, Wrench, type LucideIcon } from "lucide-react";

/** Une icône par type d'objet STIX affiché. Les types inconnus retombent sur `FALLBACK`. */
export const TYPE_ICON: Record<string, LucideIcon> = {
  "threat-actor": Skull,
  "intrusion-set": Users,
  campaign: Flag,
  malware: Bug,
  tool: Wrench,
  vulnerability: ShieldAlert,
  infrastructure: Server,
  "attack-pattern": Crosshair,
  indicator: Fingerprint,
  "course-of-action": ShieldCheck,
  identity: Building2,
  location: MapPin,
  incident: TriangleAlert,
};
export const FALLBACK: LucideIcon = Building2;
export const iconOf = (type: string): LucideIcon => TYPE_ICON[type] ?? FALLBACK;

/** Seuls les acteurs de la menace sont des rectangles dans un graphe de rapport ; le reste est rond. */
export const ACTOR_TYPES = new Set(["threat-actor", "intrusion-set", "campaign"]);
export const isRectangular = (type: string) => ACTOR_TYPES.has(type);
