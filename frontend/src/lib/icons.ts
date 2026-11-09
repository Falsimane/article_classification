import {
  AppWindow, ShieldOff, Anchor, Archive, ArrowLeftRight, Binoculars, Bot, Bug, Building2, ChevronsUp, Code, Crosshair, DoorOpen, Download, Eraser, EyeOff,
  Factory, Fingerprint, Fish, Flag, Ghost, Globe, Hammer, KeyRound, Keyboard, Landmark, Laptop, Lock, MapPin, MonitorDot, Network,
  PackageOpen, Pickaxe, Play, Radar, RadioTower, Route, ScanSearch, ServerCog, Server, ShieldAlert, ShieldCheck, Skull, Telescope,
  Terminal, TriangleAlert, Upload, User, Users, VenetianMask, Worm, Wrench, Zap, type LucideIcon,
} from "lucide-react";

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
  software: AppWindow,
};
export const FALLBACK: LucideIcon = Building2;
export const iconOf = (type: string): LucideIcon => TYPE_ICON[type] ?? FALLBACK;

/** Glyphe d'un sous-type : malware_types, infrastructure_types, tool_types (vocabulaires STIX) et tactiques ATT&CK. */
export const KIND_ICON: Record<string, LucideIcon> = {
  ransomware: Lock, backdoor: DoorOpen, "remote-access-trojan": MonitorDot, downloader: Download, loader: Download, dropper: PackageOpen,
  wiper: Eraser, spyware: Binoculars, stealer: KeyRound, keylogger: Keyboard, worm: Worm, bot: Bot, rootkit: Ghost, webshell: Code,
  "resource-exploitation": Pickaxe,
  "command-and-control": RadioTower, botnet: Network, "hosting-malware": ServerCog, phishing: Fish, exfiltration: Upload,
  anonymization: VenetianMask, reconnaissance: Radar, workstation: Laptop,
  "remote-access": MonitorDot, "credential-exploitation": KeyRound, "network-capture": Radar, "vulnerability-scanning": ScanSearch,
};

export const TACTIC_ICON: Record<string, LucideIcon> = {
  reconnaissance: Telescope, "resource-development": Hammer, "initial-access": DoorOpen, execution: Play, persistence: Anchor,
  "privilege-escalation": ChevronsUp, "defense-evasion": EyeOff, stealth: EyeOff, "defense-impairment": ShieldOff, "credential-access": KeyRound, discovery: ScanSearch,
  "lateral-movement": Route, collection: Archive, "command-and-control": ArrowLeftRight, exfiltration: Upload, impact: Zap,
};

interface Glyphable { type: string; kinds?: string[]; tactics?: string[]; identity_class?: string | null; sectors?: string[]; is_dual_use?: boolean }

/** Glyphe d'un nœud : le sous-type le plus précis connu, sinon le type. */
export function glyphOf(n: Glyphable): LucideIcon {
  if (n.type === "attack-pattern") return TACTIC_ICON[n.tactics?.[0] ?? ""] ?? Crosshair;
  if (n.type === "tool" && n.is_dual_use) return Terminal;
  for (const k of n.kinds ?? []) if (KIND_ICON[k]) return KIND_ICON[k];
  if (n.type === "identity") {
    if (n.sectors?.includes("government")) return Landmark;
    if (n.sectors?.length || n.identity_class === "class") return Factory;
    if (n.identity_class === "individual") return User;
    if (n.identity_class === "group") return Users;
  }
  if (n.type === "location") return Globe;
  return iconOf(n.type);
}

/** Code pays ISO 3166-1 affiché à la place d'un glyphe dans le disque d'une localisation. */
export const isoOf = (n: { type: string; country?: string | null }) => (n.type === "location" && n.country ? n.country.toUpperCase().slice(0, 3) : null);

/** Seuls les acteurs de la menace sont des rectangles dans un graphe de rapport ; le reste est rond. */
export const ACTOR_TYPES = new Set(["threat-actor", "intrusion-set", "campaign"]);
export const isRectangular = (type: string) => ACTOR_TYPES.has(type);
