import type { Family } from "../types";

/** Une teinte par famille, désaturée : l'information vient du glyphe et du libellé, la couleur ne fait que repérer. */
export const FAMILY: Record<Family, { label: string; color: string }> = {
  actor: { label: "Acteurs", color: "#e76a6e" },
  malware: { label: "Malwares", color: "#ec9a3c" },
  tool: { label: "Outils", color: "#4c90f0" },
  vulnerability: { label: "Vulnérabilités", color: "#c274c2" },
  infrastructure: { label: "Infrastructure", color: "#3db2cc" },
  technique: { label: "Techniques", color: "#9d7fe6" },
  detection: { label: "Détection", color: "#72ca9b" },
  target: { label: "Cibles et contexte", color: "#9aa6b6" },
};

/** Couleurs d'état, partagées par React Flow et sigma (miroir de tailwind.config.js). */
export const STATE = { select: "#e8b04b", cited: "#5fd4e8", edge: "#56677d", edgeActive: "#c9d3de", canvas: "#121a24", panel: "#18212d", ink: "#e6edf5", muted: "#9fb0c3" };

export const TYPE_LABEL: Record<string, string> = {
  "threat-actor": "Acteur de la menace", "intrusion-set": "Ensemble d'intrusion", campaign: "Campagne", malware: "Malware",
  tool: "Outil", vulnerability: "Vulnérabilité", infrastructure: "Infrastructure", "attack-pattern": "Technique",
  indicator: "Indicateur", "course-of-action": "Mesure corrective", identity: "Identité", location: "Localisation", incident: "Incident",
  software: "Logiciel",
};

/** Sous-types des vocabulaires ouverts STIX 2.1 et tactiques ATT&CK, en français. */
export const KIND_LABEL: Record<string, string> = {
  ransomware: "Rançongiciel", backdoor: "Porte dérobée", "remote-access-trojan": "Cheval de Troie (RAT)", downloader: "Chargeur",
  dropper: "Dropper", wiper: "Wiper", spyware: "Logiciel espion", keylogger: "Enregistreur de frappe", worm: "Ver", bot: "Bot",
  rootkit: "Rootkit", "exploit-kit": "Kit d'exploitation", webshell: "Webshell", "resource-exploitation": "Minage", virus: "Virus",
  trojan: "Cheval de Troie", "screen-capture": "Capture d'écran", ddos: "DDoS", stealer: "Voleur d'informations", loader: "Chargeur",
  "command-and-control": "Serveur C2", botnet: "Botnet", "hosting-malware": "Hébergement de malware", "hosting-target-lists": "Listes de cibles",
  phishing: "Hameçonnage", exfiltration: "Exfiltration", anonymization: "Anonymisation", amplification: "Amplification",
  reconnaissance: "Reconnaissance", staging: "Préparation", workstation: "Poste de travail",
  "remote-access": "Accès à distance", "credential-exploitation": "Vol d'identifiants", "network-capture": "Capture réseau",
  "vulnerability-scanning": "Scan de vulnérabilités", "information-gathering": "Collecte d'informations", exploitation: "Exploitation",
  "denial-of-service": "Déni de service",
  individual: "Individu", group: "Groupe", organization: "Organisation", class: "Secteur", system: "Système",
};

/** Tactiques ATT&CK (v20 : « stealth » et « defense-impairment » remplacent « defense-evasion »), distinctes des sous-types :
 * « command-and-control » est une tactique pour une technique, un serveur C2 pour une infrastructure. */
export const TACTIC_LABEL: Record<string, string> = {
  reconnaissance: "Reconnaissance", "resource-development": "Développement de ressources", "initial-access": "Accès initial",
  execution: "Exécution", persistence: "Persistance", "privilege-escalation": "Élévation de privilèges",
  "defense-evasion": "Contournement des défenses", stealth: "Furtivité", "defense-impairment": "Neutralisation des défenses",
  "credential-access": "Accès aux identifiants", discovery: "Découverte", "lateral-movement": "Mouvement latéral", collection: "Collecte",
  "command-and-control": "Commande et contrôle", exfiltration: "Exfiltration", impact: "Impact",
};

export const typeLabel = (t: string) => TYPE_LABEL[t] ?? t;
export const kindLabel = (k: string) => KIND_LABEL[k] ?? k.replace(/-/g, " ");
export const relationLabel = (t: string) => t.replace(/-/g, " ");

/** Légende courte d'un nœud : son sous-type le plus précis, sinon son type. */
export function captionOf(n: { type: string; kinds?: string[]; tactics?: string[]; identity_class?: string | null; is_dual_use?: boolean; sectors?: string[] }): string {
  if (n.is_dual_use) return "Outil détourné";
  if (n.type === "attack-pattern" && n.tactics?.[0]) return TACTIC_LABEL[n.tactics[0]] ?? kindLabel(n.tactics[0]);
  if (n.kinds?.[0]) return kindLabel(n.kinds[0]);
  if (n.type === "identity" && n.sectors?.length) return "Secteur";
  if (n.type === "identity" && n.identity_class) return kindLabel(n.identity_class);
  return typeLabel(n.type);
}

/** Style d'une arête selon la famille de sa relation : l'appartenance en trait double, la cible en tirets, la détection en
 * pointillés. Les mêmes groupes servent à la légende. */
export type EdgeStyle = "solid" | "double" | "dashed" | "dotted";
export function edgeStyleOf(relation: string): EdgeStyle {
  if (["attributed-to", "authored-by", "part-of", "impersonates"].includes(relation)) return "double";
  if (["targets", "compromises", "originates-from", "located-at"].includes(relation)) return "dashed";
  if (["indicates", "detects", "mitigates", "based-on", "related-to"].includes(relation)) return "dotted";
  return "solid";
}
export const DASH: Record<EdgeStyle, string | undefined> = { solid: undefined, double: undefined, dashed: "6 4", dotted: "1.5 4" };
