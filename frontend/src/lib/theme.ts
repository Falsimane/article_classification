import type { Family } from "../types";

/** Une teinte par famille, désaturée : l'information vient de la forme et du libellé, la couleur ne fait que repérer. */
export const FAMILY: Record<Family, { label: string; color: string }> = {
  actor: { label: "Acteurs", color: "#e76a6e" },
  malware: { label: "Malwares", color: "#ec9a3c" },
  tool: { label: "Outils", color: "#4c90f0" },
  vulnerability: { label: "Vulnérabilités", color: "#c274c2" },
  infrastructure: { label: "Infrastructure", color: "#2d9cb5" },
  technique: { label: "Techniques", color: "#9d7fe6" },
  detection: { label: "Détection", color: "#72ca9b" },
  target: { label: "Cibles et contexte", color: "#8f99a8" },
};

export const TYPE_LABEL: Record<string, string> = {
  "threat-actor": "Acteur de la menace", "intrusion-set": "Ensemble d'intrusion", campaign: "Campagne", malware: "Malware",
  tool: "Outil", vulnerability: "Vulnérabilité", infrastructure: "Infrastructure", "attack-pattern": "Technique",
  indicator: "Indicateur", "course-of-action": "Mesure corrective", identity: "Identité", location: "Localisation", incident: "Incident",
};

export const typeLabel = (t: string) => TYPE_LABEL[t] ?? t;
export const relationLabel = (t: string) => t.replace(/-/g, " ");
