export type Family = "actor" | "malware" | "tool" | "vulnerability" | "infrastructure" | "technique" | "detection" | "target";

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  family: Family;
  aliases: string[];
  references: { source: string; id: string }[];
  tactics: string[];
  sectors: string[];
  identity_class: string | null;
  is_family: boolean | null;
  labels: string[];
  is_dual_use: boolean;
  kinds: string[]; // sous-types STIX (malware_types, infrastructure_types…) : choisissent le glyphe
  country: string | null;
  article_ids: number[];
  degree: number;
  ioc_count?: number;
}

export interface Evidence { article: number | null; quote: string; procedure?: string }

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  confidence: number | null;
  tactic: string;
  evidence: Evidence[];
  article_ids: number[];
}

export interface ArticleSummary {
  id: number;
  title: string;
  url: string;
  site_name: string | null;
  publication_date: string | null;
  category: string | null;
  entities_count: number;
  relations_count: number;
}

export interface Stats {
  articles_count: number;
  entities_count: number;
  relations_count: number;
  dual_use_count: number;
  iocs_count: number;
  entity_types: Record<string, number>;
  relation_types: Record<string, number>;
}

export interface ArticleGraph {
  article_id: number | null;
  article: { id: number; title: string; url: string; site_name: string | null; category: string | null; published: string | null } | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** Texte de l'article tel que l'extraction l'a lu : markdown nettoyé (backend/dashboard/stix_dashboard.py `article_text`). */
export interface ArticleText {
  id: number;
  title: string;
  url: string;
  site_name: string | null;
  published: string | null;
  category: string | null;
  markdown: string;
}

export type IocStatus = "active" | "aging" | "stale" | "unknown";

export interface IocRow {
  id: string;
  kind: string;
  value: string;
  algo: string | null;
  name?: string | null; // fichier : nom donné avec ses hachages
  hashes?: Record<string, string>; // fichier : tous ses hachages (MD5, SHA-1, SHA-256)
  role: string;
  roles: string[];
  confidence: number | null;
  first_seen: string | null;
  last_seen: string | null;
  status: IocStatus;
  sources: number;
  article_ids: number[];
  attached_to: { id: string; name: string; type: string }[];
  evidence: Evidence[];
}

export type RuleKind = "yara" | "sigma";

/** Règle de détection (backend/dashboard/stix_dashboard.py `_rule_row`) : `source` est le texte exact de l'article. */
export interface RuleRow {
  id: string;
  kind: RuleKind;
  name: string;
  description: string | null;
  source: string;
  confidence: number | null;
  article_ids: number[];
  detects: { id: string; name: string; type: string }[];
}

export interface ActorRow extends GraphNode { relations: number; reports: number }

export interface ProfileEntry { node: GraphNode; relation: string; confidence: number | null; evidence: Evidence[] }

export interface OrgProfile {
  origin: ProfileEntry[];
  sponsors: ProfileEntry[];
  parents: ProfileEntry[];
  divisions: ProfileEntry[];
  malware: ProfileEntry[];
  tools: ProfileEntry[];
  infrastructure: ProfileEntry[];
  targets: ProfileEntry[];
  vulnerabilities: ProfileEntry[];
  techniques: Record<string, ProfileEntry[]>;
}

export interface ActorProfile {
  actor: GraphNode;
  profile: OrgProfile;
  iocs: IocRow[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  reports: { id: number; title: string; url: string; site_name: string | null; category: string | null; published: string | null }[];
}

/** Graphe global (backend/dashboard/stix_dashboard.py `global_graph`) : sans preuves, chargées par `/api/kg/node`. */
export interface KgNode {
  id: string;
  label: string;
  type: string;
  family: Family;
  article_ids: number[];
  kinds?: string[];
  country?: string;
  tactics?: string[];
  aliases?: string[];
  is_dual_use?: boolean;
  ioc_count?: number; // indicateurs que désigne l'entité, tous articles confondus
}

export interface KgEdge { id: string; source: string; target: string; type: string; confidence: number | null; article_ids: number[] }

export interface KgArticle { id: number; title: string; published: string | null }

export interface KnowledgeGraph { nodes: KgNode[]; edges: KgEdge[]; articles: KgArticle[] }

export interface NodeDetail { node: GraphNode; nodes: GraphNode[]; edges: GraphEdge[]; iocs: IocRow[]; reports: ActorProfile["reports"] }

/** Entité citée par l'assistant : `handle` est le repère (E3) écrit `[[E3]]` dans le texte de la réponse. */
export interface CitedEntity { handle: string; id: string; label: string; type: string; family: Family }

export type AskEvent =
  | { type: "step"; tool: string; args: Record<string, unknown>; count: number }
  | { type: "answer"; text: string; entities: CitedEntity[]; consulted: number }
  | { type: "error"; message: string };
