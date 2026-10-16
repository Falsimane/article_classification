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
  article_ids: number[];
  degree: number;
}

export interface Evidence { article: number | null; quote: string }

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
  entity_types: Record<string, number>;
  relation_types: Record<string, number>;
}

export interface ArticleGraph {
  article_id: number | null;
  article: { id: number; title: string; url: string; site_name: string | null; category: string | null; published: string | null } | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
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
  nodes: GraphNode[];
  edges: GraphEdge[];
  reports: { id: number; title: string; url: string; site_name: string | null; category: string | null; published: string | null }[];
}
