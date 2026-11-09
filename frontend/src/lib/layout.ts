import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";
import type { GraphEdge, GraphNode } from "../types";

export type Positions = Record<string, { x: number; y: number }>;

interface SimNode extends SimulationNodeDatum { id: string }

/** Centres des nœuds d'un graphe de rapport. Déterministe : départ sur un cercle, ordre trié, nombre de pas fixe. */
export function forceLayout(nodes: GraphNode[], edges: GraphEdge[]): Positions {
  const ordered = [...nodes].sort((a, b) => a.id.localeCompare(b.id));
  const sim: SimNode[] = ordered.map((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(ordered.length, 1);
    return { id: n.id, x: Math.cos(angle) * 240, y: Math.sin(angle) * 240 };
  });
  const known = new Set(sim.map((n) => n.id));
  const links: SimulationLinkDatum<SimNode>[] = edges.filter((e) => known.has(e.source) && known.has(e.target)).map((e) => ({ source: e.source, target: e.target }));
  const simulation = forceSimulation(sim)
    .force("link", forceLink<SimNode, SimulationLinkDatum<SimNode>>(links).id((d) => d.id).distance(190).strength(0.5))
    .force("charge", forceManyBody().strength(-1100))
    .force("collide", forceCollide(78))
    // gravité douce : les composantes déconnectées restent près du reste au lieu d'élargir le cadrage
    .force("x", forceX(0).strength(0.09))
    .force("y", forceY(0).strength(0.09))
    .stop();
  for (let i = 0; i < 320; i++) simulation.tick();
  return Object.fromEntries(sim.map((n) => [n.id, { x: n.x ?? 0, y: n.y ?? 0 }]));
}
