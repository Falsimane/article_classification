import dagre from '@dagrejs/dagre';
import { MarkerType } from 'reactflow';

/**
 * Construit les nœuds et arêtes React Flow à partir de la réponse de l'API /api/threat-actors/<id>/tree
 * en reproduisant fidèlement l'arborescence :
 * 
 *               [ Armée populaire de Chine ]  (Root / Sponsor)
 *                             |
 *                             v
 *                          [ APT1 ]          (Threat Actor)
 *                         /   |   \
 *                        /    |    \
 *                       v     v     v
 *           [Infrastructure] [TTPs Kill Chain] [Outils]
 *              /         \
 *             v           v
 *        [Serveurs C2] [Localisation]
 */
export function buildThreatActorTreeElements(treeData, options = {}) {
  if (!treeData || !treeData.actor) {
    return { nodes: [], edges: [] };
  }

  const { actor, root_sponsor, infrastructure, ttps_kill_chain, tools } = treeData;
  const nodes = [];
  const edges = [];

  // 1. Racine (Niveau 0) : Sponsor Étatique / Pays d'attribution (ex: "Armée populaire de Chine")
  const sponsorName = root_sponsor?.name || actor.state_affiliation || `${actor.flag || '🌐'} ${actor.country}`;
  const rootNodeId = 'node-root-sponsor';
  nodes.push({
    id: rootNodeId,
    type: 'sponsorNode',
    position: { x: 0, y: 0 },
    data: {
      title: sponsorName,
      country: actor.country,
      flag: actor.flag || '🌐',
      stateAffiliation: actor.state_affiliation,
      affiliationType: actor.affiliation_type,
      attributionSource: actor.attribution_source,
      width: 280,
      height: 75,
    },
  });

  // 2. Acteur de Menace (Niveau 1) : ex: "APT1"
  const actorNodeId = 'node-threat-actor';
  nodes.push({
    id: actorNodeId,
    type: 'actorNode',
    position: { x: 0, y: 0 },
    data: {
      name: actor.name,
      aliases: actor.aliases || [],
      confidence: actor.confidence || 'Élevé',
      description: actor.description,
      width: 260,
      height: 75,
    },
  });

  // Arête Racine -> Acteur
  edges.push({
    id: `edge-${rootNodeId}->${actorNodeId}`,
    source: rootNodeId,
    target: actorNodeId,
    type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: '#94a3b8', width: 20, height: 20 },
    style: { stroke: '#94a3b8', strokeWidth: 2.5 },
  });

  // 3. Branches Principales (Niveau 2) : Infrastructure, TTPs Kill Chain, Outils
  const infraNodeId = 'node-branch-infra';
  const ttpsNodeId = 'node-branch-ttps';
  const toolsNodeId = 'node-branch-tools';

  const c2Count = (infrastructure?.c2_servers || []).length;
  const locCount = (infrastructure?.locations || []).length;
  const ttpsCount = (ttps_kill_chain?.all_ttps || infrastructure?.ttps || []).length;
  const malwaresCount = (tools?.dedicated_malwares || []).length;
  const lolbinsCount = (tools?.lolbins || []).length;

  nodes.push({
    id: infraNodeId,
    type: 'categoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'Infrastructure',
      icon: '🌐',
      color: '#06b6d4',
      badge: `${c2Count + locCount} actif(s)`,
      width: 230,
      height: 70,
    },
  });

  nodes.push({
    id: ttpsNodeId,
    type: 'categoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'TTPs Kill Chain',
      icon: '⚡',
      color: '#10b981',
      badge: `${ttpsCount} technique(s)`,
      width: 230,
      height: 70,
    },
  });

  nodes.push({
    id: toolsNodeId,
    type: 'categoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'Outils',
      icon: '⚔️',
      color: '#f97316',
      badge: `${malwaresCount + lolbinsCount} outil(s)`,
      width: 230,
      height: 70,
    },
  });

  // Arêtes Acteur -> Branches
  [
    { id: infraNodeId, color: '#06b6d4' },
    { id: ttpsNodeId, color: '#10b981' },
    { id: toolsNodeId, color: '#f97316' },
  ].forEach((branch) => {
    edges.push({
      id: `edge-${actorNodeId}->${branch.id}`,
      source: actorNodeId,
      target: branch.id,
      type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed, color: branch.color, width: 18, height: 18 },
      style: { stroke: branch.color, strokeWidth: 2 },
    });
  });

  // 4. Sous-branches Infrastructure (Niveau 3) : Serveurs C2, Localisation
  const c2NodeId = 'node-infra-c2';
  const locNodeId = 'node-infra-loc';

  nodes.push({
    id: c2NodeId,
    type: 'subCategoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'Serveurs C2',
      icon: '🖥️',
      color: '#38bdf8',
      count: c2Count,
      items: (infrastructure?.c2_servers || []).map((i) => ({
        label: i.value,
        type: i.type,
        copyable: true,
      })),
      width: 230,
      height: 90,
    },
  });

  nodes.push({
    id: locNodeId,
    type: 'subCategoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'Localisation',
      icon: '📍',
      color: '#22d3ee',
      count: locCount,
      items: (infrastructure?.locations || []).map((l) => ({
        label: l.value,
        type: l.type,
        copyable: false,
      })),
      width: 230,
      height: 90,
    },
  });

  // Arêtes Infrastructure -> Serveurs C2 / Localisation
  [
    { id: c2NodeId, color: '#38bdf8' },
    { id: locNodeId, color: '#22d3ee' },
  ].forEach((sub) => {
    edges.push({
      id: `edge-${infraNodeId}->${sub.id}`,
      source: infraNodeId,
      target: sub.id,
      type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed, color: sub.color, width: 16, height: 16 },
      style: { stroke: sub.color, strokeWidth: 1.8 },
    });
  });

  // 5. Sous-branches TTPs Kill Chain (Niveau 3)
  const ttpsItems = (ttps_kill_chain?.all_ttps || []).slice(0, 5);
  const ttpsSubNodeId = 'node-ttps-techniques';
  nodes.push({
    id: ttpsSubNodeId,
    type: 'subCategoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'Techniques MITRE ATT&CK',
      icon: '🎯',
      color: '#34d399',
      count: ttpsCount,
      items: ttpsItems.map((t) => ({
        label: `${t.mitreId ? t.mitreId + ' : ' : ''}${t.name}`,
        desc: t.description,
        copyable: false,
      })),
      width: 240,
      height: 90,
    },
  });
  edges.push({
    id: `edge-${ttpsNodeId}->${ttpsSubNodeId}`,
    source: ttpsNodeId,
    target: ttpsSubNodeId,
    type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: '#34d399', width: 16, height: 16 },
    style: { stroke: '#34d399', strokeWidth: 1.8 },
  });

  // 6. Sous-branches Outils (Niveau 3) : Malwares Dédiés vs LOLBins
  const malwareNodeId = 'node-tools-malware';
  const lolbinNodeId = 'node-tools-lolbin';

  nodes.push({
    id: malwareNodeId,
    type: 'subCategoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'Malwares Dédiés',
      icon: '🦠',
      color: '#fb923c',
      count: malwaresCount,
      items: (tools?.dedicated_malwares || []).slice(0, 4).map((m) => ({
        label: m.name,
        type: 'Malware',
        copyable: true,
      })),
      width: 220,
      height: 90,
    },
  });

  nodes.push({
    id: lolbinNodeId,
    type: 'subCategoryNode',
    position: { x: 0, y: 0 },
    data: {
      title: 'LOLBins / Utilitaires',
      icon: '🛠️',
      color: '#c084fc',
      count: lolbinsCount,
      items: (tools?.lolbins || []).slice(0, 4).map((l) => ({
        label: l.name,
        type: 'Dual-Use',
        copyable: true,
      })),
      width: 220,
      height: 90,
    },
  });

  [
    { id: malwareNodeId, color: '#fb923c' },
    { id: lolbinNodeId, color: '#c084fc' },
  ].forEach((sub) => {
    edges.push({
      id: `edge-${toolsNodeId}->${sub.id}`,
      source: toolsNodeId,
      target: sub.id,
      type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed, color: sub.color, width: 16, height: 16 },
      style: { stroke: sub.color, strokeWidth: 1.8 },
    });
  });

  // Calcul du layout hiérarchique avec Dagre
  return layoutDagreTree(nodes, edges);
}

/**
 * Calcule les positions automatiques (x, y) de tous les nœuds de façon symétrique
 */
export function layoutDagreTree(nodes, edges, direction = 'TB') {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({
    rankdir: direction,
    nodesep: 40,
    ranksep: 70,
    marginx: 40,
    marginy: 30,
  });

  nodes.forEach((node) => {
    const width = node.data?.width || 240;
    const height = node.data?.height || 85;
    dagreGraph.setNode(node.id, { width, height });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodePos = dagreGraph.node(node.id);
    const width = node.data?.width || 240;
    const height = node.data?.height || 85;
    return {
      ...node,
      position: {
        x: Math.round(nodePos.x - width / 2),
        y: Math.round(nodePos.y - height / 2),
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}
