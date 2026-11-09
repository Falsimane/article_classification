import { Background, BackgroundVariant, BaseEdge, Controls, EdgeLabelRenderer, Handle, MarkerType, MiniMap, Position, ReactFlow, ReactFlowProvider, useInternalNode, useStore, type Edge, type EdgeProps, type InternalNode, type Node, type NodeProps } from "@xyflow/react";
import { useMemo } from "react";
import { isRectangular } from "../lib/icons";
import { forceLayout } from "../lib/layout";
import { DASH, FAMILY, STATE, edgeStyleOf, relationLabel } from "../lib/theme";
import { NodeMark, tileWidth } from "./NodeMark";
import type { GraphEdge, GraphNode } from "../types";

const DISC = 52; // diamètre d'un nœud rond
const RECT_W = tileWidth(DISC / 2);
const RECT_H = 48;
const LABEL_ZOOM = 1.1; // sans sélection, les étiquettes d'arêtes n'apparaissent qu'à partir de ce zoom
const size = (type: string) => (isRectangular(type) ? { w: RECT_W, h: RECT_H } : { w: DISC, h: DISC });

type CtiNode = Node<{ node: GraphNode; dim: boolean; selected: boolean }, "cti">;
type CtiEdge = Edge<{ relation: string; active: boolean; focused: boolean }, "floating">;

const hidden = "!left-1/2 !top-1/2 !h-0 !w-0 !border-0 !opacity-0";

function CtiNodeView({ data }: NodeProps<CtiNode>) {
  const { node, dim, selected } = data;
  const { w, h } = size(node.type);
  return (
    <div className="relative" style={{ width: w, height: h }} title={node.label}>
      <div className="absolute" style={{ left: w / 2, top: h / 2 }}>
        <NodeMark node={node} radius={DISC / 2} state={selected ? "select" : dim ? "dim" : "none"} />
      </div>
      <Handle type="target" position={Position.Top} className={hidden} />
      <Handle type="source" position={Position.Top} className={hidden} />
    </div>
  );
}

/** Point où le segment centre→`toward` quitte la forme du nœud (cercle ou rectangle), pour que la flèche touche le bord. */
function border(n: InternalNode, toward: { x: number; y: number }, gap = 3) {
  const w = n.measured.width ?? DISC;
  const h = n.measured.height ?? DISC;
  const c = { x: n.internals.positionAbsolute.x + w / 2, y: n.internals.positionAbsolute.y + h / 2 };
  const dx = toward.x - c.x;
  const dy = toward.y - c.y;
  const len = Math.hypot(dx, dy) || 1;
  const circle = w === h;
  const reach = circle ? w / 2 : Math.min(w / 2 / (Math.abs(dx) / len || 1e-9), h / 2 / (Math.abs(dy) / len || 1e-9));
  return { x: c.x + (dx / len) * (reach + gap), y: c.y + (dy / len) * (reach + gap), c };
}

export function FloatingEdge({ id, source, target, markerEnd, style, data }: EdgeProps<CtiEdge>) {
  const s = useInternalNode(source);
  const t = useInternalNode(target);
  const zoom = useStore((st) => st.transform[2]);
  if (!s || !t) return null;
  const tc = border(t, { x: s.internals.positionAbsolute.x + (s.measured.width ?? DISC) / 2, y: s.internals.positionAbsolute.y + (s.measured.height ?? DISC) / 2 }, 0).c;
  const a = border(s, tc);
  const b = border(t, a.c, 4);
  const kind = edgeStyleOf(data?.relation ?? "");
  const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
  const off = kind === "double" ? { x: (-(b.y - a.y) / len) * 2, y: ((b.x - a.x) / len) * 2 } : { x: 0, y: 0 };
  const line = (k: number) => `M ${a.x + off.x * k},${a.y + off.y * k} L ${b.x + off.x * k},${b.y + off.y * k}`;
  const showLabel = data?.focused || (data?.active && zoom >= LABEL_ZOOM);
  return (
    <>
      {kind === "double" && <BaseEdge id={`${id}-2`} path={line(-1)} style={style} />}
      <BaseEdge id={id} path={line(1)} markerEnd={markerEnd} style={{ ...style, strokeDasharray: DASH[kind] }} />
      {showLabel && (
        <EdgeLabelRenderer>
          <div
            className="pointer-events-none absolute bg-bg px-1 text-[11px] leading-4 text-[#c9d3de]"
            style={{ transform: `translate(-50%, -50%) translate(${(a.x + b.x) / 2}px, ${(a.y + b.y) / 2}px)` }}
          >
            {relationLabel(data?.relation ?? "")}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const nodeTypes = { cti: CtiNodeView };
const edgeTypes = { floating: FloatingEdge };

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}

function Canvas({ nodes, edges, selectedId, onSelect }: Props) {
  const centers = useMemo(() => forceLayout(nodes, edges), [nodes, edges]);
  const neighbours = useMemo(() => {
    if (!selectedId) return null;
    const set = new Set([selectedId]);
    for (const e of edges) {
      if (e.source === selectedId) set.add(e.target);
      if (e.target === selectedId) set.add(e.source);
    }
    return set;
  }, [edges, selectedId]);

  const flowNodes: CtiNode[] = nodes.map((n) => {
    const { w, h } = size(n.type);
    const c = centers[n.id] ?? { x: 0, y: 0 };
    return {
      id: n.id, type: "cti", position: { x: c.x - w / 2, y: c.y - h / 2 }, width: w, height: h,
      data: { node: n, dim: !!neighbours && !neighbours.has(n.id), selected: n.id === selectedId },
    };
  });
  const flowEdges: CtiEdge[] = edges.map((e) => {
    const focused = !!selectedId && (e.source === selectedId || e.target === selectedId);
    const active = !selectedId || focused;
    const color = focused ? STATE.edgeActive : active ? "#6b7c91" : "#2f3b4a";
    return {
      id: e.id, source: e.source, target: e.target, type: "floating", selectable: false, data: { relation: e.type, active, focused },
      markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18, color },
      style: { stroke: color, strokeWidth: focused ? 1.75 : 1.5 },
    };
  });

  return (
    <ReactFlow
      nodes={flowNodes} edges={flowEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={{ padding: 0.2, maxZoom: 1 }} minZoom={0.15} maxZoom={2}
      nodesConnectable={false} elementsSelectable onNodeClick={(_, n) => onSelect(n.id)} onPaneClick={() => onSelect(null)} proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#22303f" />
      <Controls showInteractive={false} />
      <MiniMap pannable zoomable maskColor="rgba(18,26,36,0.7)" nodeColor={(n) => FAMILY[(n.data as CtiNode["data"]).node.family].color} />
    </ReactFlow>
  );
}

export function GraphCanvas(props: Props) {
  // `key` : un nouveau jeu de données doit recadrer la vue
  const key = props.nodes.map((n) => n.id).join("|");
  return (
    <ReactFlowProvider key={key}>
      <Canvas {...props} />
    </ReactFlowProvider>
  );
}
