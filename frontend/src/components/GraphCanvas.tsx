import { Background, BackgroundVariant, BaseEdge, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, ReactFlowProvider, useInternalNode, type Edge, type EdgeProps, type InternalNode, type Node, type NodeProps } from "@xyflow/react";
import clsx from "clsx";
import { useMemo } from "react";
import { iconOf, isRectangular } from "../lib/icons";
import { forceLayout } from "../lib/layout";
import { FAMILY, relationLabel, typeLabel } from "../lib/theme";
import type { GraphEdge, GraphNode } from "../types";

const DISC = 56; // diamètre d'un nœud rond
const RECT_W = 176;
const RECT_H = 48;
const size = (type: string) => (isRectangular(type) ? { w: RECT_W, h: RECT_H } : { w: DISC, h: DISC });

type CtiNode = Node<{ node: GraphNode; dim: boolean; selected: boolean }, "cti">;

const hidden = "!left-1/2 !top-1/2 !h-0 !w-0 !border-0 !opacity-0";

function CtiNodeView({ data }: NodeProps<CtiNode>) {
  const { node, dim, selected } = data;
  const color = FAMILY[node.family].color;
  const Icon = iconOf(node.type);
  const handles = (
    <>
      <Handle type="target" position={Position.Top} className={hidden} />
      <Handle type="source" position={Position.Top} className={hidden} />
    </>
  );
  if (isRectangular(node.type)) {
    return (
      <div
        className={clsx("flex items-center gap-2 border-2 bg-panel px-2 transition-opacity", selected ? "border-accent" : "border-line-strong", dim && "opacity-25")}
        style={{ width: RECT_W, height: RECT_H, borderLeftColor: color, borderLeftWidth: 5 }} title={node.label}
      >
        <Icon size={20} color={color} strokeWidth={1.75} className="shrink-0" />
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold leading-4">{node.label}</div>
          <div className="truncate font-mono text-[10px] uppercase leading-4 tracking-wide text-faint">{typeLabel(node.type)}</div>
        </div>
        {handles}
      </div>
    );
  }
  return (
    <div className={clsx("relative transition-opacity", dim && "opacity-25")} style={{ width: DISC, height: DISC }} title={node.label}>
      <div
        className={clsx("flex h-full w-full items-center justify-center rounded-full border-2 bg-panel", selected ? "border-accent" : "")}
        style={selected ? undefined : { borderColor: color }}
      >
        <Icon size={24} color={color} strokeWidth={1.75} />
      </div>
      <div className="pointer-events-none absolute left-1/2 top-full mt-1 w-max max-w-[8rem] -translate-x-1/2 bg-bg px-1 text-center">
        <div className="truncate text-xs font-medium leading-4">{node.label}{node.is_dual_use && " ·"}</div>
        <div className="truncate font-mono text-[9px] uppercase leading-3 tracking-wide text-faint">{typeLabel(node.type)}</div>
      </div>
      {handles}
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

function FloatingEdge({ id, source, target, markerEnd, style, label, labelStyle }: EdgeProps) {
  const s = useInternalNode(source);
  const t = useInternalNode(target);
  if (!s || !t) return null;
  const tc = border(t, { x: s.internals.positionAbsolute.x + (s.measured.width ?? DISC) / 2, y: s.internals.positionAbsolute.y + (s.measured.height ?? DISC) / 2 }, 0).c;
  const a = border(s, tc);
  const b = border(t, a.c, 4);
  const path = `M ${a.x},${a.y} L ${b.x},${b.y}`;
  return (
    <BaseEdge
      id={id} path={path} markerEnd={markerEnd} style={style} label={label} labelX={(a.x + b.x) / 2} labelY={(a.y + b.y) / 2}
      labelStyle={labelStyle} labelBgStyle={{ fill: "#111418", fillOpacity: 0.95 }} labelBgPadding={[4, 2]} labelShowBg
    />
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
  const flowEdges: Edge[] = edges.map((e) => {
    const active = !selectedId || e.source === selectedId || e.target === selectedId;
    const color = active ? "#c5cbd3" : "#3a414b";
    return {
      id: e.id, source: e.source, target: e.target, label: relationLabel(e.type), type: "floating", selectable: false,
      markerEnd: { type: MarkerType.ArrowClosed, width: 20, height: 20, color },
      style: { stroke: color, strokeWidth: 1.75 },
      labelStyle: { opacity: active ? 1 : 0.3, fill: "#c5cbd3" },
    };
  });

  return (
    <ReactFlow
      nodes={flowNodes} edges={flowEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={{ padding: 0.2, maxZoom: 1 }} minZoom={0.15} maxZoom={2}
      nodesConnectable={false} elementsSelectable onNodeClick={(_, n) => onSelect(n.id)} onPaneClick={() => onSelect(null)} proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#2f343c" />
      <Controls showInteractive={false} />
      <MiniMap pannable zoomable maskColor="rgba(17,20,24,0.7)" nodeColor={(n) => FAMILY[(n.data as CtiNode["data"]).node.family].color} />
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
