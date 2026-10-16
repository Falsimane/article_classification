import { Background, BackgroundVariant, Controls, Handle, Position, ReactFlow, ReactFlowProvider, type Edge, type Node, type NodeProps } from "@xyflow/react";
import clsx from "clsx";
import { iconOf } from "../lib/icons";
import { BOX_H, BOX_W, buildOrg, orgPositions, type OrgBox, type Tab } from "../lib/org";
import { FAMILY } from "../lib/theme";
import type { ActorProfile } from "../types";

type BoxNode = Node<{ box: OrgBox; onOpen: (t: Tab) => void }, "box">;

function BoxView({ data }: NodeProps<BoxNode>) {
  const { box, onOpen } = data;
  const Icon = iconOf(box.type);
  const clickable = !!box.tab && !box.empty;
  const accent = box.level === 1 ? "#e76a6e" : box.level === 3 ? "#4c90f0" : "#8f99a8";
  return (
    <div
      className={clsx("border bg-panel", box.level === 1 ? "border-2 border-line-strong" : "border-line-strong", box.empty && "opacity-60", clickable && "cursor-pointer hover:border-accent")}
      style={{ width: BOX_W, height: BOX_H, borderTopColor: accent, borderTopWidth: 3 }}
      onClick={() => clickable && box.tab && onOpen(box.tab)}
    >
      <Handle type="target" position={Position.Top} className="!h-0 !w-0 !border-0 !opacity-0" />
      <div className="flex items-center gap-2 px-3 pt-2">
        <Icon size={16} color={accent === "#8f99a8" ? FAMILY.target.color : accent} strokeWidth={1.75} className="shrink-0" />
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold leading-5">{box.title}</div>
          {box.caption && <div className="truncate font-mono text-[10px] uppercase leading-3 tracking-wide text-faint">{box.caption}</div>}
        </div>
      </div>
      {box.lines.length > 0 && (
        <ul className="mt-1 space-y-px px-3 text-xs text-muted">
          {box.lines.map((l, i) => (<li key={i} className="truncate">{l}</li>))}
        </ul>
      )}
      <Handle type="source" position={Position.Bottom} className="!h-0 !w-0 !border-0 !opacity-0" />
    </div>
  );
}

const nodeTypes = { box: BoxView };

export function OrgChart({ data, onOpen }: { data: ActorProfile; onOpen: (t: Tab) => void }) {
  const org = buildOrg(data);
  const pos = orgPositions(org.boxes);
  const nodes: BoxNode[] = org.boxes.map((b) => ({ id: b.id, type: "box", position: pos[b.id], width: BOX_W, height: BOX_H, draggable: false, data: { box: b, onOpen } }));
  const edges: Edge[] = org.links.map(([s, t]) => ({ id: `${s}>${t}`, source: s, target: t, type: "smoothstep", style: { stroke: "#5f6b7c", strokeWidth: 1.5 } }));
  return (
    <ReactFlowProvider key={data.actor.id}>
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.15, maxZoom: 1 }} nodesConnectable={false} nodesDraggable={false} elementsSelectable={false} proOptions={{ hideAttribution: true }}>
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#2f343c" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </ReactFlowProvider>
  );
}

