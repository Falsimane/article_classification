import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";
import { MultiDirectedGraph } from "graphology";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import Sigma from "sigma";
import { EdgeArrowProgram } from "sigma/rendering";
import { isRectangular } from "../lib/icons";
import { FAMILY, STATE, edgeStyleOf, relationLabel } from "../lib/theme";
import type { KgNode, KnowledgeGraph } from "../types";
import { NodeMark, type MarkState } from "./NodeMark";

interface Props {
  kg: KnowledgeGraph;
  revision: string;
  visibleNodes: Set<string>;
  visibleEdges: Set<string>;
  selectedId: string | null;
  cited: Set<string>;
  hovered: string | null; // entité survolée dans le panneau de l'assistant
  onSelect: (id: string | null) => void;
}

/** Niveau de détail, choisi d'après l'espace moyen dont dispose un nœud à l'écran : points (canvas), puis nœuds HTML de
 * plus en plus grands, avec leurs noms quand il y a la place. */
type Lod = "dots" | "small" | "medium" | "full";
const RADIUS: Record<Exclude<Lod, "dots">, number> = { small: 12, medium: 17, full: 22 };
const MAX_HTML_NODES = 450;

type Pos = Record<string, [number, number]>;
const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const TRANSPARENT = "rgba(0,0,0,0)";

/** Positions mises en cache par révision du graphe : la disposition n'est calculée qu'une fois par état du graphe. */
const cacheKey = (revision: string) => `cti-kg-layout-v2:${revision}`;
function loadPositions(revision: string): Pos | null {
  try {
    const raw = localStorage.getItem(cacheKey(revision));
    return raw ? (JSON.parse(raw) as Pos) : null;
  } catch {
    return null;
  }
}
function savePositions(revision: string, pos: Pos) {
  try {
    for (const k of Object.keys(localStorage)) if (k.startsWith("cti-kg-layout")) localStorage.removeItem(k);
    localStorage.setItem(cacheKey(revision), JSON.stringify(pos));
  } catch {
    /* stockage indisponible : la disposition sera recalculée */
  }
}

interface SimNode extends SimulationNodeDatum { id: string; actor: boolean }

/** Disposition d3-force, déterministe (spirale de départ, ordre trié), calculée par tranches pour ne pas bloquer la page ;
 * `onStep` reçoit les positions à chaque tranche, ce qui montre le graphe se déployer. */
function layout(kg: KnowledgeGraph, onStep: (p: Pos) => void, onDone: (p: Pos) => void): () => void {
  const nodes: SimNode[] = [...kg.nodes].sort((a, b) => a.id.localeCompare(b.id)).map((n, i) => {
    const r = 14 * Math.sqrt(i + 1), a = i * 2.399963;
    return { id: n.id, actor: isRectangular(n.type), x: r * Math.cos(a), y: r * Math.sin(a) };
  });
  const known = new Set(nodes.map((n) => n.id));
  const links: SimulationLinkDatum<SimNode>[] = kg.edges.filter((e) => known.has(e.source) && known.has(e.target) && e.source !== e.target).map((e) => ({ source: e.source, target: e.target }));
  const sim = forceSimulation(nodes)
    .force("link", forceLink<SimNode, SimulationLinkDatum<SimNode>>(links).id((d) => d.id).distance(90).strength(0.35))
    .force("charge", forceManyBody<SimNode>().strength((d) => (d.actor ? -900 : -320)).distanceMax(900))
    .force("collide", forceCollide<SimNode>((d) => (d.actor ? 95 : 42)))
    // gravité douce plutôt qu'un centrage : les composantes isolées restent près du cœur au lieu d'élargir le cadrage
    .force("x", forceX(0).strength(0.07))
    .force("y", forceY(0).strength(0.07))
    .stop();
  const snapshot = (): Pos => Object.fromEntries(nodes.map((n) => [n.id, [Math.round(n.x ?? 0), Math.round(n.y ?? 0)]]));
  const total = 320, chunk = nodes.length > 2000 ? 4 : 20;
  let done = 0, timer = 0;
  // setTimeout et non requestAnimationFrame : un onglet en arrière-plan suspend les frames, la disposition doit continuer
  const step = () => {
    for (let i = 0; i < chunk && done < total; i++, done++) sim.tick();
    if (done < total) { onStep(snapshot()); timer = window.setTimeout(step, 16); } else onDone(snapshot());
  };
  timer = window.setTimeout(step, 0);
  return () => window.clearTimeout(timer);
}

export function KgCanvas({ kg, revision, visibleNodes, visibleEdges, selectedId, cited, hovered, onSelect }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const sigma = useRef<Sigma | null>(null);
  const marks = useRef(new Map<string, HTMLDivElement>());
  const [overlay, setOverlay] = useState<{ ids: string[]; lod: Lod }>({ ids: [], lod: "dots" });
  const [pointer, setPointer] = useState<string | null>(null); // nœud sous la souris dans le canvas
  const [layingOut, setLayingOut] = useState(false);
  const byId = useRef(new Map<string, KgNode>());
  const degree = useRef(new Map<string, number>());
  const state = useRef({ visibleNodes, visibleEdges, selectedId, cited, hovered, pointer, focus: new Set<string>(), lod: "dots" as Lod });
  const select = useRef(onSelect);
  select.current = onSelect;

  /** Place chaque nœud HTML sur la position à l'écran de son nœud sigma. */
  const place = () => {
    const r = sigma.current;
    if (!r) return;
    const g = r.getGraph();
    for (const [id, el] of marks.current) {
      if (!g.hasNode(id)) continue;
      const p = r.graphToViewport(g.getNodeAttributes(id) as { x: number; y: number });
      el.style.transform = `translate(${p.x}px, ${p.y}px)`;
    }
  };

  /** Nœuds visibles à l'écran et niveau de détail ; l'état React n'est modifié que s'ils changent. */
  const measure = () => {
    const r = sigma.current;
    if (!r) return;
    const g = r.getGraph();
    const { width, height } = r.getDimensions();
    const ids: string[] = [];
    for (const id of state.current.visibleNodes) {
      if (!g.hasNode(id)) continue;
      const p = r.graphToViewport(g.getNodeAttributes(id) as { x: number; y: number });
      if (p.x > -80 && p.x < width + 80 && p.y > -60 && p.y < height + 60) ids.push(id);
    }
    const spacing = ids.length ? Math.sqrt((width * height) / ids.length) : Infinity;
    const lod: Lod = ids.length > MAX_HTML_NODES || spacing < 34 ? "dots" : spacing < 75 ? "small" : spacing < 125 ? "medium" : "full";
    const shown = lod === "dots" ? [] : ids;
    setOverlay((cur) => (cur.lod === lod && cur.ids.length === shown.length && cur.ids.every((id, i) => id === shown[i]) ? cur : { ids: shown, lod }));
    if (state.current.lod !== lod) {
      state.current.lod = lod;
      r.refresh({ skipIndexation: true });
    }
  };

  // Graphe et rendu : recréés seulement quand le graphe change
  useEffect(() => {
    if (!container.current) return;
    const graph = new MultiDirectedGraph();
    byId.current = new Map(kg.nodes.map((n) => [n.id, n]));
    degree.current = new Map();
    for (const e of kg.edges) for (const id of [e.source, e.target]) degree.current.set(id, (degree.current.get(id) ?? 0) + 1);
    const cached = loadPositions(revision);
    for (const n of kg.nodes) {
      const [x, y] = cached?.[n.id] ?? [0, 0];
      graph.addNode(n.id, { x, y, size: 4, label: n.label, color: FAMILY[n.family].color });
    }
    for (const e of kg.edges) {
      if (!graph.hasNode(e.source) || !graph.hasNode(e.target) || e.source === e.target) continue;
      graph.addDirectedEdgeWithKey(e.id, e.source, e.target, { relation: e.type, size: edgeStyleOf(e.type) === "double" ? 2.6 : 1.6, color: STATE.edge });
    }

    const renderer = new Sigma(graph, container.current, {
      defaultEdgeType: "arrow",
      edgeProgramClasses: { arrow: EdgeArrowProgram },
      zoomToSizeRatioFunction: () => 1, // tailles en pixels d'écran, comme les nœuds HTML
      renderEdgeLabels: true,
      labelFont: "Barlow, sans-serif",
      labelWeight: "600",
      labelSize: 12,
      labelColor: { color: STATE.ink },
      labelDensity: 0.4,
      labelRenderedSizeThreshold: 7,
      edgeLabelFont: "Barlow, sans-serif",
      edgeLabelSize: 12,
      edgeLabelColor: { color: STATE.edgeActive },
      defaultDrawNodeHover: () => {}, // le survol est montré par les nœuds HTML et le voisinage mis en avant
      zIndex: true,
      minCameraRatio: 0.05,
      maxCameraRatio: 4,
      stagePadding: 60,
      nodeReducer: (id, data) => {
        const s = state.current;
        if (!s.visibleNodes.has(id)) return { ...data, hidden: true };
        const n = byId.current.get(id)!;
        const lit = id === s.selectedId || s.cited.has(id) || id === s.hovered;
        const dim = s.focus.size > 0 && !s.focus.has(id);
        if (s.lod === "dots") {
          const size = Math.min(10, 3 + Math.sqrt(degree.current.get(id) ?? 0) * 1.1) + (isRectangular(n.type) ? 3 : 0);
          return { ...data, size, color: dim ? "#2b394a" : id === s.selectedId ? STATE.select : s.cited.has(id) ? STATE.cited : data.color, forceLabel: lit, label: dim ? "" : data.label, zIndex: lit ? 2 : 1 };
        }
        const radius = RADIUS[s.lod];
        return { ...data, size: isRectangular(n.type) ? radius * 1.6 : radius, color: TRANSPARENT, label: "", zIndex: 1 };
      },
      edgeReducer: (id, data) => {
        const s = state.current;
        if (!s.visibleEdges.has(id)) return { ...data, hidden: true };
        const [a, b] = [graph.source(id), graph.target(id)];
        const anchor = s.selectedId ?? s.pointer;
        if (anchor && (a === anchor || b === anchor)) return { ...data, color: STATE.edgeActive, size: data.size + 0.6, label: relationLabel(data.relation), forceLabel: true, zIndex: 2 };
        if (s.cited.has(a) && s.cited.has(b)) return { ...data, color: STATE.cited, size: data.size + 0.8, label: relationLabel(data.relation), forceLabel: true, zIndex: 2 };
        if (s.focus.size > 0) return { ...data, color: "#222d3a", zIndex: 0 };
        return data;
      },
    });
    sigma.current = renderer;
    renderer.on("clickNode", ({ node }) => select.current(node));
    renderer.on("clickStage", () => select.current(null));
    renderer.on("enterNode", ({ node }) => { container.current!.style.cursor = "pointer"; setPointer(node); });
    renderer.on("leaveNode", () => { container.current!.style.cursor = "default"; setPointer(null); });
    renderer.on("afterRender", place);
    let pending = 0;
    const onCamera = () => { cancelAnimationFrame(pending); pending = requestAnimationFrame(measure); };
    renderer.getCamera().on("updated", onCamera);

    let stop = () => {};
    if (!cached && graph.order > 1) {
      setLayingOut(true);
      const apply = (p: Pos) => { for (const [id, [x, y]] of Object.entries(p)) if (graph.hasNode(id)) graph.mergeNodeAttributes(id, { x, y }); };
      stop = layout(kg, (p) => { apply(p); renderer.refresh(); onCamera(); }, (p) => {
        apply(p);
        savePositions(revision, p);
        setLayingOut(false);
        renderer.refresh();
        renderer.getCamera().animatedReset({ duration: reduced() ? 0 : 400 });
      });
    } else {
      onCamera();
    }
    return () => {
      stop();
      cancelAnimationFrame(pending);
      renderer.kill();
      sigma.current = null;
    };
  }, [kg, revision]); // eslint-disable-line react-hooks/exhaustive-deps

  // États (filtres, sélection, survol, citations) : seul le rendu est rafraîchi
  useEffect(() => {
    const r = sigma.current;
    const focus = new Set<string>();
    const anchor = selectedId ?? pointer;
    if (r && anchor && r.getGraph().hasNode(anchor)) {
      focus.add(anchor);
      r.getGraph().forEachNeighbor(anchor, (id) => { focus.add(id); });
    }
    state.current = { ...state.current, visibleNodes, visibleEdges, selectedId, cited, hovered, pointer, focus };
    r?.refresh({ skipIndexation: true });
    measure();
  }, [visibleNodes, visibleEdges, selectedId, cited, hovered, pointer]); // eslint-disable-line react-hooks/exhaustive-deps

  // Nouveaux nœuds HTML : placés avant d'être peints
  useLayoutEffect(place, [overlay]); // eslint-disable-line react-hooks/exhaustive-deps

  // Une sélection venue d'ailleurs (recherche, puce de l'assistant) amène la caméra sur le nœud
  useEffect(() => {
    const r = sigma.current;
    if (!r || !selectedId || !r.getGraph().hasNode(selectedId)) return;
    const pos = r.getNodeDisplayData(selectedId);
    if (pos) r.getCamera().animate({ x: pos.x, y: pos.y, ratio: Math.min(r.getCamera().ratio, 0.5) }, { duration: reduced() ? 0 : 450 });
  }, [selectedId]);

  const s = state.current;
  const focus = s.focus;
  const lod = overlay.lod;
  const important = (id: string) => {
    const n = byId.current.get(id)!;
    return isRectangular(n.type) || (degree.current.get(id) ?? 0) >= 6;
  };
  return (
    <div className="absolute inset-0 overflow-hidden" style={{ backgroundImage: "radial-gradient(#1f2b39 1px, transparent 1px)", backgroundSize: "24px 24px" }}>
      <div ref={container} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0">
        {lod !== "dots" && overlay.ids.map((id) => {
          const n = byId.current.get(id);
          if (!n) return null;
          const look: MarkState = id === selectedId ? "select" : cited.has(id) || id === hovered ? "cited" : focus.size > 0 && !focus.has(id) ? "dim" : "none";
          const label = lod === "full" || look === "select" || look === "cited" || id === pointer || (lod === "medium" && important(id) && look !== "dim");
          return (
            <div key={id} ref={(el) => { if (el) marks.current.set(id, el); else marks.current.delete(id); }} className="absolute left-0 top-0" style={{ zIndex: look === "dim" ? 0 : look !== "none" ? 4 : isRectangular(n.type) ? 2 : 1 }}>
              <NodeMark node={n} radius={isRectangular(n.type) && lod !== "small" ? RADIUS[lod] * 1.1 : RADIUS[lod]} state={look} label={label} />
            </div>
          );
        })}
      </div>
      {layingOut && <div className="pointer-events-none absolute bottom-3 left-1/2 -translate-x-1/2 rounded border border-line bg-panel px-3 py-1 text-xs text-muted">Disposition du graphe en cours…</div>}
      {lod === "dots" && !layingOut && <div className="pointer-events-none absolute bottom-3 left-1/2 -translate-x-1/2 rounded border border-line bg-panel px-3 py-1 text-xs text-muted">Zoomez pour afficher les glyphes et les noms</div>}
      <div className="absolute bottom-3 right-3 flex flex-col overflow-hidden rounded border border-line bg-panel">
        {([["Zoom avant", "+", () => sigma.current?.getCamera().animatedZoom({ duration: 200 })], ["Zoom arrière", "−", () => sigma.current?.getCamera().animatedUnzoom({ duration: 200 })], ["Ajuster à la vue", "⤢", () => sigma.current?.getCamera().animatedReset({ duration: 300 })]] as const).map(([label, sign, act]) => (
          <button key={label} aria-label={label} title={label} onClick={act} className="h-8 w-8 border-b border-line text-muted last:border-0 hover:bg-raised hover:text-ink">{sign}</button>
        ))}
      </div>
    </div>
  );
}

