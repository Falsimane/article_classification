import clsx from "clsx";
import { glyphOf, isoOf, isRectangular } from "../lib/icons";
import { FAMILY, STATE, captionOf } from "../lib/theme";
import type { Family } from "../types";

export type MarkState = "none" | "select" | "cited" | "dim";

export interface Markable {
  label: string;
  type: string;
  family: Family;
  kinds?: string[];
  tactics?: string[];
  identity_class?: string | null;
  sectors?: string[];
  country?: string | null;
  is_dual_use?: boolean;
  ioc_count?: number;
}

/** Largeur d'une tuile d'acteur pour un rayon de disque donné (graphe de rapport : rayon 26). */
export const tileWidth = (radius: number) => Math.round(radius * 7);

/** Nœud dessiné en HTML (net à tout zoom) : disque avec glyphe et nom dessous, ou tuile pour un acteur de la menace. Partagé
 * par le graphe d'un rapport (React Flow) et le graphe global (au-dessus du canvas sigma). Centré sur son point d'ancrage. */
export function NodeMark({ node, radius, state = "none", label = true }: { node: Markable; radius: number; state?: MarkState; label?: boolean }) {
  const color = FAMILY[node.family].color;
  const Icon = glyphOf(node);
  const iso = isoOf(node);
  const ring = state === "select" ? STATE.select : state === "cited" ? STATE.cited : null;
  const halo = ring ? { boxShadow: `0 0 0 3px ${STATE.canvas}, 0 0 0 ${state === "select" ? 5 : 4}px ${ring}` } : undefined;
  const glyph = Math.round(radius * 0.85);
  const small = radius < 16;

  if (isRectangular(node.type)) {
    const h = Math.max(radius * 1.85, 26);
    return (
      <div
        className={clsx("flex items-center gap-2 rounded border-[1.5px] bg-panel px-2 transition-opacity duration-150", state === "dim" && "opacity-25")}
        style={{ width: small ? undefined : tileWidth(radius), maxWidth: small ? 170 : undefined, height: h, borderColor: color, boxShadow: `inset 4px 0 0 ${color}${halo ? `, ${halo.boxShadow}` : ""}`, transform: "translate(-50%, -50%)" }}
      >
        <Icon size={glyph} color={color} strokeWidth={1.75} className="ml-0.5 shrink-0" />
        <div className="min-w-0">
          <div className={clsx("truncate font-semibold leading-4", small ? "text-xs" : "text-sm", state === "select" ? "text-select" : "text-ink")}>{node.label}</div>
          {label && !small && <div className="truncate text-[11px] leading-4 text-muted">{captionOf(node)}</div>}
        </div>
      </div>
    );
  }
  return (
    <div className={clsx("relative transition-opacity duration-150", state === "dim" && "opacity-25")} style={{ width: radius * 2, height: radius * 2, transform: "translate(-50%, -50%)" }}>
      <div className="flex h-full w-full items-center justify-center rounded-full bg-panel" style={{ border: `${small ? 1.5 : 2}px solid ${color}`, ...halo }}>
        {iso ? (
          <span className="font-display font-semibold tracking-wide" style={{ color, fontSize: Math.round(radius * 0.66) }}>{iso}</span>
        ) : (
          <Icon size={glyph} color={color} strokeWidth={small ? 2 : 1.75} />
        )}
      </div>
      {node.is_dual_use && <span className="absolute -right-0.5 -top-0.5 h-[10px] w-[10px] rotate-45 border-2 border-bg bg-warn" title="Outil légitime détourné" />}
      {!!node.ioc_count && (
        <span className="absolute -right-5 -top-2 rounded-sm border border-line-strong bg-raised px-1 text-[11px] leading-4 text-ink" title={`${node.ioc_count} indicateurs rattachés à cette infrastructure`}>
          {node.ioc_count} IOC
        </span>
      )}
      {label && (
        <div className="pointer-events-none absolute left-1/2 top-full mt-1.5 w-max max-w-[10rem] -translate-x-1/2 rounded-sm bg-bg/85 px-1 text-center">
          <div className={clsx("truncate text-xs font-semibold leading-4", state === "select" ? "text-select" : "text-ink")}>{node.label}</div>
          {!small && <div className="truncate text-[11px] leading-[13px] text-muted">{captionOf(node)}</div>}
        </div>
      )}
    </div>
  );
}
