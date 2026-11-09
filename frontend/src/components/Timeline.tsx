import clsx from "clsx";
import { useState } from "react";

const MONTHS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];
export const monthLabel = (key: string) => `${MONTHS[Number(key.slice(5, 7)) - 1]} ${key.slice(0, 4)}`;

/** Histogramme des publications des articles sources ; glisser sur les barres retient une période (un clic : un mois). */
export function Timeline({ bins, period, onPeriod }: { bins: { month: string; count: number }[]; period: [string, string] | null; onPeriod: (p: [string, string] | null) => void }) {
  const [drag, setDrag] = useState<[number, number] | null>(null);
  if (bins.length === 0) return null;
  const max = Math.max(...bins.map((b) => b.count), 1);
  const range = drag ? [Math.min(...drag), Math.max(...drag)] : period ? [bins.findIndex((b) => b.month === period[0]), bins.findIndex((b) => b.month === period[1])] : null;
  const finish = () => {
    if (drag) onPeriod([bins[Math.min(...drag)].month, bins[Math.max(...drag)].month]);
    setDrag(null);
  };
  const ticks = [0, Math.floor(bins.length / 3), Math.floor((2 * bins.length) / 3), bins.length - 1].filter((v, i, a) => a.indexOf(v) === i);
  return (
    <div className="shrink-0 select-none border-t border-line bg-panel px-4 pb-2 pt-2.5">
      <div className="mb-1.5 flex items-baseline justify-between gap-4">
        <span className="font-display text-sm font-semibold">Publications des articles sources</span>
        <span className="text-xs text-muted">
          {period ? `Période retenue : ${monthLabel(period[0])} à ${monthLabel(period[1])}` : "Glissez sur les barres pour retenir une période"}
          {period && <button onClick={() => onPeriod(null)} className="ml-3 text-accent hover:underline">Toute la période</button>}
        </span>
      </div>
      <div className="flex h-12 items-end gap-[2px]" onMouseLeave={finish} onMouseUp={finish}>
        {bins.map((b, i) => {
          const inRange = range && i >= range[0] && i <= range[1];
          return (
            <div
              key={b.month} title={`${monthLabel(b.month)} : ${b.count} article${b.count > 1 ? "s" : ""}`}
              onMouseDown={() => setDrag([i, i])} onMouseEnter={() => drag && setDrag([drag[0], i])}
              className="flex h-full max-w-[28px] flex-1 cursor-crosshair items-end"
            >
              <div className={clsx("w-full rounded-t-[1px]", inRange ? "bg-accent" : range ? "bg-line-strong/60" : "bg-line-strong")} style={{ height: `${Math.max(b.count ? 8 : 2, (b.count / max) * 100)}%` }} />
            </div>
          );
        })}
      </div>
      <div className="mt-1 flex gap-[2px] text-[11px] tabular-nums text-faint">
        {bins.map((b, i) => (
          <span key={b.month} className="relative h-4 max-w-[28px] flex-1">
            {ticks.includes(i) && <span className="absolute left-0 whitespace-nowrap">{monthLabel(b.month)}</span>}
          </span>
        ))}
      </div>
    </div>
  );
}
