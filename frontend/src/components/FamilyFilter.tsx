import clsx from "clsx";
import { FAMILY } from "../lib/theme";
import type { Family } from "../types";

export function FamilyFilter({ value, onChange }: { value: Family | "all"; onChange: (f: Family | "all") => void }) {
  const items: [Family | "all", string, string?][] = [["all", "Tout"], ...(Object.entries(FAMILY) as [Family, { label: string; color: string }][]).map(([k, v]): [Family, string, string] => [k, v.label, v.color])];
  return (
    <div className="flex flex-wrap gap-1">
      {items.map(([id, label, color]) => (
        <button
          key={id} onClick={() => onChange(id)}
          className={clsx("flex items-center gap-1.5 border px-2 py-0.5 text-xs", value === id ? "border-accent bg-raised text-ink" : "border-line text-muted hover:border-line-strong")}
        >
          {color && <span className="h-1.5 w-1.5" style={{ background: color }} />}
          {label}
        </button>
      ))}
    </div>
  );
}
