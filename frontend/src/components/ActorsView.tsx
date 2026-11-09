import clsx from "clsx";
import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { iconOf } from "../lib/icons";
import { techniqueCount, type Tab } from "../lib/org";
import { FAMILY, typeLabel } from "../lib/theme";
import { useAsync } from "../lib/useAsync";
import type { ActorProfile } from "../types";
import { EntryTable } from "./EntryTable";
import { IocTable } from "./IocTable";
import { OrgChart } from "./OrgChart";

const Empty = ({ children }: { children: string }) => <div className="flex h-full items-center justify-center p-8 text-sm text-faint">{children}</div>;
const Group = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <section>
    <h3 className="border-b border-line bg-panel px-6 py-1.5 text-xs font-semibold text-muted">{title}</h3>
    {children}
  </section>
);

const TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "stealth", "defense-evasion", "defense-impairment", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"];
const tacticRank = (t: string) => (TACTIC_ORDER.indexOf(t) === -1 ? 99 : TACTIC_ORDER.indexOf(t));

function TabContent({ tab, data, onOpen }: { tab: Tab; data: ActorProfile; onOpen: (t: Tab) => void }) {
  const p = data.profile;
  switch (tab) {
    case "org":
      return <OrgChart data={data} onOpen={onOpen} />;
    case "arsenal":
      return (
        <div className="h-full overflow-y-auto">
          <Group title={`Malwares (${p.malware.length})`}><EntryTable entries={p.malware} empty="Aucun malware attribué à cet acteur." /></Group>
          <Group title={`Outils (${p.tools.length})`}><EntryTable entries={p.tools} empty="Aucun outil attribué à cet acteur." /></Group>
        </div>
      );
    case "techniques": {
      const tactics = Object.keys(p.techniques).sort((a, b) => tacticRank(a) - tacticRank(b));
      return (
        <div className="h-full overflow-y-auto">
          {tactics.length === 0 && <p className="px-6 py-8 text-sm text-faint">Aucune technique ATT&CK attribuée à cet acteur.</p>}
          {tactics.map((t) => (<Group key={t} title={`${t} (${p.techniques[t].length})`}><EntryTable entries={p.techniques[t]} empty="" /></Group>))}
        </div>
      );
    }
    case "infrastructure":
      return (
        <div className="h-full overflow-y-auto">
          <Group title={`Infrastructure (${p.infrastructure.length})`}><EntryTable entries={p.infrastructure} empty="Aucune infrastructure directement attribuée." /></Group>
          <Group title={`Indicateurs rattachés (${data.iocs.length})`}><IocTable rows={data.iocs} empty="Aucun indicateur n'est rattaché à cet acteur ni à ses outils." /></Group>
        </div>
      );
    case "targets":
      return (
        <div className="h-full overflow-y-auto">
          <Group title={`Victimes et régions (${p.targets.length})`}><EntryTable entries={p.targets} empty="Aucune cible connue." /></Group>
          <Group title={`Vulnérabilités exploitées (${p.vulnerabilities.length})`}><EntryTable entries={p.vulnerabilities} empty="Aucune vulnérabilité connue." /></Group>
        </div>
      );
    case "references":
      return (
        <div className="h-full overflow-y-auto">
          <Group title={`Rapports sources (${data.reports.length})`}>
            <ul>
              {data.reports.map((r) => (
                <li key={r.id} className="border-b border-line px-6 py-3">
                  <a href={r.url} target="_blank" rel="noreferrer noopener" className="text-sm text-accent hover:underline">{r.title}</a>
                  <div className="mt-0.5 text-xs text-faint">{r.site_name} · {r.published ?? "date inconnue"} · {r.category}</div>
                </li>
              ))}
            </ul>
          </Group>
          {data.actor.aliases.length > 0 && <Group title="Alias"><p className="px-6 py-3 text-sm">{data.actor.aliases.join(", ")}</p></Group>}
          {data.actor.references.length > 0 && <Group title="Références externes"><p className="px-6 py-3 font-mono text-sm">{data.actor.references.map((r) => `${r.source} ${r.id}`).join(" · ")}</p></Group>}
        </div>
      );
  }
}

export function ActorsView() {
  const actors = useAsync(api.actors, []);
  const [actorId, setActorId] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>(() => {
    const t = new URLSearchParams(location.search).get("tab");
    return (["org", "arsenal", "techniques", "infrastructure", "targets", "references"] as const).find((x) => x === t) ?? "org";
  });
  const firstActor = useRef(true);
  const list = actors.data ?? [];
  useEffect(() => { if (!actorId && list.length) setActorId(list[0].id); }, [list, actorId]);
  useEffect(() => {
    if (actorId && firstActor.current) { firstActor.current = false; return; }  // l'onglet demandé par l'URL survit au premier chargement
    setTab("org");
  }, [actorId]);

  const profile = useAsync(() => (actorId ? api.actor(actorId) : Promise.resolve(null)), [actorId]);
  const data = profile.data;

  if (actors.error) return <Empty>{actors.error}</Empty>;
  if (!actors.loading && list.length === 0) return <Empty>Aucun acteur dans le graphe STIX.</Empty>;

  const p = data?.profile;
  const tabs: [Tab, string, number | null][] = [
    ["org", "Organigramme", null],
    ["arsenal", "Arsenal", p ? p.malware.length + p.tools.length : null],
    ["techniques", "Techniques", p ? techniqueCount(p) : null],
    ["infrastructure", "Infrastructure", data ? data.profile.infrastructure.length + data.iocs.length : null],
    ["targets", "Cibles", p ? p.targets.length + p.vulnerabilities.length : null],
    ["references", "Références", data ? data.reports.length : null],
  ];
  const Icon = data ? iconOf(data.actor.type) : null;

  return (
    <div className="grid h-full grid-cols-[300px_1fr]">
      <aside className="overflow-y-auto border-r border-line bg-panel">
        <h2 className="border-b border-line px-4 py-2 text-xs font-semibold text-muted">Acteurs ({list.length})</h2>
        <ul>
          {list.map((a) => {
            const I = iconOf(a.type);
            return (
              <li key={a.id}>
                <button onClick={() => setActorId(a.id)} className={clsx("flex w-full items-start gap-2.5 border-b border-line px-4 py-2.5 text-left", a.id === actorId ? "bg-raised" : "hover:bg-raised/50")}>
                  <I size={16} color={FAMILY.actor.color} strokeWidth={1.75} className="mt-0.5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{a.label}</div>
                    <div className="mt-0.5 flex gap-3 text-xs text-faint">
                      <span>{typeLabel(a.type)}</span><span className="ml-auto">{a.relations} rel · {a.reports} art.</span>
                    </div>
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      </aside>

      <section className="flex min-w-0 flex-col">
        {profile.error && <Empty>{profile.error}</Empty>}
        {data && Icon && (
          <>
            <header className="flex items-center gap-3 border-b border-line bg-panel px-6 py-3">
              <Icon size={22} color={FAMILY.actor.color} strokeWidth={1.75} />
              <div>
                <h2 className="text-lg font-semibold leading-6">{data.actor.label}</h2>
                <div className="text-xs font-semibold text-muted">{typeLabel(data.actor.type)}{data.actor.aliases.length > 0 && ` · alias ${data.actor.aliases.join(", ")}`}</div>
              </div>
            </header>
            <nav className="flex border-b border-line bg-panel px-3">
              {tabs.map(([id, label, count]) => (
                <button key={id} onClick={() => setTab(id)} className={clsx("border-b-2 px-4 py-2 text-sm", tab === id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink")}>
                  {label}{count != null && <span className="ml-1.5 font-mono text-xs text-faint">{count}</span>}
                </button>
              ))}
            </nav>
            <div className="min-h-0 flex-1"><TabContent tab={tab} data={data} onOpen={setTab} /></div>
          </>
        )}
      </section>
    </div>
  );
}
