import { CornerDownLeft, Share2 } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../lib/api";
import { glyphOf } from "../lib/icons";
import { splitCitations } from "../lib/kg";
import { FAMILY } from "../lib/theme";
import type { AskEvent, CitedEntity, KgNode } from "../types";

interface Exchange {
  question: string;
  steps: Extract<AskEvent, { type: "step" }>[];
  answer?: Extract<AskEvent, { type: "answer" }>;
  error?: string;
}

const TOOL_LABEL: Record<string, string> = { search_entities: "Recherche", get_entity: "Fiche", neighbors: "Voisins", paths: "Chemins", top: "Classement" };
const argText = (args: Record<string, unknown>) => Object.values(args).filter((v) => v != null && v !== "").map(String).join(", ");

/** Questions de départ : générales sans sélection, sinon adaptées au type de l'entité sélectionnée. */
function suggestions(n: KgNode | null): string[] {
  if (!n) return ["Quels acteurs sont cités par le plus d'articles ?", "Quelles techniques reviennent le plus souvent ?", "Quelles infrastructures sont partagées par plusieurs malwares ?"];
  if (n.family === "actor") return [`Quels malwares et outils ${n.label} utilise-t-il ?`, `Quels secteurs et pays ${n.label} cible-t-il ?`];
  if (n.family === "malware" || n.family === "tool") return [`Quels acteurs utilisent ${n.label} ?`, `Quelles infrastructures sont liées à ${n.label} ?`];
  if (n.family === "technique") return [`Quels acteurs emploient ${n.label} ?`, `Quels malwares mettent en œuvre ${n.label} ?`];
  return [`Que dit le graphe de ${n.label} ?`, `Quelles entités sont reliées à ${n.label} ?`];
}

function Chip({ e, onHover, onPick }: { e: CitedEntity; onHover: (id: string | null) => void; onPick: (id: string) => void }) {
  const Icon = glyphOf({ type: e.type });
  return (
    <button
      onMouseEnter={() => onHover(e.id)} onMouseLeave={() => onHover(null)} onFocus={() => onHover(e.id)} onBlur={() => onHover(null)} onClick={() => onPick(e.id)}
      className="mx-0.5 inline-flex items-center gap-1 rounded-sm border border-cited px-1 align-baseline leading-[18px] text-ink hover:bg-cited/10"
    >
      <Icon size={12} color={FAMILY[e.family].color} strokeWidth={2} className="shrink-0" />
      {e.label}
    </button>
  );
}

export function AskPanel({ selected, onCited, onHover, onPick, onIsolate }: {
  selected: KgNode | null;
  onCited: (ids: Set<string>) => void;
  onHover: (id: string | null) => void;
  onPick: (id: string) => void;
  onIsolate: (ids: string[]) => void;
}) {
  const [thread, setThread] = useState<Exchange[]>([]);
  const [draft, setDraft] = useState("");
  const [pending, setPending] = useState(false);
  const end = useRef<HTMLDivElement>(null);
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => abort.current?.abort(), []);
  useEffect(() => end.current?.scrollIntoView({ block: "end" }), [thread]);

  const send = async (question: string) => {
    if (!question.trim() || pending) return;
    // échanges précédents rejoués en texte : les repères [[E3]] d'une réponse ne valent que pour elle, ils sont remplacés par les noms
    const history = thread.filter((x) => x.answer).slice(-3).map((x) => ({
      question: x.question,
      answer: splitCitations(x.answer!.text).map((p) => ("text" in p ? p.text : x.answer!.entities.find((e) => e.handle === p.handle)?.label ?? "")).join(""),
    }));
    const index = thread.length;
    const update = (fn: (x: Exchange) => Exchange) => setThread((t) => t.map((x, i) => (i === index ? fn(x) : x)));
    setThread((t) => [...t, { question, steps: [] }]);
    setDraft("");
    setPending(true);
    abort.current = new AbortController();
    try {
      await api.ask({ question, focus: selected?.id ?? null, history }, (e) => {
        if (e.type === "step") update((x) => ({ ...x, steps: [...x.steps, e] }));
        else if (e.type === "answer") { update((x) => ({ ...x, answer: e })); onCited(new Set(e.entities.map((c) => c.id))); }
        else update((x) => ({ ...x, error: e.message }));
      }, abort.current.signal);
    } catch (err) {
      if ((err as Error).name !== "AbortError") update((x) => ({ ...x, error: `Le dashboard ne répond pas (${(err as Error).message}).` }));
    } finally {
      setPending(false);
    }
  };
  const submit = (ev: FormEvent) => { ev.preventDefault(); void send(draft); };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <h2 className="flex-1 font-display text-[15px] font-semibold">Interroger le graphe</h2>
        {thread.length > 0 && !pending && <button onClick={() => { setThread([]); onCited(new Set()); }} className="text-xs text-muted hover:text-ink">Nouvelle conversation</button>}
      </header>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
        {thread.length === 0 && (
          <p className="text-sm text-muted">
            Posez une question sur les acteurs, malwares, techniques ou infrastructures du graphe. L'assistant cherche dans le graphe et cite chaque entité qu'il mentionne : survolez une citation pour la repérer, cliquez pour la sélectionner.
          </p>
        )}
        {thread.map((x, i) => (
          <div key={i} className="space-y-2.5">
            <div className="ml-auto w-fit max-w-[85%] rounded bg-raised px-3 py-2 text-sm">{x.question}</div>
            {x.steps.length > 0 && (
              <details className="rounded border border-line text-xs text-muted" open={!x.answer && !x.error}>
                <summary className="cursor-pointer px-2.5 py-1.5">
                  {x.steps.length} recherche{x.steps.length > 1 ? "s" : ""}, {x.answer?.consulted ?? x.steps.reduce((s, st) => s + st.count, 0)} entités consultées
                </summary>
                <ol className="list-decimal space-y-0.5 py-1.5 pl-8 pr-2.5">
                  {x.steps.map((st, j) => <li key={j}><span className="text-ink">{TOOL_LABEL[st.tool] ?? st.tool}</span> {argText(st.args)}</li>)}
                </ol>
              </details>
            )}
            {!x.answer && !x.error && <p className="text-xs text-muted">Recherche dans le graphe…</p>}
            {x.error && <p className="text-sm text-danger">{x.error}</p>}
            {x.answer && (
              <>
                <p className="whitespace-pre-line text-sm leading-[22px]">
                  {splitCitations(x.answer.text).map((p, j) => {
                    if ("text" in p) return <span key={j}>{p.text}</span>;
                    const e = x.answer!.entities.find((c) => c.handle === p.handle);
                    return e ? <Chip key={j} e={e} onHover={onHover} onPick={onPick} /> : null;
                  })}
                </p>
                {x.answer.entities.length > 1 && (
                  <button onClick={() => onIsolate(x.answer!.entities.map((e) => e.id))} className="flex items-center gap-1.5 rounded border border-line-strong bg-raised px-2.5 py-1.5 text-xs hover:border-cited">
                    <Share2 size={13} className="text-cited" /> Isoler les {x.answer.entities.length} entités citées
                  </button>
                )}
              </>
            )}
          </div>
        ))}
        {!pending && (
          <div className="space-y-1.5">
            {selected && <p className="text-xs text-muted">À partir de votre sélection ({selected.label})</p>}
            {suggestions(selected).map((s) => (
              <button key={s} onClick={() => void send(s)} className="block w-full rounded border border-line px-2.5 py-1.5 text-left text-sm hover:border-line-strong hover:bg-raised">{s}</button>
            ))}
          </div>
        )}
        <div ref={end} />
      </div>

      <form onSubmit={submit} className="space-y-1.5 border-t border-line px-4 py-3">
        <label htmlFor="ask" className="text-xs text-muted">Votre question</label>
        <div className="flex items-end gap-2">
          <textarea
            id="ask" rows={2} value={draft} onChange={(e) => setDraft(e.target.value)} disabled={pending}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(draft); } }}
            placeholder="Ex. : quelles techniques partagent ces deux acteurs ?"
            className="min-w-0 flex-1 resize-none rounded border border-line bg-bg px-2.5 py-2 text-sm placeholder:text-faint focus:border-accent focus:outline-none disabled:opacity-60"
          />
          <button type="submit" disabled={pending || !draft.trim()} className="flex h-11 items-center gap-1.5 rounded bg-accent px-3.5 text-sm font-semibold text-[#0a1220] disabled:opacity-40">
            <CornerDownLeft size={14} /> Envoyer
          </button>
        </div>
      </form>
    </div>
  );
}
