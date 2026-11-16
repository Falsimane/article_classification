"""Étape 3 : les techniques, tactique par tactique, pour chaque grappe de l'incident.

3a. La grille : une case par tactique ATT&CK v20, remplie des procédures du centre ou laissée vide.
3b. Le choix : pour chaque case remplie, la technique dans la liste COMPLÈTE de la tactique (parentes et sous-techniques),
    sans recherche qui la tronque ; la liste est dans le message système (relue depuis le cache pour chaque grappe).
Le code écrit `centre --uses--> technique` (procédure en description, phrases citées) ; une technique d'une grappe sans
porteur nommé entre dans le rapport sans relation. Aucun raisonnement sur le choix : il dégrade les techniques (Qian 2026)."""

import os
from functools import cache

from backend.extracting import llm
from backend.extracting.cascade.clusters import Cluster
from backend.extracting.cascade.graph import Call, ref
from backend.extracting.cascade.schemas import choice_schema, grid_schema
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.attack import get_attack_kb
from backend.preprocessing.cleaning.text.evidence import mentions

GRID_TOKENS = 2500
CHOICE_TOKENS = 400
SUMMARY_CHARS = 140
# « global » : parente parmi les 227 techniques, puis sous-technique (une procédure rangée sous la mauvaise tactique reste
# trouvable) ; « tactic » : liste fermée de la tactique de la grille (v1, cascade_a / cascade_b)
CHOICE_MODE = os.environ.get("CTI_CASCADE_CHOICE", "global").strip().lower()

GRID_SYSTEM = """You map the behaviours of one attacker-side entity (the "center") to the MITRE ATT&CK v20 tactics.
You receive the center and the numbered passages [n] that describe it.
For EACH tactic, list the concrete procedures OF THE CENTER that serve it, as short prose
("sends spearphishing emails with a malicious attachment", "decrypts its payload with a hardcoded XOR key").
Leave a tactic empty when the passages show no behaviour of the center for it: an empty tactic is the normal answer.
Only behaviours the passages state; no generic capability, no guess, nothing the passages attribute to another entity.
Carrier rule: what the code of a malware or tool does (decrypt itself, contact its server, persist, steal data) belongs to that
malware or tool; what the operators do (send the emails, pick the victims, deploy or sign the malware, rent or compromise
infrastructure, exploit a vulnerability) belongs to the named group or, without a named group, to the campaign.
A third-party tool only carries what the tool itself does when it runs; what the operators do to it or with it (rename,
disguise, deliver, run it) belongs to the operators.
Boundaries that are often confused:
- User Execution only when a person opens, clicks or pastes something; automatic execution by a malware, script or shortcut is not.
  A fake verification page that makes the user paste a command is not Drive-by Compromise (exploitation with no user action).
- Masquerade File Type only when a file's type is falsified; a genuine decoy document shipped with the payload is not.
- Software Packing is the compression or encryption of an executable; obfuscating a macro or a script is not.
- Ingress Tool Transfer only when a transfer from outside is described; extracting an archive already on the host is not.
- Exfiltration Over C2 Channel only when the passages say the data goes through the command-and-control channel; data sent
  with another tool to an attacker address is Exfiltration Over Alternative Protocol. Web Protocols describes the C2 channel.
- Develop Capabilities only when the passages say the attacker built the tool (custom, bespoke); deploying a malware is not.
- Reconnaissance is information gathering before the attack; the victimology the report observes is not.
- Waiting for a process to end before deleting its file is File Deletion, not time-based evasion.
- Patching a security product in memory is Impair Defenses or Rootkit, not modification of a binary on disk.
- Describe only what the passages state with their own verb; never infer a behaviour from an introduction or a summary.
Each procedure cites the numbers of the passages that state it.

Tactics:
{tactics}"""

CHOICE_SYSTEM = """You choose the MITRE ATT&CK technique that each procedure is an instance of, within the tactic "{tactic}".
Pick the most specific matching entry: a sub-technique only when the procedure states the detail that defines it (protocol,
channel, storage location, direction); otherwise its parent technique.
Several techniques for one procedure only when it clearly performs several. "none" when no entry fits.

Techniques of {tactic} (ATT&CK v20):
{lines}"""


@cache
def _tactics() -> tuple[tuple[str, str, str], ...]:
    return tuple(get_attack_kb().tactic_rows())


@cache
def _choice_system(tactic: str) -> tuple[str, tuple[str, ...]]:
    hits = get_attack_kb().techniques_of_tactic(tactic)
    lines = "\n".join(f"{h.attack_id} {h.name} — {h.summary[:SUMMARY_CHARS]}" for h in hits)
    return CHOICE_SYSTEM.format(tactic=tactic, lines=lines), tuple(h.attack_id for h in hits)


def _grid_system() -> str:
    return GRID_SYSTEM.format(tactics="\n".join(f"- {t} ({name}): {summary[:200]}" for t, name, summary in _tactics()))


def _label(draft: DraftGraph, cluster: Cluster) -> str:
    return f"{draft.name_of(cluster.center)} ({draft.type_of(cluster.center)})" if cluster.center else "an attacker the report does not name"


def grid_prompt(draft: DraftGraph, title: str, cluster: Cluster) -> str:
    passages = "\n".join(f"[{n}] {draft.by_uid[n].prompt_text}" for n in cluster.sentences)
    return f"Report: {title}\nCenter: {_label(draft, cluster)}\n\nPassages:\n{passages}"


def choice_prompt(draft: DraftGraph, cluster: Cluster, procs: list[dict]) -> str:
    return f"Center: {_label(draft, cluster)}\nProcedures:\n" + "\n".join(f"{k}. {p['procedure']}" for k, p in enumerate(procs, 1))


def _evidence(draft: DraftGraph, cluster: Cluster, nums: list[int]) -> list[int]:
    """Phrases de la procédure, plus au plus deux phrases de la grappe qui nomment le centre (une procédure écrite « il
    chiffre… » cite une phrase qui ne nomme pas son malware)."""
    naming = [n for n in cluster.sentences if n not in nums and mentions(draft.by_uid[n].text, draft.terms.get(cluster.center, set()))]
    return nums + naming[:2]


def _write(draft: DraftGraph, cluster: Cluster, aid: str, proc: dict, result) -> None:
    nums = [n for n in dict.fromkeys(proc.get("sentences", [])) if isinstance(n, int) and n in draft.by_uid]
    if not nums:
        result.refused_techniques.append((f"{aid} {proc['procedure']}", "procédure sans phrase valide"))
        result.refused += 1
        return
    if cluster.center is None:
        sid, err = draft.technique(aid)
        if sid:
            draft.kept.add(sid)
    else:
        line = f"{ref(draft, cluster.center)}|uses|{aid}|"
        err = draft.relate(line + ",".join(map(str, nums)))
        if err and "ne nomment pas" in err:
            err = draft.relate(line + ",".join(map(str, _evidence(draft, cluster, nums))))
        sid = draft.names.get(aid)
        if err:
            result.refused_relations.append((cluster.center, "uses", sid or aid, err.split(" : ", 1)[-1]))
    if err:
        draft.log.append(f"reject {aid} pour {_label(draft, cluster)} : {err}")
        result.refused += 1
        return
    result.accepted += 1
    known = draft.procedures.setdefault(sid, [])
    if proc["procedure"] not in known:
        known.append(proc["procedure"])


PARENT_SYSTEM = """You choose the MITRE ATT&CK technique that each procedure is an instance of.
The tactic in brackets is only a hint: a procedure may belong to a technique listed under another tactic.
Several techniques for one procedure only when it clearly performs several. "none" when no technique fits.

Techniques (ATT&CK v20, parent techniques):
{lines}"""

SUB_SYSTEM = """For each procedure, a parent MITRE ATT&CK technique was chosen. Choose the most specific entry among the options:
a sub-technique when the procedure matches it, otherwise the parent itself."""


@cache
def _parent_system() -> tuple[str, tuple[str, ...]]:
    hits = get_attack_kb().parent_techniques()
    lines = "\n".join(f"{h.attack_id} {h.name} [{', '.join(h.tactics)}] — {h.summary[:SUMMARY_CHARS]}" for h in hits)
    return PARENT_SYSTEM.format(lines=lines), tuple(h.attack_id for h in hits)


@cache
def _children(parent: str) -> tuple[tuple[str, str], ...]:
    """(identifiant, « nom — résumé ») des sous-techniques actives d'une parente."""
    kb = get_attack_kb()
    return tuple((aid, f"{name} — {(kb.get(aid) or {}).get('summary', '')[:SUMMARY_CHARS]}") for aid, name in kb.subtechniques(parent))


def _pairs(answer: dict, n: int, allowed: set[str]) -> dict[int, list[str]]:
    """{numéro de procédure: techniques choisies}, réponses hors liste ou tronquées ignorées."""
    out: dict[int, list[str]] = {}
    for c in answer.get("choices", []):
        k, aid = c.get("procedure"), c.get("technique")
        if isinstance(k, int) and 1 <= k <= n and aid in allowed and aid not in out.setdefault(k, []):
            out[k].append(aid)
    return out


def choose_global(draft: DraftGraph, cluster: Cluster, procs: list[tuple[str, dict]], call: Call) -> dict[int, list[str]]:
    """Parente dans la liste fermée des 227 techniques (toutes tactiques), puis sous-technique parmi ses enfants."""
    system, ids = _parent_system()
    listing = "\n".join(f"{k}. [{t}] {p['procedure']}" for k, (t, p) in enumerate(procs, 1))
    prompt = f"Center: {_label(draft, cluster)}\nProcedures:\n{listing}"
    parents = _pairs(call("choice:parent", system, prompt, choice_schema(len(procs), list(ids)), 60 + 40 * len(procs)), len(procs), set(ids))
    picks = [(k, aid) for k, chosen in sorted(parents.items()) for aid in chosen if _children(aid)]
    final = {k: list(v) for k, v in parents.items()}
    if not picks:
        return final
    blocks, options = [], set()
    for m, (k, aid) in enumerate(picks, 1):
        rows = [f"   {aid} (the parent itself)"] + [f"   {cid} {label}" for cid, label in _children(aid)]
        options |= {aid, *(cid for cid, _ in _children(aid))}
        blocks.append(f"{m}. {procs[k - 1][1]['procedure']}\n" + "\n".join(rows))
    prompt = f"Center: {_label(draft, cluster)}\n\n" + "\n\n".join(blocks)
    subs = _pairs(call("choice:sub", SUB_SYSTEM, prompt, choice_schema(len(picks), sorted(options)), 60 + 40 * len(picks)), len(picks), options)
    for m, (k, aid) in enumerate(picks, 1):
        chosen = [s for s in subs.get(m, []) if s == aid or s.startswith(f"{aid}.")]
        if chosen:  # la sous-technique remplace sa parente ; une réponse hors des enfants garde la parente
            rest = [x for x in final[k] if x != aid]
            final[k] = rest + [s for s in chosen if s not in rest]
    return final


def attach_techniques(draft: DraftGraph, title: str, clusters: list[Cluster], result, call: Call) -> None:
    incident = [c for c in clusters if c.scope == "incident"]
    tactics = [t for t, _, _ in _tactics()]
    grid_system = _grid_system()
    grids = llm.map_parallel(lambda c: call("grid", grid_system, grid_prompt(draft, title, c), grid_schema(tactics), GRID_TOKENS), incident)
    if CHOICE_MODE == "global":
        work = [(c, [(t, p) for t in tactics for p in (g.get(t) or []) if isinstance(p, dict) and p.get("procedure")]) for c, g in zip(incident, grids)]
        work = [w for w in work if w[1]]
        answers = llm.map_parallel(lambda w: choose_global(draft, w[0], w[1], call), work)
        _, ids = _parent_system()
        for (cluster, procs), chosen in zip(work, answers):
            for k, (tactic, proc) in enumerate(procs, 1):
                result.behaviors.append({
                    "uids": proc.get("sentences", []), "text": proc["procedure"], "tactic": tactic,
                    "center": cluster.center, "candidates": list(ids), "chosen": chosen.get(k, []),
                })  # fmt: skip
                for aid in chosen.get(k, []):
                    _write(draft, cluster, aid, proc, result)
        return
    jobs = [(c, t, [p for p in g[t] if isinstance(p, dict) and p.get("procedure")]) for c, g in zip(incident, grids) for t in tactics if g.get(t)]
    jobs = [j for j in jobs if j[2]]

    def choose(job):
        cluster, tactic, procs = job
        system, ids = _choice_system(tactic)
        return call(f"choice:{tactic}", system, choice_prompt(draft, cluster, procs), choice_schema(len(procs), list(ids)), CHOICE_TOKENS)

    answers = llm.map_parallel(choose, jobs)
    for (cluster, tactic, procs), answer in zip(jobs, answers):
        chosen: dict[int, list[str]] = {}
        for c in answer.get("choices", []):
            if not isinstance(c.get("procedure"), int) or not 1 <= c["procedure"] <= len(procs) or not c.get("technique"):
                continue
            if c["technique"] != "none" and c["technique"] not in chosen.setdefault(c["procedure"], []):
                chosen[c["procedure"]].append(c["technique"])
        _, ids = _choice_system(tactic)
        for k, proc in enumerate(procs, 1):
            result.behaviors.append({
                "uids": proc.get("sentences", []), "text": proc["procedure"], "tactic": tactic,
                "center": cluster.center, "candidates": list(ids), "chosen": chosen.get(k, []),
            })  # fmt: skip
            for aid in chosen.get(k, []):
                _write(draft, cluster, aid, proc, result)
