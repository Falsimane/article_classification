"""Agent d'extraction du Knowledge Graph : articles classifiés -> bundle STIX 2.1 (bibliothèque `stix2`) -> Neo4j.

    uv run cti-agent --limit 10                          # les 10 prochains articles non extraits, vers Neo4j
    uv run cti-agent --article-id 1553 --dry-run         # sans écrire dans Neo4j
    uv run cti-agent --article-id 1553 --show-tools      # chaque appel d'outil et son résultat
    uv run cti-agent --stats

    [Rapport brut] -> phrases numérotées -> passages
        pour chaque passage, une conversation avec outils (appel natif d'Ollama, `/api/chat`) :
          1. le modèle repère acteurs, campagnes, malwares, outils, CVE et comportements de l'attaquant ;
          2. lookup_name / search_attack / get_attack : il normalise chaque comportement en technique ATT&CK v20.0 ;
          3. submit : il relie les entités aux techniques (triplets STIX, preuves = numéros de phrase) ;
          4. chaque ligne est créée par `stix2` ; les refus (stix2, ATT&CK, texte) lui reviennent à corriger.
    -> IOC (valeurs par règles) et règles YARA / Sigma (texte par analyse syntaxique), rattachés aux entités retenues
    -> `stix2.Bundle` écrit dans db_outputs/stix_bundles/article_<id>.json, puis Neo4j (sans les IOC jugés bénins)
"""

import argparse
import json
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from backend.config import LLM_MODEL, OLLAMA_NUM_CTX, SOURCE_ARTICLES_DB  # noqa: E402
from backend.extracting import llm  # noqa: E402
from backend.extracting.agent_tools import DraftGraph, get_attack, lookup_name, search_attack_many  # noqa: E402
from backend.extracting.evidence import normalize_name, parse_date  # noqa: E402
from backend.extracting.iocs import IocResult, extract_iocs  # noqa: E402
from backend.extracting.rules import RuleResult, extract_rules  # noqa: E402
from backend.extracting.segment import Pass, Unit, make_passes, segment  # noqa: E402
from backend.stix.attack import get_attack_kb  # noqa: E402
from backend.stix.iocs import build_ioc_objects, without_benign  # noqa: E402
from backend.stix.objects import ENTITY_CLASSES, ArticleContext, as_dict, bundle, report  # noqa: E402
from backend.stix.rules import build_rule_objects  # noqa: E402

STIX_BUNDLES_DIR = root_dir / "db_outputs" / "stix_bundles"  # bundle final de chaque article, pour l'annotation
CATEGORIES = ("operational", "tactical", "strategic")
MAX_PASS_CHARS = 5000  # caractères d'article par conversation
MAX_TURNS = 10  # tours de modèle par passage
SUBMIT_DEADLINE = 3  # tours restants à partir desquels un passage sans soumission est relancé
MAX_OUTPUT_TOKENS = 1400  # par tour : une soumission de ~60 lignes courtes
CONTEXT_BUDGET = 0.8  # part de num_ctx au-delà de laquelle les anciens résultats d'outils sont résumés
OUTLINE_CHARS = 1500

console = Console()


# --- Outils exposés au modèle ---------------------------------------------------------------------------------------------
def tool_specs() -> list[dict]:
    tactics = [t for t, _ in get_attack_kb().tactics()]

    def fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
        return {"type": "function", "function": {"name": name, "description": description, "parameters": {"type": "object", "properties": properties, "required": required}}}

    return [
        fn(
            "search_attack",
            "Cherche dans MITRE ATT&CK v20.0 les techniques qui correspondent aux comportements de l'attaquant. Donner en UN appel "
            "la liste de TOUS les comportements du passage, une requête par comportement, en anglais avec les mots du comportement "
            "(commande, mécanisme, but), pas le nom d'un acteur. Retourne, pour chaque requête, identifiant, nom, tactiques et "
            "définition des techniques candidates.",
            {"queries": {"type": "array", "description": "une entrée par comportement", "items": {"type": "object", "properties": {
                "query": {"type": "string", "description": "comportement en anglais : « <action> <mécanisme> to <but> »"},
                "tactic": {"type": "string", "enum": tactics, "description": "facultatif : restreindre à une tactique"}},
                "required": ["query"]}}},
            ["queries"],
        ),  # fmt: skip
        fn(
            "get_attack",
            "Fiche ATT&CK v20.0 d'un identifiant (T####, T####.###, G####, S####, C####) : définition complète, tactiques, "
            "sous-techniques ou alias. À utiliser pour départager deux techniques voisines ou choisir la sous-technique.",
            {"id": {"type": "string"}},
            ["id"],
        ),
        fn(
            "lookup_name",
            "Un nom d'acteur, de malware, d'outil ou de campagne est-il connu d'ATT&CK v20.0 (alias compris) ? Donne son "
            "identifiant et son type STIX (intrusion-set, malware, tool, campaign).",
            {"name": {"type": "string"}},
            ["name"],
        ),
        fn(
            "submit",
            "Soumet les entités et relations du passage. Chaque ligne est créée par la bibliothèque stix2 et vérifiée contre "
            "ATT&CK v20.0 et le texte : les lignes valides sont ajoutées au graphe, les refus reviennent avec leur raison.",
            {
                "entities": {"type": "array", "items": {"type": "string"}, "description": "« type|nom », « type|nom|alias1;alias2 », « software|nom|éditeur », « location|nom|code pays »"},
                "relations": {"type": "array", "items": {"type": "string"}, "description": "« source|relation|cible|numéros de phrases », ex. « <malware>|uses|T####.###|42,43 »"},
            },
            ["entities", "relations"],
        ),
    ]


def system_prompt() -> str:
    return f"""Tu es analyste CTI. Tu construis la couche sémantique STIX 2.1 d'un rapport de menace : qui (acteurs, campagnes), avec quoi (malwares, outils, infrastructures nommées), comment (techniques MITRE ATT&CK v20.0), contre quoi (vulnérabilités, produit visé, victimes).

ENTITÉS (déclarées dans submit.entities, « type|nom » ; types : {', '.join(ENTITY_CLASSES)}) :
- intrusion-set : groupe d'attaquants nommé (nom ou code de suivi donné par le rapport ou un éditeur). threat-actor : personne ou organisation réelle identifiée.
- campaign : l'activité malveillante que le rapport décrit (une opération contre des cibles sur une période). Crée UNE campagne par vague distincte (cibles ou périodes différentes), avec un nom descriptif (« Campagne <acteur> contre <cible>, <période> »). Pas de campagne si le texte ne décrit aucune opération (simple analyse de vulnérabilité).
- malware : code malveillant nommé, ou composant que l'article désigne par un libellé descriptif (reprendre ce libellé).
- tool : logiciel légitime détourné par l'attaquant (binaire natif du système, outil d'administration, packer, obfuscateur).
- infrastructure : service ou infrastructure NOMMÉ utilisé par l'attaquant. Jamais une IP, un domaine ou une URL.
- vulnerability : une CVE. software : produit légitime visé, « software|<produit>|<éditeur> ».
- identity : victime (organisation, secteur) ou éditeur du produit visé. location : pays ou région ciblés (« location|<pays>|<code ISO 3166-1> »).
- attack-pattern : NE PAS déclarer. Une technique se désigne directement par son identifiant ATT&CK dans les relations (T####.###).
JAMAIS : l'auteur du rapport, les chercheurs ou éditeurs de sécurité comme acteur ; un hachage, une IP, un domaine, une URL ou un nom de fichier ordinaire (ce sont des IOC, hors périmètre).

RELATIONS (types de relation de STIX 2.1, source --relation--> cible) :
- campaign --attributed-to--> intrusion-set | threat-actor ; intrusion-set --attributed-to--> threat-actor
- intrusion-set | threat-actor | campaign | malware | tool --uses--> attack-pattern | malware | tool | infrastructure
- intrusion-set | threat-actor | campaign --targets--> identity | location | vulnerability ; malware | tool --targets--> identity | location
- attack-pattern --targets--> vulnerability | identity | location ; malware --exploits--> vulnerability
- software --has--> vulnerability ; software --related-to--> identity (éditeur)
- malware | tool --drops--> malware | tool ; malware --downloads--> malware | tool ; malware --variant-of--> malware
- malware --communicates-with | beacons-to | exfiltrates-to--> infrastructure
Format d'une relation dans submit.relations : « nom source|relation|nom cible|numéros de phrases », SANS les types, avec les noms exacts déclarés ou l'identifiant ATT&CK. Gabarits : « <malware>|uses|T####.###|42,43 », « <campagne>|attributed-to|<intrusion-set>|5 », « <software>|has|CVE-AAAA-NNNN|1 », « T####|targets|CVE-AAAA-NNNN|2 ».

MÉTHODE :
1. Lis le passage. Repère chaque comportement de l'attaquant ou d'un logiciel malveillant (exécution, persistance, découverte, communication, chiffrement, exfiltration, livraison, obfuscation…).
2. Appelle search_attack UNE fois avec la liste de TOUS les comportements repérés (une requête en anglais par comportement). Si un comportement reste sans technique adaptée, un second appel avec des requêtes reformulées. N'écris JAMAIS un identifiant ATT&CK de mémoire : seulement un identifiant renvoyé par search_attack ou get_attack. Choisis la sous-technique quand le texte nomme le mécanisme précis, sinon la technique parente. Une seule technique par comportement, la plus précise. Appelle get_attack en cas de doute entre deux techniques.
3. Qui emploie la technique : le malware ou l'outil qui l'exécute (« malware|uses|T… », « tool|uses|T… ») quand le texte décrit sa capacité ; la campagne quand c'est une étape de l'opération (« campaign|uses|T… »). Un outil ou malware employé pendant la campagne : « campaign|uses|outil ». Un groupe qui emploie un malware : « intrusion-set|uses|malware ». Attribution explicite : « campaign|attributed-to|intrusion-set ».
4. Vulnérabilité : « campaign|targets|CVE » ou « intrusion-set|targets|CVE » ; exploitation décrite sans opération : « T…|targets|CVE » ; produit vulnérable : « software|has|CVE » ; éditeur : « software|related-to|éditeur ».
5. Preuves : chaque relation cite les numéros des phrases qui l'affirment (1 à 3). La phrase (ou les 3 précédentes de la même section, ou le titre de section) doit nommer le malware, l'outil, la CVE ou la victime reliés. N'invente rien que le texte ne dise.
6. Appelle submit UNE fois avec tout le passage. Si des lignes sont refusées, corrige-les et renvoie seulement les lignes corrigées, ou abandonne celles que le texte n'étaye pas. Quand tout est accepté, réponds « FIN ».
Un passage sans rien d'utile : submit avec des listes vides."""


def passage_prompt(title: str, outline: str, known: str, p: Pass) -> str:
    return (
        f"RAPPORT : {title}\n\nPLAN DE L'ARTICLE :\n{outline}\n\n"
        f"ENTITÉS DÉJÀ DÉCLARÉES (réutiliser exactement ces noms) :\n{known}\n\n"
        f"PASSAGE {p.index + 1} (phrases numérotées) :\n{p.render()}"
    )


def outline_of(units: list[Unit]) -> str:
    heads = list(dict.fromkeys(u.heading_path for u in units if u.heading_path))
    text = "\n".join(f"- {h}" for h in heads)
    return text if len(text) <= OUTLINE_CHARS else text[:OUTLINE_CHARS].rsplit("\n", 1)[0] + "\n- …"


def clean_title(title: str, site_name: str | None) -> str:
    """Titre sans le suffixe de l'éditeur (« Rapport - The DFIR Report » -> « Rapport »)."""
    for sep in (" - ", " | ", " – ", " — "):
        head, _, tail = title.rpartition(sep)
        if head and site_name and normalize_name(tail) == normalize_name(site_name):
            return head.strip()
    return title


# --- Boucle de l'agent ----------------------------------------------------------------------------------------------------
@dataclass
class TurnStat:
    passage: int
    turn: int
    prompt_tokens: int
    output_tokens: int
    seconds: float
    tool_calls: list[str]
    truncated: bool


@dataclass
class AgentResult:
    article_id: int
    draft: DraftGraph
    n_units: int
    n_passages: int
    turns: list[TurnStat] = field(default_factory=list)
    accepted: int = 0
    refused: int = 0
    failed_passages: list[str] = field(default_factory=list)
    iocs: IocResult = field(default_factory=IocResult)
    rules: RuleResult = field(default_factory=RuleResult)
    seconds: float = 0.0

    @property
    def output_tokens(self) -> int:
        return sum(t.output_tokens for t in self.turns) + sum(c.output_tokens for c in self.iocs.calls + self.rules.calls)

    @property
    def tool_calls(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for t in self.turns:
            for name in t.tool_calls:
                counts[name] = counts.get(name, 0) + 1
        return counts


def _estimate_tokens(messages: list[dict]) -> int:
    return sum(len(m.get("content") or "") + len(json.dumps(m.get("tool_calls") or "")) for m in messages) // 3


def _compact(messages: list[dict], budget: int) -> None:
    """Résume les plus anciens résultats d'outils de recherche quand la conversation approche de `num_ctx`."""
    for m in messages:
        if _estimate_tokens(messages) <= budget:
            return
        if m["role"] == "tool" and m.get("tool_name") != "submit" and not m["content"].startswith("[résultat"):
            m["content"] = "[résultat déjà exploité]"


def run_passage(draft: DraftGraph, system: str, user: str, p: Pass, result: AgentResult, show_tools: bool = False) -> None:
    kb = draft.attack
    tools = tool_specs()
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    submitted, nudged = False, False
    budget = int(OLLAMA_NUM_CTX * CONTEXT_BUDGET)
    for turn in range(MAX_TURNS):
        if turn == MAX_TURNS - SUBMIT_DEADLINE and not submitted:  # le modèle cherche sans fin : il soumet ce qu'il a établi
            messages.append({"role": "user", "content": "Recherches terminées : appelle submit MAINTENANT avec les entités et relations établies."})
        _compact(messages, budget)
        r = llm.chat(messages, tools, max_output_tokens=MAX_OUTPUT_TOKENS)
        messages.append(r.message)
        result.turns.append(TurnStat(p.index, turn, r.prompt_tokens, r.output_tokens, r.seconds, [c["name"] for c in r.tool_calls], r.truncated))
        if not r.tool_calls:
            if submitted or nudged:
                return
            nudged = True  # le modèle a répondu en texte sans soumettre : une relance
            messages.append({"role": "user", "content": "Appelle submit avec les entités et relations du passage (listes vides s'il n'y a rien)."})
            continue
        clean_submit = False
        for call in r.tool_calls:
            name, args = call["name"], call["arguments"]
            if name == "search_attack":
                queries = args.get("queries") or [{"query": args.get("query", ""), "tactic": args.get("tactic")}]
                out = search_attack_many(kb, queries if isinstance(queries, list) else [queries])
            elif name == "get_attack":
                out = get_attack(kb, str(args.get("id", "")))
            elif name == "lookup_name":
                out = lookup_name(kb, str(args.get("name", "")))
            elif name == "submit":
                ents, rels = args.get("entities") or [], args.get("relations") or []
                out, accepted, refused = draft.submit(ents if isinstance(ents, list) else [ents], rels if isinstance(rels, list) else [rels])
                result.accepted += accepted
                result.refused += refused
                submitted, clean_submit = True, refused == 0
            else:
                out = f"outil inconnu : {name}"
            if show_tools:
                console.print(f"  [cyan]{name}[/] {json.dumps(args, ensure_ascii=False)[:300]}\n  [dim]{out[:600]}[/]")
            messages.append({"role": "tool", "tool_name": name, "content": out})
        if clean_submit:
            return


def extract_article(
    art: dict,
    *,
    max_pass_chars: int = MAX_PASS_CHARS,
    show_tools: bool = False,
    with_iocs: bool = True,
    with_rules: bool = True,
) -> AgentResult:
    """Extrait un article (ligne de `knowledge` jointe à sa classification) : graphe vérifié, IOC et règles."""
    t0 = time.perf_counter()
    title = clean_title(art["title"] or f"Article {art['id']}", art.get("site_name"))
    units = segment(art["clean_markdown"])
    passes = [p for p in make_passes(units, max_pass_chars) if any(u.is_evidence_eligible for u in p.units)]
    ctx = ArticleContext(art["id"], art.get("site_name"), art.get("url"), art.get("title"))
    draft = DraftGraph(units, ctx)
    result = AgentResult(art["id"], draft, len(units), len(passes))
    system, outline = system_prompt(), outline_of(units)
    for p in passes:
        if show_tools:
            console.print(f"[bold]Passage {p.index + 1}/{len(passes)}[/] ({p.heading_path})")
        try:
            run_passage(draft, system, passage_prompt(title, outline, draft.table(), p), p, result, show_tools)
        except (TimeoutError, llm.requests.RequestException) as exc:  # un passage perdu n'arrête pas l'article
            result.failed_passages.append(f"passage {p.index + 1} : {type(exc).__name__}: {exc}")
    rows = draft.entity_rows()
    if with_iocs:
        result.iocs = extract_iocs(title, units, rows, url=art.get("url"), published=parse_date(art.get("publication_date")))
    if with_rules:
        result.rules = extract_rules(title, art["clean_markdown"], rows)
    result.seconds = time.perf_counter() - t0
    return result


def article_objects(result: AgentResult, art: dict) -> tuple[list, list]:
    """Objets `stix2` de l'article (éditeur, entités, objets ATT&CK, relations, IOC, règles), puis les objets de support : l'auteur
    et le marquage que référencent les objets ATT&CK, joints au bundle mais ni au rapport ni à Neo4j."""
    draft, ctx = result.draft, result.draft.ctx
    published = parse_date(art.get("publication_date"))
    objects = [ctx.publisher, *draft.linked(), *draft.relationships()]
    objects += build_ioc_objects(result.iocs.findings, ctx, published)
    objects += build_rule_objects(result.rules.rules, ctx, published)
    objects = list({o["id"]: o for o in objects}.values())
    known = {o["id"] for o in objects}
    refs = {r for o in objects for r in [o.get("created_by_ref"), *(o.get("object_marking_refs") or [])] if r and r not in known}
    return objects, draft.attack.support_objects(refs)


def article_bundle(result: AgentResult, art: dict, objects: list, support: list = ()):
    """`stix2.Bundle` de l'article : le `stix2.Report` qui liste ses objets, les objets, et les objets de support."""
    ctx = result.draft.ctx
    title = clean_title(art["title"] or "", art.get("site_name")) or art["title"]
    rep = report(ctx, title, parse_date(art.get("publication_date")), [o["id"] for o in objects if o["id"] != ctx.publisher.id], [art["primary_category"]] if art.get("primary_category") else None)
    return bundle([rep, *objects, *support])


def process_article(art: dict, *, out_dir: Path = STIX_BUNDLES_DIR, store=None, show_tools: bool = False, fast: bool = False, closed: bool = False, oneshot: bool = False) -> AgentResult:
    """Extrait un article, écrit `out_dir/article_<id>.json` et, si `store` est donné, l'enregistre dans Neo4j. `fast` : extraction
    en deux appels contraints par partie (`fast_extract`) au lieu de la boucle d'outils ; `closed` : questions fermées courtes, en parallèle
    (`closed_extract`), pour les modèles de taille réduite ; `oneshot` : l'article entier en un appel (`oneshot_extract`), sans décomposition."""
    if oneshot:
        from backend.extracting import oneshot_extract  # importe ce module

        result = oneshot_extract.extract_article(art)
    elif closed:
        from backend.extracting import closed_extract  # importe ce module

        result = closed_extract.extract_article(art)
    elif fast:
        from backend.extracting import fast_extract  # fast_extract importe ce module

        result = fast_extract.extract_article(art)
    else:
        result = extract_article(art, show_tools=show_tools)
    objects, support = article_objects(result, art)
    out_dir.mkdir(parents=True, exist_ok=True)
    # indent et non pretty=True : le tri des clés dans l'ordre de la spécification prenait 150 s sur un bundle de 2 000 objets
    (out_dir / f"article_{art['id']}.json").write_text(article_bundle(result, art, objects, support).serialize(indent=1), encoding="utf-8")
    if store is not None:
        # Neo4j : sans les IOC jugés bénins (l'indicateur d'une valeur est partagé entre articles, un verdict écraserait l'autre)
        nodes = [as_dict(o) for o in article_bundle(result, art, without_benign(objects)).objects]
        store.save_article(
            nodes, art["id"],
            {"title": art["title"], "url": art["url"], "site_name": art["site_name"], "category": art["primary_category"],
             "model": LLM_MODEL, "extraction_seconds": round(result.seconds, 1), "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "llm_failures": len(result.failed_passages)},
        )  # fmt: skip
    return result


# --- Ligne de commande ----------------------------------------------------------------------------------------------------
def read_articles(where: str, params: list) -> list[dict]:
    """Articles joints à leur classification, en lecture seule (le graphe vit dans Neo4j) : `where` filtre la jointure."""
    query = f"""
        SELECT k.id, k.title, k.url, k.site_name, k.publication_date, c.primary_category, c.clean_markdown
        FROM knowledge k JOIN article_classifications c ON c.knowledge_id = k.id WHERE {where}
    """
    with sqlite3.connect(f"file:{SOURCE_ARTICLES_DB}?mode=ro", uri=True, timeout=30.0) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(query, params)]


def _marks(values) -> str:
    return ",".join("?" * len(values))


def fetch_articles(limit: int, article_ids: list[int] | None, skip_ids: set[int]) -> list[dict]:
    """Articles classifiés, dans l'ordre des identifiants, sans ceux déjà extraits."""
    where = f"c.is_processable = 1 AND c.primary_category IN ({_marks(CATEGORIES)}) AND c.clean_markdown IS NOT NULL AND c.clean_markdown != ''"
    params: list = list(CATEGORIES)
    if article_ids:
        where += f" AND k.id IN ({_marks(article_ids)})"
        params += article_ids
    if skip_ids:
        where += f" AND k.id NOT IN ({_marks(skip_ids)})"
        params += sorted(skip_ids)
    return read_articles(f"{where} ORDER BY k.id ASC LIMIT ?", [*params, limit])


def summary_line(result: AgentResult) -> str:
    tools = ", ".join(f"{k} {v}" for k, v in sorted(result.tool_calls.items()))
    failed = f" │ {len(result.failed_passages)} passage(s) en échec" if result.failed_passages else ""
    iocs = len(result.iocs.findings) - result.iocs.n_not_malicious
    return (
        f"Article {result.article_id} {result.seconds:.0f}s │ {len(result.draft.linked())} entités {len(result.draft.evidence)} relations "
        f"{iocs} IOC (+{result.iocs.n_not_malicious} bénins) {len(result.rules.rules)} règles │ {result.n_passages} passages, "
        f"{len(result.turns)} tours, {result.output_tokens} tokens générés │ outils : {tools} │ "
        f"lignes acceptées {result.accepted}, refusées {result.refused}{failed}"
    )


def print_stats() -> None:
    from backend.database.stix_store import StixStore

    store = StixStore()
    ok, err = store._store.check_connection()
    if not ok:
        console.print(f"[bold red]Neo4j non joignable ({err})[/]")
        return
    stats = store.stats()
    table = Table(title=f"Knowledge Graph STIX : {stats['articles']} article(s)", header_style="bold magenta", border_style="dim")
    for col in ("Nœuds (type STIX)", "Effectif", "Relations", "Effectif "):
        table.add_column(col)
    nodes, edges = list(stats["nodes"].items()), list(stats["edges"].items())
    for i in range(max(len(nodes), len(edges))):
        n = nodes[i] if i < len(nodes) else ("", "")
        e = edges[i] if i < len(edges) else ("", "")
        table.add_row(n[0], str(n[1]), e[0], str(e[1]))
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent d'extraction STIX 2.1 (stix2) avec outils ATT&CK v20.0")
    parser.add_argument("--article-id", type=int, action="append", help="Article à extraire (option répétable ; ré-extrait même s'il existe)")
    parser.add_argument("--limit", type=int, default=10, help="Nombre maximal d'articles")
    parser.add_argument("--force", action="store_true", help="Ré-extraire aussi les articles déjà dans Neo4j")
    parser.add_argument("--dry-run", action="store_true", help="N'écrit rien dans Neo4j")
    parser.add_argument("--out", type=Path, default=STIX_BUNDLES_DIR, help=f"Dossier des bundles STIX 2.1 (défaut : {STIX_BUNDLES_DIR})")
    parser.add_argument("--show-tools", action="store_true", help="Affiche chaque appel d'outil et son résultat")
    parser.add_argument("--fast", action="store_true", help="Extraction rapide : candidates calculées par le code, deux appels par partie")
    parser.add_argument("--closed", action="store_true", help="Extraction à questions fermées : le code propose, de petits appels parallèles choisissent")
    parser.add_argument("--show-log", action="store_true", help="Affiche les corrections et refus de la vérification")
    parser.add_argument("--stats", action="store_true", help="Statistiques du graphe STIX dans Neo4j")
    args = parser.parse_args()
    if args.stats:
        print_stats()
        return
    store, skip = None, set()
    if not args.dry_run:
        from backend.database.stix_store import StixStore

        store = StixStore()
        ok, err = store._store.check_connection()
        if not ok:
            console.print(f"[bold red]Neo4j non joignable ({err}) : relancer avec --dry-run pour n'écrire que les bundles[/]")
            return
        store.init_schema()
        skip = set() if args.force or args.article_id else store.extracted_article_ids()
    articles = fetch_articles(len(args.article_id) if args.article_id else args.limit, args.article_id, skip)
    for art in articles:
        result = process_article(art, out_dir=args.out, store=store, show_tools=args.show_tools, fast=args.fast, closed=args.closed)
        console.print(summary_line(result))
        for f in result.failed_passages:
            console.print(f"  [red]{f}[/]")
        if args.show_log:
            for line in result.draft.log:
                console.print(f"  [dim]{line}[/]")
        console.print(f"  bundle : {args.out / f'article_{art['id']}.json'}")


if __name__ == "__main__":
    main()
