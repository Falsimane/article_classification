"""Score d'un bundle STIX prédit contre un bundle gold annoté à la main (méthode : Annotations/methode_annotation.md).

    Rappel (principal) = required trouvés / total required
    Précision          = (required + acceptable trouvés) / total prédit

- Périmètre : la couche sémantique. Les IOC (indicator, file, ipv4-addr, domain-name, url…) sont ignorés des deux côtés,
  ainsi que les conteneurs (report, sighting, attack-flow…) et l'identité de l'éditeur (`created_by_ref`). `software`
  (produit visé) est dans le périmètre.
- Normalisation : identifiant ATT&CK v20.0 (alias ATT&CK compris : « Stardust Chollima » = G0082), CVE, puis nom
  normalisé (nom, alias, `x_gold_name_variants`). Types équivalents : malware/tool, intrusion-set/threat-actor,
  campaign/incident (une intrusion décrite par l'article est un `incident` chez le pipeline, une `campaign` dans le gold).
- Crédit partiel des techniques : même identifiant = 1 ; même technique parente (T1059 contre T1059.001, ou deux
  sous-techniques soeurs) = 0,5. Une relation vaut le plus petit crédit de ses deux extrémités. Le score strict (sans crédit
  partiel) est publié à côté.
- Score relâché des relations « uses » : la source prédite peut être toute entité du même groupe d'activité que la source du
  gold (campagne, groupe auquel elle est attribuée, malwares et outils qu'ils emploient, reliés entre eux dans le gold). Il
  répond à la question de l'attribution (la technique a-t-elle été vue dans cette activité ?) sans la convention du porteur.
- Victimes par le fait (`victims`) : les secteurs STIX et les pays ou régions qui reçoivent une relation « targets », comparés
  comme ensembles. Le nom et le grain d'une victime (« les tribunaux de Kyiv » ou « institutions de l'État ukrainien ») relèvent
  de la modélisation de l'analyste ; le secteur et le pays visés n'en dépendent pas.
- Appariement un pour un (glouton, meilleur crédit d'abord) : un doublon prédit est un faux positif.
- Campagnes : sans nom commun (le gold les nomme en français), elles sont appariées par le plus grand nombre de
  relations partagées.
- Hallucination : un identifiant ATT&CK absent de la v20.0 est rejeté, compté comme hallucination et comme faux positif.
- Ancrage (sans gold) : chaque citation de relation est recherchée dans le texte source, exacte puis approximative.
- Une prédiction absente du gold n'est pas jugée ici : elle est listée pour revue analyste (`review`).
"""

import difflib
import re
from dataclasses import dataclass, field

from backend.preprocessing.cleaning.text.evidence import evidence_in_source, normalize_name, normalize_quote, tokens
from backend.extracting.stix.attack import AttackKB, get_attack_kb

IOC_TYPES = frozenset(
    {
        "indicator", "file", "ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "email-message", "x509-certificate",
        "mutex", "autonomous-system", "network-traffic", "artifact", "directory", "windows-registry-key", "mac-addr", "process",
        "user-account",
    }
)  # fmt: skip
CONTAINER_TYPES = frozenset(
    {
        "report", "note", "opinion", "grouping", "observed-data", "sighting", "marking-definition", "extension-definition",
        "language-content", "attack-flow", "attack-action", "attack-asset", "attack-condition", "attack-operator", "relationship",
    }
)  # fmt: skip
TYPE_CLASS = {"tool": "malware", "threat-actor": "intrusion-set", "incident": "campaign"}
LABEL_REQUIRED, LABEL_ACCEPTABLE = "gold:required", "gold:acceptable"
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_FUZZY_THRESHOLD = 0.8  # part des mots d'une citation retrouvés dans l'ordre au même endroit du texte


def type_class(stix_type: str) -> str:
    return TYPE_CLASS.get(stix_type, stix_type)


def in_scope(obj: dict) -> bool:
    return obj.get("type") not in IOC_TYPES and obj.get("type") not in CONTAINER_TYPES and not obj.get("type", "").startswith("x-")


def attack_ids(obj: dict) -> list[str]:
    ids = [r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack" and r.get("external_id")]
    ids += [a for a in obj.get("aliases", []) if re.match(r"^[TGSC]\d{4}(?:\.\d{3})?$", a)]
    return list(dict.fromkeys(i.upper() for i in ids))


@dataclass
class Entity:
    sid: str
    stix_type: str
    name: str
    label: str | None  # gold : required / acceptable ; prédiction : None
    technique: str | None = None  # identifiant ATT&CK d'un attack-pattern
    keys: frozenset = frozenset()  # formes normalisées (noms, alias, identifiants) pour l'appariement
    hallucinated: str | None = None  # identifiant ATT&CK inconnu de la v20.0

    @property
    def klass(self) -> str:
        return type_class(self.stix_type)

    def describe(self) -> str:
        return f"{self.stix_type}:{self.name}" + (f" [{self.technique}]" if self.technique else "")


@dataclass
class Relation:
    sid: str
    source: str
    rel: str
    target: str
    label: str | None
    quotes: list[str] = field(default_factory=list)


def _entity(obj: dict, kb: AttackKB, label: str | None) -> Entity:
    names = [obj.get("name", ""), *obj.get("aliases", []), *obj.get("x_gold_name_variants", []), *obj.get("x_mitre_aliases", [])]
    keys = {normalize_name(n) for n in names if n and not _TECHNIQUE.match(n)}
    technique, hallucinated = None, None
    ids = attack_ids(obj)
    for aid in ids:
        status, replaced = kb.status(aid)
        if status == "unknown":
            hallucinated = aid
            continue
        keys.add(aid)
        if replaced:
            keys.add(replaced)
    if obj["type"] == "attack-pattern":
        valid = [i for i in ids if _TECHNIQUE.match(i) and kb.status(i)[0] != "unknown"]
        if valid:
            status, replaced = kb.status(valid[0])
            technique = replaced if status == "revoked" and replaced else valid[0]
        elif not ids:  # sans identifiant : nom exact d'une technique ATT&CK, sinon non apparié
            hits = kb.search_techniques(obj.get("name", ""), limit=3)
            exact = [h for h in hits if normalize_name(h.name.split(": ")[-1]) == normalize_name(obj.get("name"))]
            technique = exact[0].attack_id if len(exact) == 1 else None
    elif obj["type"] in ("intrusion-set", "threat-actor", "malware", "tool", "campaign"):
        for n in names[:1]:  # un nom connu d'ATT&CK prend son identifiant (alias compris)
            hits = [h for h in kb.lookup(n) if h["status"] == "active" and type_class(h["type"]) == type_class(obj["type"])]
            if len(hits) == 1:
                keys.add(hits[0]["attack_id"])
    elif obj["type"] == "vulnerability":
        keys |= {m.upper() for n in names for m in _CVE.findall(n or "")}
        keys |= {r["external_id"].upper() for r in obj.get("external_references", []) if r.get("source_name") == "cve" and r.get("external_id")}
    elif obj["type"] == "location":
        keys |= {normalize_name(obj[k]) for k in ("country", "region") if obj.get(k)}
    keys.discard("")
    return Entity(obj["id"], obj["type"], obj.get("name", ""), label, technique, frozenset(keys), hallucinated)


def _label(obj: dict) -> str:
    labels = obj.get("labels", [])
    return LABEL_ACCEPTABLE if LABEL_ACCEPTABLE in labels and LABEL_REQUIRED not in labels else LABEL_REQUIRED


def _quotes(rel: dict) -> list[str]:
    quotes = [r["description"] for r in rel.get("external_references", []) if r.get("description")]
    if not quotes and rel.get("description"):
        quotes = [q.strip() for q in rel["description"].split(" | ") if q.strip()]
    for key in ("x_gold_evidence_quote", "evidence_quote", "x_evidence_quote"):
        if rel.get(key):
            quotes.append(rel[key])
    return quotes


def load_bundle(bundle: dict, kb: AttackKB, gold: bool) -> tuple[dict[str, Entity], list[Relation]]:
    """Entités et relations du périmètre. Pour le gold, chaque objet porte un label required / acceptable."""
    objs = bundle.get("objects", [])
    publishers = {o["created_by_ref"] for o in objs if o.get("created_by_ref")}
    entities = {
        o["id"]: _entity(o, kb, _label(o) if gold else None)
        for o in objs
        if in_scope(o) and o["id"] not in publishers
    }
    relations = [
        Relation(o["id"], o["source_ref"], o["relationship_type"], o["target_ref"], _label(o) if gold else None, _quotes(o))
        for o in objs
        if o.get("type") == "relationship" and o.get("source_ref") in entities and o.get("target_ref") in entities
    ]
    return entities, relations


# --- Appariement -------------------------------------------------------------------------------------------------------
def entity_credit(gold: Entity, pred: Entity, strict: bool = False) -> float:
    if gold.klass != pred.klass or pred.hallucinated and not pred.keys & gold.keys:
        return 0.0
    if gold.stix_type == "attack-pattern":
        if not gold.technique or not pred.technique:
            return 0.0
        if gold.technique == pred.technique:
            return 1.0
        return 0.5 if not strict and gold.technique.split(".")[0] == pred.technique.split(".")[0] else 0.0
    return 1.0 if gold.keys & pred.keys else 0.0


def _greedy(pairs: list[tuple[float, str, str]]) -> dict[str, tuple[str, float]]:
    """Appariement un pour un, meilleur crédit d'abord : {prédit: (gold, crédit)}."""
    used_g, out = set(), {}
    for credit, p, g in sorted(pairs, key=lambda x: (-x[0], x[1], x[2])):
        if credit > 0 and p not in out and g not in used_g:
            out[p] = (g, credit)
            used_g.add(g)
    return out


def _candidates(gold: dict[str, Entity], pred: dict[str, Entity], strict: bool = False) -> dict[str, dict[str, float]]:
    """{prédit: {gold: crédit}} pour toutes les paires compatibles (plusieurs par entité prédite possibles)."""
    out: dict[str, dict[str, float]] = {}
    for p in pred.values():
        for g in gold.values():
            c = entity_credit(g, p, strict)
            if c:
                out.setdefault(p.sid, {})[g.sid] = c
    return out


def _align_operations(gold, pred, gold_rels, pred_rels, cands) -> None:
    """Campagnes et incidents sans nom commun : appariés par le nombre de relations partagées (type + autre extrémité)."""
    g_ops = [g for g in gold.values() if g.klass == "campaign" and not any(g.sid in c for c in cands.values())]
    p_ops = [p for p in pred.values() if p.klass == "campaign" and p.sid not in cands]
    if not g_ops or not p_ops:
        return

    def signature(rels, sid, mapper):
        sig = set()
        for r in rels:
            if r.source == sid:
                sig |= {("out", r.rel, g) for g in mapper(r.target)}
            elif r.target == sid:
                sig |= {("in", r.rel, g) for g in mapper(r.source)}
        return sig

    to_gold = lambda sid: set(cands.get(sid, {}))  # noqa: E731
    identity = lambda sid: {sid}  # noqa: E731
    pairs = []
    for p in p_ops:
        ps = signature(pred_rels, p.sid, to_gold)
        for g in g_ops:
            overlap = len(ps & signature(gold_rels, g.sid, identity))
            pairs.append((overlap + (0.5 if len(g_ops) == len(p_ops) == 1 else 0), p.sid, g.sid))
    for p_sid, (g_sid, _) in _greedy(pairs).items():
        cands.setdefault(p_sid, {})[g_sid] = 1.0


_ACTIVITY = frozenset({"campaign", "intrusion-set", "malware"})  # classes (malware inclut tool, intrusion-set inclut threat-actor)


def activity_groups(gold: dict[str, Entity], gold_rels: list[Relation]) -> dict[str, set[str]]:
    """Entité gold du côté de l'attaquant -> son groupe d'activité : les entités de ces classes reliées entre elles dans le gold
    (campagne attribuée à un groupe, qui emploie ou dépose tel malware…)."""
    parent = {sid: sid for sid, e in gold.items() if e.klass in _ACTIVITY}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in gold_rels:
        if r.source in parent and r.target in parent:
            parent[find(r.source)] = find(r.target)
    groups: dict[str, set[str]] = {}
    for sid in parent:
        groups.setdefault(find(sid), set()).add(sid)
    return {sid: groups[find(sid)] for sid in parent}


def victim_facts(objects: list[dict]) -> set[tuple[str, str]]:
    """(« sector », secteur) et (« place », code pays ou région) des identités et lieux visés par une relation « targets »."""
    by_id = {o["id"]: o for o in objects}
    targeted = {o["target_ref"] for o in objects if o.get("type") == "relationship" and o.get("relationship_type") == "targets"}
    facts: set[tuple[str, str]] = set()
    for sid in targeted:
        o = by_id.get(sid, {})
        if o.get("type") == "identity":
            facts |= {("sector", x) for x in o.get("sectors") or []}
        elif o.get("type") == "location":
            facts |= {("place", (o.get("country") or o.get("region") or "").lower())} - {("place", "")}
    return facts


def _match_relations(gold_rels: list[Relation], pred_rels: list[Relation], cands: dict, sources=None) -> dict[str, tuple[str, float]]:
    """Appariement un pour un des relations : même type, extrémités compatibles. `sources(relation gold)` élargit les sources
    gold admises (score relâché)."""
    pairs = []
    for i, pr in enumerate(pred_rels):
        for gr in gold_rels:
            if gr.rel != pr.rel:
                continue
            allowed = sources(gr) if sources else (gr.source,)
            cs, ct = max((cands.get(pr.source, {}).get(g, 0) for g in allowed), default=0), cands.get(pr.target, {}).get(gr.target, 0)
            if cs and ct:
                pairs.append((min(cs, ct), str(i), gr.sid))
    return _greedy(pairs)


@dataclass
class Counts:
    gold_required: int = 0
    gold_acceptable: int = 0
    predicted: int = 0
    found_required: float = 0.0
    found_acceptable: float = 0.0

    def add(self, other: "Counts") -> None:
        for k in vars(self):
            setattr(self, k, getattr(self, k) + getattr(other, k))

    @property
    def recall(self) -> float | None:
        return self.found_required / self.gold_required if self.gold_required else None

    @property
    def precision(self) -> float | None:
        return (self.found_required + self.found_acceptable) / self.predicted if self.predicted else None

    def as_dict(self) -> dict:
        r, p = self.recall, self.precision
        return {**vars(self), "recall": None if r is None else round(r, 4), "precision": None if p is None else round(p, 4)}


@dataclass
class ArticleScore:
    article_id: int
    entities: Counts
    relations: Counts
    by_type: dict[str, Counts]  # entités par type gold
    by_pattern: dict[str, Counts]  # relations par motif (classe source, relation, classe cible)
    hallucinations: list[str]
    grounding: dict
    matched_entities: list[tuple[str, str, float]]
    missed_entities: list[str]
    missed_relations: list[str]
    review_entities: list[str]  # prédictions absentes du gold : à revoir par un analyste
    review_relations: list[dict]
    entities_strict: Counts = field(default_factory=Counts)  # sans crédit partiel des techniques
    relations_strict: Counts = field(default_factory=Counts)
    relations_relaxed: Counts = field(default_factory=Counts)  # source « uses » dans le même groupe d'activité
    victims: Counts = field(default_factory=Counts)  # secteurs et pays visés, comparés comme ensembles

    def as_dict(self) -> dict:
        return {
            "article_id": self.article_id,
            "entities": self.entities.as_dict(),
            "relations": self.relations.as_dict(),
            "entities_strict": self.entities_strict.as_dict(),
            "relations_strict": self.relations_strict.as_dict(),
            "relations_relaxed": self.relations_relaxed.as_dict(),
            "victims": self.victims.as_dict(),
            "entities_by_type": {k: v.as_dict() for k, v in sorted(self.by_type.items())},
            "relations_by_pattern": {k: v.as_dict() for k, v in sorted(self.by_pattern.items())},
            "hallucinations": self.hallucinations,
            "grounding": self.grounding,
            "matched_entities": self.matched_entities,
            "missed_entities": self.missed_entities,
            "missed_relations": self.missed_relations,
            "review_entities": self.review_entities,
            "review_relations": self.review_relations,
        }


@dataclass
class SourceIndex:
    """Texte source normalisé, ses mots et la position de chaque trigramme : sert à retrouver une citation, exacte ou
    approximative, sans renormaliser ni balayer le texte à chaque citation."""

    haystack: str
    words: list[str]
    trigrams: dict[tuple[str, ...], list[int]]

    @classmethod
    def of(cls, text: str) -> "SourceIndex":
        words = tokens(text)
        trigrams: dict[tuple[str, ...], list[int]] = {}
        for i in range(len(words) - 2):
            trigrams.setdefault(tuple(words[i : i + 3]), []).append(i)
        return cls(normalize_quote(text), words, trigrams)


def _fuzzy_share(quote: list[str], src: SourceIndex) -> float:
    """Part des mots de la citation retrouvés dans l'ordre autour du meilleur ancrage (vote des trigrammes communs)."""
    votes: dict[int, int] = {}
    for i in range(len(quote) - 2):
        for pos in src.trigrams.get(tuple(quote[i : i + 3]), ()):
            votes[pos - i] = votes.get(pos - i, 0) + 1
    best = 0.0
    for start, _ in sorted(votes.items(), key=lambda kv: -kv[1])[:3]:
        window = src.words[max(0, start - 3) : start + len(quote) + 3]
        matched = sum(b.size for b in difflib.SequenceMatcher(None, quote, window, autojunk=False).get_matching_blocks())
        best = max(best, matched / len(quote))
    return best


def grounding_status(quote: str, source_text: str, source: SourceIndex | None = None) -> str:
    """« exact » (citation normalisée présente, coupes « [...] » admises), « approximate » (≥ 80 % de ses mots retrouvés dans
    l'ordre au même endroit du texte) ou « missing »."""
    source = source or SourceIndex.of(source_text)
    if evidence_in_source(quote, source_text, haystack=source.haystack):
        return "exact"
    words = tokens(quote)
    if len(words) < 3:
        return "missing"
    return "approximate" if _fuzzy_share(words, source) >= _FUZZY_THRESHOLD else "missing"


def _pattern(rel: Relation, ents: dict[str, Entity]) -> str:
    return f"{ents[rel.source].klass} {rel.rel} {ents[rel.target].klass}"


def _tally(gold: dict, predicted: dict, matches: dict, bucket_of) -> tuple[Counts, dict[str, Counts]]:
    """Comptes globaux et par rubrique. `gold` et `predicted` sont indexés par identifiant, `matches` associe une prédiction
    à (gold, crédit) ; `bucket_of(élément, est_gold)` donne sa rubrique. Une prédiction appariée compte dans la rubrique du gold
    qu'elle vise, les autres dans la leur."""
    total, buckets = Counts(predicted=len(predicted)), {}
    for g in gold.values():
        for c in (total, buckets.setdefault(bucket_of(g, True), Counts())):
            c.gold_required += g.label == LABEL_REQUIRED
            c.gold_acceptable += g.label == LABEL_ACCEPTABLE
    for g_key, credit in matches.values():
        g = gold[g_key]
        for c in (total, buckets[bucket_of(g, True)]):
            if g.label == LABEL_REQUIRED:
                c.found_required += credit
            else:
                c.found_acceptable += credit
    for key, p in predicted.items():
        g_key = matches.get(key, (None,))[0]
        buckets.setdefault(bucket_of(gold[g_key], True) if g_key else bucket_of(p, False), Counts()).predicted += 1
    return total, buckets


def score_article(article_id: int, gold_bundle: dict, pred_bundle: dict, source_text: str | None = None, kb: AttackKB | None = None) -> ArticleScore:
    kb = kb or get_attack_kb()
    gold, gold_rels = load_bundle(gold_bundle, kb, gold=True)
    pred, pred_rels = load_bundle(pred_bundle, kb, gold=False)

    # Entités
    cands = _candidates(gold, pred)
    _align_operations(gold, pred, gold_rels, pred_rels, cands)
    matched = _greedy([(c, p, g) for p, gs in cands.items() for g, c in gs.items()])
    ents, by_type = _tally(gold, pred, matched, lambda e, _: e.stix_type)

    # Relations : extrémités prédites -> toutes leurs entités gold compatibles (doublons d'entités compris)
    gold_by_sid, pred_by_key = {r.sid: r for r in gold_rels}, {str(i): r for i, r in enumerate(pred_rels)}
    rel_match = _match_relations(gold_rels, pred_rels, cands)
    rels, by_pattern = _tally(gold_by_sid, pred_by_key, rel_match, lambda r, is_gold: _pattern(r, gold if is_gold else pred))

    # Variantes : sans crédit partiel ; source « uses » prise dans le groupe d'activité de la source gold
    strict = _candidates(gold, pred, strict=True)
    for p_sid, gs in cands.items():  # campagnes appariées par leurs relations : même appariement
        strict.setdefault(p_sid, {}).update({g: c for g, c in gs.items() if gold[g].klass == "campaign"})
    ents_strict, _ = _tally(gold, pred, _greedy([(c, p, g) for p, gs in strict.items() for g, c in gs.items()]), lambda e, _: e.stix_type)
    rels_strict, _ = _tally(gold_by_sid, pred_by_key, _match_relations(gold_rels, pred_rels, strict), lambda r, _: "")
    groups = activity_groups(gold, gold_rels)
    relaxed = _match_relations(gold_rels, pred_rels, cands, lambda gr: groups.get(gr.source, {gr.source}) if gr.rel == "uses" else (gr.source,))
    rels_relaxed, _ = _tally(gold_by_sid, pred_by_key, relaxed, lambda r, _: "")

    # Ancrage des citations des relations prédites
    grounding = {"relations": len(pred_rels), "with_quote": 0, "exact": 0, "approximate": 0, "missing": 0, "missing_quotes": []}
    if source_text is not None:
        src = SourceIndex.of(source_text)
        for pr in pred_rels:
            if not pr.quotes:
                continue
            grounding["with_quote"] += 1
            statuses = [grounding_status(q, source_text, src) for q in pr.quotes]
            best = "exact" if "exact" in statuses else "approximate" if "approximate" in statuses else "missing"
            grounding[best] += 1
            if best == "missing":
                grounding["missing_quotes"].append(pr.quotes[0][:160])

    def rel_text(r: Relation, ents) -> str:
        return f"{ents[r.source].describe()} --{r.rel}--> {ents[r.target].describe()}"

    matched_gold_rels = {g for g, _ in rel_match.values()}
    return ArticleScore(
        article_id=article_id,
        entities=ents,
        relations=rels,
        by_type=by_type,
        by_pattern=by_pattern,
        hallucinations=sorted({p.hallucinated for p in pred.values() if p.hallucinated}),
        grounding=grounding,
        matched_entities=sorted((pred[p].describe(), gold[g].describe(), c) for p, (g, c) in matched.items()),
        missed_entities=sorted(f"[{g.label.split(':')[1]}] {g.describe()}" for g in gold.values() if g.sid not in {x for x, _ in matched.values()}),
        missed_relations=sorted(f"[{r.label.split(':')[1]}] {rel_text(r, gold)}" for r in gold_rels if r.sid not in matched_gold_rels),
        review_entities=sorted(p.describe() + (f" (hallucination {p.hallucinated})" if p.hallucinated else "") for p in pred.values() if p.sid not in matched),
        review_relations=[
            {"relation": rel_text(pr, pred), "quote": (pr.quotes or [""])[0][:300]} for i, pr in enumerate(pred_rels) if str(i) not in rel_match
        ],
        entities_strict=ents_strict,
        relations_strict=rels_strict,
        relations_relaxed=rels_relaxed,
        victims=Counts(
            gold_required=len(gv := victim_facts(gold_bundle.get("objects", []))), predicted=len(pv := victim_facts(pred_bundle.get("objects", []))),
            found_required=float(len(gv & pv)),
        ),
    )


def total(scores: list[ArticleScore]) -> dict:
    """Micro-moyenne sur les articles (sommes des comptes, puis ratios)."""
    ents, rels, by_type, by_pattern = Counts(), Counts(), {}, {}
    variants = {k: Counts() for k in ("entities_strict", "relations_strict", "relations_relaxed", "victims")}
    for s in scores:
        ents.add(s.entities)
        rels.add(s.relations)
        for k, c in variants.items():
            c.add(getattr(s, k))
        for src, dst in ((s.by_type, by_type), (s.by_pattern, by_pattern)):
            for k, v in src.items():
                dst.setdefault(k, Counts()).add(v)
    ground = {k: sum(s.grounding[k] for s in scores) for k in ("relations", "with_quote", "exact", "approximate", "missing")}
    return {
        "entities": ents.as_dict(),
        "relations": rels.as_dict(),
        **{k: c.as_dict() for k, c in variants.items()},
        "entities_by_type": {k: v.as_dict() for k, v in sorted(by_type.items())},
        "relations_by_pattern": {k: v.as_dict() for k, v in sorted(by_pattern.items())},
        "hallucinations": sum(len(s.hallucinations) for s in scores),
        "grounding": ground,
    }
