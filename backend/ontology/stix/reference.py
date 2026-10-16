"""Base de référence ATT&CK : ancrer les entités extraites sur des identifiants externes.

C'est la pratique des plateformes CTI (OpenCTI importe ATT&CK comme jeu de données de base) : une entité extraite
n'est plus un simple libellé produit par un modèle de langage, elle est rapprochée d'un objet connu.

Ce que cela apporte contre les faux positifs et les doublons :
- une technique citée « T1059.001 » reçoit son vrai nom ; un nom qui contredit l'identifiant est signalé ;
- un identifiant révoqué (T1086, T1562.001…) est corrigé vers son remplaçant, pas rejeté ;
- les alias (« Cozy Bear », « NOBELIUM », « Midnight Blizzard ») convergent vers un seul objet (G0016, APT29) ;
- un nom classé dans le mauvais type (un outil étiqueté « acteur de la menace ») est détecté.

La base est un fichier de données (`reference/attack_enterprise.json`, produit par `update_reference.py`), pas du
code : la mettre à jour ne demande aucune modification des règles.
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .identity import normalize_name
from .vocab import LEGACY_TACTICS

REFERENCE_FILE = Path(__file__).resolve().parent / "reference" / "attack_enterprise.json"

# type de la base ATT&CK -> type STIX de l'objet correspondant
_KIND_TO_STIX = {"group": "intrusion-set", "campaign": "campaign", "technique": "attack-pattern"}


@dataclass(frozen=True)
class Match:
    kind: str  # "group" | "software" | "campaign" | "technique"
    attack_id: str
    name: str
    stix_type: str  # type STIX correspondant
    aliases: tuple[str, ...]
    status: str = "active"
    replaced_by: str | None = None


@dataclass(frozen=True)
class Grounding:
    """Résultat du rapprochement d'une entité extraite avec la base de référence."""

    status: str  # "grounded" | "ambiguous" | "unknown"
    match: Match | None = None  # l'objet retenu (statut "grounded" uniquement)
    candidates: tuple[Match, ...] = ()


@dataclass(frozen=True)
class TechniqueResolution:
    attack_id: str | None  # identifiant retenu (le remplaçant si l'original est révoqué)
    name: str | None
    status: str  # "active" | "revoked" | "deprecated" | "unknown"
    original_id: str | None = None
    name_conflict: bool = False  # le nom fourni contredit l'identifiant
    tactics: tuple[str, ...] = ()


class ReferenceKB:
    def __init__(self, data: dict):
        self.meta = data["meta"]
        self.tactics = {t["shortname"]: t for t in data["tactics"]}
        self._techniques = {t["id"]: t for t in data["techniques"]}
        self._by_name: dict[str, list[Match]] = {}
        self._technique_names: dict[str, list[str]] = {}

        for kind, rows in (("group", data["groups"]), ("campaign", data["campaigns"]), ("software", data["software"])):
            for row in rows:
                stix_type = row.get("type") or _KIND_TO_STIX[kind]
                match = Match(
                    kind, row["id"], row["name"], stix_type, tuple(row.get("aliases", [])),
                    row.get("status", "active"), row.get("replaced_by"),
                )  # fmt: skip
                for label in (row["name"], *row.get("aliases", [])):
                    key = normalize_name(label)
                    if key and match not in self._by_name.setdefault(key, []):
                        self._by_name[key].append(match)
        for row in data["techniques"]:
            self._technique_names.setdefault(normalize_name(row["name"]), []).append(row["id"])

    # --- Acteurs, logiciels, campagnes ----------------------------------------------------------------------------
    def lookup(self, name: str, kinds: tuple[str, ...] = ("group", "software", "campaign")) -> list[Match]:
        """Objets ATT&CK portant ce nom ou cet alias. Les objets actifs passent avant les révoqués."""
        hits = [m for m in self._by_name.get(normalize_name(name), []) if m.kind in kinds]
        return sorted(hits, key=lambda m: m.status != "active")

    def ground(self, stix_type: str, name: str) -> Grounding:
        """Rapproche (type, nom) d'un objet ATT&CK de type compatible.

        ATT&CK recoupe parfois ses propres alias (« NOBELIUM » désigne à la fois APT29 et UNC2452 ; « Cozy Bear »
        désigne APT29 et le malware CozyCar). On filtre d'abord par type ; s'il reste plusieurs objets actifs
        distincts, on ne tranche pas (`ambiguous`) : un faux rapprochement est pire qu'une absence de rapprochement.
        """
        candidates = [
            m for m in self.lookup(name) if m.status == "active" and self._compatible(stix_type, m.stix_type)
        ]
        if len(candidates) == 1:
            return Grounding("grounded", candidates[0], tuple(candidates))
        exact = [m for m in candidates if normalize_name(m.name) == normalize_name(name)]
        if len(exact) == 1:  # un seul objet porte exactement ce nom : les autres ne l'ont que comme alias
            return Grounding("grounded", exact[0], tuple(candidates))
        return Grounding("ambiguous" if candidates else "unknown", None, tuple(candidates))

    def type_conflict(self, stix_type: str, name: str) -> Match | None:
        """Si `name` est connu d'ATT&CK uniquement sous un autre type STIX que `stix_type`, retourne cet objet.

        Exemple : « Cobalt Strike » étiqueté `threat-actor` alors qu'ATT&CK le range en `tool`. Un `malware`
        étiqueté `tool` (ou l'inverse) n'est PAS un conflit : la frontière dépend de l'usage décrit.
        """
        hits = self.lookup(name)
        if not hits or any(self._compatible(stix_type, m.stix_type) for m in hits):
            return None
        return hits[0]

    @staticmethod
    def _compatible(extracted: str, known: str) -> bool:
        software = {"malware", "tool"}
        adversary = {"threat-actor", "intrusion-set"}
        return extracted == known or {extracted, known} <= software or {extracted, known} <= adversary

    # --- Techniques ------------------------------------------------------------------------------------------------
    def resolve_technique(self, attack_id: str | None = None, name: str | None = None) -> TechniqueResolution:
        """Rapproche une technique de la base par identifiant, sinon par nom."""
        original = (attack_id or "").strip().upper() or None
        if original and original in self._techniques:
            row = self._techniques[original]
            status = row.get("status", "active")
            target = row
            if status == "revoked" and row.get("replaced_by") in self._techniques:
                target = self._techniques[row["replaced_by"]]
            conflict = bool(name) and normalize_name(name) not in {
                normalize_name(row["name"]),
                normalize_name(target["name"]),
            }
            return TechniqueResolution(
                target["id"], target["name"], status, original if target is not row else None,
                conflict, tuple(target.get("tactics", ())),
            )  # fmt: skip
        if name:
            ids = [i for i in self._technique_names.get(normalize_name(name), []) if "status" not in self._techniques[i]]
            if len(ids) == 1:
                row = self._techniques[ids[0]]
                return TechniqueResolution(row["id"], row["name"], "active", None, False, tuple(row.get("tactics", ())))
        return TechniqueResolution(original, None, "unknown", original)

    # --- Tactiques ---------------------------------------------------------------------------------------------------
    def tactic_names(self) -> tuple[str, ...]:
        return tuple(self.tactics)

    def normalize_tactic(self, phase: str) -> tuple[str, ...]:
        """Tactique ATT&CK actuelle correspondant à un nom de phase (accepte les anciens noms)."""
        key = (phase or "").strip().lower().replace(" ", "-").replace("_", "-")
        if key in self.tactics:
            return (key,)
        return tuple(t for t in LEGACY_TACTICS.get(key, ()) if t in self.tactics)


@lru_cache(maxsize=1)
def get_reference_kb() -> ReferenceKB:
    """Charge la base de référence (une seule fois). Lève FileNotFoundError avec la commande de génération."""
    if not REFERENCE_FILE.exists():
        raise FileNotFoundError(
            f"{REFERENCE_FILE} introuvable. Générer avec : uv run python -m backend.ontology.stix.update_reference"
        )
    return ReferenceKB(json.loads(REFERENCE_FILE.read_text(encoding="utf-8")))
