# Ontologie CTI fondée sur STIX 2.1

Remplace l'ontologie maison de `backend/ontology/ontology.py` (dépréciée, encore utilisée par l'extracteur, Neo4j et
le serveur tant qu'ils n'ont pas migré).

## Pourquoi remplacer l'ancienne ontologie

| Défaut | Conséquence |
|---|---|
| 12 classes maison. `SoftwareSystem` fusionne malware, outil légitime, logiciel victime et agent IA ; `ObservableIndicator` fusionne observable et indicateur | Le modèle de langage range tout dans la même classe ; les « postures » (`lotl`, `dedicated_malware`…) recréent mal la distinction STIX `malware` / `tool` |
| 15 prédicats dont 8 décrivent un processus (`spawns_process`, `injects_into`, `drops_artifact`…) | Relations propres à un incident, sans valeur de connaissance réutilisable, impossibles à exporter vers un outil CTI |
| `leads_to_step` et préconditions maison | Réinvente, sans standard, la séquence d'attaque (MITRE Attack Flow) |
| Liste noire d'éditeurs écrite en dur | Incomplète par construction, ne généralise pas à une nouvelle source |
| `cveId`, `mitreId` : propriétés maison | STIX place la CVE et l'identifiant ATT&CK dans `external_references` |
| Aucune provenance (`Report`, auteur), aucune notion d'observation (`Sighting`) | « Vu dans cet incident » et « capacité connue » sont confondus |
| Prédicats libres : aucun ancrage externe | « APT29 », « Cozy Bear » et « Midnight Blizzard » font trois nœuds |

## Deux niveaux, volontairement distincts

1. **Ontologie complète** (`schema.py`, `relationships.py`) : tout ce qui est valide en STIX 2.1. 44 types, 193 triplets.
2. **Profils d'extraction** (`profiles.py`) : le sous-ensemble qu'il vaut la peine d'extraire d'un texte, selon la
   catégorie donnée par le classifieur. Moins de types, moins de relations, chacune définie avec « utiliser quand » et
   « éviter ». C'est cet écart qui limite les faux positifs.

| Profil | Types | Paires de relations | Particularités |
|---|---|---|---|
| `operational` | 12 | 67 | + observations (`sighting`) + séquence (Attack Flow) |
| `tactical` | 12 | 70 | capacités, lignée (`variant-of`, `authored-by`), détection |
| `strategic` | 8 | 31 | attribution, victimologie, structure des groupes ; aucun détail d'exécution |
| `out_of_scope` | 0 | 0 | rien n'est extrait |

## Décisions de modélisation

- **Malware ou outil** : code écrit pour nuire → `malware` ; logiciel légitime détourné → `tool` ; binaire natif de l'OS
  → `tool` avec le label `living-off-the-land`. Service légitime abusé → `infrastructure` + `abused-legitimate-service`.
- **Acteur ou groupe** : un nom de groupe d'éditeur (APT29, UNC2452, Storm-0558) → `intrusion-set` ;
  `threat-actor` est réservé aux personnes et organisations réelles identifiées.
- **Un acteur *cible* une vulnérabilité, seul un malware l'*exploite*** (`threat-actor --uses--> vulnerability` n'existe
  pas en STIX ; le validateur le rejette et propose `targets`).
- **Observé ou connu** : `uses` = connaissance générale (comme ATT&CK) ; `sighting` = observation datée chez une victime.
- **Séquence d'une intrusion** : Attack Flow (`attack-flow`, `attack-action`, `attack-asset`, `attack-condition`,
  `attack-operator`, extension `extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4`), pas de lien ad hoc.
- **Règle de détection** : un `indicator` avec `pattern_type` (yara, sigma, snort, suricata), pas un « DefensiveMeasure ».
- **Observables** (IP, domaine, URL, condensat, e-mail) : extraits par règles, jamais par le LLM. Le LLM ne relie que
  des entités.
- **Provenance** : l'article est un `report` dont `object_refs` liste tout ce qui en est extrait ; l'éditeur est une
  `identity` en `created_by_ref`, jamais un nœud de l'attaque. Chaque relation garde sa citation et sa confiance dans
  des champs STIX standard (`description`, `external_references[].description` et `url`, `confidence`).
- **Confiance** : échelles normatives STIX 2.1 Annexe A. Sans formule nuancée, un fait affirmé vaut 85 (« High »).

## Ce que fait le validateur (`sanitize_extraction`)

Il corrige ce que la norme ou la base ATT&CK permet de corriger avec certitude, et rejette le reste.

| Corrige | Rejette |
|---|---|
| Identifiant ATT&CK révoqué → remplaçant (`T1562.001` → `T1685`) | Éditeur ou chercheur pris pour un acteur (`PUBLISHER_AS_ADVERSARY`) |
| Nom de technique contredit par son identifiant | Terme générique (`GENERIC_TERM`) |
| Alias → nom canonique + alias, par rapprochement ATT&CK (UNC3944 → Scattered Spider G1015) | Relation inexistante en STIX (`INVALID_RELATIONSHIP`) avec les relations valides en retour |
| Type contredit par ATT&CK (`Cobalt Strike` acteur → malware) | Relation hors profil (`RELATION_NOT_IN_PROFILE`) |
| Acteur rapproché d'un groupe ATT&CK (G…) → `intrusion-set`, type de la donnée de référence | Citation absente, trop courte ou **introuvable dans le texte** |
| Relation écrite à l'envers (sens inversé) | **Citation qui ne parle pas des entités reliées** (`EVIDENCE_NOT_ABOUT_ENTITIES`) |
| Valeur hors vocabulaire ouvert STIX | Entité sans aucune relation étayée (`ORPHAN`) |

Chaque décision est un `Issue(level, code, subject, message)` : sert d'audit et de retour au modèle.

## Sources et vérifications

Aucune table n'est écrite de mémoire ; chacune a été confrontée à une source.

| Élément | Source | Vérification |
|---|---|---|
| Relations STIX | Spécification OASIS STIX 2.1, Annexe B et sections 4 et 6 | Table extraite du HTML de la spécification |
| Relations ATT&CK | `attack-stix-data` (MITRE, v20.0) | `tests` : les 15 triplets publiés (10 739 `malware uses attack-pattern`, 869 `tool uses attack-pattern`…) sont valides |
| Extensions OpenCTI (Filigran) | `stixCoreRelationshipsMapping` du dépôt OpenCTI | Table des paires parsée ; seules les extensions utiles à des articles CTI sont retenues |
| Vocabulaires ouverts | bibliothèque `stix2` 3.0.2 | Importés, non copiés (a corrigé deux erreurs de ma mémoire : `identity_class` `unknown`, types d'infrastructure) |
| Séquences | MITRE Attack Flow 2.0 | Schéma JSON officiel |
| Confiance | STIX 2.1 Annexe A | Tables lues dans la spécification |

ATT&CK change : la v20 a 15 tactiques dont `stealth` et `defense-impairment`, et `defense-evasion` n'existe plus.
Les tactiques et techniques sont donc lues dans `reference/attack_enterprise.json`, et les objets révoqués ou
dépréciés (179) y sont conservés avec leur remplaçant.

Mise à jour de la base : `uv run python -m backend.ontology.stix.update_reference`.
© The MITRE Corporation, reproduit avec sa permission (notice dans le fichier de données).

### Volontairement non codé : les conventions de nommage d'éditeurs

Les noms d'acteurs (familles météo de Microsoft, animaux de CrowdStrike, préfixes Mandiant ou Unit 42…) sont des
conventions propriétaires, sans spécification publiée, qui changent (Microsoft a abandonné ses noms d'éléments
chimiques ; ATT&CK a remplacé « Defense Evasion » par « Stealth » et « Defense Impairment »). Les coder dans l'ontologie
figerait des conventions qui évolueront. STIX ne normalise pas les noms, il normalise la façon de les relier : un
objet et plusieurs `aliases`. Les alias convergent donc par le rapprochement avec ATT&CK ; l'origine géographique
d'un acteur vient du texte (`originates-from` étayée par une citation), jamais de la forme de son nom ; la
distinction `threat-actor` / `intrusion-set` suit les définitions STIX.

### Non couvert

- **Rapid7, BloodHound** : je n'ai pas vérifié de schéma public de graphe de connaissances pour Rapid7. BloodHound
  modélise des chemins d'attaque dans un environnement (Active Directory), pas des rapports de menace : sa leçon
  (arêtes typées à la sémantique précise) est déjà reflétée par les définitions de relations, mais son modèle n'est
  pas intégré.
- ATT&CK Enterprise seulement (pas ICS ni Mobile), pas de D3FEND, CAPEC ni CWE.

## Standard ou choix du projet

| Élément | Statut |
|---|---|
| Types SDO/SCO/SRO, relations de l'Annexe B, vocabulaires ouverts, `aliases`, `kill_chain_phases`, `external_references`, `confidence`, `sighting`, TLP | **Standard STIX 2.1** |
| Séquences (`attack-flow`, `attack-action`…) | **Extension MITRE CTID**, mécanisme `extension-definition` de STIX |
| `subtechnique-of`, `tool uses attack-pattern` | **Données ATT&CK** (relations publiées par MITRE, hors table STIX) |
| `part-of`, `cooperates-with`, `participates-in`, objet `incident` | **Extensions OpenCTI** : valides pour OpenCTI, `relationship_type` libre en STIX |
| Identifiants CVE, CWE, CAPEC, ATT&CK (G, S, T, C) | Normes de fait (MITRE) |
| Valeurs de confiance | Échelles de l'Annexe A ; **choix du projet** : un fait affirmé sans réserve vaut 85, et le mapping des formules d'analyste (« likely », « allegedly »…) vers ces valeurs |
| Labels `living-off-the-land`, `abused-legitimate-service` | **Choix du projet** (les `labels` STIX sont libres, mais ces termes ne viennent d'aucun vocabulaire) |
| Identifiants déterministes (UUIDv5) | **Choix du projet** pour l'idempotence ; l'espace de noms est fixe et ne doit jamais changer |
| `GENERIC_TERMS`, suffixes ignorés par `normalize_name` (« group », « team »…), `LEGACY_TACTICS` | **Heuristiques du projet** (rapprochement et rejet de termes vagues) ; `LEGACY_TACTICS` est déduit de la renommée de TA0005 |
| Propriétés personnalisées `x_*` | **Aucune** dans le bundle exporté (vérifié en mode strict de `stix2`) |

## Correspondance avec l'ancienne ontologie

| Ancien | STIX 2.1 |
|---|---|
| `threat_actor` | `threat-actor` ou `intrusion-set` (+ `campaign`) |
| `victim_profile` | `identity` (organisation, individu, secteur : classe `class` + `sectors`) |
| `software_system` dédié / outil / LOLBin | `malware` / `tool` / `tool` + label `living-off-the-land` |
| `software_system` victime | `software` (observable) ou `identity` classe `system` |
| `hardware_or_host` | `identity` classe `system` |
| `identity_or_credential` | `user-account` (jamais la valeur du secret) |
| `data_repository` | `attack-asset` (Attack Flow) |
| `vulnerability`, `misconfiguration` | `vulnerability` (CVE ou CWE en `external_references`) |
| `attack_pattern` | `attack-pattern` + `external_references` ATT&CK |
| `infrastructure` | `infrastructure` (+ observables liés) |
| `observable_indicator` | observable (SCO) et/ou `indicator` |
| `defensive_measure` | `course-of-action` (parade) ou `indicator` (règle de détection) |
| postures, modalités | `malware`/`tool` ; `sighting` pour « observé » ; `confidence` |
| `spawns_process`, `injects_into`, `drops_artifact`, `exfiltrates_to`… | `attack-action` (Attack Flow) ou `drops`, `downloads`, `exfiltrates-to` |
| `leads_to_step`, préconditions | `effect_refs` d'Attack Flow |

## Utilisation

```python
from backend.ontology.stix import PROFILES, render_prompt_card, sanitize_extraction, build_stix_objects, to_bundle

card = render_prompt_card("operational")          # ontologie à injecter dans le prompt (~2 800 tokens)
graph = sanitize_extraction(llm_output, "operational", source_text=clean_markdown, publisher_names=[site_name])
objects = build_stix_objects(graph, {"source_id": 597, "title": ..., "url": ..., "site_name": ..., "published": ..., "category": "operational"})
bundle_json = to_bundle(objects)                   # validé par stix2, importable dans OpenCTI
```

Tests : `uv run python -m unittest tests.test_stix_ontology -v`.

## État

Ontologie, validation et export : faits et testés. **Pas encore branchés** : `cti_extractor.py` (prompt et schéma de
sortie), `neo4j_store.py`, `server.py` et le tableau de bord utilisent toujours l'ancienne ontologie. La réduction des
faux positifs n'est pas encore mesurée sur de vraies extractions du modèle.

Reste à faire : validation des `sighting` et des objets Attack Flow dans `sanitize_extraction` (types enregistrés,
règles non écrites) ; résolution pays/secteur vers ISO 3166-1 et `industry-sector-ov` ; test de la carte de prompt avec
Qwen (sa taille est de l'ordre de 2 800 tokens pour le profil opérationnel).
