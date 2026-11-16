# Extraction fiable : proposer large, vérifier strict — conception

Date : 2026-11-12 · branche `feature/cascade-extraction` · s'appuie sur la cascade v2
(`backend/extracting/cascade/`, plan `docs/superpowers/plans/2026-11-11-extraction-en-cascade.md`).

## 1. Intention

Le Knowledge Graph agrège les articles : le graphe global et les profils d'acteurs additionnent ce que chaque article
affirme. Une affirmation fausse ne reste donc pas locale ; elle pollue le profil d'un groupe pour tous les articles
suivants. Le but est un STIX par article qui modélise **correctement et complètement le mode opératoire de l'attaquant**,
sans affirmation fausse ni trompeuse.

« Utile » (définition de l'utilisateur) : essentiel à la compréhension du mode opératoire, sans induire en erreur la
connaissance future du graphe. Concrètement, la chaîne **qui → avec quoi → comment → contre qui → par quelle
infrastructure** : acteur, campagne, malwares, outils, techniques, infrastructure, cibles, vulnérabilités, et les
relations entre eux. Chercheurs, éditeurs, historique, mentions générales : secondaires.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs, par priorité** (décision de l'utilisateur : la qualité d'abord, l'optimisation après) :

1. **Précision** : aucune affirmation fausse, aucune erreur de jugement (mécanisme, porteur, incident, statut).
2. **Exhaustivité** de la chaîne du mode opératoire.
3. **Robustesse** : même article → même STIX d'une exécution à l'autre ; tenue sur tous les types d'articles (vulnérabilité
   seule, article très long, analyse de malware seule).
4. **Coût en tokens** : mesuré à chaque étape, optimisé seulement une fois 1 à 3 atteints.

**Non-objectifs** : battre le gold sur son score ; reproduire les conventions du gold quand elles contredisent la
modélisation correcte ; entraîner un modèle (pas de fine-tuning, voir la mémoire du projet).

**Anti-objectifs** (échec même si les chiffres montent) :
- un vérificateur qui valide dès qu'un nom apparaît dans la phrase (Qian 2026 : l'auto-vérification valide 92,5 % des
  faux positifs de contexte) ;
- une hypothèse de l'analyste ou un démenti enregistré comme fait établi ;
- une sous-technique devinée là où le texte n'établit que la parente ;
- un gain obtenu par une phrase de prompt qui vise un article annoté (fuite du gold, règle 6 de CLAUDE.md).

## 3. Convention de modélisation (décisions de l'utilisateur, 2026-11-12)

- **Porteur = celui qui fait l'action.** Ce que fait le code d'un malware ou d'un outil est porté par ce malware ou cet
  outil ; ce que font les opérateurs est porté par l'acteur (`intrusion-set` nommé). Une relation ne part jamais de la
  campagne par commodité.
- **La campagne est le nœud central** quand l'article en décrit une : elle relie les entités centrales du mode opératoire
  (`campaign attributed-to intrusion-set`, `campaign uses malware / tool / infrastructure`, `campaign targets` identité,
  lieu, secteur, vulnérabilité), d'où dérivent les entités qui détaillent le mode opératoire (techniques du malware,
  infrastructure de l'acteur…).
  *Décision de conception* : une action d'opérateurs sans groupe nommé (pas d'`intrusion-set` anonyme, méthode
  d'annotation) est portée par la campagne, qui représente alors l'opération de ces opérateurs.
- **Campagne non nommée** : créée seulement si l'article décrit une opération (vague ou ensemble d'intrusions sur une
  période) ; jamais forcée. Le modèle lui donne un nom tiré du contexte selon une convention fixe.
  *Décision de conception* : convention `<élément distinctif> campaign (<acteur ou malware principal>[, <période>])`, en
  anglais ; le nom généré est marqué (`x_cti_generated_name: true`) pour qu'il ne serve jamais à fusionner des campagnes
  entre articles dans Neo4j.
- **Pas d'hypothèses dans le graphe** : une affirmation présentée comme spéculative (« may », « could », « possibly »)
  ou démentie est retirée, pas gardée avec une confiance basse.
  *Décision de conception, à confirmer* : une conclusion que l'auteur assume avec un qualificatif (« we assess with
  moderate confidence that… », « likely attributed to… ») est une affirmation de la source, pas une inférence de
  l'extracteur ; elle est gardée avec `confidence` 60. Les attributions passent très souvent par ce type de phrase.
- **Le gold suit la même convention** : là où il fait partir de la campagne ce que fait un malware ou un acteur, il est
  révisé (phase 0).
- **Faits généraux sur un acteur** (décision du 2026-11-13) : une connaissance CTI établie sur un acteur ou son outil, hors
  de l'incident (secteurs qu'il vise d'habitude, malware qu'il emploie, capacités connues d'un malware), est gardée,
  rattachée à l'acteur avec sa confiance, jamais à la campagne de l'incident ; l'alignement entre articles fusionne ou
  enrichit. Un événement passé précis et une généralité sans acteur sont retirés.
- **Systèmes d'exploitation** (plus tard) : compatibilité d'exécution d'un malware par la propriété standard
  `operating_system_refs` vers des objets `software` (seul usage de `software` encore envisagé, sans relation).
- **STIX 2.1 strict** (décisions du 2026-11-13, après l'audit des faux positifs de `cascade2_a`) : seules les relations de
  la norme ; plus de `targets software` ni de `software has vulnerability`, et plus d'objet `software` dans la couche
  sémantique (le produit est nommé dans la description de la vulnérabilité ou de la technique). Les règles de types et de
  techniques qui en découlent sont dans `Annotations/methode_annotation.md` (« Types d'entités », « Ce que porte un
  logiciel », « Techniques : frontières ATT&CK ») :
  - pays → `location` ; nom de fichier jamais nom de malware ; binaire natif `tool` seulement s'il a un identifiant
    logiciel ATT&CK v20 (cmd, certutil, Expand), sinon technique seule ;
  - infrastructure nommée avec les mots du texte, sans IP ni qualificatif ajouté ; hébergeur ≠ infrastructure ;
  - course-of-action limitée au correctif d'une vulnérabilité nommée (`remediates`) ;
  - commanditaire étatique : `intrusion-set attributed-to threat-actor (nation-state) attributed-to identity`, confiance
    du statut ; noms tels qu'écrits dans l'article (jamais un alias ATT&CK d'un autre éditeur à la place) ;
  - un logiciel tiers ne porte que ce qu'il fait lui-même, sous la forme normée `attack-pattern uses tool` (STIX 2.1 n'a
    pas `tool uses attack-pattern`) ; ce que les opérateurs en font part des opérateurs ;
  - table `RELATIONS` ramenée à la norme (modèle : `docs/stix-v2.1-os.pdf`, sections 4.x.2, qui font foi sur l'annexe B) : retirer `targets software`,
    `software has / related-to`, `malware communicates-with infrastructure`, `tool uses *`, `tool drops tool`,
    `av-analysis-of` ; garder `remediates` et `attack-pattern uses malware/tool`, qui sont dans la norme ;
  - organisation usurpée dans un leurre ≠ cible ; sous-technique seulement si le détail distinctif est dans le texte.

## 3 bis. Contraintes (inchangées)

- Modèle distant vLLM `cti-qwen` (Qwen 27B AWQ, contexte 32k), sortie contrainte par schéma JSON ; jamais plus de requêtes
  simultanées que `CTI_LLM_SLOTS`.
- Le modèle décide du sens ; le code propose, borne, vérifie la forme et informe. Aucune règle déterministe ne type une
  entité ni ne juge un nom.
- Pas de raisonnement libre sur le choix de la technique (Qian 2026 : il dégrade). Pas de confiance verbalisée par le
  modèle (ne vaut rien).
- Aucun nom ni identifiant des articles annotés dans les prompts ou le code.
- Chaque variante se mesure sur au moins deux exécutions et se compare avec `cti-eval --compare`.
- SQLite en lecture seule ; Neo4j via `stix_store` uniquement.

## 4. Ce que disent les données (2026-11-12, `cascade2_a` / `cascade2_b`, sans appel au modèle)

| Constat | Chiffres | Conséquence |
|---|---|---|
| Les erreurs sont des erreurs de jugement, pas des hallucinations | audit des 21 techniques hors famille du gold : 7 F, 8 D, 6 J ; F = piège du mot-clé, confusion de phase ; D = sous-technique trop précise, voisine, hypothèse prise pour un fait | le vérificateur juge le sens, pas la présence des noms |
| La première cause d'omission est le **choix de la technique** | techniques du gold manquées : 18–19 « candidate non retenue », 7–8 « aucun comportement relevé » ; relations perdues par extrémité manquante : 27–33 viennent d'une technique non retenue | proposer plusieurs techniques par procédure, le vérificateur tranche |
| La deuxième est le **porteur** | 36–44 relations « autre source » : campagne ↔ malware ↔ intrusion-set, dans les deux sens | convention du porteur à fixer (§8) puis vérification de l'agent |
| Relations jamais proposées | `campaign uses malware` (6), `attack-pattern targets vulnerability/software` (5), `campaign targets location` (3) | passage de liens entre grappes |
| Une campagne non nommée manquée coûte cher | 1558 : la campagne décrite mais sans nom n'est pas créée → 8 relations perdues | question de convention (§8) |
| 1079 | les relations `technique targets vulnerability/software` ne sont jamais écrites ; le vérificateur retire `software has vulnerability` | relations des techniques et vérificateur à revoir |
| Stabilité entre deux exécutions | Jaccard entités 0,86, techniques 0,85, relations 0,77 ; 1438 : techniques 0,00 | la robustesse est un vrai chantier |
| La stabilité est un signal | entités stables : 69 % appariées au gold ; instables : 43 % | le consensus entre lectures classe et stabilise ; il ne prouve pas (Qian) |

## 5. Ce que retient la littérature, et ses angles morts

Retenu : le graphe comme **vérificateur / contrainte** plutôt que source de recherche (méta-analyse Sardianos 2026 :
1,7 % de sorties non étayées contre 21,4 %) ; union de lectures pour le rappel (MTPE) ; liens entre îlots (CTINexus) ;
séparation extraire / vérifier / consolider (TACTIC-KG, KGAgent4CTI) ; contexte et trous du gold comme causes principales
des faux positifs (Qian).

Angles morts que cette conception doit couvrir :

1. **Vérificateur naïf** : une question « la phrase étaye-t-elle l'affirmation ? » est validée par la simple mention.
   → questions d'extraction fermées (qui fait l'action, de quel incident, quel mécanisme), et vérificateur validé sur un
   jeu étiqueté avant d'être branché (§6.4).
2. **Statut épistémique absent** : aucun papier ne distingue fait, évaluation, hypothèse, démenti ; Qian montre qu'une
   phrase d'attribution injectée fait rebasculer l'événement dans 73–96 % des cas. → statut par affirmation (§6.2 V5).
3. **Triplets isolés** : personne ne mesure la chaîne ni le porteur. → mesure du porteur, contrôle de cohérence.
4. **Textes courts** : MTPE et CTINexus évaluent sur des extraits. → texte entier + grappes + liens entre grappes.
5. **Variance ignorée** (10 études sur 53 la rapportent). → stabilité mesurée (§7).
6. **Omissions non diagnostiquées**. → pertes par étape (`losses.py`) et audit des omissions.
7. **Contamination du graphe agrégé**. → plus tard : conflits entre articles signalés à l'agrégation (§9, phase 5).

## 6. Architecture

Trois couches, chacune mesurée à part : la proposition porte le rappel, la vérification la précision, la consolidation
la cohérence.

### 6.1 Proposer large (rappel)

Base : la cascade v2 (entités, relations, grappes incident/contexte, grille des 15 tactiques, choix parente puis
sous-technique, relations des techniques).

Ajouts :
- **P1 — plusieurs techniques par procédure.** Le choix renvoie jusqu'à 3 techniques candidates par procédure au lieu
  d'une (3 : décision de conception) ; la vérification retient. Cible : les 18–19 « candidate non retenue ».
- **P2 — liens entre grappes.** Après les grappes, un appel propose les relations entre centres de grappes et entités de
  l'incident qui ne figurent dans aucune relation (`campaign uses malware`, `campaign targets location`,
  `attack-pattern targets vulnerability/software`, `attributed-to`). Même schéma à branches que `relation_schema`.
- **P4 — campagne non nommée.** L'étape des grappes indique si l'incident est une opération décrite ; si oui et qu'aucune
  campagne n'est nommée, elle propose un nom selon la convention du §3. Cible : 1558 (8 relations perdues).
- **P3 — deuxième lecture.** La grille est produite deux fois (température 0 et une température plus haute) ; l'union
  alimente le choix ; chaque affirmation garde le nombre de lectures qui l'ont produite (signal de classement, jamais
  de preuve).

### 6.2 Vérifier strict (précision)

Chaque affirmation candidate (entité de la chaîne, relation, couple porteur–technique) passe des contrôles. Les contrôles
du modèle sont des **questions d'extraction à réponse fermée** sur les phrases citées, pas des « oui / non ». Ils sont
regroupés par grappe : un appel vérifie toutes les affirmations d'une grappe, une réponse énumérée par affirmation.

| Contrôle | Qui | Question | Réponses |
|---|---|---|---|
| V1 ancrage | code (existant, `DraftGraph.relate`) | les phrases citées nomment-elles les deux extrémités ? | accepte / refuse |
| V2 agent | modèle | dans ces phrases, qui effectue l'action décrite ? | une entité de l'incident (énumération) / « non dit » |
| V3 portée | modèle | ces phrases décrivent-elles l'incident du rapport ou autre chose ? | incident / fait général sur un acteur / événement passé / généralité sans acteur |
| V4 mécanisme | modèle | la phrase décrit-elle le mécanisme de cette définition ATT&CK ? | la technique / seulement la parente / aucune |
| V5 statut | modèle | comment le texte présente-t-il cette affirmation ? | établie / évaluée probable / hypothèse / démentie |

Décisions :
- V2 ≠ porteur proposé → la relation est réécrite sur l'agent répondu s'il existe, retirée s'il est « non dit ».
- V3 « fait général sur un acteur » → gardée sur l'acteur (réattribuée si elle partait de la campagne, retirée sans acteur
  nommé) ; « événement passé » ou « généralité » → retirée.
- V4 « seulement la parente » → remontée à la parente ; « aucune » → retirée.
- V5 → établie : `confidence` 85 ; conclusion assumée par l'auteur : `confidence` 60 ; hypothèse ou démentie : retirée
  (§3). Valeurs : décision de conception, ajustables.
- V2, V3, V5 s'appliquent aussi aux relations entre entités (`attributed-to`, `targets`, `uses` malware/outil).

### 6.3 Consolider (cohérence)

Code : dédoublonnage, `prune_subsumed_techniques` (existant), fusion des couples (porteur, technique), retrait des
entités sans relation (`DraftGraph.linked`). **Signalements de cohérence** (le code signale, ne décide pas) : une
technique de préparation (Reconnaissance, Resource Development) portée par un malware ou un outil, une technique
d'opérateur portée par du code, etc. ; une affirmation signalée repasse par V2 avec le signalement en contexte.

### 6.4 Barrière avant de brancher le vérificateur

Le vérificateur est d'abord évalué hors ligne, sur un jeu étiqueté construit à partir des exécutions existantes :
- les faux positifs audités (F à rejeter ; J et D à garder ou remonter) ;
- les vrais positifs appariés au gold (à garder) ;
- les faux positifs de contexte (V3 doit les rejeter : le test que Qian exige).

Il n'est branché que s'il rejette au moins deux tiers des F **et** garde au moins 95 % des vrais positifs (rejets à tort
mesurés, comme le demande la méta-analyse ; seuils : décision de conception). Sinon on corrige les questions, pas les
seuils.

## 7. Mesure

Trois chiffres principaux, en plus du score habituel (conservé pour la continuité) :

1. **Taux d'erreurs** : audit de tout ce qui n'est pas apparié au gold — techniques, mais aussi entités et relations
   (extension de `fp_audit.py` et de son interface). Précision corrigée = (appariés + J) / prédits ; D publié à part.
2. **Omissions de la chaîne** : éléments `gold:required` des motifs de la chaîne du mode opératoire manqués, par étape
   de perte (`losses.py`) ; un audit des omissions marque ceux que le gold rend discutables.
3. **Stabilité** : Jaccard entités / techniques / relations entre deux exécutions du même code (script de l'analyse du
   2026-11-12, à intégrer à `cti-eval --compare`).

Secondaires : tokens générés et appels par article ; taux de rejets à tort du vérificateur.

**Limite des références.** Le gold a été produit par Claude et les verdicts d'audit avec l'aide de Gemini. Tous les
chiffres mesurent donc un accord avec des références produites par des LLM, pas une vérité experte ; un même biais
partagé par l'extracteur et le gold passe inaperçu. *Décision de conception* : un **noyau validé à la main** (2 ou 3
articles dont l'utilisateur relit entièrement le gold révisé, plus les verdicts du jeu de test du vérificateur) sert de
référence pour les décisions de branchement ; les 9 articles restent l'indicateur courant. Les publications
mentionnent l'origine des références.

## 8. Questions tranchées

1. Porteur, campagne centrale, révision du gold : §3.
2. Campagne non nommée : créée seulement si décrite, nommée par le modèle selon une convention (§3, P4).
3. Hypothèses : retirées (§3).
4. Étiquetage : gold produit par Claude, audits aidés par Gemini ; noyau validé à la main (§7).

## 9. Ordre de réalisation

Chaque phase est mesurée sur deux exécutions contre `cascade2_a/b` avant la suivante.

0. **Références et mesure** : règle du porteur et campagne centrale écrites dans `Annotations/methode_annotation.md` ;
   gold révisé selon cette règle, **à partir du texte de l'article et jamais des sorties de l'extracteur** (sinon la
   mesure devient circulaire), puis relu par l'utilisateur sur le noyau validé ; audit étendu aux entités et relations ;
   stabilité dans `--compare` ; jeu étiqueté du vérificateur. Les références `cascade2_a/b` sont re-notées contre le gold
   révisé avant toute comparaison.
1. **Vérificateur** V2–V5 construit, évalué hors ligne (§6.4), puis branché.
2. **Proposition large** : P1, puis P2, puis P3 (une à la fois).
3. **Statut épistémique** dans le STIX (`confidence`) et dans le dashboard.
4. **Robustesse** sur les cas limites (vulnérabilité seule, article long, sorties vides) et l'article du holdout.
5. Plus tard : conflits entre articles à l'agrégation dans Neo4j ; optimisation des tokens.

## 10. Laissé au constructeur

Formulation exacte des prompts (sans nom du gold), découpage des appels de vérification par grappe ou par lot, schémas
JSON, température de la deuxième lecture, noms des modules (proposition : `backend/extracting/cascade/verify.py`),
format du jeu étiqueté.
