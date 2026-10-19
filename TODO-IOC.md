# TODO-IOC — Reprise du chantier « IOC malveillants datés, rattachés à l'infrastructure »

Contexte et raisonnement : voir `ROADMAP.md` (section « À refaire », point 1). Ce fichier dit **où en est le code** et **ce qu'il reste à faire**.
Dernière mise à jour : 2026-10-19. Travail sur la branche `feature/ioc-infrastructure`.

## 1. Ce qui est fait (et comment c'est vérifié)

| Élément | Fichier | Vérification |
| :--- | :--- | :--- |
| Données de référence : TLD IANA (1 437) et 5 000 domaines populaires Tranco, datées | `backend/ontology/stix/reference/{tlds,popular_domains}.txt`, mise à jour : `uv run python -m backend.ontology.stix.update_ioc_reference` | Fichiers générés |
| Modèle STIX des IOC : observable (SCO, id de la norme) + indicator (pattern STIX) + sighting par article + infrastructure dérivée ; `valid_from` = première observation | `backend/ontology/stix/iocs.py` | `tests/test_iocs.py` (22 tests), bundle validé en mode strict par `stix2` |
| Statut calculé à la lecture (actif / vieillissant / périmé / inconnu), jamais stocké | `ioc_status`, `LIFETIMES` dans `iocs.py` | `tests/test_stix_dashboard.py` |
| Extraction des valeurs par règles : IPv4/IPv6, domaines (TLD réel), URL, courriels, hachages MD5/SHA-1/SHA-256, refanging de sécurité, dates explicites | `backend/extracting/iocs.py` (`find_iocs`) | Tests + mesure sur les 1 105 articles du corpus (voir §3) |
| Filtrage : adresses privées/réservées, versions et user-agents, domaines populaires, éditeur de l'article, noms de fichier (`.py`, `.sh`…), liens de référence, règles Sigma/YARA | idem | Tests ; échantillons relus à la main |
| Étape LLM à réponse fermée : rôle (c2, payload-delivery, exfiltration, phishing, staging-or-proxy, malware-sample, other-malicious, not-malicious, unknown) + entité de rattachement parmi des candidats | idem (`extract_iocs`) | Tests avec faux modèle ; 1 vrai article (600) |
| Câblage pipeline, export, CLI (`--show-iocs`), Neo4j (sightings, `valid_from` qui ne régresse pas, IOC exclus des comptages et du graphe d'entités) | `pipeline.py`, `export.py`, `cti_extractor.py`, `stix_store.py` | Article 600 extrait et relu dans Neo4j |
| API : `/api/iocs?article_id=`, IOC dans `/api/actors/<id>`, `iocs_count`, `ioc_count` par infrastructure | `backend/stix_dashboard.py`, `backend/server.py` | `tests/test_stix_dashboard.py` (17 tests) |
| UI : tableau d'IOC (filtre « actifs seulement », recherche, copie, preuves), onglet « Indicateurs » d'un rapport, pastille « n IOC » sur les infrastructures, onglet Infrastructure des acteurs, résumé dans l'organigramme | `frontend/src/components/IocTable.tsx`, `ReportsView.tsx`, `ActorsView.tsx`, `lib/ioc.ts`, `lib/org.ts` | `npm test` (14 tests), `tsc`, build OK |

Décisions prises à la place de l'utilisateur (à confirmer, voir `ROADMAP.md`, « Points ouverts ») :
- trois statuts (pas de score numérique) ;
- demi-vies par défaut **heuristiques, non calibrées** : IP 30/180 j, domaine 90/365, URL 60/270, courriel 180/730, fichier 365/1825 ;
- IOC sans sujet explicite → rattaché à l'incident décrit (confiance 55) ; rôle inconnu → jamais rattaché (confiance 35).

## 2. Ce qui est cassé ou jamais vérifié

1. ~~Bug des localisations~~ **corrigé** (commit `945ef7c`) : `backend/ontology/stix/places.py` résout nom → pays ISO / région STIX, sinon rejet `UNRESOLVED_LOCATION`. Tests : `tests.test_stix_ontology.Locations`. L'article 615 a ensuite abouti (voir §6).
2. **Interface des IOC jamais vue** : aucune capture d'écran du tableau, de l'onglet Indicateurs, des pastilles ni de l'onglet Infrastructure avec des IOC. Seuls `tsc`, `vitest` et le build ont été exécutés.
3. **Endpoints jamais appelés sur le serveur réel** après ces changements : `/api/iocs`, `/api/actors/<id>` (champ `iocs`), `/api/stats` (`iocs_count`), `/api/graph` (`ioc_count`). Les requêtes Cypher `actor_iocs` et `article_ioc_counts` n'ont été exécutées sur aucune donnée (l'article 600 n'a que 4 IOC, rattachés à une infrastructure et non à un acteur).
4. **Qualité du rôle et du rattachement** relue sur un seul article (600 : 4 IOC, cohérents avec le texte). L'article 615 a abouti (83 IOC retenus sur 86 valeurs, 15 écartées) mais n'a **pas** été relu à la main.
5. **Purge et ré-extraction** d'un article partageant des IOC avec un autre : non testées (les nœuds partagés sont conservés tant qu'un article les étaye, par `article_ids`).

## 3. Mesures déjà faites (sans LLM, sur les 1 105 articles classifiés)

- Valeurs candidates : 5 431 hachages, 5 420 domaines, 3 465 URL, 2 701 IPv4, 107 courriels, 23 IPv6 (avant ajout des filtres « règle/document », « version »). 438 articles sans aucun IOC.
- Coût LLM estimé : 920 appels pour tout le corpus (médiane 1 par article, 8 au pire).
- Faux positifs repérés à la main puis corrigés : URL de règles Sigma/YARA sur GitHub, `Chrome/118.0.0.0`, numéros de version.
- Ce sont des **comptages et des échantillons**, pas une mesure de précision ni de rappel.

## 4. Reste à faire, dans l'ordre

1. ~~Bug des localisations~~ fait ; article 615 extrait dans Neo4j (265 s).
2. Démarrer `uv run cti-dashboard --port 8080`, sonder les 4 endpoints (§2.3), puis prendre des captures de : Rapports > Indicateurs, graphe avec pastilles, Acteurs > Infrastructure, organigramme. Corriger ce qui apparaît.
3. Relire à la main les rôles et rattachements de l'article 615 (hachages, IP, domaines) ; ajuster le prompt de `ioc_system()` si nécessaire.
4. **Évaluation (étape 8 de la feuille de route, non commencée)** : annoter à la main au moins 20 articles de sources variées ; mesurer précision et rappel par type d'IOC, taux de faux positifs bénins (victime, service légitime, ressource de l'éditeur), et vérifier que le refanging et le masquage des unités d'indicateurs ne font perdre aucun IOC.
5. **Calibrer `LIFETIMES`** sur des sources publiées (durée de vie des IP, domaines, URL) ; tant que ce n'est pas fait, l'interface doit continuer de dire que le statut est indicatif.
6. Trancher avec l'utilisateur les trois points ouverts de `ROADMAP.md`.
7. Documentation à mettre à jour : `.claude/CLAUDE.md` (modules `extracting/iocs.py`, `ontology/stix/iocs.py`, `update_ioc_reference`, option `--show-iocs`, tests `tests.test_iocs`, composant `IocTable`), `backend/ontology/stix/README.md`, fichier mémoire du projet, et cocher l'avancement dans `ROADMAP.md`.
8. Lancer toute la suite avant de commiter : `uv run python -m unittest tests.test_iocs tests.test_stix_dashboard tests.test_stix_ontology tests.test_extraction_pipeline` et, dans `frontend/`, `npm test && npm run build`.

## 5. Limites connues du design actuel (à garder en tête)

- Un rôle par **élément** : toute une section d'annexe reçoit le même rôle et le même rattachement ; une section qui mélange C2 et hébergement de charge sera mal classée.
- Seuls les 5 000 premiers domaines Tranco sont écartés : un service légitime moins populaire est envoyé au modèle ; un domaine très populaire ET abusé n'est conservé que sous forme d'URL.
- Pas de liste de hachages bénins, pas de mutex, clés de registre, JA3 ni certificats ; pas de SHA-512.
- Les périodes d'activité (« entre mars et avril ») ne sont pas lues ; seule une date explicite **unique** dans la phrase remplace la date de l'article.
- L'infrastructure dérivée porte un nom en anglais (« Command-and-control infrastructure — <sujet> ») : elle fusionne entre articles par ce nom.
- Aucun enrichissement externe (DNS passif, VirusTotal) : « actif » veut dire « observé récemment », pas « confirmé en ligne ».
- Le marquage TLP n'est posé que par défaut ; pas de gestion du partage.

## 6. Durée d'extraction : mesure faite, optimisation NON faite (décision : ne pas optimiser pour l'instant)

Objectif exprimé : ≤ 20 s par article. Mesuré sur l'article 615 (49 385 caractères, 246 phrases, 7 passes), serveur Ollama avec **qwen3:32b seul** (pas d'autre modèle de génération installé), exécution complète : **260-265 s**.

| Étape | Appels | Tokens lus | Tokens générés | Secondes |
| :--- | ---: | ---: | ---: | ---: |
| entités | 7 | 22 993 | 921 | 95 |
| vérification des entités | 1 | 2 252 | 177 | 14 |
| relations | 3 | 13 511 | 731 | 54 |
| vérification des relations | 4 | 14 270 | 615 | 55 |
| IOC (rôle, rattachement) | 3 | 7 220 | 596 | 42 |
| **Total** | **18** | **≈ 60 000** | **3 040** | **≈ 260** |

Débits mesurés : génération ≈ 38 tok/s, lecture du prompt ≈ 330 tok/s (≈ 180 s de lecture + ≈ 80 s de génération). Le serveur traite les requêtes une à une, donc le parallélisme n'aide pas. Conséquence : **le budget de 20 s ≈ 3 000 tokens lus + 300 générés** ; le seul texte de l'article (≈ 12 000 tokens) dépasse déjà ce budget. Le pipeline actuel ne peut pas y arriver en changeant des paramètres.
Constat annexe : l'appel `entities#0` est tronqué (limite de tokens atteinte) : des entités ont pu être perdues sur cet article.

Pistes, par gain décroissant (à trancher avec l'utilisateur ; rien n'est implémenté) :
1. **Hybride déterministe** : entités, CVE, ATT&CK, IOC et candidats de relations par règles et base de référence ; le LLM ne voit que quelques phrases choisies. Vise 15-25 s, rappel un peu plus faible.
2. **Modèle plus petit** (8B, ≈ 4× plus rapide) à installer sur le serveur ; ne garantit pas 20 s sur un article long.
3. **Allègements sans changer de modèle** : vérifications optionnelles par défaut (−70 s), plafonner le texte lu, fusionner les appels, ne soumettre au LLM que les IOC ambigus (−40 s) → ≈ 90-120 s.
4. Dans tous les cas, mesurer avant/après avec un script de profilage par étape (celui utilisé ici n'est pas versionné) et vérifier la qualité sur les articles annotés de l'étape 8.
