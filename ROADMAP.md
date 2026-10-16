# ROADMAP — Pipeline CTI Knowledge Graph

Voir aussi `ROADMAP-UI.md` (refonte de l'interface, réalisée).

## À refaire

### 1. Extraction des IOC malveillants, rattachés à l'infrastructure de l'attaquant, datés par l'article

**Besoin.** Extraire les indicateurs de compromission cités dans les articles, les rattacher à l'infrastructure (et au malware ou à l'acteur) concernée, et conserver la date de l'article pour juger plus tard s'ils sont encore pertinents.

**État actuel.** Le prétraitement garde les IOC à leur place dans le récit (décision durable, voir mémoire du projet) et le moteur Rust ne les extrait pas. L'extracteur STIX masque les unités qui ne sont que des indicateurs : aucun IOC n'arrive dans le graphe. L'onglet « Infrastructure » de l'acteur ne montre que des entités nommées par le LLM (ex. « Telegram bot »).

#### Ce que feraient les chercheurs en CTI et les éditeurs (à valider par lecture des sources avant de figer le design : ces points viennent de la pratique du domaine, pas d'une vérification faite dans ce projet)

1. **Distinguer indicateur et observable.** Une IP citée dans un article n'est pas un indicateur de compromission par nature : elle devient un indicateur quand le texte la dit malveillante. STIX 2.1 sépare l'*observable* (objet de cyber-observable : `ipv4-addr`, `domain-name`, `url`, `file` avec hashes, `email-addr`…) de l'*indicator* (motif de détection avec `valid_from`, `valid_until`, `confidence`). OpenCTI et MISP font la même séparation (observable, indicateur, score).
2. **Qualifier le rôle de l'IOC dans l'attaque**, car c'est ce qui permet de le rattacher à l'infrastructure : serveur C2, distribution de la charge, exfiltration, phishing, relais ou proxy, domaine de staging. Un hash de fichier se rattache au malware ou à l'outil, une IP ou un domaine à une `infrastructure`.
3. **Écarter ce qui n'est pas malveillant**, première source de faux positifs des plateformes de renseignement :
   - victime, chercheur, éditeur, IP de sinkhole ;
   - plages privées et réservées (RFC 1918, documentation) ;
   - services légitimes abusés (CDN, hébergeurs de fichiers, Telegram, GitHub, DNS publics) : l'IOC malveillant est alors le chemin ou le compte, pas l'hôte ;
   - hashes de fichiers système connus.
   MISP appelle cela les *warninglists* ; les éditeurs utilisent des listes de domaines populaires et de plages cloud. Ces listes sont de la donnée de référence versionnée, pas du code (même principe que l'invariant « aucune liste en dur dans Rust »).
4. **Normaliser et valider** : refanging (déjà fait en amont), minuscules pour les domaines et hashes, validation syntaxique (octets d'IP, longueur du hash selon MD5/SHA-1/SHA-256, TLD plausible), dédoublonnage, identifiant déterministe (comme les UUIDv5 de l'ontologie). Les extracteurs de référence (ioc-finder, iocextract, cyobstract du CERT/CC, txt2stix) font de l'extraction par motifs, puis le contexte est traité à part. L'extraction des valeurs doit donc être **déterministe**, pas générée par le LLM.
5. **Dater correctement.** La date de l'article n'est pas la date de l'activité. Retenir trois dates distinctes : publication de l'article (certaine), période d'activité si le texte la donne (« entre mars et avril 2026 »), et première et dernière observation agrégées entre articles (min et max des dates des articles qui citent l'IOC). Un IOC cité à nouveau par un article plus récent repousse `last_seen`. STIX modélise cela par `Sighting` (`first_seen`, `last_seen`, `where_sighted_refs` = l'éditeur) et `valid_from` / `valid_until` sur l'indicateur.
6. **Faire vieillir les IOC (decay), et ne jamais stocker le verdict.** La durée de vie dépend du type (Pyramid of Pain de D. Bianco) : un hash reste vrai longtemps mais est trivial à changer pour l'attaquant ; une IP est réattribuée vite (cloud, hébergement mutualisé) ; un domaine dure de quelques jours à quelques mois. MISP a des modèles de *decaying* par taxonomie, OpenCTI a des règles de décroissance de score avec `valid_until`, Recorded Future pondère le risque par l'ancienneté. Pour ce projet : stocker les dates et les sources, calculer le statut (actif probable, ancien, périmé) **à la lecture** avec une table de demi-vies par type, jamais le statut lui-même.
7. **Mesurer la confiance par corroboration** : nombre d'articles indépendants, éditeurs distincts, cohérence du rôle entre articles. Un IOC cité par un seul rapport reste « non corroboré ».
8. **Traçabilité et partage** : chaque IOC garde l'article source et la phrase de preuve, comme les relations aujourd'hui. Prévoir le marquage TLP au moment d'un export, qui est hors périmètre actuel.
9. **Enrichissement externe (optionnel, hors ligne par défaut)** : résolution DNS passive, VirusTotal, Shodan ou Censys confirment qu'un IOC est encore actif. Ils exigent des clés et des appels réseau : à garder comme une étape facultative, jamais comme une dépendance du pipeline.

#### Plan proposé

| # | Étape | Détail |
| :-- | :--- | :--- |
| 1 | Modèle | Observables STIX (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file`, `email-addr`) + `indicator` (pattern STIX) ; `infrastructure consists-of` observable ; `indicator indicates` infrastructure / malware / acteur ; `sighting` pour chaque citation (date de l'article). Aucune propriété `x_*`. |
| 2 | Extraction déterministe | Module `extracting/iocs.py` : motifs, validation, normalisation, positions dans le texte, section d'origine. Pas d'appel LLM pour les valeurs. |
| 3 | Filtrage | Listes de référence versionnées (domaines populaires, plages privées et cloud, hashes bénins) dans `ontology/stix/reference/`, avec test de non-régression. |
| 4 | Rôle et rattachement | Une classification LLM à réponse fermée (enum : c2, distribution, exfiltration, phishing, autre, non malveillant) par candidat, avec le contexte de la phrase ; rattachement au sujet de la section, comme pour les relations. Peu de tokens générés : respecte le débit mesuré du serveur Ollama. |
| 5 | Dates et agrégation | `first_seen` / `last_seen` entre articles ; période d'activité extraite du texte quand elle existe. |
| 6 | Decay à la lecture | Table de demi-vies par type d'IOC dans la configuration ; statut calculé dans `stix_dashboard.py`. |
| 7 | API et interface | Onglet « Infrastructure » de l'acteur : tableau valeur, type, rôle, première et dernière observation, nombre de sources, statut ; filtre « actifs seulement ». Dans un rapport, les IOC apparaissent en nœuds ronds rattachés à l'infrastructure. |
| 8 | Évaluation | Échantillon annoté à la main (au moins 20 articles de sources variées) : précision et rappel par type, taux de faux positifs bénins, vérification que le refang et le masquage des unités d'indicateurs ne font perdre aucun IOC. |

**Points ouverts à trancher avec l'utilisateur.**
- Faut-il un score de pertinence numérique (OpenCTI) ou seulement trois statuts ?
- Quelles demi-vies par défaut ? Il faudra les choisir à partir de sources publiées, pas de mon intuition.
- Les IOC d'une annexe « Indicators of Compromise » sans phrase de contexte sont-ils rattachés à l'acteur de l'article, ou laissés non rattachés ?

**Risque connu.** Sans corroboration ni enrichissement, la « pertinence » ne reflète que l'âge et le nombre de sources : l'interface doit l'afficher ainsi et ne pas laisser croire qu'un IOC récent est actif.

---

### 2. Autres points à refaire (déjà identifiés)

- Rappel faible de l'extraction sur les articles thématiques (1 relation sur 1207 et 1338) ; typage incohérent des services abusés (outil ou infrastructure).
- Fusion des alias d'acteurs (Dr. Tube et @BonJoviGoesHard sont le même opérateur) : alignement d'entités par embeddings et validation par alias explicite.
- Pas de coréférence ; sighting, Attack Flow et course-of-action non extraits.
- Précision auditée à la main sur un seul article : faire un audit sur plusieurs articles (un à la fois, vu la durée).
- Architecture multi-format (CSV d'IOC, captures d'écran de blogs) : aucun OCR ni modèle de vision installé aujourd'hui. L'extraction d'IOC déterministe ci-dessus doit être pensée pour recevoir aussi un CSV d'IOC comme source directe.
- Question ouverte : retirer `LEGACY_TACTICS` (la correspondance defense-evasion vers stealth / defense-impairment est une inférence).
