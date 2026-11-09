# Frontend

Interface Web du CTI Knowledge Graph : exploration des rapports extraits (graphe, indicateurs, règles de détection,
texte de l'article) et profils des acteurs de la menace.

**Pile** : React 18, TypeScript 5, Tailwind CSS 3, React Flow 12 (`@xyflow/react`), d3-force, sigma.js 3 + graphology (arêtes du graphe global, WebGL), react-markdown, Vite 5,
Vitest. L'application est construite dans `dist/` et servie par le backend (`backend/dashboard/server.py`) ; elle ne lit que
l'API REST `/api/*`.

---

## Démarrage

```bash
npm install
npm run dev          # http://localhost:5173, /api proxifié vers http://localhost:8095 (CTI_API_PORT pour un autre port)
npm run build        # vérification de types (tsc --noEmit) puis build Vite vers dist/
npm run typecheck    # types seulement
npm test             # Vitest : layouts, organigramme, filtres, sécurité du rendu
```

En développement, le backend doit tourner : `uv run cti-dashboard --port 8095` depuis la racine, ou tout lancer avec
`scripts/dashboard.sh --dev` (backend + Vite, Ctrl+C arrête les deux). En production, `scripts/dashboard.sh` reconstruit
`dist/` si une source est plus récente que le dernier build, puis sert l'application sur `http://localhost:8095`.

---

## Structure

```text
frontend/
├── index.html
├── src/
│   ├── main.tsx              # point d'entrée React
│   ├── App.tsx               # routage (/ = rapports, /actors = acteurs), chargement des stats et des articles
│   ├── types.ts              # formes JSON de l'API (miroir de backend/dashboard/stix_dashboard.py)
│   ├── index.css             # Tailwind + styles React Flow
│   ├── components/
│   │   ├── Shell.tsx         # barre supérieure : navigation et totaux (articles, entités, relations, IOC)
│   │   ├── ReportsView.tsx   # vue Rapports : liste, onglets, export STIX, inspecteur
│   │   ├── GraphCanvas.tsx   # graphe d'un article (React Flow, positions d3-force)
│   │   ├── Inspector.tsx     # attributs, relations et preuves du nœud sélectionné
│   │   ├── FamilyFilter.tsx  # filtre par famille de types STIX
│   │   ├── IocTable.tsx      # indicateurs : rôle, entité rattachée, statut, filtres
│   │   ├── RuleTable.tsx     # règles YARA / Sigma : texte exact, filtre, copie
│   │   ├── ArticleView.tsx   # markdown nettoyé de l'article
│   │   ├── ActorsView.tsx    # vue Acteurs : liste et onglets du profil
│   │   ├── OrgChart.tsx      # organigramme d'un acteur (React Flow)
│   │   ├── EntryTable.tsx    # tableau générique d'entrées de profil (nom, relation, preuves)
│   │   ├── GlobalView.tsx    # vue Graphe global : calques, recherche (Ctrl K), fiche de sélection, détails, histogramme
│   │   ├── KgCanvas.tsx      # sigma (WebGL) : arêtes, caméra, clics ; nœuds en HTML par-dessus selon le niveau de détail (points,
│   │   │                     #   glyphes, glyphes et noms) ; disposition d3-force par tranches, mise en cache par révision du graphe
│   │   ├── NodeMark.tsx      # nœud HTML (disque à glyphe ou tuile d'acteur, états), partagé par le graphe de rapport et le global
│   │   ├── Timeline.tsx      # histogramme des publications ; glisser retient une période
│   │   └── AskPanel.tsx      # assistant : étapes (outils), réponse avec entités citées, questions suggérées
│   └── lib/
│       ├── api.ts            # client REST typé
│       ├── useAsync.ts       # chargement asynchrone, réponses périmées ignorées
│       ├── layout.ts         # placement déterministe d3-force
│       ├── org.ts            # boîtes et positions de l'organigramme
│       ├── ioc.ts            # libellés de rôles et de statuts, filtres des IOC
│       ├── rules.ts          # filtre et concaténation des règles
│       ├── icons.ts          # glyphe (lucide-react) par type et sous-type STIX / tactique ATT&CK, forme ronde ou rectangulaire
│       ├── kg.ts             # graphe global : filtres, voisins par relation, histogramme, citations [[E3]]
│       ├── theme.ts          # couleurs par famille et d'état, libellés français des types et sous-types, style d'arête par relation
│       └── *.test.ts         # tests Vitest
├── tailwind.config.js        # palette et typographie
├── vite.config.ts            # proxy /api, configuration Vitest
└── legacy/                   # ancienne interface (HTML/Vis-Network/React Flow 11), archivée, non servie, non versionnée
```

---

## Vues

### Rapports (`/`)

Mise en page en trois colonnes :

1. **Liste des rapports** extraits : titre, source, date, nombre d'entités et de relations.
2. **Zone centrale** à onglets :
   - **Graphe** : sous-graphe de l'article sélectionné, et de lui seul (aucun graphe global). Filtre par famille et
     recherche par nom ou alias (`/api/graph?type=&search=`). Lien vers l'article d'origine.
   - **Indicateurs** : IOC retenus comme malveillants, avec rôle (C2, distribution de la charge…), entité rattachée et
     statut calculé à la lecture (actif probable, vieillissant, périmé, date inconnue).
   - **Détection** : règles YARA et Sigma, texte exact tel que cité par l'article, entité détectée, copie groupée.
   - **Article** : markdown nettoyé, celui qu'a lu l'extraction.
   - Bouton **Exporter STIX** : télécharge `article_<id>.stix.json`. Si l'en-tête `X-Bundle-Matches-Graph` vaut `0`, un
     avertissement signale que le bundle a été réécrit par une extraction en `--dry-run` et ne correspond plus au graphe.
3. **Inspecteur** : attributs du nœud sélectionné (alias, références ATT&CK, tactiques, secteurs, usage détourné,
   articles sources), puis ses relations avec leur confiance et leurs **phrases de preuve**. Cliquer une entité liée la
   sélectionne.

### Acteurs (`/actors`)

Seule vue qui agrège plusieurs articles. Liste des acteurs (intrusion-set, threat-actor, campagne) à gauche, profil à
droite, en onglets :

| Onglet | Contenu |
| :--- | :--- |
| Organigramme | 4 niveaux : origine (pays, sponsor ; « Origine non établie » si aucun article ne l'atteste), acteur, divisions et campagnes, puis domaines Arsenal / Techniques / Infrastructure / Cibles. Cliquer un domaine ouvre son onglet. |
| Arsenal | malwares et outils |
| Techniques | techniques ATT&CK groupées par tactique, dans l'ordre de la kill chain |
| Infrastructure | infrastructures et IOC rattachés à l'acteur ou à ses outils |
| Cibles | victimes, régions, vulnérabilités exploitées |
| Références | rapports sources, alias, références externes |

Le profil est calculé côté serveur (`stix_dashboard._profile`) ; le frontend ne fait que le disposer. Une rubrique vide
reste vide.

---

## Contrat avec l'API

`src/lib/api.ts` est le seul module qui appelle le réseau. `src/types.ts` reflète les réponses de
`backend/dashboard/stix_dashboard.py` : toute modification d'une forme JSON côté serveur doit être reportée ici.

| Fonction | Route | Type |
| :--- | :--- | :--- |
| `api.stats()` | `/api/stats` | `Stats` |
| `api.articles()` | `/api/articles` | `ArticleSummary[]` |
| `api.graph(id, filtres)` | `/api/graph?article_id=` | `ArticleGraph` (`GraphNode[]`, `GraphEdge[]`) |
| `api.iocs(id)` | `/api/iocs?article_id=` | `IocRow[]` |
| `api.rules(id)` | `/api/rules?article_id=` | `RuleRow[]` |
| `api.article(id)` | `/api/article?article_id=` | `ArticleText` |
| `api.bundle(id)` | `/api/bundle?article_id=` | `Blob` + `matchesGraph` |
| `api.actors()` | `/api/actors` | `ActorRow[]` |
| `api.actor(id)` | `/api/actors/<id>` | `ActorProfile` |

L'API ne renvoie que des **données** : couleurs, formes, icônes et libellés sont décidés ici (`theme.ts`, `icons.ts`,
`ioc.ts`). Le champ `family` de chaque nœud (`actor`, `malware`, `tool`, `vulnerability`, `infrastructure`, `technique`,
`detection`, `target`) relie les deux côtés.

---

## Conventions

### Rendu du graphe

- **Formes** : nœuds ronds avec une icône par type STIX ; rectangles réservés aux acteurs de la menace (intrusion-set,
  threat-actor, campagne). La forme et le libellé portent l'information, la couleur ne fait que repérer la famille.
- **Arêtes flottantes** : elles partent du bord du nœud le plus proche de l'autre extrémité, avec une flèche.
- **Placement déterministe** (`layout.ts`) : départ sur un cercle, nœuds triés par identifiant, nombre de pas fixe. Le
  même article donne toujours la même image.

### Style

Palette sobre inspirée de Blueprint (Palantir), définie dans `tailwind.config.js` : fonds gris-bleu sombres, **une seule
couleur d'accent** (`accent`, bleu), aucun dégradé ni ombre, coins presque droits. Polices Inter (texte) et JetBrains Mono
(identifiants, métadonnées), embarquées par `@fontsource-variable`. Les couleurs de famille sont désaturées
(`theme.ts`).

### Sécurité du rendu

Le texte affiché vient d'articles scrappés : il n'est jamais interprété comme du HTML.

- Aucun `innerHTML` ni `dangerouslySetInnerHTML` dans `src/` ; le test `safety.test.ts` échoue si l'un apparaît.
- `ArticleView` rend le markdown avec `react-markdown`, qui construit des éléments React : le HTML brut de l'article
  s'affiche comme du texte.
- Les images de l'article ne sont pas chargées (requête vers un hôte tiers) : leur lien est affiché à la place.
- Les liens externes s'ouvrent avec `rel="noreferrer noopener"`.

---

## Tests

| Fichier | Vérifie |
| :--- | :--- |
| `layout.test.ts` | le placement est déterministe et sans chevauchement |
| `org.test.ts` | niveaux de l'organigramme, origine jamais inventée, renvoi vers les onglets, cases sans chevauchement |
| `icons.test.ts` | chaque type STIX libellé a son icône ; seuls les acteurs sont rectangulaires |
| `ioc.test.ts` | filtre « actifs seulement » (un statut inconnu n'est pas actif), recherche |
| `rules.test.ts` | filtre par langage, concaténation YARA / Sigma |
| `safety.test.ts` | aucune injection HTML dans les sources |
