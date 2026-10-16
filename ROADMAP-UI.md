# ROADMAP-UI — Refonte visuelle des vues Rapports et Acteurs

## 1. Contexte

- L'interface est en React 18 + TypeScript + Tailwind 3 + React Flow 12 (Vite), dans `frontend/`. Elle lit l'API de `backend/stix_dashboard.py` (données pures : pas de couleurs ni de HTML).
- Deux vues existent : **Rapports** (graphe d'UN article) et **Acteurs** (profil agrégé sur tous les articles).
- Aujourd'hui, les deux vues utilisent le même nœud rectangulaire. Dans la vue Rapports les arêtes vont de centre à centre, donc leurs flèches sont cachées sous les nœuds. La vue Acteurs n'est qu'un petit graphe : l'acteur et ses voisins directs.
- Données disponibles pour un acteur (relations STIX de `ontology/stix/profiles.py`) :
  - pays ou origine : `originates-from` → `location`, ou `attributed-to` → `identity` ;
  - divisions : `part-of` entre acteurs ou ensembles d'intrusion, et `attributed-to` (campagne → ensemble → acteur) ;
  - arsenal : `uses` → malware, outil ; techniques : `uses` → attack-pattern ; infrastructure : `uses` / `controls` → infrastructure ;
  - cibles : `targets` → identité, localisation, vulnérabilité ;
  - références : les rapports qui mentionnent l'acteur, avec les citations des relations.

## 2. Demandes

1. **Vue Rapports** : nœuds ronds, flèches nettement visibles ; le rectangle est réservé aux acteurs de la menace (et à leurs sponsors / États).
2. **Icône par type de nœud** (malware = fléau/insecte, acteur = tête de mort ou démon, etc.), sans emoji, en SVG.
3. **Vue Acteurs** : ce n'est plus un graphe de connaissances mais un **organigramme** en rectangles : identité ou pays en haut, divisions en dessous, puis infrastructures, outils, références. Le tout réparti en **onglets** pour rester ergonomique.

## 3. Décisions de conception

| Sujet | Décision | Raison |
| :--- | :--- | :--- |
| Icônes | `lucide-react` (SVG, arborescence tree-shakée) | Jeu cohérent, trait fin, sobre ; aucun emoji (cohérent avec le style Palantir) |
| Nœud rond | Disque de 56 px, icône au centre, libellé sous le disque, anneau de la couleur de famille | Lisible, le libellé n'agrandit pas le nœud |
| Nœud rectangle (graphe de rapport) | Seulement `threat-actor`, `intrusion-set`, `campaign` (acteurs) et les identités de classe `nation-state` si présentes | Demande utilisateur |
| Flèches | Arêtes « flottantes » : le trait s'arrête au bord du cercle ou du rectangle (intersection), pointe de 18 px, trait 1,5 px, libellé sur fond opaque | Les flèches du centre au centre sont invisibles |
| Organigramme | Mise en page déterministe en couches (pas de dagre sur le graphe d'acteur) : niveau 0 identité/pays, niveau 1 acteur, niveau 2 divisions ; chaque onglet affiche sa propre liste | Un organigramme est un arbre, pas un nuage |
| Onglets de l'acteur | Organigramme · Arsenal (malwares, outils) · Techniques (par tactique ATT&CK) · Infrastructure · Cibles · Références | Un onglet par question d'analyste |
| Backend | Ajouter à `/api/actors/<id>` une section `profile` structurée (identité/pays, divisions, arsenal, techniques par tactique, infrastructure, cibles, références) calculée côté serveur à partir des arêtes | L'UI ne devine pas la sémantique STIX ; testable en Python |

## 3 bis. Limites assumées

- Les « divisions » n'existent dans le graphe que si l'extraction a produit des `part-of` ou des attributions. Sur le seul article extrait aujourd'hui, l'organigramme sera pauvre : il faut le dire dans l'interface (« aucune division connue ») plutôt que d'inventer.
- Pas de pays : la case reste vide avec la mention « origine non établie » (jamais déduite d'une langue ou d'un fuseau).

## 4. Plan d'exécution (réalisé)

1. [x] Écrire ce plan (fait).
2. [x] Backend : `actor_profile()` dans `stix_dashboard.py` + test unitaire (pays, divisions, arsenal, techniques par tactique, infrastructure, cibles, références) ; renvoyé par `/api/actors/<id>` sous `profile`.
3. [x] Frontend, icônes : `lib/icons.ts` (type STIX → icône) + test que chaque type STIX connu a une icône.
4. [x] Frontend, graphe de rapport : nœud rond / rectangle pour acteurs, arêtes flottantes avec flèches visibles, fond du libellé d'arête opaque.
5. [x] Frontend, vue Acteurs : onglets, organigramme en rectangles, tableaux par onglet, références cliquables.
6. [x] Vérification : `tsc`, `vitest`, build, tests Python, captures d'écran des deux vues (cercles, flèches, icônes, chaque onglet).
7. [x] Mettre à jour `.claude/CLAUDE.md` (composants, règle d'affichage) et clore cette feuille de route.

## 5. Écarts avec le plan

- Le rectangle n'est utilisé que pour les types `threat-actor`, `intrusion-set` et `campaign` : STIX n'a pas de type « État », donc aucun sponsor n'est distingué dans le graphe de rapport. Dans l'organigramme, un sponsor est une `identity` reliée par `attributed-to` / `part-of`.
- `dagre` est retiré : l'organigramme a sa propre mise en page déterministe (`lib/org.ts`).
- Ajout : `?tab=` dans l'URL de la vue Acteurs, pour partager ou capturer un onglet précis.
