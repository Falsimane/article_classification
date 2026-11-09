# Objectif final

Produire un système NLP/IA performant pour extraire des entités et leurs relations à partir de sources non structurées de threat intelligence. Ces entités/relations alimentent directement un graphe de connaissance (backend) sur les acteurs de la menace, leurs tactiques, leurs outils, leurs infrastructures, etc. A partir de ce graphe, de nombreux cas d'usages peuvent ensuite être imaginés :
* Graphe d'attaque automatisé ;
* Attribution technique des attaques ; 
* Identification de partages d'infrastructures entre acteurs ; 
* Connaissance temps réel à partir des sources OSINT.

# Pourquoi annoter les données ? 

Les LLM ont une forte tendance à halluciner, particulièrement sur des formats tels que STIX ou MITRE. Etant donné que notre système ne sera pas fine-tuné, il est nécessaire de procéder manuellement à l'annotation de certains rapports non structurés de CTI pour avoir une base de référence sur laquelle évaluer le système d'extraction.

# Quoi annoter ? 

- La pyramid of pain démontre que ce qui fait le plus mal aux attaquants sont la découverte de leurs TTPs et de leurs outils. Sur cette base, le système sépare deux couches :
** La couche sémantique : le graphe de connaissance qui a pour noeuds les outils, les TTPs et leurs relations. 
** La couche détection : le datalake qui regroupe les IOCs extraits de manière déterministe et qui permettent la détection à court terme. 

C'est sur la couche sémantique que nous allons nous concentrer d'abord pour annoter les données.

# Méthode d'annotation

L'annotation d'un rapport doit produire en bout de chaine : 
* Un STIX JSON 2.1 correctement formé avec les entités et relations pertinentes, se concentrant sur les tools, les TTPs et l'attribution des acteurs. Il doit permettre de modéliser clairement le rapport sur lequel il porte.
- Hors périmètre : les IOCs ne sont pas annotés : hashes et fichiers (`file`), adresses IP, domaines, URLs, adresses e-mail, certificats, mutex, etc. Ils relèvent de la couche détection et sont extraits de manière déterministe. Les objets `indicator` et les SCO de type IOC produits par l'agent sont ignorés au scoring : ils ne comptent ni comme vrais ni comme faux positifs.
- Dans le périmètre : les SCO qui ne sont pas des IOCs, en particulier `software` pour le produit visé (éditeur, versions affectées). Ils sont annotés et scorés comme les autres entités.

## Campagnes et acteurs
- Une `campaign` n'est créée que si l'article décrit une opération : une vague ou un ensemble d'intrusions contre des cibles, sur une période (une intrusion racontée de bout en bout en est une). Elle n'est jamais créée pour servir de nœud central au graphe.
- Un `intrusion-set` n'est créé que si le texte nomme un groupe (nom ou code de suivi). Pas d'objet anonyme pour « l'attaquant ».
- Sans campagne décrite, les relations partent de l'entité à laquelle le texte attribue le comportement : l'acteur nommé, le malware ou l'outil. Sans acteur ni campagne (analyse d'un malware, d'une vulnérabilité), les techniques restent reliées à ce qui les porte : le malware, ou la vulnérabilité et le produit qu'elles visent.

## Labels d'annotation
Chaque entité (dont les TTP) et chaque relation porte un label :
- `gold:required` : explicite dans le texte (récit ou artefact clairement décrit).
- `gold:acceptable` : inférée par un analyste à partir des artefacts (commandes, logs) ou en recouvrement avec un élément requis.

Chaque relation porte une `x_gold_evidence_quote` : citation exacte ou artefact qui la justifie.

`x_gold_context` : courte synthèse de l'inférence, quand la citation identifie l'entité (TTP, outil, malware) sans établir à elle seule le lien avec la source de la relation. Elle indique ce qui permet ce rattachement : section de l'article, échantillon concerné, chronologie du texte, référent d'un pronom, annexe IOC. Elle complète la citation, sans la remplacer, et n'est pas scorée.

`x_gold_sequence` : étapes ordonnées du mode opératoire (`order: null` = non daté). Elle ne s'applique pas aux analyses purement techniques et n'est pas scorée pour l'instant.

## Évaluation

| Métrique | Calcul |
|---|---|
| **Rappel** (principale) | `required` trouvés / total `required` |
| **Précision** | (`required` + `acceptable` trouvés) / total prédit |

- Un `acceptable` prédit n'est jamais un faux positif ; un `acceptable` manqué n'est pas pénalisé.
- Une prédiction absente du gold part en revue analyste : si elle est validée, elle est ajoutée au gold ; sinon, c'est un faux positif.
- Scores calculés séparément pour les entités et pour les relations ; une relation est correcte si le triplet (source, type, cible) correspond après normalisation.

## Normalisation (avant comparaison)
- **Identifiants canoniques** : IDs MITRE (`G0007`, `S0154`, `T1059.001`) avec une table d'alias (ex. APT28 = Fancy Bear = Sofacy).
- **Version figée** : ATT&CK v20.0, indiquée dans chaque fichier gold.
- **Validation des IDs** : tout ID ATT&CK produit par l'agent doit exister dans le bundle v20.0 ; sinon, il est rejeté et compté comme hallucination.
- **Crédit partiel** : sous-technique exacte = 1 ; technique parente correcte = 0,5 ; sinon 0. Le score strict (sans crédit partiel) est publié à côté.
- **Score relâché** des relations `uses` : la source prédite peut être toute entité du groupe d'activité de la source gold (campagne, groupe auquel elle est attribuée, malwares et outils reliés entre eux) ; la convention du porteur ne compte que dans le score principal.

## Contrôle d'ancrage (sans gold)
Chaque relation produite par l'agent doit porter une `evidence_quote`. On vérifie automatiquement qu'elle existe dans le texte source (correspondance approximative). Une citation introuvable signale une hallucination probable.
