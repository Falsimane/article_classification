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
- Hors périmètre aussi (décision du 2026-11-13, STIX 2.1 strict) : l'objet `software`. STIX 2.1 ne lui donne aucune relation (`targets software` et `software has vulnerability` sont des extensions) ; le produit visé est nommé dans la description de la vulnérabilité (le CVE l'identifie) ou de la technique (« paquet npm <produit> » pour T1195.002).
- Seules les relations de la norme STIX 2.1 sont admises (table `specs.RELATIONS`, sans extension).

## Types d'entités
- **Pays, régions** : `location`, jamais `identity`. Un gouvernement ou une agence en tant qu'organisation : `identity` (`organization`).
- **Malware** : une famille nommée, ou un composant décrit sans nom (« C# downloader », « malicious kernel driver »). Un nom de fichier (`*.dll`, `*.log`, `*.dat`…) n'est jamais un nom de malware : c'est un IOC.
- **Tool** : un logiciel tiers légitime ou offensif employé par l'attaquant (Mimikatz, JuicyPotato, SoftEther VPN, MacroPack, yuze). Un binaire natif du système n'est un `tool` que s'il a un identifiant logiciel ATT&CK v20 (cmd S0106, certutil S0160, Expand S0361) ; sinon (rundll32, regsvr32, mshta, msiexec, wscript, curl, traceroute, choice), seule la technique est annotée, et elle nomme déjà le binaire (Rundll32 T1218.011).
- **Infrastructure** : systèmes contrôlés par l'attaquant ou service légitime détourné, nommés avec les mots du texte (« Slack », « Cloudflare Workers ») : aucun qualificatif ajouté (« C2 teams », « C2 infrastructure »), aucune adresse IP ni domaine dans le nom (couche observable), aucun regroupement fabriqué à partir d'un tableau d'IOC. Un hébergeur (entreprise) n'est pas une infrastructure.
- **Course-of-action** : seulement le correctif ou la mise à jour d'une vulnérabilité nommée (`course-of-action remediates vulnerability`). Les recommandations génériques (DMARC, blocage d'un sous-réseau, surveillance) et les produits de sécurité commerciaux ne sont pas annotés.
- **Commanditaire étatique** (lien rapporté ou évalué avec un État) : `intrusion-set attributed-to threat-actor` (`nation-state`) `attributed-to identity` (le gouvernement), avec la confiance du statut (60 si « reported », « assessed », « likely »). Jamais un gouvernement en `threat-actor` direct, jamais `intrusion-set attributed-to identity` (hors norme).
- **Noms** : tels qu'écrits dans l'article. Un alias tiré d'une référence externe (groupe ATT&CK d'un autre éditeur) ne remplace jamais le nom de l'article ; il peut figurer en `external_references`.

## Campagnes et acteurs
- Une `campaign` n'est créée que si l'article décrit une opération : une vague ou un ensemble d'intrusions contre des cibles, sur une période (une intrusion racontée de bout en bout en est une). Elle n'est jamais créée pour servir de nœud central au graphe.
- Un `intrusion-set` n'est créé que si le texte nomme un groupe (nom ou code de suivi). Pas d'objet anonyme pour « l'attaquant ».
- **Porteur = celui qui fait l'action** (règle révisée le 2026-11-12, campagne ou non) : ce que fait le code d'un malware ou d'un outil (se déchiffrer, persister, communiquer avec son serveur, voler des données) part de ce malware ou de cet outil ; ce que font les opérateurs (envoyer les courriels, choisir les cibles, déployer ou signer le malware, louer ou compromettre l'infrastructure, exploiter une vulnérabilité) part de l'`intrusion-set` nommé ; sans groupe nommé, de la campagne. Une relation ne part jamais de la campagne par commodité.
- **La campagne est le nœud central** quand l'article en décrit une : elle relie les entités centrales du mode opératoire (`campaign attributed-to intrusion-set`, `campaign uses malware / tool / infrastructure`, `campaign targets` identité, lieu, vulnérabilité), d'où dérivent les entités qui détaillent le mode opératoire (techniques du malware, infrastructure de l'acteur…).
- Une campagne décrite mais non nommée par l'article reçoit un nom descriptif en anglais (`<élément distinctif> campaign (<acteur ou malware principal>[, <période>])`) ; elle n'est jamais créée si l'article ne décrit pas d'opération.
- Sans acteur ni campagne (analyse d'un malware, d'une vulnérabilité), les techniques restent reliées à ce qui les porte : le malware, ou la vulnérabilité et le produit qu'elles visent.
- Un fait établi sur un acteur ou son outil en général, hors de l'incident (secteurs qu'il vise d'habitude, malware qu'il emploie, capacités connues d'un malware), est annoté sur l'acteur ou l'outil, jamais sur la campagne ; un événement passé précis ne l'est pas.
- Une hypothèse de l'auteur présentée comme spéculative (« may », « could », « possibly ») ou démentie n'est pas annotée ; une conclusion qu'il assume (« we assess », « likely ») l'est.
- **Ce que porte un logiciel** (précision du 2026-11-13) : un logiciel tiers légitime n'est relié qu'à ce qu'il fait lui-même quand il s'exécute (Mimikatz lit la mémoire LSASS, UPX compresse, certutil décode), et dans le sens de la norme : `attack-pattern uses tool` (l'outil sert à réaliser la technique) ; STIX 2.1 n'a pas `tool uses attack-pattern` (convention des données ATT&CK, hors norme). L'opérateur porte la technique et l'outil (`intrusion-set uses attack-pattern`, `intrusion-set uses tool`). Ce que les opérateurs font au logiciel ou avec lui (le renommer, le déguiser, le livrer) ne relie jamais le logiciel à la technique. Le malware de l'attaquant porte ses propres comportements et propriétés (compressé, déguisé, signé) par `malware uses attack-pattern`, qui est dans la norme. Un binaire natif sans identifiant ATT&CK n'est jamais un objet.
- Relations hors norme écartées aussi : `malware communicates-with infrastructure` (la norme le réserve aux IP, domaines, URL ; vers une infrastructure : `beacons-to`, `exfiltrates-to`), `tool drops tool`, `tool uses malware / tool`.
- Un comportement attribué à plusieurs malwares sans que le texte dise lequel (« multi-stage downloaders ») part de la campagne, ou du groupe nommé ; jamais d'un malware choisi au hasard.
- `authored-by` seulement si le texte dit que le groupe développe ou possède le malware (« Gamaredon's GammaDrop ») ; « uniquely attributed to » ou « used by » donnent `uses`. `controls` relie un contrôleur à un implant, jamais un chargeur à sa charge (`drops`, `downloads`).
- Une organisation usurpée dans un leurre (expéditeur falsifié, document leurre) n'est jamais une cible (`targets`) ; elle n'est reliée que par `threat-actor impersonates identity`.
- Les notes de bas de page et glossaires (définition d'un utilitaire) ne fondent aucune relation.

## Techniques : frontières ATT&CK (relevées par l'audit du 2026-11-13)
- **Sous-technique** seulement si le texte donne le détail qui la distingue (protocole web pour T1071.001, canal C2 pour T1041, navigateur pour T1555.003, sens de la communication pour T1102.002) ; sinon la technique parente.
- **User Execution (T1204.\*)** seulement si une personne ouvre, clique ou colle ; une exécution automatique par un malware, un script ou un raccourci n'en est pas. Un faux CAPTCHA qui fait coller une commande : T1204.004, pas Drive-by (T1189, exploitation sans action de la victime).
- **T1036.008** : un fichier dont le type est falsifié ; un vrai document leurre joint à la charge n'en est pas un.
- **T1027.002** : compression ou chiffrement d'un exécutable ; l'obfuscation d'une macro ou d'un script relève de T1027 ou T1027.010.
- **T1105** seulement si un transfert depuis l'extérieur est décrit ; extraire une archive déjà présente relève de T1140.
- **Exfiltration** : T1041 seulement si le texte dit que les données passent par le canal C2 ; un envoi par un autre outil (curl vers une adresse de l'attaquant) relève de T1048. T1071.001 décrit le canal C2, pas l'exfiltration.
- **T1587.001** : développer un outil (outil « sur mesure », « bespoke ») ; déployer un malware n'en est pas.
- **Reconnaissance (T1591.\*)** : la collecte d'informations avant l'attaque ; la victimologie observée n'en est pas.
- **Délai avant suppression** (attendre la fin du processus pour effacer son fichier) : T1070.004, pas une évasion temporelle.
- **Modification en mémoire d'un EDR** : T1562.001 ou T1014, pas T1554 (modification d'un binaire sur disque pour persister).
- Une phrase d'introduction ou de résumé fonde une technique quand elle nomme l'acteur et le comportement ; le verbe du comportement doit y figurer, jamais être déduit.

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
