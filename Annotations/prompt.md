Tu pré-annotes un rapport CTI pour constituer un gold standard d'évaluation, selon la méthode jointe : @methode_annotation.md. Un analyste validera ta sortie. Ton objectif est la précision, pas l'exhaustivité : en cas de doute, n'ajoute pas.

Article : {{ARTICLE}}

Règles :
1. Source unique : le texte de l'article. N'utilise aucune connaissance externe sur l'acteur ou l'outil (pas de TTPs « connues » de l'acteur si l'article ne les décrit pas).
2. `gold:required` : uniquement ce que le texte décrit explicitement.
3. `gold:acceptable` : uniquement si un artefact précis de l'article (commande, chemin, clé de registre, log) le justifie. Cite cet artefact. Une simple plausibilité ne suffit pas.
4. Chaque entité et chaque relation porte une `x_gold_evidence_quote` exacte, copiée de l'article dans sa langue d'origine, sans traduction ni reformulation. Sans citation, pas d'objet. Si la citation identifie l'entité sans établir à elle seule le lien avec la source de la relation (campagne, malware), ajoute un `x_gold_context` : courte synthèse de l'inférence (section de l'article, échantillon concerné, chronologie du texte, référent d'un pronom, annexe IOC). Il complète la citation, sans la remplacer.
5. ATT&CK v20.0 uniquement. Vérifie chaque ID avec le tool MITRE ; un ID non vérifiable va dans `candidats_rejetés`. Si la sous-technique n'est pas déterminable depuis le texte, utilise la technique parente.
6. Une seule technique par comportement décrit : choisis la plus spécifique justifiée, pas toutes celles qui pourraient s'appliquer.
7. Hors périmètre : aucun IOC (hash, fichier, IP, domaine, URL, adresse e-mail, certificat, mutex), aucun `indicator`. Les SCO qui ne sont pas des IOCs restent dans le périmètre, en particulier `software` pour le produit visé (éditeur, versions affectées).
8. Attribution : n'attribue rien que l'article n'attribue pas. Reporte son niveau de confiance dans `confidence` : faible = 15, modérée = 50, forte = 85, non précisée = champ absent.
9. Ajoute un objet `report` qui référence tous les objets et porte l'URL de l'article (`external_references`) et `x_gold_attack_version: "20.0"`.
10. `x_gold_sequence` : uniquement si l'article décrit un déroulé d'attaque ; sinon, omets-la.

Sortie :
- Le bundle STIX 2.1 en JSON, sans commentaire.  Directement écrit dans un fichier JSON dans le répertoire adéquat de l'article 
- Puis un bloc JSON séparé `candidats_rejetés` : `[{"candidat": "...", "raison": "..."}]`, pour les TTPs ou relations envisagées mais non retenues. L'analyste tranchera.