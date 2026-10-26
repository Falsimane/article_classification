## Classification parallèle

Le classifieur utilise plusieurs workers pour envoyer des requêtes indépendantes à Ollama.
La valeur par défaut est de 2. Elle peut être augmentée pour tester le débit de votre machine :

```bash
uv run cti-classifier --workers 4
```

La même valeur peut être définie avec `CTI_CLASSIFIER_WORKERS`. Commencez par 2 ou 3 :
plus de workers ne garantit pas un débit supérieur avec un modèle local volumineux, car
Ollama peut partager la mémoire GPU ou mettre les requêtes en file d'attente.

### Extraction du graphe

L'extraction utilise directement un mode rapide : deux workers, une grande fenêtre
de contexte, sans vérifications LLM répétitives.
Les entités, relations et IOC restent extraits et enregistrés dans Neo4j. Les
validations déterministes Python et la validation STIX restent actives.

```bash
uv run cti-extractor --article-id 686
```

Pour afficher la réponse JSON du modèle au fur et à mesure de sa réception :

```bash
uv run cti-extractor --article-id 686 --show-llm
```

La sortie LLM est envoyée sur stderr afin de ne pas perturber les bundles JSON ni
la sortie de l'extraction. Avec plusieurs workers, les réponses peuvent apparaître
en parallèle et sont préfixées par leur numéro d'appel.

Le délai maximal d'un appel est configurable avec `CTI_LLM_TIMEOUT` (55 secondes
par défaut). Pour diagnostiquer un modèle qui met longtemps à produire son premier
token :

```bash
CTI_LLM_TIMEOUT=55 uv run cti-extractor --article-id 686 --show-llm
```
