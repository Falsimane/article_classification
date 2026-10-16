# ==============================================================================
# Dockerfile Neo4j 5 Community - CTI Knowledge Graph & RDF/OWL Ontology
# ==============================================================================
FROM neo4j:5-community

LABEL maintainer="CTI Pipeline <falsimagne.thomas@gmail.com>"
LABEL description="Conteneur Neo4j configuré pour l'ingestion de Cyber Threat Intelligence (CTI), APOC et Neosemantics (n10s)"

# ------------------------------------------------------------------------------
# 1. Configuration des Plugins (APOC + Neosemantics n10s)
# ------------------------------------------------------------------------------
# Active APOC (Awesome Procedures on Cypher) et n10s (Neosemantics pour RDF/OWL)
ENV NEO4J_PLUGINS='["apoc", "n10s"]'

# Autorisation des procédures non restreintes pour APOC et Neosemantics
ENV NEO4J_dbms_security_procedures_unrestricted="apoc.*,n10s.*,semantics.*"
ENV NEO4J_dbms_security_procedures_allowlist="apoc.*,n10s.*,semantics.*"

# Activation du endpoint HTTP RDF pour Neosemantics (:7474/rdf/ping, etc.)
ENV NEO4J_server_unmanaged__extension__classes="n10s.endpoint=/rdf"

# Autorisation des opérations d'import/export de fichiers pour APOC
ENV NEO4J_apoc_import_file_enabled="true"
ENV NEO4J_apoc_export_file_enabled="true"

# ------------------------------------------------------------------------------
# 2. Identifiants et Sécurité (Valeurs par défaut modifiables au runtime)
# ------------------------------------------------------------------------------
# Utilisateur: neo4j / Mot de passe par défaut: password123
# Surchargeable au runtime avec: -e NEO4J_AUTH=neo4j/<votre_mot_de_passe>
ENV NEO4J_AUTH="neo4j/password123"

# ------------------------------------------------------------------------------
# 3. Optimisation Mémoire (adaptée pour Graph CTI & Attack Graph)
# ------------------------------------------------------------------------------
ENV NEO4J_server_memory_heap_initial__size="512m"
ENV NEO4J_server_memory_heap_max__size="2G"
ENV NEO4J_server_memory_pagecache_size="1G"

# ------------------------------------------------------------------------------
# 4. Exposition Réseau
# ------------------------------------------------------------------------------
# 7474 : Neo4j Browser (HTTP) & Endpoint REST/RDF
# 7687 : Protocole Bolt (Python Driver, Cypher-Shell)
EXPOSE 7474 7687

# ------------------------------------------------------------------------------
# 5. Volumes Persistants
# ------------------------------------------------------------------------------
VOLUME ["/data", "/logs", "/import", "/plugins"]

# ------------------------------------------------------------------------------
# 6. Contrôle de Santé (Healthcheck)
# ------------------------------------------------------------------------------
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:7474 || exit 1
