/**
 * OPENCTI THREAT INTELLIGENCE PLATFORM - APPLICATION LOGIC
 * Navigation à deux prismes : Rapports CTI (Graphes par incident) & Threat Actor (Arborescence & Timeline)
 */

const STATE = {
  currentView: 'view-reports',
  currentArticleId: null,
  articles: [],
  threatActors: [],
  currentActorId: null,
  currentCampaignId: null,
  graphData: { nodes: [], edges: [] },
  network: null,
  selectedNode: null,
  physicsEnabled: true,
  filters: {
    type: 'all',
    dual_use_only: false,
    hide_orphans: true,
    search: '',
  },
};

// Couleurs par type STIX 2.1 standard OpenCTI
const STIX_COLORS = {
  threat_actor: { bg: '#ef4444', border: '#dc2626', label: 'Threat Actor' },
  malware: { bg: '#f97316', border: '#ea580c', label: 'Malware' },
  tool: { bg: '#3b82f6', border: '#2563eb', label: 'Tool' },
  tool_dual_use: { bg: '#a855f7', border: '#9333ea', label: 'LOLBin (Dual-Use)' },
  vulnerability: { bg: '#ec4899', border: '#db2777', label: 'Vulnerability' },
  infrastructure: { bg: '#06b6d4', border: '#0891b2', label: 'Infrastructure' },
  attack_pattern: { bg: '#10b981', border: '#059669', label: 'ATT&CK Technique' },
  detection_rule: { bg: '#eab308', border: '#ca8a04', label: 'Detection Rule' },
  target: { bg: '#94a3b8', border: '#64748b', label: 'Target' },
};

// =====================================================================
// INITIALISATION
// =====================================================================
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupEventListeners();
  await loadInitialData();
});

async function loadInitialData() {
  await Promise.all([
    fetchStats(),
    fetchArticles(),
    fetchThreatActors(),
  ]);
}

// =====================================================================
// NAVIGATION ENTRE LES VUES (RAPPORTS CTI VS THREAT ACTOR)
// =====================================================================
function setupNavigation() {
  const navReports = document.getElementById('nav-btn-reports');
  const navActors = document.getElementById('nav-btn-actors');

  if (navReports) {
    navReports.addEventListener('click', () => switchView('view-reports'));
  }
  if (navActors) {
    navActors.addEventListener('click', () => switchView('view-threat-actors'));
  }
}

function switchView(viewId) {
  STATE.currentView = viewId;

  // Mise à jour de la barre latérale
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-view') === viewId);
  });

  // Bascule des panneaux
  document.querySelectorAll('.view-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === viewId);
  });

  // Actions spécifiques au changement de vue
  if (viewId === 'view-reports') {
    if (STATE.network) {
      setTimeout(() => STATE.network.fit(), 150);
    }
  } else if (viewId === 'view-threat-actors') {
    if (!STATE.currentActorId && STATE.threatActors.length > 0) {
      selectThreatActor(STATE.threatActors[0].id || STATE.threatActors[0].name);
    }
  }
}

// =====================================================================
// ÉVÉNEMENTS & CONTRÔLES GLOBAUX
// =====================================================================
function setupEventListeners() {
  // Recherche globale
  const searchInput = document.getElementById('global-search');
  searchInput.addEventListener('input', debounce((e) => {
    const val = e.target.value.trim().toLowerCase();
    STATE.filters.search = val;

    if (STATE.currentView === 'view-reports') {
      loadArticleGraph(STATE.currentArticleId);
    } else {
      filterThreatActorsList(val);
    }
  }, 300));

  // Raccourci ⌘K ou Ctrl+K
  window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      searchInput.focus();
    }
  });

  // Sélecteur de rapport actif
  const articleSelect = document.getElementById('article-select-dropdown');
  articleSelect.addEventListener('change', (e) => {
    const artId = e.target.value;
    if (artId) {
      STATE.currentArticleId = artId;
      loadArticleGraph(artId);
    }
  });

  // Filtre de type STIX sur le graphe de l'article
  document.querySelectorAll('.type-chips .chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.type-chips .chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      STATE.filters.type = chip.getAttribute('data-type');
      loadArticleGraph(STATE.currentArticleId);
    });
  });

  // Toggle LOLBins uniquement
  const lolbinToggle = document.getElementById('toggle-lolbins-only');
  lolbinToggle.addEventListener('change', (e) => {
    STATE.filters.dual_use_only = e.target.checked;
    loadArticleGraph(STATE.currentArticleId);
  });

  // Bouton Export RDF Turtle du rapport actif
  const exportBtn = document.getElementById('btn-export-rdf');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      const artId = STATE.currentArticleId;
      const url = artId ? `/api/export/rdf?article_id=${artId}&format=turtle` : '/api/export/rdf?format=turtle';
      window.open(url, '_blank');
    });
  }

  // Bouton Rafraîchir
  document.getElementById('btn-refresh').addEventListener('click', async () => {
    await loadInitialData();
  });

  // Contrôles HUD du graphe Vis-Network
  document.getElementById('hud-zoom-in').addEventListener('click', () => {
    if (STATE.network) {
      const scale = STATE.network.getScale();
      STATE.network.moveTo({ scale: scale * 1.3 });
    }
  });

  document.getElementById('hud-zoom-out').addEventListener('click', () => {
    if (STATE.network) {
      const scale = STATE.network.getScale();
      STATE.network.moveTo({ scale: scale / 1.3 });
    }
  });

  document.getElementById('hud-fit').addEventListener('click', () => {
    if (STATE.network) STATE.network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
  });

  const physicsBtn = document.getElementById('hud-toggle-physics');
  physicsBtn.addEventListener('click', () => {
    STATE.physicsEnabled = !STATE.physicsEnabled;
    if (STATE.network) {
      STATE.network.setOptions({ physics: { enabled: STATE.physicsEnabled } });
    }
    physicsBtn.textContent = STATE.physicsEnabled ? '⏸' : '▶';
    physicsBtn.title = STATE.physicsEnabled ? 'Figer la physique' : 'Activer la physique';
  });

  // Fermeture du Drawer Inspecteur
  document.getElementById('drawer-close').addEventListener('click', closeInspectorDrawer);

  // Recherche dans la liste des Threat Actors
  const actorSearch = document.getElementById('actors-search-input');
  if (actorSearch) {
    actorSearch.addEventListener('input', debounce((e) => {
      filterThreatActorsList(e.target.value);
    }, 250));
  }
}

// =====================================================================
// API STATS & COMPTEURS
// =====================================================================
async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    document.getElementById('pill-entities').textContent = data.entities_count || 0;
    document.getElementById('pill-dual-use').textContent = data.dual_use_count || 0;
    document.getElementById('pill-reports').textContent = data.articles_count || 0;
    document.getElementById('sidebar-reports-count').textContent = data.articles_count || 0;
  } catch (err) {
    console.error('Erreur fetchStats:', err);
  }
}

// =====================================================================
// PRISME 1 : RAPPORTS CTI & GRAPHE UNITAIRE PAR INCIDENT
// =====================================================================
async function fetchArticles() {
  try {
    const res = await fetch('/api/articles');
    const data = await res.json();
    STATE.articles = data.articles || [];

    const select = document.getElementById('article-select-dropdown');
    select.innerHTML = '';

    if (STATE.articles.length === 0) {
      select.innerHTML = '<option value="">Aucun rapport analysé disponible</option>';
      return;
    }

    STATE.articles.forEach((art, idx) => {
      const opt = document.createElement('option');
      opt.value = art.id;
      const countLabel = art.entities_count ? `(${art.entities_count} entités, ${art.relations_count || 0} rels)` : '(non extrait)';
      opt.textContent = `[#${art.id}] ${art.title.slice(0, 50)}... ${countLabel}`;
      select.appendChild(opt);
    });

    // Sélection par défaut du premier rapport
    if (!STATE.currentArticleId && STATE.articles.length > 0) {
      STATE.currentArticleId = String(STATE.articles[0].id);
      select.value = STATE.currentArticleId;
    }

    if (STATE.currentArticleId) {
      await loadArticleGraph(STATE.currentArticleId);
    }
  } catch (err) {
    console.error('Erreur fetchArticles:', err);
  }
}

async function loadArticleGraph(articleId) {
  if (!articleId) return;

  try {
    const params = new URLSearchParams();
    params.set('article_id', String(articleId));
    if (STATE.filters.type && STATE.filters.type !== 'all') params.set('type', STATE.filters.type);
    if (STATE.filters.dual_use_only) params.set('dual_use_only', '1');
    params.set('hide_orphans', STATE.filters.hide_orphans ? '1' : '0');
    if (STATE.filters.search) params.set('search', STATE.filters.search);

    const res = await fetch(`/api/graph?${params.toString()}`);
    const data = await res.json();
    STATE.graphData = data;

    // Mise à jour des métadonnées du rapport actif
    const currentArt = STATE.articles.find(a => String(a.id) === String(articleId));
    document.getElementById('meta-category').textContent = (currentArt && currentArt.primary_category) ? currentArt.primary_category.toUpperCase() : 'CTI';
    document.getElementById('meta-date').textContent = (currentArt && currentArt.publication_date) ? currentArt.publication_date : (data.article_title ? data.article_title.slice(0, 30) : 'Date —');
    document.getElementById('meta-nodes').textContent = `${data.nodes ? data.nodes.length : 0} entités`;
    document.getElementById('meta-edges').textContent = `${data.edges ? data.edges.length : 0} relations`;

    renderVisNetwork(data.nodes || [], data.edges || []);
  } catch (err) {
    console.error('Erreur loadArticleGraph:', err);
  }
}

function renderVisNetwork(rawNodes, rawEdges) {
  const container = document.getElementById('vis-network-canvas');
  const nodes = new vis.DataSet(rawNodes);
  const edges = new vis.DataSet(rawEdges);
  const data = { nodes, edges };

  const options = {
    nodes: {
      borderWidth: 2,
      font: { color: '#f8fafc', size: 13, face: 'Inter, system-ui, sans-serif' },
      scaling: { min: 14, max: 36 },
    },
    edges: {
      width: 1.5,
      arrows: { to: { enabled: true, scaleFactor: 0.8 } },
      color: { color: 'rgba(148, 163, 184, 0.45)', highlight: '#00f0ff', hover: '#38bdf8' },
      font: { color: '#94a3b8', size: 10, face: 'JetBrains Mono, monospace', background: '#0b111e', strokeWidth: 0 },
      smooth: { type: 'curvedCW', roundness: 0.15 },
    },
    physics: {
      enabled: STATE.physicsEnabled,
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant: -75,
        centralGravity: 0.015,
        springLength: 140,
        springConstant: 0.08,
        damping: 0.75,
      },
      stabilization: { iterations: 120, updateInterval: 25 },
    },
    interaction: {
      hover: true,
      tooltipDelay: 150,
      zoomView: true,
      dragView: true,
      selectable: true,
    },
  };

  if (STATE.network) {
    STATE.network.destroy();
  }

  STATE.network = new vis.Network(container, data, options);

  // Clic sur un nœud
  STATE.network.on('click', (params) => {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      const node = rawNodes.find(n => n.id === nodeId);
      if (node) {
        openInspectorDrawer(node, rawNodes, rawEdges);
        highlightNeighborhood(nodeId, rawNodes, rawEdges);
      }
    } else {
      closeInspectorDrawer();
      resetNetworkHighlight(rawNodes, rawEdges);
    }
  });
}

function highlightNeighborhood(selectedNodeId, nodes, edges) {
  if (!STATE.network) return;
  const connectedNodeIds = new Set([selectedNodeId]);

  edges.forEach(e => {
    if (e.from === selectedNodeId) connectedNodeIds.add(e.to);
    if (e.to === selectedNodeId) connectedNodeIds.add(e.from);
  });

  const updateNodes = nodes.map(n => {
    const isConn = connectedNodeIds.has(n.id);
    return {
      id: n.id,
      opacity: isConn ? 1 : 0.2,
      font: { color: isConn ? '#ffffff' : 'rgba(255, 255, 255, 0.2)' },
    };
  });

  const updateEdges = edges.map(e => {
    const isConn = e.from === selectedNodeId || e.to === selectedNodeId;
    return {
      id: e.id,
      color: {
        color: isConn ? '#00f0ff' : 'rgba(255, 255, 255, 0.06)',
        opacity: isConn ? 1 : 0.06,
      },
    };
  });

  STATE.network.body.data.nodes.update(updateNodes);
  STATE.network.body.data.edges.update(updateEdges);
}

function resetNetworkHighlight(nodes, edges) {
  if (!STATE.network) return;
  STATE.network.body.data.nodes.update(nodes.map(n => ({ id: n.id, opacity: 1, font: { color: '#f8fafc' } })));
  STATE.network.body.data.edges.update(edges.map(e => ({ id: e.id, color: { color: 'rgba(148, 163, 184, 0.45)' } })));
}

// Drawer Inspecteur
function openInspectorDrawer(node, allNodes, allEdges) {
  STATE.selectedNode = node;
  const drawer = document.getElementById('inspector-drawer');
  document.getElementById('drawer-entity-name').textContent = node.label || node.id;

  const stixMeta = STIX_COLORS[node.type] || { bg: '#64748b', label: node.type };
  const badge = document.getElementById('drawer-entity-badge');
  badge.textContent = stixMeta.label;
  badge.style.backgroundColor = stixMeta.bg;

  const lolbinBanner = document.getElementById('drawer-lolbin-banner');
  lolbinBanner.style.display = node.is_dual_use ? 'flex' : 'none';

  document.getElementById('drawer-entity-desc').textContent = node.description || 'Aucune description textuelle disponible.';

  // Relations directes et Preuves textuelles
  const connectedEdges = allEdges.filter(e => e.from === node.id || e.to === node.id);
  document.getElementById('drawer-conn-count').textContent = connectedEdges.length;

  const connectionsContainer = document.getElementById('drawer-connections-list');
  const evidenceContainer = document.getElementById('drawer-evidence-list');
  connectionsContainer.innerHTML = '';
  evidenceContainer.innerHTML = '';

  if (connectedEdges.length === 0) {
    connectionsContainer.innerHTML = '<span class="text-dim">Nœud isolé dans ce rapport.</span>';
  } else {
    connectedEdges.forEach(e => {
      const isOutgoing = e.from === node.id;
      const targetName = isOutgoing ? e.to : e.from;

      const pill = document.createElement('div');
      pill.className = 'connection-pill';
      pill.innerHTML = `
        <span class="conn-rel">${isOutgoing ? '—[' + e.label + ']→' : '←[' + e.label + ']—'}</span>
        <span class="kc-phase-tag">[${e.kill_chain_phase || 'general'}]</span>
        <span class="conn-target">${targetName}</span>
      `;
      connectionsContainer.appendChild(pill);

      if (e.evidence) {
        const evCard = document.createElement('div');
        evCard.className = 'evidence-card';
        evCard.innerHTML = `
          <div class="evidence-triple-header">
            ${e.from} → <b>${e.label}</b> → ${e.to}
            <span class="kc-phase-tag" style="float: right;">[${e.kill_chain_phase || 'general'}]</span>
          </div>
          <div>"${e.evidence}"</div>
        `;
        evidenceContainer.appendChild(evCard);
      }
    });
  }

  // Rapport d'origine
  const articlesContainer = document.getElementById('drawer-articles-list');
  articlesContainer.innerHTML = '';
  if (node.articles && node.articles.length > 0) {
    node.articles.forEach(art => {
      const aEl = document.createElement('div');
      aEl.className = 'connection-pill';
      aEl.innerHTML = `
        <span class="conn-rel">RAPPORT #${art.id}</span>
        <span class="conn-target" title="${art.title}">${art.title.slice(0, 45)}...</span>
      `;
      articlesContainer.appendChild(aEl);
    });
  }

  drawer.classList.add('open');
}

function closeInspectorDrawer() {
  STATE.selectedNode = null;
  document.getElementById('inspector-drawer').classList.remove('open');
}

// =====================================================================
// PRISME 2 : THREAT ACTOR (ARBORESCENCE & TIMELINE DES CAMPAGNES)
// =====================================================================
async function fetchThreatActors() {
  try {
    const res = await fetch('/api/threat-actors');
    const data = await res.json();
    STATE.threatActors = data.threat_actors || [];

    document.getElementById('pill-actors').textContent = STATE.threatActors.length;
    document.getElementById('sidebar-actors-count').textContent = STATE.threatActors.length;

    renderThreatActorsList(STATE.threatActors);

    // Sélectionner automatiquement le premier acteur si la vue est active
    if (STATE.threatActors.length > 0 && !STATE.currentActorId) {
      selectThreatActor(STATE.threatActors[0].id || STATE.threatActors[0].name);
    }
  } catch (err) {
    console.error('Erreur fetchThreatActors:', err);
  }
}

function renderThreatActorsList(actors) {
  const container = document.getElementById('actors-list-container');
  container.innerHTML = '';

  if (actors.length === 0) {
    container.innerHTML = '<div class="text-dim" style="padding: 1rem; text-align: center;">Aucun acteur identifié.</div>';
    return;
  }

  actors.forEach(act => {
    const card = document.createElement('div');
    card.className = `actor-card-item ${STATE.currentActorId === act.id ? 'active' : ''}`;
    card.setAttribute('data-actor-id', act.id);

    card.innerHTML = `
      <div class="actor-card-item-top">
        <span class="actor-card-name">
          <span style="font-size: 1.2rem;">${act.flag || '🌐'}</span>
          ${act.name}
        </span>
        <span class="badge-campaigns-count">${act.reports_count || 1} campagne(s)</span>
      </div>
      <span class="actor-card-country">${act.country || 'Non déterminé'}</span>
      <div class="actor-card-meta">
        <span>${act.affiliation_type || 'CTI Actor'}</span>
        <span style="color: #34d399; font-weight: 600;">${act.confidence || 'Élevé'}</span>
      </div>
    `;

    card.addEventListener('click', () => {
      selectThreatActor(act.id || act.name);
    });

    container.appendChild(card);
  });
}

function filterThreatActorsList(query) {
  const q = (query || '').toLowerCase().trim();
  const filtered = STATE.threatActors.filter(act => {
    return act.name.toLowerCase().includes(q) ||
           (act.country && act.country.toLowerCase().includes(q)) ||
           (act.aliases && act.aliases.some(al => al.toLowerCase().includes(q))) ||
           (act.state_affiliation && act.state_affiliation.toLowerCase().includes(q));
  });
  renderThreatActorsList(filtered);
}

async function selectThreatActor(actorId, campaignId = null) {
  STATE.currentActorId = actorId;
  STATE.currentCampaignId = campaignId;

  // Mise à jour de la classe active dans la liste
  document.querySelectorAll('.actor-card-item').forEach(c => {
    c.classList.toggle('active', c.getAttribute('data-actor-id') === actorId);
  });

  try {
    const params = new URLSearchParams();
    if (campaignId) params.set('campaign_id', String(campaignId));

    const res = await fetch(`/api/threat-actors/${encodeURIComponent(actorId)}/tree?${params.toString()}`);
    const data = await res.json();

    if (data.error) {
      console.error('Erreur API tree:', data.error);
      return;
    }

    renderThreatActorTree(data);
  } catch (err) {
    console.error('Erreur selectThreatActor:', err);
  }
}

function renderThreatActorTree(data) {
  const emptyState = document.getElementById('actor-empty-state');
  const contentWrapper = document.getElementById('actor-content-wrapper');

  emptyState.style.display = 'none';
  contentWrapper.style.display = 'flex';

  const actor = data.actor || {};
  const timeline = data.timeline || {};
  const infra = data.infrastructure || {};
  const tools = data.tools || {};

  // 1. CARTE IDENTITÉ RACINE
  document.getElementById('actor-flag').textContent = actor.flag || '🌐';
  document.getElementById('actor-name').textContent = actor.name || 'Acteur CTI';
  document.getElementById('actor-confidence').textContent = `Confiance : ${actor.confidence || 'Élevé'}`;
  document.getElementById('actor-country').textContent = actor.country || 'Non déterminé';
  document.getElementById('actor-affiliation-type').textContent = actor.affiliation_type || 'Syndicat Cybercriminel';
  document.getElementById('actor-state-affiliation').textContent = actor.state_affiliation || 'Non étatique / Collaborations RaaS';
  document.getElementById('actor-sources').textContent = actor.attribution_source || 'Rapports CTI ingérés';
  document.getElementById('actor-desc').textContent = actor.description || 'Groupe de menace actif documenté dans la CTI.';

  // Alias
  const aliasContainer = document.getElementById('actor-aliases-container');
  aliasContainer.innerHTML = '';
  if (actor.aliases && actor.aliases.length > 0) {
    actor.aliases.forEach(al => {
      const chip = document.createElement('span');
      chip.className = 'alias-chip';
      chip.textContent = al;
      aliasContainer.appendChild(chip);
    });
  }

  // 2. TIMELINE CLIQUABLE DES CAMPAGNES
  renderCampaignTimeline(timeline.campaigns || [], timeline.selected_campaign_id, timeline.is_consolidated);

  // 3. ARBORESCENCE INTERACTIVE CTI AVEC REACT FLOW
  if (window.renderThreatActorFlow) {
    const rfCanvas = document.getElementById('threat-actor-react-flow-canvas');
    if (rfCanvas) {
      window.renderThreatActorFlow(rfCanvas, data, (selectedNode) => {
        handleThreatActorFlowNodeClick(selectedNode);
      });
    }
  }

  // 4. RACINE ARBRE
  document.getElementById('tree-root-name').textContent = actor.name;
  document.getElementById('tree-root-country').textContent = `Attribution / Pays : ${actor.country || 'Inconnu'}`;

  // 4. BRANCHE INFRASTRUCTURE
  document.getElementById('infra-summary-count').textContent = infra.summary || 'Infrastructures et indicateurs actifs';

  // TTPs Réseau / C2
  const ttpsContainer = document.getElementById('infra-ttps-container');
  ttpsContainer.innerHTML = '';
  if (infra.ttps && infra.ttps.length > 0) {
    infra.ttps.forEach(ttp => {
      const badge = document.createElement('div');
      badge.className = 'ttp-badge';
      badge.title = ttp.description || ttp.name;
      badge.innerHTML = `
        ${ttp.mitreId ? `<span class="mitre-id">${ttp.mitreId}</span>` : ''}
        <span>${ttp.name}</span>
      `;
      ttpsContainer.appendChild(badge);
    });
  } else {
    ttpsContainer.innerHTML = '<span class="text-dim" style="font-size: 0.8rem;">Aucune technique réseau spécifique extraite.</span>';
  }

  // Nœuds d'Infrastructure & Indicateurs (IOCs)
  const infraNodesContainer = document.getElementById('infra-nodes-container');
  infraNodesContainer.innerHTML = '';
  if (infra.nodes && infra.nodes.length > 0) {
    infra.nodes.forEach(node => {
      const nodeCard = document.createElement('div');
      nodeCard.className = 'infra-node-card';

      let indicatorsHtml = '';
      if (node.indicators && node.indicators.length > 0) {
        indicatorsHtml = node.indicators.map(ind => `
          <div class="indicator-pill-row">
            <span>${ind.value}</span>
            <button class="btn-copy-ioc" onclick="copyToClipboard('${ind.value}')" title="Copier l'indicateur">
              📋 Copier
            </button>
          </div>
        `).join('');
      } else {
        indicatorsHtml = '<span class="text-dim" style="font-size: 0.75rem;">Aucun indicateur atomique lié.</span>';
      }

      nodeCard.innerHTML = `
        <div class="infra-node-name">
          <span>🌐</span> ${node.name}
        </div>
        ${node.description ? `<div style="font-size: 0.75rem; color: #94a3b8;">${node.description}</div>` : ''}
        <div class="indicators-sublist">
          ${indicatorsHtml}
        </div>
      `;
      infraNodesContainer.appendChild(nodeCard);
    });
  } else {
    infraNodesContainer.innerHTML = '<span class="text-dim" style="font-size: 0.8rem;">Aucune infrastructure réseau répertoriée pour cette campagne.</span>';
  }

  // 5. BRANCHE OUTILS & ARSENAL
  document.getElementById('tools-summary-count').textContent = tools.summary || 'Arsenal offensif et outils légitimes détournés';

  // Malwares Dédiés
  const dedicatedContainer = document.getElementById('dedicated-malwares-container');
  dedicatedContainer.innerHTML = '';
  if (tools.dedicated_malwares && tools.dedicated_malwares.length > 0) {
    tools.dedicated_malwares.forEach(tool => {
      const card = document.createElement('div');
      card.className = 'tool-item-card is-dedicated';
      card.innerHTML = `
        <div class="tool-header-row">
          <span class="tool-name">🛑 ${tool.name}</span>
          <span class="tool-posture-badge badge-dedicated">Malware Dédié</span>
        </div>
        ${tool.description ? `<p class="tool-desc">${tool.description}</p>` : ''}
        ${tool.cpe ? `<div class="tool-cpe">CPE : ${tool.cpe}</div>` : ''}
      `;
      dedicatedContainer.appendChild(card);
    });
  } else {
    dedicatedContainer.innerHTML = '<span class="text-dim" style="font-size: 0.8rem;">Aucun malware dédié spécifique recensé.</span>';
  }

  // LOLBins & Utilitaires Détournés
  const lolbinsContainer = document.getElementById('lolbins-container');
  lolbinsContainer.innerHTML = '';
  if (tools.lolbins && tools.lolbins.length > 0) {
    tools.lolbins.forEach(tool => {
      const card = document.createElement('div');
      card.className = 'tool-item-card is-lolbin';
      card.innerHTML = `
        <div class="tool-header-row">
          <span class="tool-name">⚡ ${tool.name}</span>
          <span class="tool-posture-badge badge-lolbin">LOLBin (Détourné)</span>
        </div>
        ${tool.description ? `<p class="tool-desc">${tool.description}</p>` : ''}
        ${tool.cpe ? `<div class="tool-cpe">Binaire Légitime / CPE : ${tool.cpe}</div>` : ''}
      `;
      lolbinsContainer.appendChild(card);
    });
  } else {
    lolbinsContainer.innerHTML = '<span class="text-dim" style="font-size: 0.8rem;">Aucun outil légitime détourné recensé.</span>';
  }
}

function handleThreatActorFlowNodeClick(node) {
  if (!node) return;
  
  // Highlight smooth scroll selon le nœud cliqué dans React Flow
  if (node.id === 'node-infra-c2' || node.id === 'node-branch-infra' || node.id === 'node-infra-loc') {
    const el = document.querySelector('.branch-infrastructure');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      el.classList.add('highlight-pulse');
      setTimeout(() => el.classList.remove('highlight-pulse'), 1500);
    }
  } else if (node.id === 'node-branch-tools' || node.id === 'node-tools-malware' || node.id === 'node-tools-lolbin') {
    const el = document.querySelector('.branch-tools');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      el.classList.add('highlight-pulse');
      setTimeout(() => el.classList.remove('highlight-pulse'), 1500);
    }
  } else if (node.id === 'node-root-sponsor' || node.id === 'node-threat-actor') {
    const el = document.getElementById('actor-identity-card');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      el.classList.add('highlight-pulse');
      setTimeout(() => el.classList.remove('highlight-pulse'), 1500);
    }
  }
}

function renderCampaignTimeline(campaigns, selectedCid, isConsolidated) {
  const container = document.getElementById('actor-campaigns-timeline');
  container.innerHTML = '';

  if (campaigns.length === 0) {
    container.innerHTML = '<span class="text-dim" style="font-size: 0.8rem;">Aucun rapport daté spécifié pour cet acteur.</span>';
    return;
  }

  // Jalon par défaut : Dernière Campagne (du moment)
  const latestChip = document.createElement('div');
  const isLatestActive = !isConsolidated && selectedCid === campaigns[0].id;
  latestChip.className = `timeline-chip ${isLatestActive ? 'active' : ''}`;
  latestChip.innerHTML = `
    <span class="chip-dot"></span>
    <span>🔥 Dernière Campagne (${campaigns[0].date || 'Récents'})</span>
  `;
  latestChip.addEventListener('click', () => {
    selectThreatActor(STATE.currentActorId, campaigns[0].id);
  });
  container.appendChild(latestChip);

  // Jalons des autres campagnes individuelles
  campaigns.forEach((camp, idx) => {
    if (idx === 0) return; // Déjà représenté par le premier jalon
    const chip = document.createElement('div');
    const isActive = !isConsolidated && selectedCid === camp.id;
    chip.className = `timeline-chip ${isActive ? 'active' : ''}`;
    chip.innerHTML = `
      <span class="chip-dot"></span>
      <span>${camp.date ? camp.date : 'Campagne #' + camp.id}</span>
    `;
    chip.title = camp.title;
    chip.addEventListener('click', () => {
      selectThreatActor(STATE.currentActorId, camp.id);
    });
    container.appendChild(chip);
  });

  // Jalon : Vue Consolidée / Tout l'historique
  const consolidatedChip = document.createElement('div');
  consolidatedChip.className = `timeline-chip ${isConsolidated ? 'active' : ''}`;
  consolidatedChip.innerHTML = `
    <span class="chip-dot"></span>
    <span>📚 Tout l'Historique (Consolidé)</span>
  `;
  consolidatedChip.addEventListener('click', () => {
    selectThreatActor(STATE.currentActorId, 'all');
  });
  container.appendChild(consolidatedChip);
}

// =====================================================================
// UTILITAIRES (COPIE PRESSE-PAPIER & DEBOUNCE)
// =====================================================================
function copyToClipboard(text) {
  if (!text) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
  } else {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
  }

  const toast = document.getElementById('toast-notification');
  toast.textContent = `📋 Indicateur copié : ${text}`;
  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 2200);
}

function debounce(fn, delay) {
  let timer = null;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}
