import React from 'react';
import { createRoot } from 'react-dom/client';
import { ThreatActorFlow } from './ThreatActorFlow';

// Cache des racines React par conteneur pour éviter les avertissements et conflits de createRoot
const rootsMap = new Map();

/**
 * Monte ou met à jour l'arborescence React Flow dans l'élément DOM cible
 * @param {HTMLElement | string} container - Élément DOM ou sélecteur / ID
 * @param {Object} treeData - Données complètes de l'acteur renvoyées par l'API
 * @param {Function} [onNodeSelect] - Callback lors du clic sur un nœud
 */
export function renderThreatActorFlow(container, treeData, onNodeSelect) {
  const targetEl = typeof container === 'string'
    ? (document.getElementById(container) || document.querySelector(container))
    : container;

  if (!targetEl) {
    console.error('Conteneur React Flow introuvable :', container);
    return;
  }

  let root = rootsMap.get(targetEl);
  if (!root) {
    root = createRoot(targetEl);
    rootsMap.set(targetEl, root);
  }

  root.render(
    <ThreatActorFlow
      treeData={treeData}
      onNodeSelect={onNodeSelect}
    />
  );
}

/**
 * Démonte l'instance React Flow d'un conteneur
 */
export function unmountThreatActorFlow(container) {
  const targetEl = typeof container === 'string'
    ? (document.getElementById(container) || document.querySelector(container))
    : container;

  if (targetEl && rootsMap.has(targetEl)) {
    const root = rootsMap.get(targetEl);
    root.unmount();
    rootsMap.delete(targetEl);
  }
}

// Exposition sur l'objet global window pour intégration transparente dans app.js
if (typeof window !== 'undefined') {
  window.renderThreatActorFlow = renderThreatActorFlow;
  window.unmountThreatActorFlow = unmountThreatActorFlow;
}
