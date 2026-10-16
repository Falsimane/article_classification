import React, { memo } from 'react';
import { Handle, Position } from 'reactflow';

// Nœud Racine : Sponsor Étatique / Pays (ex: "Armée populaire de Chine")
export const SponsorNode = memo(({ data, selected }) => {
  return (
    <div
      className={`rf-node rf-sponsor-node ${selected ? 'selected' : ''}`}
      style={{
        width: data.width || 280,
        borderRadius: '16px',
        border: '2px solid #e2e8f0',
        background: 'linear-gradient(145deg, #1e293b, #0f172a)',
        color: '#f8fafc',
        padding: '14px 18px',
        boxShadow: selected
          ? '0 0 0 3px rgba(59, 130, 246, 0.5), 0 10px 25px rgba(0, 0, 0, 0.4)'
          : '0 8px 20px rgba(0, 0, 0, 0.35)',
        textAlign: 'center',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        userSelect: 'none',
        position: 'relative',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginBottom: '4px' }}>
        <span style={{ fontSize: '18px' }}>{data.flag || '🌐'}</span>
        <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#94a3b8', fontWeight: 600 }}>
          {data.affiliationType || 'Affiliation Étatique / Sponsor'}
        </span>
      </div>
      <div style={{ fontSize: '16px', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.02em', lineHeight: '1.25' }}>
        {data.title || 'Autorité Étatique'}
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#94a3b8', width: 9, height: 9, border: '2px solid #0f172a' }}
      />
    </div>
  );
});

// Nœud Niveau 1 : Threat Actor (ex: "APT1")
export const ActorNode = memo(({ data, selected }) => {
  return (
    <div
      className={`rf-node rf-actor-node ${selected ? 'selected' : ''}`}
      style={{
        width: data.width || 260,
        borderRadius: '14px',
        border: '2.5px solid #ef4444',
        background: 'linear-gradient(145deg, #24131b, #150d18)',
        color: '#f8fafc',
        padding: '12px 16px',
        boxShadow: selected
          ? '0 0 0 3px rgba(239, 68, 68, 0.5), 0 10px 25px rgba(0, 0, 0, 0.4)'
          : '0 8px 20px rgba(0, 0, 0, 0.35)',
        textAlign: 'center',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        userSelect: 'none',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: '#ef4444', width: 9, height: 9, border: '2px solid #0f172a' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', marginBottom: '2px' }}>
        <span style={{ fontSize: '15px' }}>🦹</span>
        <span style={{ fontSize: '11px', fontWeight: 700, color: '#f87171', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Threat Actor
        </span>
      </div>
      <div style={{ fontSize: '18px', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.02em' }}>
        {data.name}
      </div>
      {data.aliases && data.aliases.length > 0 && (
        <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '3px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          aka {data.aliases.slice(0, 2).join(', ')}
        </div>
      )}
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: '#ef4444', width: 9, height: 9, border: '2px solid #0f172a' }}
      />
    </div>
  );
});

// Nœud Niveau 2 : Branches Catégories ("Infrastructure", "TTPs Kill Chain", "Outils")
export const CategoryNode = memo(({ data, selected }) => {
  const color = data.color || '#3b82f6';
  return (
    <div
      className={`rf-node rf-category-node ${selected ? 'selected' : ''}`}
      style={{
        width: data.width || 230,
        borderRadius: '14px',
        border: `2px solid ${color}`,
        background: 'linear-gradient(145deg, #161e2e, #0e1320)',
        color: '#f8fafc',
        padding: '12px 14px',
        boxShadow: selected
          ? `0 0 0 3px ${color}66, 0 8px 20px rgba(0, 0, 0, 0.4)`
          : '0 6px 16px rgba(0, 0, 0, 0.3)',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        userSelect: 'none',
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: color, width: 8, height: 8, border: '2px solid #0f172a' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span style={{ fontSize: '20px' }}>{data.icon}</span>
        <div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            {data.title}
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 500 }}>
            {data.badge}
          </div>
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: color, width: 8, height: 8, border: '2px solid #0f172a' }}
      />
    </div>
  );
});

// Nœud Niveau 3 : Sous-Catégories ("Serveurs C2", "Localisation", "Techniques MITRE", "Malwares", "LOLBins")
export const SubCategoryNode = memo(({ data, selected }) => {
  const color = data.color || '#06b6d4';
  const items = data.items || [];

  const handleCopy = (e, val) => {
    e.stopPropagation();
    navigator.clipboard.writeText(val);
    if (window.showCopyToast) {
      window.showCopyToast(`Copié : ${val}`);
    }
  };

  return (
    <div
      className={`rf-node rf-sub-node ${selected ? 'selected' : ''}`}
      style={{
        width: data.width || 230,
        borderRadius: '12px',
        border: `1.5px solid ${color}88`,
        background: '#0d131f',
        color: '#f8fafc',
        padding: '10px 12px',
        boxShadow: selected
          ? `0 0 0 2px ${color}, 0 6px 18px rgba(0, 0, 0, 0.35)`
          : '0 4px 14px rgba(0, 0, 0, 0.25)',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        userSelect: 'none',
        position: 'relative',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: color, width: 7, height: 7, border: '1.5px solid #0f172a' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', paddingBottom: '6px', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ fontSize: '15px' }}>{data.icon}</span>
          <span style={{ fontSize: '13px', fontWeight: 600, color: '#f1f5f9' }}>{data.title}</span>
        </div>
        <span style={{ fontSize: '11px', background: `${color}22`, color: color, padding: '2px 7px', borderRadius: '10px', fontWeight: 700 }}>
          {data.count || items.length}
        </span>
      </div>

      {/* Aperçu des éléments (IPs, Domaines, LOLBins, Malwares) */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
        {items.length === 0 ? (
          <div style={{ fontSize: '11px', color: '#64748b', fontStyle: 'italic' }}>Aucun actif recensé</div>
        ) : (
          items.slice(0, 3).map((item, idx) => (
            <div
              key={idx}
              style={{
                fontSize: '11px',
                fontFamily: item.copyable ? 'monospace' : 'inherit',
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid rgba(255, 255, 255, 0.06)',
                borderRadius: '6px',
                padding: '4px 8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                color: '#cbd5e1',
                overflow: 'hidden',
              }}
            >
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '160px' }}>
                {item.label}
              </span>
              {item.copyable && (
                <button
                  onClick={(e) => handleCopy(e, item.label)}
                  title="Copier l'indicateur"
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: '#94a3b8',
                    cursor: 'pointer',
                    padding: '2px',
                    marginLeft: '4px',
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                </button>
              )}
            </div>
          ))
        )}
        {items.length > 3 && (
          <div style={{ fontSize: '10px', color: '#94a3b8', textAlign: 'center', paddingTop: '2px' }}>
            + {items.length - 3} autre(s)
          </div>
        )}
      </div>
    </div>
  );
});

export const nodeTypes = {
  sponsorNode: SponsorNode,
  actorNode: ActorNode,
  categoryNode: CategoryNode,
  subCategoryNode: SubCategoryNode,
};
