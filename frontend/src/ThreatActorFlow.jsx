import React, { useState, useEffect, useCallback, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Panel,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
} from 'reactflow';
import 'reactflow/dist/style.css';

import { nodeTypes } from './CustomNodes';
import { buildThreatActorTreeElements, layoutDagreTree } from './treeLayout';

function ThreatActorFlowInternal({ treeData, onNodeSelect }) {
  const [direction, setDirection] = useState('TB');
  const [selectedNode, setSelectedNode] = useState(null);
  const reactFlowInstance = useReactFlow();

  const initialElements = useMemo(() => {
    return buildThreatActorTreeElements(treeData, { direction });
  }, [treeData]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialElements.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialElements.edges);

  useEffect(() => {
    const { nodes: newNodes, edges: newEdges } = buildThreatActorTreeElements(treeData, { direction });
    setNodes(newNodes);
    setEdges(newEdges);
    setTimeout(() => {
      reactFlowInstance.fitView({ padding: 0.25, duration: 400 });
    }, 50);
  }, [treeData, reactFlowInstance, setNodes, setEdges, direction]);

  const toggleDirection = useCallback(() => {
    const nextDir = direction === 'TB' ? 'LR' : 'TB';
    setDirection(nextDir);
    const layouted = layoutDagreTree(nodes, edges, nextDir);
    setNodes(layouted.nodes);
    setEdges(layouted.edges);
    setTimeout(() => {
      reactFlowInstance.fitView({ padding: 0.25, duration: 400 });
    }, 50);
  }, [direction, nodes, edges, setNodes, setEdges, reactFlowInstance]);

  const handleNodeClick = useCallback(
    (event, node) => {
      setSelectedNode(node);
      if (onNodeSelect) {
        onNodeSelect(node);
      }
      if (window.onThreatActorFlowNodeSelected) {
        window.onThreatActorFlowNodeSelected(node);
      }
    },
    [onNodeSelect]
  );

  return (
    <div style={{ width: '100%', height: '100%', minHeight: '580px', position: 'relative', background: '#0a0e17' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        onNodeClick={handleNodeClick}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        minZoom={0.3}
        maxZoom={1.8}
        attributionPosition="bottom-left"
        defaultEdgeOptions={{
          type: 'smoothstep',
        }}
      >
        <Background color="#334155" gap={20} size={1} />
        <Controls
          style={{
            background: '#131b2e',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            fill: '#94a3b8',
          }}
        />
        <MiniMap
          nodeStrokeColor={(n) => {
            if (n.type === 'sponsorNode') return '#e2e8f0';
            if (n.type === 'actorNode') return '#ef4444';
            if (n.type === 'categoryNode') return n.data?.color || '#3b82f6';
            return '#06b6d4';
          }}
          nodeColor={(n) => {
            if (n.type === 'sponsorNode') return '#1e293b';
            if (n.type === 'actorNode') return '#24131b';
            return '#0e1320';
          }}
          maskColor="rgba(10, 14, 23, 0.75)"
          style={{
            background: '#0a0e17',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            width: 140,
            height: 95,
          }}
        />

        {/* Barre d'outils flottante React Flow */}
        <Panel position="top-right" style={{ display: 'flex', gap: '8px', margin: '14px' }}>
          <button
            onClick={toggleDirection}
            title="Basculer l'orientation de l'arborescence (Vertical / Horizontal)"
            style={{
              background: '#131b2e',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#f8fafc',
              padding: '6px 12px',
              borderRadius: '7px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
            }}
          >
            <span>⇄</span>
            <span>{direction === 'TB' ? 'Vue Verticale' : 'Vue Horizontale'}</span>
          </button>

          <button
            onClick={() => reactFlowInstance.fitView({ padding: 0.25, duration: 400 })}
            title="Recentrer et ajuster l'arborescence"
            style={{
              background: '#131b2e',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#f8fafc',
              padding: '6px 10px',
              borderRadius: '7px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
            }}
          >
            ⛶ Recentrer
          </button>
        </Panel>
      </ReactFlow>
    </div>
  );
}

export function ThreatActorFlow(props) {
  return (
    <ReactFlowProvider>
      <ThreatActorFlowInternal {...props} />
    </ReactFlowProvider>
  );
}
