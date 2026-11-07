"use client";

import { memo, useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import type { WorkflowGraph as WorkflowGraphData, WorkflowLane, WorkflowNode } from "@/data/serverSource";

import "@xyflow/react/dist/style.css";

const DEFAULT_LANE_WIDTH = 280;
const DEFAULT_NODE_WIDTH = 240;

const FALLBACK_LANES: WorkflowLane[] = [
  "Scope",
  "Recon",
  "Planning",
  "Execution",
  "Validation",
  "Chain / Impact",
  "Reporting",
].map((label, order) => ({
  id: label.toLowerCase().replaceAll(" / ", "_"),
  label,
  order,
  active: false,
  node_count: 0,
}));

const STATUS_STYLES: Record<string, string> = {
  pending: "bg-zinc-500",
  blocked: "bg-amber-500",
  ready: "bg-cyan-400",
  running: "bg-blue-500",
  succeeded: "bg-emerald-500",
  completed: "bg-emerald-500",
  reported: "bg-emerald-500",
  confirmed: "bg-emerald-500",
  failed: "bg-red-500",
  cancelled: "bg-zinc-600",
  skipped: "bg-zinc-600",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "#71717a",
  blocked: "#f59e0b",
  ready: "#22d3ee",
  running: "#3b82f6",
  succeeded: "#10b981",
  completed: "#10b981",
  reported: "#10b981",
  confirmed: "#10b981",
  failed: "#ef4444",
  cancelled: "#52525b",
  skipped: "#52525b",
};

function WorkflowNodeComponent({ data, selected }: NodeProps) {
  const node = data as unknown as WorkflowNode;
  const statusClass = STATUS_STYLES[node.status] ?? "bg-zinc-500";
  return (
    <div
      className={`relative w-full rounded-lg border px-3 py-2.5 shadow-lg transition-colors ${
        selected ? "border-cyan-300/70 bg-[#101a1d]" : "border-[#30383a] bg-[#090d0e] hover:border-[#52666a]"
      }`}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} className="!h-1.5 !w-1.5 !border-0 !bg-[#60767a]" />
      <div className="flex items-start gap-2">
        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${statusClass} ${node.status === "running" ? "animate-pulse" : ""}`} />
        <div className="min-w-0 flex-1">
          <div className="line-clamp-2 text-xs font-semibold leading-snug text-white">{node.label}</div>
          <div className="mt-1 flex flex-wrap gap-1">
            <span className="rounded border border-[#334449] px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-cyan-200/80">{node.type}</span>
            <span className="rounded border border-[#333] px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-[#aaa]">{node.status}</span>
          </div>
        </div>
      </div>
      <div className="mt-2 grid grid-cols-2 gap-x-2 text-[9px] text-[#778488]">
        <span>risk: {node.risk}</span>
        <span>attempts: {node.attempts}</span>
        <span>sources: {node.source_information.length}</span>
        <span>deps: {node.dependencies.length}</span>
      </div>
      <div className="mt-1 truncate text-[9px] text-[#596467]">from: {node.generated_by ?? "planner/root"}</div>
      <Handle type="source" position={Position.Right} isConnectable={false} className="!h-1.5 !w-1.5 !border-0 !bg-[#60767a]" />
    </div>
  );
}

function LaneLabelComponent({ data }: NodeProps) {
  const lane = data as unknown as WorkflowLane;
  return (
    <div className={`w-full border-b px-2 pb-2 text-[10px] font-semibold uppercase tracking-[0.16em] ${lane.active ? "border-cyan-500/60 text-cyan-200" : "border-[#273235] text-[#7d898c]"}`}>
      <span>{lane.label}</span>
      <span className="ml-2 text-[9px] font-normal tracking-normal text-[#566164]">{lane.node_count}</span>
    </div>
  );
}

const nodeTypes = { workflowNode: memo(WorkflowNodeComponent), laneLabel: memo(LaneLabelComponent) };

function buildElements(workflow: WorkflowGraphData, laneWidth: number, nodeWidth: number) {
  const occupied = new Set(workflow.nodes.map((node) => node.lane));
  const lanes = (workflow.lanes.length > 0 ? [...workflow.lanes] : FALLBACK_LANES)
    .filter((lane) => lane.node_count > 0 || occupied.has(lane.id))
    .sort((a, b) => a.order - b.order);
  const visibleLanes = lanes.length > 0 ? lanes : FALLBACK_LANES.slice(0, 1);
  const laneIndex = new Map(visibleLanes.map((lane, index) => [lane.id, index]));
  const byLane = new Map<string, WorkflowNode[]>();
  for (const node of workflow.nodes) {
    const list = byLane.get(node.lane) ?? [];
    list.push(node);
    byLane.set(node.lane, list);
  }

  const nodes: Node[] = visibleLanes.map((lane, index) => ({
    id: `lane:${lane.id}`,
    type: "laneLabel",
    position: { x: index * laneWidth + 10, y: 8 },
    data: lane,
    draggable: false,
    selectable: false,
    zIndex: -1,
    style: { width: laneWidth - 20 },
  }));

  const positions = new Map<string, { x: number; y: number }>();
  for (const [laneId, laneNodes] of byLane) {
    const index = laneIndex.get(laneId) ?? 0;
    laneNodes.forEach((node, nodeIndex) => {
      const position = { x: index * laneWidth + 10, y: 50 + nodeIndex * 138 };
      positions.set(node.id, position);
      nodes.push({
        id: node.id,
        type: "workflowNode",
        position,
        data: node,
        style: { width: nodeWidth },
      });
    });
  }

  const edges: Edge[] = workflow.edges.flatMap((edge) => {
    if (!positions.has(edge.source) || !positions.has(edge.target)) return [];
    return [{
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: "smoothstep",
      animated: ["dependency", "assignment", "agent", "impact", "chain"].includes(edge.type) && workflow.status === "running",
      style: {
        stroke: edge.type === "source" ? "#64748b" : edge.type === "assignment" ? "#d09b45" : edge.type === "agent" ? "#a78bfa" : edge.type === "impact" ? "#f97316" : edge.type === "chain" ? "#eab308" : "#28a9b8",
        strokeWidth: edge.type === "impact" ? 2 : 1.5,
        strokeDasharray: edge.type === "source" ? "5 4" : undefined,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: edge.type === "source" ? "#64748b" : edge.type === "assignment" ? "#d09b45" : edge.type === "agent" ? "#a78bfa" : edge.type === "impact" ? "#f97316" : edge.type === "chain" ? "#eab308" : "#28a9b8" },
    }];
  });
  return { nodes, edges };
}

function FitWorkflow({ nodes }: { nodes: Node[] }) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    if (nodes.length > 0) {
      const timer = window.setTimeout(() => fitView({ padding: 0.15, duration: 350 }), 40);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [fitView, nodes.length]);
  return null;
}

interface WorkflowGraphProps {
  workflow: WorkflowGraphData;
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
}

export default function WorkflowGraph({ workflow, selectedNodeId, onSelectNode }: WorkflowGraphProps) {
  const [metrics, setMetrics] = useState({ laneWidth: DEFAULT_LANE_WIDTH, nodeWidth: DEFAULT_NODE_WIDTH });
  useEffect(() => {
    const updateMetrics = () => {
      const viewportWidth = window.innerWidth;
      const nodeWidth = Math.round(Math.min(300, Math.max(210, viewportWidth * 0.18)));
      setMetrics({ nodeWidth, laneWidth: nodeWidth + 40 });
    };
    updateMetrics();
    window.addEventListener("resize", updateMetrics);
    return () => window.removeEventListener("resize", updateMetrics);
  }, []);
  const elements = useMemo(() => buildElements(workflow, metrics.laneWidth, metrics.nodeWidth), [metrics, workflow]);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>(elements.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(elements.edges);

  useEffect(() => {
    setNodes(elements.nodes.map((node) => ({
      ...node,
      selected: node.id === selectedNodeId,
    })));
    setEdges(elements.edges);
  }, [elements, selectedNodeId, setEdges, setNodes]);

  return (
    <div className="h-full w-full bg-[#050707]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_, node) => {
          if (!node.id.startsWith("lane:")) onSelectNode(node.id);
        }}
        onPaneClick={() => onSelectNode(null)}
        nodeTypes={nodeTypes}
        nodesConnectable={false}
        nodesDraggable={false}
        edgesReconnectable={false}
        minZoom={0.15}
        maxZoom={1.35}
        proOptions={{ hideAttribution: true }}
        className="bg-[#050707]"
      >
        <Background color="#172022" gap={22} />
        <FitWorkflow nodes={nodes} />
        <Controls showZoom showFitView position="bottom-right" className="!bg-[#0b1011] !border-[#263033]" />
        <MiniMap
          position="bottom-left"
          nodeColor={(node) => {
            if (node.id.startsWith("lane:")) return "#334449";
            const status = (node.data as WorkflowNode)?.status;
            return STATUS_COLORS[status ?? ""] ?? "#4b5563";
          }}
          maskColor="rgba(0,0,0,0.78)"
          style={{ width: 100, height: 62 }}
          className="!bg-[#080c0d] !border-[#263033]"
        />
      </ReactFlow>
    </div>
  );
}
