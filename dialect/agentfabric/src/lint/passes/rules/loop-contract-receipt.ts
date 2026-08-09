/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Evidence-bound loop contract receipt.
 *
 * Adapted from "Looping Is Not Reliability: State-Bound Evidence and Typed
 * Revision Contracts for Agentic Code Repair" (arXiv:2607.24604). The paper's
 * mechanically enforceable contribution is an evidence-bound typed loop
 * contract that (a) binds verifier evidence to an EXACT code state, (b)
 * preserves that binding as a checkpoint, and (c) emits an auditable admission
 * receipt. Repetition / generate-test-revise looping alone is no reliability
 * guarantee — what matters is that a certification is bound to the precise
 * state it certified, so a later revision cannot silently inherit it.
 *
 * This module instantiates that subset as a STATIC conformance artifact over
 * the AgentFabric execution graph (the repo's exact substrate): the existing
 * cycle (`cycle-rules`) and terminal-reachability (`terminal-status-rules`)
 * passes are the verifiers, and `extractGraph` is the state under inspection.
 * `certifyLoopContract` re-derives the certification over the graph and binds
 * the verdict to a content-addressed digest of that exact state, returning a
 * typed receipt separating admission / grounded certification / liveness.
 *
 * What is intentionally NOT ported (cut as auxiliary): the paper's runtime
 * generate-test-revise repair loop, the HumanEval / 5-seed study, the rollout
 * policy, and competence / verifier-dependence measurement. Those are a
 * downstream evaluation concern; this is the statically-enforceable contract.
 */

import { createHash } from 'node:crypto';
import {
  attachDiagnostic,
  DiagnosticSeverity,
  isNamedMap,
} from '@agentscript/language';
import type { AstNodeLike } from '@agentscript/language';
import { extractGraph } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo, A2A_TERMINAL_STATES } from '../../../schema.js';
import { AGENTFABRIC_LINT_SOURCE, extractStringValue } from './shared.js';

/**
 * Typed loop-contract receipt. Mirrors the paper's separated concerns:
 * - `stateDigest`   — preservation: a checkpoint of the EXACT state certified.
 * - `admission`     — the graph slice admitted for certification.
 * - `certification` — grounded verdicts re-derived over the admitted state.
 * - `liveness`      — the admitted graph can both start and terminate.
 * - `conforms`      — the contract holds.
 */
export interface LoopContractReceipt {
  /** Content-addressed digest (sha1, 12 hex) of the exact graph state certified. */
  readonly stateDigest: string;
  readonly admission: {
    readonly nodeCount: number;
    readonly edgeCount: number;
    readonly triggerCount: number;
  };
  readonly certification: {
    readonly acyclic: boolean;
    readonly terminalReachable: boolean;
    /** First cycle found (node ids), or undefined when the graph is acyclic. */
    readonly firstCycle: string[] | undefined;
    /** Leaf nodes with no reachable terminal-status echo. */
    readonly unguardedTerminals: readonly string[];
  };
  readonly liveness: boolean;
  readonly conforms: boolean;
}

const ZERO_RANGE = {
  start: { line: 0, character: 0 },
  end: { line: 0, character: 0 },
};

/**
 * Deterministic content-addressed digest of the graph state. Node ids and
 * `from>to` edges are sorted before hashing so the digest is invariant under
 * source-order / traversal-order reshuffling — only a genuine topology or
 * node-set change moves the digest, which is exactly the "stale certification"
 * signal the paper wants preserved checkpoints to surface.
 */
export function computeStateDigest(
  nodes: readonly { id: string }[],
  edges: readonly { from: string; to: string }[]
): string {
  const nodeIds = nodes.map(n => n.id).sort();
  const edgeKeys = edges.map(e => `${e.from}>${e.to}`).sort();
  const canonical = `n:${nodeIds.join(',')}|e:${edgeKeys.join(',')}`;
  return createHash('sha1').update(canonical).digest('hex').slice(0, 12);
}

type VisitState = 0 | 1 | 2;

interface DfsFrame {
  node: string;
  next: number;
}

/**
 * Iterative DFS returning the first back-edge cycle (node ids along the cycle),
 * or undefined when the subgraph is acyclic. Trigger sources are excluded so a
 * trigger's own outgoing edge cannot form a spurious self-loop — matching
 * `cycle-rules`.
 */
function findFirstCycle(
  nodeIds: Set<string>,
  adjacency: Map<string, string[]>
): string[] | undefined {
  const visit = new Map<string, VisitState>();
  for (const id of nodeIds) visit.set(id, 0);
  const path: string[] = [];
  const pathPos = new Map<string, number>();
  const stack: DfsFrame[] = [];

  const enter = (node: string): void => {
    visit.set(node, 1);
    pathPos.set(node, path.length);
    path.push(node);
    stack.push({ node, next: 0 });
  };

  for (const root of nodeIds) {
    if (visit.get(root) !== 0) continue;
    enter(root);
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const neighbors = adjacency.get(frame.node) ?? [];
      if (frame.next >= neighbors.length) {
        visit.set(frame.node, 2);
        pathPos.delete(frame.node);
        path.pop();
        stack.pop();
        continue;
      }
      const next = neighbors[frame.next++];
      const state = visit.get(next);
      if (state === 1) {
        const start = pathPos.get(next);
        if (start !== undefined) return path.slice(start);
      } else if (state === 0) {
        enter(next);
      }
    }
  }
  return undefined;
}

function buildCycleSubgraph(
  graph: Readonly<{
    nodes: readonly { id: string }[];
    edges: readonly { from: string; to: string; via?: string }[];
  }>
): { nodeIds: Set<string>; adjacency: Map<string, string[]> } {
  const triggerSources = new Set(
    graph.edges.filter(e => e.via === 'trigger').map(e => e.from)
  );
  const nodeIds = new Set(
    graph.nodes.map(n => n.id).filter(id => !triggerSources.has(id))
  );
  const adjacency = new Map<string, string[]>();
  for (const id of nodeIds) adjacency.set(id, []);
  for (const e of graph.edges) {
    if (!nodeIds.has(e.from) || !nodeIds.has(e.to)) continue;
    adjacency.get(e.from)!.push(e.to);
  }
  return { nodeIds, adjacency };
}

/** Ids of echo nodes emitting a terminal A2A status update. */
function collectTerminalStatusEchoIds(
  root: Record<string, unknown>
): Set<string> {
  const ids = new Set<string>();
  const echoEntries = root.echo;
  if (!isNamedMap(echoEntries)) return ids;
  for (const [name, entry] of echoEntries) {
    if (entry == null || typeof entry !== 'object') continue;
    const echoEntry = entry as Record<string, unknown>;
    if (extractStringValue(echoEntry.kind) !== 'a2a:status_update_event')
      continue;
    const state = extractStringValue(echoEntry.state);
    if (state !== undefined && A2A_TERMINAL_STATES.has(state)) {
      ids.add(`echo.${name}`);
    }
  }
  return ids;
}

/** BFS backwards from `startId` to test whether any `targetSet` node is an ancestor. */
function hasAncestorInSet(
  startId: string,
  targetSet: Set<string>,
  reverseAdj: Map<string, string[]>
): boolean {
  const visited = new Set<string>([startId]);
  const queue = [startId];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    for (const pred of reverseAdj.get(current) ?? []) {
      if (targetSet.has(pred)) return true;
      if (!visited.has(pred)) {
        visited.add(pred);
        queue.push(pred);
      }
    }
  }
  return false;
}

/** Leaf (no outgoing edge) non-trigger nodes with no reachable terminal-status echo. */
function findUnguardedTerminals(
  root: Record<string, unknown>,
  graph: Readonly<{
    nodes: readonly { id: string; namespace: string }[];
    edges: readonly { from: string; to: string }[];
  }>
): string[] {
  const triggerIds = new Set(
    graph.nodes.filter(n => n.namespace === 'trigger').map(n => n.id)
  );
  const nonTrigger = graph.nodes.filter(n => !triggerIds.has(n.id));
  if (nonTrigger.length === 0) return [];

  const outgoing = new Map<string, number>();
  for (const n of nonTrigger) outgoing.set(n.id, 0);
  for (const e of graph.edges) {
    if (!outgoing.has(e.from)) continue;
    outgoing.set(e.from, (outgoing.get(e.from) ?? 0) + 1);
  }
  const leaves = nonTrigger
    .filter(n => (outgoing.get(n.id) ?? 0) === 0)
    .map(n => n.id);
  if (leaves.length === 0) return [];

  const echoIds = collectTerminalStatusEchoIds(root);
  if (echoIds.size === 0) return leaves;

  const reverseAdj = new Map<string, string[]>();
  for (const n of nonTrigger) reverseAdj.set(n.id, []);
  for (const e of graph.edges) {
    if (!reverseAdj.has(e.to)) continue;
    reverseAdj.get(e.to)!.push(e.from);
  }

  const unguarded: string[] = [];
  for (const leaf of leaves) {
    if (echoIds.has(leaf)) continue;
    if (hasAncestorInSet(leaf, echoIds, reverseAdj)) continue;
    unguarded.push(leaf);
  }
  return unguarded;
}

function findAstNodeById(
  root: Record<string, unknown>,
  nodeId: string
): AstNodeLike | null {
  const dot = nodeId.indexOf('.');
  if (dot < 0) return null;
  const namespace = nodeId.slice(0, dot);
  const name = nodeId.slice(dot + 1);
  const group = root[namespace];
  if (!isNamedMap(group)) return null;
  for (const [key, entry] of group) {
    if (key === name && entry != null && typeof entry === 'object') {
      return entry as AstNodeLike;
    }
  }
  return null;
}

function formatCycle(cycle: string[]): string {
  const closed = [...cycle, cycle[0]];
  return closed.map(id => `@${id}`).join(' → ');
}

/**
 * Certify the loop contract over a parsed AgentFabric document and return a
 * typed receipt binding the verdict to a digest of the exact graph state.
 * Pure: attaches no diagnostics. Callers compare `stateDigest` across revisions
 * to detect stale certification (a repaired graph that still reproduces an
 * offending digest has not actually changed the certified state).
 */
export function certifyLoopContract(
  root: Record<string, unknown>
): LoopContractReceipt {
  const graph = extractGraph(root, AgentFabricSchemaInfo);
  const stateDigest = computeStateDigest(graph.nodes, graph.edges);
  const triggerCount = graph.nodes.filter(
    n => n.namespace === 'trigger'
  ).length;

  const { nodeIds, adjacency } = buildCycleSubgraph(graph);
  const firstCycle = findFirstCycle(nodeIds, adjacency);
  const acyclic = firstCycle === undefined;

  const unguardedTerminals = findUnguardedTerminals(root, graph);
  const terminalReachable = unguardedTerminals.length === 0;

  const terminalEchoCount = collectTerminalStatusEchoIds(root).size;
  const liveness =
    graph.nodes.length > 0 && triggerCount > 0 && terminalEchoCount > 0;

  const conforms = acyclic && terminalReachable && liveness;

  return {
    stateDigest,
    admission: {
      nodeCount: graph.nodes.length,
      edgeCount: graph.edges.length,
      triggerCount,
    },
    certification: {
      acyclic,
      terminalReachable,
      firstCycle,
      unguardedTerminals,
    },
    liveness,
    conforms,
  };
}

/**
 * Lint hook for the evidence-bound loop contract. Emits a single
 * state-bound admission receipt (Information) when the contract's acyclicity
 * clause is violated — i.e. when a cycle is present — binding the no-loop
 * failure to a digest of the exact graph state. Terminal-reachability and
 * liveness are certified in the receipt payload but surfaced as user-facing
 * diagnostics by the existing `terminal-status-rules`, so they are not
 * duplicated here.
 */
export function checkLoopContractRules(root: Record<string, unknown>): void {
  const receipt = certifyLoopContract(root);
  const cycle = receipt.certification.firstCycle;
  if (cycle === undefined || cycle.length === 0) return;

  const anchor = findAstNodeById(root, cycle[0]);
  const diagnostics = anchor?.__diagnostics;
  if (!anchor || !Array.isArray(diagnostics)) return;

  const cst = anchor.__cst as { range?: unknown } | undefined;
  const range = (cst?.range ?? ZERO_RANGE) as never;
  attachDiagnostic(anchor as never, {
    range,
    message:
      `Evidence-bound loop contract violated at state ${receipt.stateDigest}: ` +
      `certification.acyclic failed (${formatCycle(cycle)}). ` +
      `The no-loop guarantee is bound to this exact graph state; a revision ` +
      `with a different state digest must be re-certified.`,
    severity: DiagnosticSeverity.Information,
    code: 'loop-contract-violation',
    source: AGENTFABRIC_LINT_SOURCE,
    data: {
      stateDigest: receipt.stateDigest,
      clause: 'certification.acyclic',
      cycle,
      conforms: receipt.conforms,
    },
  });
}
