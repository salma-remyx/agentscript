/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { isNamedMap } from '@agentscript/language';
import { extractGraph } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo } from '../../../schema.js';
import { attachWarning, type AstLike } from './shared.js';

/**
 * Behavioral reachability & liveness checks over the extracted agent
 * execution graph.
 *
 * Adapted (Mode 2) from the resource-flow / Petri-net methodology of "From
 * Resource Flow to Executable Tests: Petri-Net-Guided LLM Test Generation
 * for Concurrent Stateful Rust APIs" (arXiv:2607.21530). That paper models a
 * system's resources, lifecycle, and causal dependencies as a colored Petri
 * net and derives reachable / liveness scenarios. The LLM test-synthesis
 * wrapper and Rust concretization layer do not transfer to a static TS lint
 * pass, but the reachability + transition-liveness analysis layer does: the
 * execution graph that `extractGraph` already produces is exactly the
 * place/transition substrate. These checks approximate the paper's firing
 * semantics with parameter-free graph-topology proxies — no token-color
 * engine, no constraint solver — which is the sanctioned Mode-2 substitution.
 *
 * Three behavioral hazards the structural rules (cycle / terminal-status /
 * unused-node) do not already cover:
 *
 *   - `unreachable-from-trigger`: a non-trigger node that is referenced by
 *     another node (so it is not merely "unused") yet lives in a subgraph no
 *     trigger can reach — a dead state that can never run. Petri-net analog:
 *     a dead place (a place unreachable from the initial marking).
 *
 *   - `overlapping-route-predicates`: a router with two routes gated by the
 *     same condition — both transitions are enabled by the same marking, so
 *     the branch fires nondeterministically. Petri-net analog: a transition
 *     conflict (the paper's "high-conflict concurrency skeleton").
 *
 *   - `shared-state-convergence`: a node reachable from two or more distinct
 *     trigger entry points — independent concurrent executions can reach it
 *     and race on shared state. Petri-net analog: a place fed by competing
 *     interleavings.
 *
 * Division of labor with `unused-node`: nodes with no incoming edge at all
 * are owned by `unused-node`; this pass only claims nodes that ARE referenced
 * (incoming edge present) but still unreachable, so the two never overlap.
 */
export function checkReachabilityRules(root: Record<string, unknown>): void {
  const { nodes, edges } = extractGraph(root, AgentFabricSchemaInfo);
  if (nodes.length === 0) return;

  const nodeIds = new Set(nodes.map(n => n.id));
  const triggerIds = new Set(
    nodes.filter(n => n.namespace === 'trigger').map(n => n.id)
  );

  // Forward adjacency and incoming-edge counts, restricted to real nodes.
  const forward = new Map<string, Set<string>>();
  const incoming = new Map<string, number>();
  for (const id of nodeIds) {
    forward.set(id, new Set());
    incoming.set(id, 0);
  }
  for (const edge of edges) {
    if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) continue;
    forward.get(edge.from)!.add(edge.to);
    incoming.set(edge.to, (incoming.get(edge.to) ?? 0) + 1);
  }

  checkUnreachableSubgraphs(root, nodes, triggerIds, forward, incoming);
  checkOverlappingRoutePredicates(root, nodes, nodeIds, edges);
  checkSharedStateConvergence(root, nodes, triggerIds, forward);
}

/**
 * Flag non-trigger nodes that no trigger can reach — dead states inside an
 * orphaned subgraph — while deferring to `unused-node` to avoid duplicate
 * reports.
 *
 * `unused-node` reports any node with no incoming edge (an orphan "root").
 * Any unreachable node reachable *forwards* (within the orphaned region) from
 * such a root is merely downstream of an unused node, so flagging it would
 * only echo `unused-node`. We therefore skip every orphan component that
 * contains an unused root and report only the closed components — cycles and
 * isolated subgraphs whose every node has an incoming edge, which
 * `unused-node` cannot see at all.
 */
function checkUnreachableSubgraphs(
  root: Record<string, unknown>,
  nodes: { id: string; namespace: string }[],
  triggerIds: Set<string>,
  forward: Map<string, Set<string>>,
  incoming: Map<string, number>
): void {
  // Without an entry point, "reachable from a trigger" is undefined; skip.
  if (triggerIds.size === 0) return;

  const reachable = bfsForward(triggerIds, forward);

  const unreachable = new Set<string>();
  for (const node of nodes) {
    if (triggerIds.has(node.id)) continue;
    if (!reachable.has(node.id)) unreachable.add(node.id);
  }
  if (unreachable.size === 0) return;

  // Orphan roots (no incoming edge) and everything downstream of them, within
  // the unreachable region, belong to `unused-node` — skip the lot.
  const orphanRoots = new Set<string>();
  for (const id of unreachable) {
    if ((incoming.get(id) ?? 0) === 0) orphanRoots.add(id);
  }
  const downstreamOfRoot = bfsForward(orphanRoots, forward, unreachable);

  for (const id of unreachable) {
    if (downstreamOfRoot.has(id)) continue;
    const astNode = findAstNode(root, id);
    if (!astNode) continue;
    attachWarning(
      astNode,
      `Node '@${id}' belongs to an execution subgraph that no trigger ` +
        `can reach; it can never run (dead state).`,
      'unreachable-from-trigger'
    );
  }
}

/**
 * Flag routers whose routes overlap: two or more outgoing edges gated by the
 * same predicate fire on the same input, making the branch nondeterministic.
 */
function checkOverlappingRoutePredicates(
  root: Record<string, unknown>,
  nodes: { id: string; namespace: string }[],
  nodeIds: Set<string>,
  edges: { from: string; to: string; predicate?: string }[]
): void {
  // Only routers carry predicate-gated routes alongside an unconditional
  // `otherwise`; restrict the conflict check there to avoid flagging ordinary
  // transition fan-out.
  const routerIds = nodes.filter(n => n.namespace === 'router').map(n => n.id);
  if (routerIds.length === 0) return;

  for (const routerId of routerIds) {
    // normalized predicate -> count of routes gated by it
    const counts = new Map<string, number>();
    for (const edge of edges) {
      if (edge.from !== routerId || !nodeIds.has(edge.to)) continue;
      const pred = normalizePredicate(edge.predicate);
      if (pred === undefined) continue; // `otherwise` / ungated edge
      counts.set(pred, (counts.get(pred) ?? 0) + 1);
    }

    const overlaps = [...counts.values()].filter(c => c >= 2).length;
    if (overlaps === 0) continue;

    const astNode = findAstNode(root, routerId);
    if (!astNode) continue;
    attachWarning(
      astNode,
      `Multiple routes are gated by the same condition ` +
        `(${overlaps} overlapping predicate group${overlaps > 1 ? 's' : ''}); ` +
        `they fire on the same input, making this branch nondeterministic.`,
      'overlapping-route-predicates'
    );
  }
}

/**
 * Flag nodes reachable from two or more distinct triggers — independent
 * concurrent entry points converge there and may race on shared state.
 */
function checkSharedStateConvergence(
  root: Record<string, unknown>,
  nodes: { id: string; namespace: string }[],
  triggerIds: Set<string>,
  forward: Map<string, Set<string>>
): void {
  // Needs at least two independent entry points; otherwise never fires.
  if (triggerIds.size < 2) return;

  // For each node, the set of trigger roots that can reach it.
  const sources = new Map<string, Set<string>>();
  for (const node of nodes) sources.set(node.id, new Set<string>());
  for (const trigger of triggerIds) {
    const reached = bfsForward(new Set([trigger]), forward);
    for (const id of reached) {
      sources.get(id)?.add(trigger);
    }
  }

  for (const node of nodes) {
    if (triggerIds.has(node.id)) continue;
    const roots = sources.get(node.id);
    if (roots === undefined || roots.size < 2) continue;

    const astNode = findAstNode(root, node.id);
    if (!astNode) continue;
    attachWarning(
      astNode,
      `Node '@${node.id}' is reachable from ${roots.size} independent ` +
        `triggers; concurrent executions may race on shared state.`,
      'shared-state-convergence'
    );
  }
}

/**
 * Forward reachability from `seeds` over `forward` adjacency. Returns the set
 * of node ids reachable from any seed (seeds included). When `allow` is given,
 * traversal is restricted to ids in `allow` (used to stay within a subregion).
 */
function bfsForward(
  seeds: Set<string>,
  forward: Map<string, Set<string>>,
  allow?: Set<string>
): Set<string> {
  const reachable = new Set<string>();
  const queue: string[] = [];
  const permitted = (id: string): boolean =>
    allow === undefined || allow.has(id);
  for (const seed of seeds) {
    if (!permitted(seed) || reachable.has(seed)) continue;
    reachable.add(seed);
    queue.push(seed);
  }
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const next of forward.get(current) ?? []) {
      if (permitted(next) && !reachable.has(next)) {
        reachable.add(next);
        queue.push(next);
      }
    }
  }
  return reachable;
}

/**
 * Normalize a gating predicate for textual comparison: trim and collapse
 * internal whitespace. Returns undefined for absent / blank predicates so the
 * caller can treat `otherwise` and ungated edges uniformly.
 */
function normalizePredicate(predicate: string | undefined): string | undefined {
  if (predicate === undefined) return undefined;
  const trimmed = predicate.trim();
  if (trimmed.length === 0) return undefined;
  return trimmed.replace(/\s+/g, ' ');
}

/** Resolve a graph node id (`namespace.name`) to its defining AST entry. */
function findAstNode(
  root: Record<string, unknown>,
  nodeId: string
): AstLike | null {
  const dotIndex = nodeId.indexOf('.');
  if (dotIndex < 0) return null;
  const namespace = nodeId.slice(0, dotIndex);
  const name = nodeId.slice(dotIndex + 1);
  const group = root[namespace];
  if (!isNamedMap(group)) return null;
  for (const [key, entry] of group as Iterable<[string, unknown]>) {
    if (key === name && entry != null && typeof entry === 'object') {
      return entry as AstLike;
    }
  }
  return null;
}
