/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Scoped (neighborhood-local) verification of transition targets in the
 * schema-derived agent graph.
 *
 * Adapted from Graph-Regularized Agentic Context Evolution (GRACE), whose
 * central requirement for reliable long-horizon evolution is a *structural
 * substrate that makes verification local*: a proposed change is validated
 * within the local typed neighborhood of the modified node rather than by
 * re-checking the whole graph. This module applies that insight to AgentFabric's
 * existing schema-driven graph extraction (`graph/extractor.ts`) — it adds no
 * new extraction, only a verifier over the topology the extractor already
 * produces.
 *
 * The typed contract verified here: every transition edge must land on a node
 * whose kind declares the schema `'transitionTarget'` capability. The set of
 * legal transition-target kinds is derived from the schema (never hardcoded), so
 * it is also a step toward the schema TODO at `ROUTER_TARGET_NAMESPACES`, which
 * asks for exactly this list to be derived rather than hand-maintained. A
 * transition into, e.g., a `trigger` node is a *typed* neighborhood error — the
 * target is a defined symbol of the wrong type — that existence checks
 * (`undefinedReferencePass`) cannot catch, because the symbol resolves fine.
 *
 * `verifyTypedNeighborhood` is the GRACE-shaped scoped verifier: pass
 * `modifiedNodeIds` to re-verify only the 1-hop neighborhoods of changed nodes
 * (incremental evolution); omit it to verify the whole graph (full lint). The
 * `checkTransitionTargetRules` lint entry uses full-graph mode and is wired into
 * the AgentFabric semantic pass alongside `cycle-rules`.
 */
import { isNamedCollectionFieldType, isNamedMap } from '@agentscript/language';
import type { FieldType, SchemaInfo } from '@agentscript/language';
import { extractGraph } from '../../../graph/extractor.js';
import type { ExtractedGraph } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo } from '../../../schema.js';
import { attachError, type AstLike } from './shared.js';

/** Diagnostic code reported for a transition into a non-target node kind. */
const INVALID_TRANSITION_TARGET_CODE = 'invalid-transition-target';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** A transition whose target node kind is not a legal transition-target kind. */
export interface NeighborhoodViolation {
  /** Qualified id of the node that owns the transition (the edge source). */
  fromId: string;
  /** Qualified id of the invalid transition target. */
  toId: string;
  /** Schema namespace (kind) of the invalid target, e.g. "trigger". */
  toKind: string;
  /** Every legal transition-target kind, derived from the schema, sorted. */
  legalKinds: string[];
}

/** Options for the scoped neighborhood verifier. */
export interface VerifyTypedNeighborhoodOptions {
  /**
   * When provided, only the 1-hop neighborhoods of these node ids are verified
   * (GRACE scoped verification of modified nodes — both a node's outgoing
   * targets and any edges that now land on it). When omitted, the whole graph
   * is verified (full-graph lint mode).
   */
  modifiedNodeIds?: Iterable<string>;
}

// ---------------------------------------------------------------------------
// Schema-driven typed contract
// ---------------------------------------------------------------------------

/** Resolve a possibly-array-wrapped schema entry to a single FieldType. */
function resolveFieldType(ft: FieldType | FieldType[]): FieldType {
  return Array.isArray(ft) ? ft[0] : ft;
}

/**
 * Derive the set of legal transition-target kinds purely from schema metadata:
 * every top-level NamedCollection whose entry block declares the
 * `'transitionTarget'` capability. Adding a new node kind to the dialect is a
 * schema change and nothing else — this set tracks it automatically. `trigger`
 * is intentionally absent because triggers are entry points, not targets.
 */
function deriveTransitionTargetKinds(schemaInfo: SchemaInfo): Set<string> {
  const kinds = new Set<string>();
  for (const [namespace, rawFt] of Object.entries(schemaInfo.schema)) {
    const ft = resolveFieldType(rawFt);
    if (!isNamedCollectionFieldType(ft)) continue;
    const capabilities =
      (
        ft as {
          entryBlock?: { capabilities?: readonly string[] };
        }
      ).entryBlock?.capabilities ?? [];
    if (capabilities.includes('transitionTarget')) kinds.add(namespace);
  }
  return kinds;
}

// ---------------------------------------------------------------------------
// Scoped neighborhood verifier (GRACE core)
// ---------------------------------------------------------------------------

/**
 * Verify the typed transition-target contract over the extracted graph, scoped
 * to the local neighborhoods of `modifiedNodeIds` when given.
 *
 * For every edge incident to an in-scope node, confirm the target resolves to a
 * node whose kind is a legal transition-target kind. Edges whose target is
 * absent (a dangling reference) are intentionally skipped — existence is the
 * `undefinedReferencePass`'s responsibility; this check is strictly about the
 * target's *type*. Returns one violation per offending edge.
 */
export function verifyTypedNeighborhood(
  extracted: ExtractedGraph,
  schemaInfo: SchemaInfo,
  options?: VerifyTypedNeighborhoodOptions
): NeighborhoodViolation[] {
  const legalKinds = deriveTransitionTargetKinds(schemaInfo);
  const sortedLegalKinds = [...legalKinds].sort();
  const nodeById = new Map(extracted.nodes.map(node => [node.id, node]));

  // Scoped mode (GRACE): only inspect edges in the 1-hop neighborhood of a
  // modified node — its outgoing targets plus any edge that now lands on it.
  const scope =
    options?.modifiedNodeIds === undefined
      ? undefined
      : new Set(options.modifiedNodeIds);

  const violations: NeighborhoodViolation[] = [];
  for (const edge of extracted.edges) {
    if (scope !== undefined && !scope.has(edge.from) && !scope.has(edge.to)) {
      continue;
    }
    const target = nodeById.get(edge.to);
    // Absent target → undefinedReferencePass reports the dangling reference.
    if (target === undefined) continue;
    if (legalKinds.has(target.namespace)) continue;

    violations.push({
      fromId: edge.from,
      toId: edge.to,
      toKind: target.namespace,
      legalKinds: sortedLegalKinds,
    });
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Lint entry point
// ---------------------------------------------------------------------------

/**
 * Index graph-node ids → their defining AST instance so diagnostics can be
 * attached. Mirrors the helper in `cycle-rules.ts`; kept local so each graph
 * rule stays self-contained.
 */
function buildASTNodesIndex(
  root: Record<string, unknown>,
  nodeIds: Set<string>
): Map<string, AstLike> {
  const index = new Map<string, AstLike>();
  for (const [namespace, group] of Object.entries(root)) {
    if (!isNamedMap(group)) continue;
    for (const [name, entry] of group as Iterable<[string, unknown]>) {
      const id = `${namespace}.${name}`;
      if (!nodeIds.has(id)) continue;
      if (entry == null || typeof entry !== 'object') continue;
      index.set(id, entry as AstLike);
    }
  }
  return index;
}

function formatViolation(violation: NeighborhoodViolation): string {
  return (
    `Transition target '@${violation.toId}' is a ${violation.toKind} node, ` +
    `which cannot be a transition target (valid kinds: ${violation.legalKinds.join(', ')}).`
  );
}

/**
 * Graph-aware lint entry: extract the schema-derived graph and verify the typed
 * transition-target contract over every node's 1-hop neighborhood (full-graph
 * mode of `verifyTypedNeighborhood`). Invalid transitions are reported on the
 * AST node that owns them.
 */
export function checkTransitionTargetRules(
  root: Record<string, unknown>
): void {
  const extracted = extractGraph(root, AgentFabricSchemaInfo);
  if (extracted.nodes.length === 0) return;

  const violations = verifyTypedNeighborhood(extracted, AgentFabricSchemaInfo);
  if (violations.length === 0) return;

  const nodeIds = new Set(extracted.nodes.map(node => node.id));
  const astNodesIndex = buildASTNodesIndex(root, nodeIds);
  for (const violation of violations) {
    const astNode = astNodesIndex.get(violation.fromId);
    if (astNode === undefined) continue;
    attachError(
      astNode,
      formatViolation(violation),
      INVALID_TRANSITION_TARGET_CODE
    );
  }
}
