/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Chain-level (workflow-level) security lint.
 *
 * Adapted from the defence side of ColluSkill / ChainGuard
 * (arxiv:2608.09732): per-node semantic rules approve each agent on its
 * own, yet a harmful workflow can emerge only when nodes are composed.
 * The canonical blind spot is an untrusted trigger payload that flows
 * through an LLM "carrier" node — which looks benign, it just summarises
 * or classifies — into an `executor` that invokes an action. Every node
 * passes local lint (triggers are entry points; generators are ordinary
 * LLM calls; executors may legitimately read `@request.*` and prior node
 * `.output`); the risk is visible only as a cross-node reachability +
 * data-flow property. That is the composition risk this pass flags.
 *
 * It reconstructs cross-node artifact flow over the transition graph
 * (the same graph `extractGraph` produces) and warns when an executor's
 * `run @actions.*` input is derived from:
 *   - `@request.*`         — the untrusted trigger payload, directly; or
 *   - `@<carrier>.<name>.output` where the carrier (a `generator` or
 *     `subagent`, i.e. an LLM hop an attacker can prompt-inject to
 *     forward intent) is reachable from a trigger through the graph.
 *
 * Target-native substitutions / scope cuts (Mode 2):
 *   - The attack-side ColluSkill planner and its LLM-based scanner-
 *     feedback refinement are not hostable in a static linter and are
 *     out of scope; only the ChainGuard defence signal is implemented.
 *   - "Artifact flow" is approximated by transition-graph reachability
 *     plus syntactic reference scanning of action inputs, not a learned
 *     data-flow estimator.
 */

import {
  BinaryExpression,
  CallExpression,
  ComparisonExpression,
  DictLiteral,
  ListLiteral,
  MemberExpression,
  RunStatement,
  SpreadExpression,
  SubscriptExpression,
  TemplateExpression,
  TemplateInterpolation,
  TernaryExpression,
  UnaryExpression,
  WithClause,
  decomposeAtMemberExpression,
  isNamedMap,
} from '@agentscript/language';
import type { Expression, Statement } from '@agentscript/language';
import { extractGraph } from '../../../graph/extractor.js';
import type { GraphEdge, GraphNode } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo } from '../../../schema.js';
import { normalizeId } from '../../utils.js';
import { asStatements, attachWarning, type AstLike } from './shared.js';

/** Edge provenance that marks a node as a trigger entry point. */
const TRIGGER_VIA = 'trigger';
/** LLM-bearing node namespaces that can forward attacker intent. */
const CARRIER_NAMESPACES = new Set(['generator', 'subagent']);
/** Namespace of the untrusted trigger payload (`@request.*`). */
const REQUEST_NAMESPACE = 'request';
/** The `run @actions.*` executor namespace. */
const EXECUTOR_NAMESPACE = 'executor';

interface NodeRef {
  namespace: string;
  property: string;
}

/** A carrier node reachable from a trigger, plus the chain that reaches it. */
interface ReachableCarrier {
  id: string;
  chain: string[];
}

/** Taint summary gathered from one executor's action inputs. */
interface TaintResult {
  directRequest: boolean;
  carriers: ReachableCarrier[];
}

/**
 * Multi-source BFS from every trigger entry over the transition graph,
 * recording one predecessor per node. Returns the carrier nodes
 * (`generator` / `subagent`) reachable from a trigger, each with the
 * reconstructed `trigger -> ... -> carrier` chain.
 */
function computeReachableCarriers(
  nodes: GraphNode[],
  edges: GraphEdge[]
): Map<string, ReachableCarrier> {
  const nodeIds = new Set(nodes.map(node => node.id));
  const adjacency = new Map<string, string[]>();
  for (const id of nodeIds) adjacency.set(id, []);

  const triggerSources: string[] = [];
  for (const edge of edges) {
    if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) continue;
    adjacency.get(edge.from)!.push(edge.to);
    if (edge.via === TRIGGER_VIA) triggerSources.push(edge.from);
  }

  // `prev` carries one predecessor per visited node; trigger sources map
  // to `null` so chain reconstruction terminates at the entry point.
  const prev = new Map<string, string | null>();
  const queue: string[] = [];
  const seenSource = new Set<string>();
  for (const source of triggerSources) {
    if (!nodeIds.has(source) || seenSource.has(source)) continue;
    seenSource.add(source);
    prev.set(source, null);
    queue.push(source);
  }
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const next of adjacency.get(current) ?? []) {
      if (prev.has(next)) continue;
      prev.set(next, current);
      queue.push(next);
    }
  }

  const carriers = new Map<string, ReachableCarrier>();
  for (const node of nodes) {
    if (!CARRIER_NAMESPACES.has(node.namespace)) continue;
    if (!prev.has(node.id)) continue;
    const chain: string[] = [];
    let cursor: string | null = node.id;
    while (cursor) {
      chain.unshift(cursor);
      cursor = prev.get(cursor) ?? null;
    }
    carriers.set(normalizeId(node.id), { id: node.id, chain });
  }
  return carriers;
}

/**
 * Recursively collect every `@namespace.property` reference in an
 * expression. Mirrors the expression walker in execute-rules but
 * gathers references instead of validating them. Needed because a
 * carrier reference can sit inside templates, dicts, or subscripts
 * (e.g. `"Hello {@generator.summarize.output}"`).
 */
function collectMemberRefs(expr: unknown, out: NodeRef[] = []): NodeRef[] {
  if (expr == null || typeof expr !== 'object') return out;
  const node = expr as Expression;
  if (typeof node.__kind !== 'string') return out;

  if (node instanceof MemberExpression) {
    const decomposed = decomposeAtMemberExpression(node);
    if (decomposed) out.push(decomposed);
    // `decomposeAtMemberExpression` only matches the two-level `@ns.prop`
    // form, so deeper refs like `@generator.x.output` are found by
    // recursing into the member object.
    if (node.object) collectMemberRefs(node.object, out);
    return out;
  }
  if (node instanceof SubscriptExpression) {
    if (node.object) collectMemberRefs(node.object, out);
    if (node.index) collectMemberRefs(node.index, out);
    return out;
  }
  if (
    node instanceof BinaryExpression ||
    node instanceof ComparisonExpression
  ) {
    collectMemberRefs(node.left, out);
    collectMemberRefs(node.right, out);
    return out;
  }
  if (node instanceof UnaryExpression) {
    collectMemberRefs(node.operand, out);
    return out;
  }
  if (node instanceof TernaryExpression) {
    collectMemberRefs(node.condition, out);
    collectMemberRefs(node.consequence, out);
    collectMemberRefs(node.alternative, out);
    return out;
  }
  if (node instanceof CallExpression) {
    if (node.func) collectMemberRefs(node.func, out);
    for (const arg of node.args) collectMemberRefs(arg, out);
    return out;
  }
  if (node instanceof ListLiteral) {
    for (const element of node.elements) collectMemberRefs(element, out);
    return out;
  }
  if (node instanceof DictLiteral) {
    for (const entry of node.entries) {
      collectMemberRefs(entry.key, out);
      collectMemberRefs(entry.value, out);
    }
    return out;
  }
  if (node instanceof TemplateExpression) {
    for (const part of node.parts) {
      if (part instanceof TemplateInterpolation) {
        collectMemberRefs(part.expression, out);
      }
    }
    return out;
  }
  if (node instanceof SpreadExpression) {
    collectMemberRefs(node.expression, out);
    return out;
  }
  return out;
}

/** Index executor AST entries by graph node id so warnings attach to source. */
function buildExecutorIndex(
  root: Record<string, unknown>,
  nodeIds: Set<string>
): Map<string, AstLike> {
  const index = new Map<string, AstLike>();
  const executors = root.executor;
  if (!isNamedMap(executors)) return index;
  for (const [name, entry] of executors as Iterable<[string, unknown]>) {
    const id = `${EXECUTOR_NAMESPACE}.${name}`;
    if (!nodeIds.has(id)) continue;
    if (entry == null || typeof entry !== 'object') continue;
    index.set(id, entry as AstLike);
  }
  return index;
}

/** Scan an executor's `run @actions.*` inputs for untrusted-derived data. */
function analyzeExecutorTaint(
  entry: AstLike,
  reachableCarriers: Map<string, ReachableCarrier>
): TaintResult {
  const result: TaintResult = { directRequest: false, carriers: [] };
  const seenCarrierIds = new Set<string>();
  const statements = asStatements(
    (entry as Record<string, unknown>).do
  ) as unknown as Statement[];

  for (const stmt of statements) {
    if (!(stmt instanceof RunStatement)) continue;
    for (const child of stmt.body) {
      if (!(child instanceof WithClause)) continue;
      for (const ref of collectMemberRefs(child.value)) {
        if (ref.namespace === REQUEST_NAMESPACE) {
          result.directRequest = true;
        } else if (CARRIER_NAMESPACES.has(ref.namespace)) {
          const carrier = reachableCarriers.get(
            normalizeId(`${ref.namespace}.${ref.property}`)
          );
          if (carrier && !seenCarrierIds.has(carrier.id)) {
            seenCarrierIds.add(carrier.id);
            result.carriers.push(carrier);
          }
        }
      }
    }
  }
  return result;
}

function formatArrowChain(ids: string[]): string {
  return ids.map(id => `@${id}`).join(' → ');
}

function formatTaintMessage(executorId: string, taint: TaintResult): string {
  const sources: string[] = [];
  if (taint.directRequest) {
    sources.push('direct @request.* payload');
  }
  for (const carrier of taint.carriers) {
    sources.push(`LLM carrier @${carrier.id}`);
  }
  const via = sources.join(' and ');
  const chain = taint.carriers.length
    ? ` Chain: ${formatArrowChain([...taint.carriers[0]!.chain, executorId])}.`
    : '';
  const note =
    'Each node passes local lint; this risk only emerges from composition.';
  const head = `Untrusted trigger data reaches an action input via ${via}.`;
  return `${head}${chain} ${note}`;
}

/**
 * Entry point: detect cross-node (chain-level) flows where untrusted
 * trigger data — direct or relayed through an LLM carrier — reaches an
 * executor action input, and attach a warning to each such executor.
 */
export function checkUntrustedActionFlow(root: Record<string, unknown>): void {
  const { nodes, edges } = extractGraph(root, AgentFabricSchemaInfo);
  if (nodes.length === 0) return;

  const nodeIds = new Set(nodes.map(node => node.id));
  const reachableCarriers = computeReachableCarriers(nodes, edges);
  const executorIndex = buildExecutorIndex(root, nodeIds);

  for (const node of nodes) {
    if (node.namespace !== EXECUTOR_NAMESPACE) continue;
    const entry = executorIndex.get(node.id);
    if (!entry) continue;
    const taint = analyzeExecutorTaint(entry, reachableCarriers);
    if (taint.directRequest || taint.carriers.length > 0) {
      attachWarning(
        entry,
        formatTaintMessage(node.id, taint),
        'untrusted-action-input'
      );
    }
  }
}
