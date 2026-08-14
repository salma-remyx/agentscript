/**
 * Lint rules for cross-skill chain composition risks.
 *
 * Adapted from ChainGuard (the defense side of "ColluSkill: Adversarial
 * Cross-Skill Composition for Evading Agent Skill Scanners",
 * arXiv:2608.09732): individually plausible action bindings can compose
 * into a risky workflow once artifact flows and execution handoffs are
 * taken into account. This module reconstructs those flows over the
 * schema-driven graph (`extractGraph`) and warns when an artifact
 * produced by one action is handed off to an external messaging action
 * (`a2a:send_message`) on a *different* connection — a pattern that no
 * per-action check can see, because each action is benign in isolation
 * and the risk only emerges at the workflow level.
 *
 * Substitutions vs. the paper (Mode 2): ChainGuard's learned
 * downstream-behavior model is replaced by a parameter-free taint walk
 * over the extracted node/edge graph, and its installed-skill corpus is
 * the document's own `actions` block. The adversarial chain generator
 * (ColluSkill itself) is intentionally out of scope — this is the
 * scanner, not the attack.
 */

import {
  BinaryExpression,
  CallExpression,
  ComparisonExpression,
  DictLiteral,
  ListLiteral,
  MemberExpression,
  RunStatement,
  SetClause,
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
import { extractGraph } from '../../../graph/extractor.js';
import type { GraphEdge } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo } from '../../../schema.js';
import { iterateCollection, normalizeId } from '../../utils.js';
import {
  asStatements,
  attachWarning,
  extractStringValue,
  type AstLike,
} from './shared.js';
import type { Expression, Statement, NamedMap } from '@agentscript/language';

/** Node namespaces whose entries can bind or run actions. */
const AGENTIC_NODE_TYPES = new Set(['orchestrator', 'subagent', 'generator']);

/** Namespaces that own graph nodes (used to recognize `@ns.name.output`). */
const NODE_NAMESPACES = new Set([
  'orchestrator',
  'subagent',
  'generator',
  'executor',
  'router',
  'echo',
]);

interface ActionDefInfo {
  name: string;
  kind: string;
  connection: string;
}

/** `@variables.*` and `@<ns>.<node>.output` reads found in an expression. */
interface Refs {
  variables: Set<string>;
  nodeOutputs: Set<string>;
}

/** Mutable taint state carried along the topological node walk. */
interface ChainState {
  /** variable name -> actions whose results the value derives from. */
  variableTaint: Map<string, Set<string>>;
  /** node id -> actions whose results influenced the node's output. */
  nodeOutputTaint: Map<string, Set<string>>;
  /** dedupe key for emitted diagnostics. */
  reported: Set<string>;
}

function emptyRefs(): Refs {
  return { variables: new Set(), nodeOutputs: new Set() };
}

// Recursively collect @-references from an expression, mirroring the
// expression walker in execute-rules but gathering instead of validating.
function collectRefs(expr: Expression, refs: Refs): void {
  if (expr == null || typeof expr !== 'object') return;

  if (expr instanceof MemberExpression) {
    const decomposed = decomposeAtMemberExpression(expr);
    if (decomposed) {
      if (decomposed.namespace === 'variables') {
        refs.variables.add(normalizeId(decomposed.property));
      } else if (NODE_NAMESPACES.has(decomposed.namespace)) {
        // Node ids keep their raw (un-normalized) name segment.
        refs.nodeOutputs.add(`${decomposed.namespace}.${decomposed.property}`);
      }
    }
    collectRefs(expr.object, refs);
    return;
  }

  if (
    expr instanceof BinaryExpression ||
    expr instanceof ComparisonExpression
  ) {
    collectRefs(expr.left, refs);
    collectRefs(expr.right, refs);
    return;
  }

  if (expr instanceof SubscriptExpression) {
    collectRefs(expr.object, refs);
    collectRefs(expr.index, refs);
    return;
  }

  if (expr instanceof UnaryExpression) {
    collectRefs(expr.operand, refs);
    return;
  }

  if (expr instanceof TernaryExpression) {
    collectRefs(expr.condition, refs);
    collectRefs(expr.consequence, refs);
    collectRefs(expr.alternative, refs);
    return;
  }

  if (expr instanceof CallExpression) {
    collectRefs(expr.func, refs);
    for (const arg of expr.args) collectRefs(arg, refs);
    return;
  }

  if (expr instanceof ListLiteral) {
    for (const el of expr.elements) collectRefs(el, refs);
    return;
  }

  if (expr instanceof DictLiteral) {
    for (const entry of expr.entries) {
      collectRefs(entry.key, refs);
      collectRefs(entry.value, refs);
    }
    return;
  }

  if (expr instanceof TemplateExpression) {
    for (const part of expr.parts) {
      if (part instanceof TemplateInterpolation) {
        collectRefs(part.expression, refs);
      }
    }
    return;
  }

  if (expr instanceof SpreadExpression) {
    collectRefs(expr.expression, refs);
  }
}

function collectActionDefs(
  root: Record<string, unknown>
): Map<string, ActionDefInfo> {
  const defs = new Map<string, ActionDefInfo>();
  const actions = root.actions as unknown;
  if (!isNamedMap(actions)) return defs;

  for (const [name, entry] of actions as NamedMap<unknown>) {
    if (entry == null || typeof entry !== 'object') continue;
    const record = entry as Record<string, unknown>;
    const kind = extractStringValue(record.kind) ?? '';
    const target = extractStringValue(record.target) ?? '';
    const schemeIndex = target.indexOf('://');
    const connection =
      schemeIndex >= 0 ? target.slice(schemeIndex + 3) : target;
    const normalizedName = normalizeId(name);
    defs.set(normalizedName, {
      name: normalizedName,
      kind,
      connection,
    });
  }
  return defs;
}

// Kahn topological order over non-trigger edges. Nodes stuck in a cycle
// (already reported by cycle-detected) are appended in declaration order
// so their flows are still examined once.
function topoOrder(edges: GraphEdge[], nodeIds: Set<string>): string[] {
  const indegree = new Map<string, number>();
  const adjacency = new Map<string, string[]>();
  for (const id of nodeIds) {
    indegree.set(id, 0);
    adjacency.set(id, []);
  }
  for (const edge of edges) {
    if (edge.via === 'trigger') continue;
    if (!indegree.has(edge.from) || !indegree.has(edge.to)) continue;
    adjacency.get(edge.from)!.push(edge.to);
    indegree.set(edge.to, (indegree.get(edge.to) ?? 0) + 1);
  }

  const queue = [...nodeIds].filter(id => (indegree.get(id) ?? 0) === 0);
  const ordered = new Set<string>();
  const order: string[] = [];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (ordered.has(id)) continue;
    ordered.add(id);
    order.push(id);
    for (const next of adjacency.get(id) ?? []) {
      const remaining = (indegree.get(next) ?? 0) - 1;
      indegree.set(next, remaining);
      if (remaining === 0) queue.push(next);
    }
  }
  for (const id of nodeIds) {
    if (!ordered.has(id)) order.push(id);
  }
  return order;
}

function taintOfRefs(refs: Refs, state: ChainState): Set<string> {
  const taint = new Set<string>();
  for (const variable of refs.variables) {
    for (const source of state.variableTaint.get(variable) ?? []) {
      taint.add(source);
    }
  }
  for (const nodeId of refs.nodeOutputs) {
    for (const source of state.nodeOutputTaint.get(nodeId) ?? []) {
      taint.add(source);
    }
  }
  return taint;
}

function mergeRefTaint(
  taint: Set<string>,
  expr: Expression,
  state: ChainState
): void {
  const refs = emptyRefs();
  collectRefs(expr, refs);
  for (const source of taintOfRefs(refs, state)) taint.add(source);
}

// Record the taint of a `set` target (`@variables.<name>` only —
// `@outputs.*` targets never feed later reads).
function assignVariableTaint(
  target: Expression,
  taint: Set<string>,
  state: ChainState
): void {
  const decomposed = decomposeAtMemberExpression(target);
  if (!decomposed || decomposed.namespace !== 'variables') return;
  const name = normalizeId(decomposed.property);
  if (taint.size === 0) {
    state.variableTaint.delete(name);
    return;
  }
  state.variableTaint.set(name, new Set(taint));
}

// The ChainGuard check itself: a messaging action that receives an
// artifact sourced from a *different* connection. Same-connection reuse
// is normal tool orchestration and is deliberately not flagged.
function checkSink(
  sink: ActionDefInfo,
  sinkTaint: Set<string>,
  actionDefs: Map<string, ActionDefInfo>,
  nodeAst: AstLike,
  nodeId: string,
  state: ChainState
): void {
  if (sink.kind !== 'a2a:send_message') return;

  for (const sourceName of sinkTaint) {
    if (sourceName === sink.name) continue;
    const source = actionDefs.get(sourceName);
    if (!source || source.connection === sink.connection) continue;

    const signature = `${nodeId}|${sink.name}|${sourceName}`;
    if (state.reported.has(signature)) continue;
    state.reported.add(signature);

    attachWarning(
      nodeAst,
      `Cross-connection artifact flow: output of @actions.${sourceName} ` +
        `(connection ${source.connection}) reaches external action ` +
        `@actions.${sink.name} (connection ${sink.connection}) at ` +
        `@${nodeId}. Each action passes on its own; the risk emerges only ` +
        `from the composed workflow.`,
      'chain-cross-connection-egress'
    );
  }
}

function processExecutorDo(
  entry: Record<string, unknown>,
  actionDefs: Map<string, ActionDefInfo>,
  state: ChainState,
  nodeId: string,
  runActions: Set<string>
): void {
  const node = entry as AstLike;
  for (const stmt of asStatements(entry.do) as unknown as Statement[]) {
    if (stmt instanceof SetClause) {
      const taint = new Set<string>();
      mergeRefTaint(taint, stmt.value, state);
      assignVariableTaint(stmt.target, taint, state);
      continue;
    }

    if (stmt instanceof RunStatement) {
      const decomposed = decomposeAtMemberExpression(stmt.target);
      const actionName = decomposed
        ? normalizeId(decomposed.property)
        : undefined;
      const actionDef = actionName
        ? actionDefs.get(actionName)
        : undefined;
      if (actionDef) runActions.add(actionDef.name);

      // `with` inputs are evaluated before the action's own result exists.
      const inputRefs = emptyRefs();
      for (const child of stmt.body) {
        if (child instanceof WithClause) collectRefs(child.value, inputRefs);
      }
      if (actionDef) {
        checkSink(
          actionDef,
          taintOfRefs(inputRefs, state),
          actionDefs,
          node,
          nodeId,
          state
        );
      }

      // `set` clauses inside the run body read this action's result.
      for (const child of stmt.body) {
        if (!(child instanceof SetClause)) continue;
        const taint = new Set<string>();
        if (actionDef) taint.add(actionDef.name);
        mergeRefTaint(taint, child.value, state);
        assignVariableTaint(child.target, taint, state);
      }
    }
  }
}

// Mirrors the private helpers in action-binding-rules.ts.
function getActionDefName(
  toolEntry: Record<string, unknown>
): string | undefined {
  const rawColinear =
    toolEntry.value ??
    toolEntry.__colinear ??
    toolEntry.colinear ??
    toolEntry.__value;
  const ref = decomposeAtMemberExpression(rawColinear);
  if (ref && ref.namespace === 'actions') return ref.property;
  const strValue = extractStringValue(rawColinear);
  if (strValue) {
    return strValue.startsWith('@actions.')
      ? strValue.substring(9)
      : strValue;
  }
  return undefined;
}

function getBodyStatements(toolEntry: Record<string, unknown>): unknown[] {
  const body = toolEntry.body as { statements?: unknown[] } | undefined;
  if (body && Array.isArray(body.statements)) return body.statements;
  if (Array.isArray(toolEntry.statements)) return toolEntry.statements;
  return [];
}

function processAgenticActions(
  entry: Record<string, unknown>,
  actionDefs: Map<string, ActionDefInfo>,
  state: ChainState,
  nodeId: string,
  boundActions: Set<string>
): void {
  const reasoning = entry.reasoning as Record<string, unknown> | undefined;
  if (!reasoning) return;

  const node = entry as AstLike;
  for (const [, binding] of iterateCollection(reasoning.actions)) {
    const actionName = getActionDefName(binding);
    if (!actionName) continue;
    const actionDef = actionDefs.get(normalizeId(actionName));
    if (!actionDef) continue;
    boundActions.add(actionDef.name);

    const refs = emptyRefs();
    for (const stmt of getBodyStatements(binding) as unknown as Statement[]) {
      if (stmt instanceof WithClause) collectRefs(stmt.value, refs);
    }
    checkSink(
      actionDef,
      taintOfRefs(refs, state),
      actionDefs,
      node,
      nodeId,
      state
    );
  }
}

// Entry point: walk the extracted graph in execution order and flag
// artifact flows between actions on different connections that terminate
// in an external messaging sink.
export function checkChainCompositionRules(
  root: Record<string, unknown>
): void {
  const actionDefs = collectActionDefs(root);
  if (actionDefs.size === 0) return;

  const { nodes, edges } = extractGraph(root, AgentFabricSchemaInfo);
  const nodeIds = new Set(nodes.map(node => node.id));
  if (nodeIds.size === 0) return;

  const state: ChainState = {
    variableTaint: new Map(),
    nodeOutputTaint: new Map(),
    reported: new Set(),
  };

  for (const nodeId of topoOrder(edges, nodeIds)) {
    const dotIndex = nodeId.indexOf('.');
    if (dotIndex <= 0) continue;
    const namespace = nodeId.slice(0, dotIndex);
    const name = nodeId.slice(dotIndex + 1);

    const group = root[namespace] as unknown;
    if (!isNamedMap(group)) continue;
    const entry = (group as NamedMap<unknown>).get(
      name
    ) as Record<string, unknown> | undefined;
    if (entry == null || typeof entry !== 'object') continue;

    const influencedActions = new Set<string>();
    if (namespace === 'executor') {
      processExecutorDo(
        entry,
        actionDefs,
        state,
        nodeId,
        influencedActions
      );
    } else if (AGENTIC_NODE_TYPES.has(namespace)) {
      processAgenticActions(
        entry,
        actionDefs,
        state,
        nodeId,
        influencedActions
      );
    }
    if (influencedActions.size > 0) {
      state.nodeOutputTaint.set(nodeId, influencedActions);
    }
  }
}
