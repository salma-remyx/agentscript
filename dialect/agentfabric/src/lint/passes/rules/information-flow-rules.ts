/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { decomposeAtMemberExpression, isNamedMap } from '@agentscript/language';
import { extractGraph } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo } from '../../../schema.js';
import { normalizeId } from '../../utils.js';
import { attachWarning, extractStringValue, type AstLike } from './shared.js';

/**
 * Information-flow / prompt-injection lint rule.
 *
 * Adapted from APPA — "Agentic Permissions Policy Algebra for Taint
 * Confinement in LLM Agents" (arXiv:2607.24625). APPA enforces, at runtime,
 * that unvetted external data cannot reach an agent's control-flow (LLM
 * reasoning) context without an explicit remedy (Authorize / Accept) or a
 * confinement boundary (a label-seeded child trajectory whose bounded,
 * sanitized derivative is all that returns to the parent).
 *
 * This rule is a statically-decidable, target-native analog over the
 * schema-driven execution graph: it flags control-flow nodes — orchestrator /
 * subagent / generator, the LLM-reasoning nodes where injected content could
 * hijack routing — that are reached DIRECTLY from a node which itself ingests
 * unvetted external data by calling an external mcp/a2a action. A direct
 * transition has no intervening node, so no deterministic / sanitizer node can
 * bound the data first — exactly the surface APPA's prospective acquisition
 * enforcement guards. Routing the data through a deterministic executor first
 * averts the flag, mirroring APPA's confinement boundary.
 *
 * Mode-2 adaptation: APPA's runtime two-monoid label algebra, label-seeded
 * child trajectories, and shared event-log merge model are auxiliary machinery
 * this static-analysis engine does not host, and are intentionally out of
 * scope. The retained core signal is the one that matters here — unvetted
 * external data reaching control flow unchecked.
 */

// LLM-reasoning node namespaces: control flow that unvetted data can hijack.
const CONTROL_FLOW_NAMESPACES = new Set([
  'orchestrator',
  'subagent',
  'generator',
]);

// Action-def kinds that pull unvetted data across the external boundary.
const EXTERNAL_ACTION_KINDS = new Set(['mcp:tool', 'a2a:send_message']);

interface ActionBindingLike {
  value?: unknown;
  __colinear?: unknown;
  colinear?: unknown;
  __value?: unknown;
}

/**
 * Resolve a `reasoning.actions` binding to the `@actions.<name>` it references,
 * if any. Handles both resolved ReferenceValue and raw member-expression forms.
 */
function resolveActionRefName(binding: unknown): string | undefined {
  if (binding == null || typeof binding !== 'object') return undefined;
  const raw =
    (binding as ActionBindingLike).value ??
    (binding as ActionBindingLike).__colinear ??
    (binding as ActionBindingLike).colinear ??
    (binding as ActionBindingLike).__value;
  const ref = decomposeAtMemberExpression(raw);
  if (ref && ref.namespace === 'actions') return ref.property;
  const strValue = extractStringValue(raw);
  if (typeof strValue === 'string' && strValue.startsWith('@actions.')) {
    return strValue.slice('@actions.'.length);
  }
  return undefined;
}

/**
 * Build a `namespace.name` -> AST entry index over every named collection in
 * the document, so a graph node id can be resolved back to the AST instance
 * that defines it (the attach target for diagnostics).
 */
function buildAstIndex(root: Record<string, unknown>): Map<string, AstLike> {
  const index = new Map<string, AstLike>();
  for (const [namespace, group] of Object.entries(root)) {
    if (!isNamedMap(group)) continue;
    for (const [name, entry] of group as Iterable<[string, unknown]>) {
      if (entry == null || typeof entry !== 'object') continue;
      index.set(`${namespace}.${name}`, entry as AstLike);
    }
  }
  return index;
}

/**
 * Identify graph nodes that ingest unvetted external data — those binding at
 * least one external mcp/a2a action in `reasoning.actions`. A referenced but
 * unresolved `@actions.*` binding is treated conservatively as external, since
 * a security lint should err on the side of flagging.
 */
function collectExternalSourceIds(
  root: Record<string, unknown>,
  nodeIds: Set<string>,
  astIndex: Map<string, AstLike>
): Set<string> {
  const actionDefs = isNamedMap(root.actions)
    ? new Map<string, Record<string, unknown>>(
        [...root.actions].map(([k, v]) => [
          normalizeId(k),
          v as Record<string, unknown>,
        ])
      )
    : new Map<string, Record<string, unknown>>();

  const externalIds = new Set<string>();
  for (const nodeId of nodeIds) {
    const entry = astIndex.get(nodeId);
    if (!entry) continue;
    const reasoning = (entry as { reasoning?: unknown }).reasoning;
    if (!reasoning || typeof reasoning !== 'object') continue;
    const actionsMap = (reasoning as { actions?: unknown }).actions;
    if (!actionsMap || typeof actionsMap !== 'object') continue;

    const bindings = isNamedMap(actionsMap)
      ? ([...actionsMap] as [string, unknown][])
      : [];
    for (const [, binding] of bindings) {
      const refName = resolveActionRefName(binding);
      if (!refName) continue;
      const def = actionDefs.get(normalizeId(refName));
      // Resolved def: check its kind. Unresolved binding: assume external.
      const kind = def
        ? extractStringValue((def as { kind?: unknown }).kind)
        : undefined;
      if (kind === undefined || EXTERNAL_ACTION_KINDS.has(kind)) {
        externalIds.add(nodeId);
        break;
      }
    }
  }
  return externalIds;
}

function namespaceOf(nodeId: string): string {
  const dot = nodeId.indexOf('.');
  return dot < 0 ? '' : nodeId.slice(0, dot);
}

/**
 * Entry point: flag control-flow nodes that receive unvetted external data
 * directly from an external-action-calling node, with no intervening
 * sanitizer. One diagnostic per (target, source) pair, attached to the
 * at-risk control-flow node.
 */
export function checkInformationFlowRules(root: Record<string, unknown>): void {
  const { nodes, edges } = extractGraph(root, AgentFabricSchemaInfo);
  if (nodes.length === 0) return;

  const nodeIds = new Set(nodes.map(node => node.id));
  const astIndex = buildAstIndex(root);
  const externalSourceIds = collectExternalSourceIds(root, nodeIds, astIndex);
  if (externalSourceIds.size === 0) return;

  const reported = new Set<string>();
  for (const edge of edges) {
    // Triggers are the normal external entry surface — not flagged here.
    if (edge.via === 'trigger') continue;
    if (edge.from === edge.to) continue;
    if (!externalSourceIds.has(edge.from)) continue;
    if (!CONTROL_FLOW_NAMESPACES.has(namespaceOf(edge.to))) continue;

    const key = `${edge.to}::${edge.from}`;
    if (reported.has(key)) continue;
    reported.add(key);

    const target = astIndex.get(edge.to);
    if (!target) continue;
    attachWarning(
      target,
      `Unvetted external data from '@${edge.from}' (calls an external mcp/a2a action) ` +
        `reaches control-flow node '@${edge.to}' with no intervening sanitizer node ` +
        `— prompt-injection surface. Route through a deterministic node or authorize the flow.`,
      'untrusted-data-to-control-flow'
    );
  }
}
