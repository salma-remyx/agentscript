/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Lint rule detecting the "specification gap" coordination hazard.
 *
 * Adapted from "The Specification Gap: Coordination Failure Under Partial
 * Knowledge in Code Agents" (arXiv:2603.24284). The paper studies what
 * happens when several LLM code agents independently implement against a
 * shared but under-specified contract: they fail to agree on the implicit
 * internal representation, and the failure worsens as the spec is stripped
 * from full docstrings (L0) down to a bare signature (L3).
 *
 * AgentFabric mirrors that setting exactly. An `actions` definition is a
 * shared contract that several agentic nodes (orchestrator / subagent /
 * generator) may bind independently through `reasoning.actions`. When that
 * contract carries no declared inputs beyond the implicit allow-list, every
 * consumer is free to invent its own input shape — the inter-consumer
 * coordination hazard the paper documents. This rule surfaces it statically.
 *
 * Mode 2 (adapted port): the paper's L0 -> L3 specification-completeness
 * taxonomy is ported at full fidelity as a static score over each action's
 * `inputs:` contract (`actionInputSpecLevel`). The paper's empirical
 * multi-agent agreement study — run N LLM implementers, measure divergence
 * across 51 class-generation tasks — is the auxiliary that does not fit a
 * static linter and is substituted by a parameter-free proxy: the count of
 * distinct agentic consumers binding the action. More independent consumers
 * of an under-specified contract means higher coordination-failure risk, no
 * agent execution required. A single consumer is intentionally exempt: with
 * no one to disagree with there is no coordination hazard.
 */

import { decomposeAtMemberExpression, isNamedMap } from '@agentscript/language';
import {
  IMPLICIT_WITH_PARAMS,
  listActionDefInputNames,
  normalizeId,
} from '../../utils.js';
import { attachWarning, extractStringValue, type AstLike } from './shared.js';

/** Agentic node namespaces that may bind actions via `reasoning.actions`. */
const AGENTIC_NODE_TYPES = ['orchestrator', 'subagent', 'generator'] as const;

/**
 * Minimum distinct consumers for a binding to count as a coordination point.
 * Below this there is no second party to disagree with, so the spec gap is
 * not a coordination hazard.
 */
const MIN_CONSUMERS_FOR_HAZARD = 2;

/** Maximum consumer refs enumerated verbatim before "and N more" kicks in. */
const VISIBLE_CONSUMER_REFS = 3;

type ActionInputSpecLevel = 'specified' | 'implicit-only' | 'none';

/**
 * Score an action definition's input contract on the paper's
 * specification-completeness axis:
 * - 'specified'     — at least one declared, non-implicit input (the L0/L1
 *                     end: the shared contract pins a concrete shape).
 * - 'implicit-only' — inputs are declared but every one is an implicit
 *                     allow-listed parameter (under-specified).
 * - 'none'          — no declared inputs at all, i.e. a bare signature (L3).
 */
function actionInputSpecLevel(
  actionDef: Record<string, unknown>
): ActionInputSpecLevel {
  const declared = listActionDefInputNames(actionDef);
  const nonImplicit = declared.filter(name => !IMPLICIT_WITH_PARAMS.has(name));
  if (nonImplicit.length > 0) return 'specified';
  if (declared.length > 0) return 'implicit-only';
  return 'none';
}

function describeSpecLevel(level: ActionInputSpecLevel): string {
  switch (level) {
    case 'none':
      return 'undeclared (bare signature)';
    case 'implicit-only':
      return 'only implicit parameters';
    default:
      return '';
  }
}

/**
 * Resolve the action-definition name a `reasoning.actions` entry binds to.
 *
 * Mirrors the binding-name resolution in `action-binding-rules.ts` so the two
 * rules agree on what counts as "binding action X": an `@actions.<name>`
 * member reference or a colinear `@actions.<name>` / `<name>` string.
 */
function resolveActionDefName(
  toolEntry: Record<string, unknown>
): string | undefined {
  const rawColinear =
    toolEntry.value ??
    toolEntry.__colinear ??
    toolEntry.colinear ??
    toolEntry.__value;
  const ref = decomposeAtMemberExpression(rawColinear);
  if (ref && ref.namespace === 'actions') {
    return ref.property;
  }
  const strValue = extractStringValue(rawColinear);
  if (strValue) {
    return strValue.startsWith('@actions.') ? strValue.substring(9) : strValue;
  }
  return undefined;
}

/** Action-definition names bound by a single agentic node's `reasoning.actions`. */
function boundActionDefNames(nodeEntry: Record<string, unknown>): string[] {
  const reasoning = nodeEntry.reasoning as Record<string, unknown> | undefined;
  if (!reasoning) return [];

  const actionsMap = reasoning.actions;
  if (!actionsMap || typeof actionsMap !== 'object') return [];

  const entries =
    actionsMap instanceof Map
      ? actionsMap.entries()
      : Symbol.iterator in actionsMap
        ? (actionsMap as Iterable<[string, unknown]>)
        : undefined;
  if (!entries) return [];

  const names: string[] = [];
  for (const [, toolEntry] of entries) {
    if (toolEntry == null || typeof toolEntry !== 'object') continue;
    const name = resolveActionDefName(toolEntry as Record<string, unknown>);
    if (name) names.push(name);
  }
  return names;
}

function summarizeConsumers(refs: string[]): string {
  const visible = refs.slice(0, VISIBLE_CONSUMER_REFS);
  const extra = refs.length - visible.length;
  const joined = visible.join(', ');
  return extra > 0 ? `${joined} and ${extra} more` : joined;
}

/**
 * Report the specification-gap coordination hazard: an action definition
 * with an under-specified input contract that is a coordination point (bound
 * by two or more distinct agentic nodes).
 *
 * Run as part of `AgentFabricSemanticPass.finalize` over the parsed root.
 */
export function checkActionSpecGapRules(root: Record<string, unknown>): void {
  if (!isNamedMap(root.actions)) return;

  const actionDefs = new Map<string, Record<string, unknown>>(
    [...root.actions].map(([k, v]) => [
      normalizeId(k),
      v as Record<string, unknown>,
    ])
  );

  // Reverse index: normalized action-def name -> distinct consumer node refs.
  const consumersByAction = new Map<string, string[]>();
  for (const nodeType of AGENTIC_NODE_TYPES) {
    const nodes = root[nodeType];
    if (!isNamedMap(nodes)) continue;

    for (const [nodeName, entry] of nodes) {
      if (entry == null || typeof entry !== 'object') continue;
      const ref = `${nodeType}.${nodeName}`;
      for (const name of boundActionDefNames(
        entry as Record<string, unknown>
      )) {
        const norm = normalizeId(name);
        if (!actionDefs.has(norm)) continue;
        const list = consumersByAction.get(norm);
        if (list) {
          if (!list.includes(ref)) list.push(ref);
        } else {
          consumersByAction.set(norm, [ref]);
        }
      }
    }
  }

  for (const [actionName, refs] of consumersByAction) {
    if (refs.length < MIN_CONSUMERS_FOR_HAZARD) continue;

    const actionDef = actionDefs.get(actionName);
    if (!actionDef) continue;

    const level = actionInputSpecLevel(actionDef);
    if (level === 'specified') continue;

    attachWarning(
      actionDef as AstLike,
      `\`actions.${actionName}\` is bound by ${refs.length} agents ` +
        `(${summarizeConsumers(refs)}) but its input contract is ` +
        `${describeSpecLevel(level)} — a specification gap. Independent ` +
        `consumers may bind incompatible inputs. Declare an \`inputs:\` map ` +
        `on this action to pin the shared contract.`,
      'action-spec-gap'
    );
  }
}
