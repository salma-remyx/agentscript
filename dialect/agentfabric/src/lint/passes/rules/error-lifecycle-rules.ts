/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { isNamedMap } from '@agentscript/language';
import { extractGraph } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo, A2A_TERMINAL_STATES } from '../../../schema.js';
import {
  attachError,
  attachWarning,
  extractStringValue,
  type AstLike,
} from './shared.js';

/**
 * Failure terminal states — an echo emitting one of these surfaces a runtime
 * error to the caller. A failure signal is "born" at such an echo.
 */
const FAILURE_STATES = new Set(['TASK_STATE_FAILED', 'TASK_STATE_REJECTED']);

/**
 * Non-failure terminal states — end the task without reporting an error.
 * Reaching one of these AFTER a failure state overwrites (masks) the error.
 */
const NON_FAILURE_TERMINAL_STATES = new Set([
  'TASK_STATE_COMPLETED',
  'TASK_STATE_CANCELED',
]);

/**
 * Node namespaces that perform fallible runtime work (tool / LLM calls). When
 * one of these errors, the failure must be able to reach a failure-status echo
 * to stay observable and attributable downstream.
 */
const ERROR_PRONE_NAMESPACES = new Set([
  'executor',
  'subagent',
  'orchestrator',
  'generator',
]);

interface TerminalEchoes {
  failureEchoIds: Set<string>;
  nonFailureEchoIds: Set<string>;
}

/**
 * Error-lifecycle lint rules — flag agent graphs that mask or swallow failures.
 *
 * Adapted from TrajDebug's error-lifecycle tracing (critical-error attribution
 * via each error's resolution status and terminal impact), projected onto
 * AgentFabric's static transition graph. TrajDebug traces a runtime error's
 * lifecycle to decide whether it survives to the final outcome; statically we
 * can only observe how failure-status *signals* can flow, so that runtime
 * notion becomes two graph-shape checks:
 *
 *  1. Masked failure — a failure-status echo (TASK_STATE_FAILED /
 *     TASK_STATE_REJECTED) that can still forward-reach a non-failure terminal
 *     echo (TASK_STATE_COMPLETED / TASK_STATE_CANCELED). The failure's
 *     lifecycle is cut short by a later success, so the caller's final status
 *     hides the error — the static shape TrajDebug calls a "failed-status
 *     overwritten" critical failure.
 *
 *  2. Unobservable error path — a fallible node (executor / subagent /
 *     orchestrator / generator) that cannot forward-reach any failure-status
 *     echo. When such a node errors at runtime, no distinguishable failure
 *     terminal is reachable, so the error is un-attributable. Only fires when
 *     the graph already handles failures elsewhere, so a deliberately
 *     success-only graph is left alone.
 *
 * This is distinct from checkTerminalStatusRules, which checks that every leaf
 * has *some* terminal-status ancestor (a reachability/completeness property);
 * here we check the *resolution* of failure signals (survivability and
 * observability), a separate concern.
 */
export function checkErrorLifecycleRules(root: Record<string, unknown>): void {
  const { nodes, edges } = extractGraph(root, AgentFabricSchemaInfo);
  if (nodes.length === 0) return;

  const { failureEchoIds, nonFailureEchoIds } = collectTerminalEchoes(root);
  if (failureEchoIds.size === 0 && nonFailureEchoIds.size === 0) return;

  const forwardAdj = buildForwardAdjacency(edges);

  checkMaskedFailures(root, failureEchoIds, nonFailureEchoIds, forwardAdj);
  checkUnobservableErrorPaths(root, nodes, failureEchoIds, forwardAdj);
}

/**
 * Partition the graph's status-update echoes by whether their state reports a
 * failure. Non-terminal / non-status echoes are ignored.
 */
function collectTerminalEchoes(root: Record<string, unknown>): TerminalEchoes {
  const failureEchoIds = new Set<string>();
  const nonFailureEchoIds = new Set<string>();
  const echoEntries = root.echo;
  if (!isNamedMap(echoEntries)) {
    return { failureEchoIds, nonFailureEchoIds };
  }

  for (const [name, entry] of echoEntries) {
    if (entry == null || typeof entry !== 'object') continue;
    const echoEntry = entry as Record<string, unknown>;
    if (extractStringValue(echoEntry.kind) !== 'a2a:status_update_event') {
      continue;
    }
    const state = extractStringValue(echoEntry.state);
    if (state === undefined || !A2A_TERMINAL_STATES.has(state)) continue;

    const id = `echo.${name}`;
    if (FAILURE_STATES.has(state)) {
      failureEchoIds.add(id);
    } else if (NON_FAILURE_TERMINAL_STATES.has(state)) {
      nonFailureEchoIds.add(id);
    }
  }
  return { failureEchoIds, nonFailureEchoIds };
}

function buildForwardAdjacency(
  edges: ReadonlyArray<{ from: string; to: string }>
): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const edge of edges) {
    const list = adj.get(edge.from);
    if (list) {
      list.push(edge.to);
    } else {
      adj.set(edge.from, [edge.to]);
    }
  }
  return adj;
}

/**
 * BFS forward from `startId`, returning true if any node in `targets` is
 * reachable. `startId` itself is not tested against `targets` — callers only
 * start from nodes that cannot be their own target (a failure echo vs. a
 * non-failure set, or a fallible node vs. an echo set).
 */
function canReachAny(
  startId: string,
  targets: ReadonlySet<string>,
  forwardAdj: ReadonlyMap<string, string[]>
): boolean {
  const visited = new Set<string>([startId]);
  const queue: string[] = [startId];

  while (queue.length > 0) {
    const current = queue.shift() as string;
    for (const next of forwardAdj.get(current) ?? []) {
      if (targets.has(next)) return true;
      if (!visited.has(next)) {
        visited.add(next);
        queue.push(next);
      }
    }
  }
  return false;
}

/**
 * Rule 1 — flag a failure terminal whose status can be overwritten by a
 * downstream non-failure terminal before the task ends.
 */
function checkMaskedFailures(
  root: Record<string, unknown>,
  failureEchoIds: ReadonlySet<string>,
  nonFailureEchoIds: ReadonlySet<string>,
  forwardAdj: ReadonlyMap<string, string[]>
): void {
  if (failureEchoIds.size === 0 || nonFailureEchoIds.size === 0) return;

  for (const failedId of failureEchoIds) {
    if (!canReachAny(failedId, nonFailureEchoIds, forwardAdj)) continue;

    const astNode = findAstNode(root, failedId);
    if (!astNode) continue;

    const shortName = failedId.split('.').pop() ?? failedId;
    attachError(
      astNode,
      `Failure status at '${shortName}' may be masked: a downstream ` +
        `TASK_STATE_COMPLETED/TASK_STATE_CANCELED terminal is reachable from ` +
        `it, so the task can end without surfacing this error. Do not let a ` +
        `non-failure terminal overwrite a failure terminal on the same path.`,
      'error-lifecycle-masked-failure'
    );
  }
}

/**
 * Rule 2 — flag a fallible node whose runtime errors cannot reach any failure
 * terminal, making them unobservable. Skipped entirely when the graph has no
 * failure handling (a success-only graph is a separate, intentional shape).
 */
function checkUnobservableErrorPaths(
  root: Record<string, unknown>,
  nodes: ReadonlyArray<{ id: string; namespace: string }>,
  failureEchoIds: ReadonlySet<string>,
  forwardAdj: ReadonlyMap<string, string[]>
): void {
  if (failureEchoIds.size === 0) return;

  for (const node of nodes) {
    if (!ERROR_PRONE_NAMESPACES.has(node.namespace)) continue;
    if (canReachAny(node.id, failureEchoIds, forwardAdj)) continue;

    const astNode = findAstNode(root, node.id);
    if (!astNode) continue;

    const shortName = node.id.split('.').pop() ?? node.id;
    attachWarning(
      astNode,
      `Fallible node '${shortName}' has no path to a failure terminal ` +
        `(TASK_STATE_FAILED/TASK_STATE_REJECTED). A runtime error here would ` +
        `not surface as a distinguishable failure and would be hard to ` +
        `attribute. Route an error branch to a failure-status echo.`,
      'error-lifecycle-unobservable-error'
    );
  }
}

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
