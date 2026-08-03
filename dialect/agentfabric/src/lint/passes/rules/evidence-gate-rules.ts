/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { isNamedMap } from '@agentscript/language';
import { extractGraph } from '../../../graph/extractor.js';
import type { GraphEdge } from '../../../graph/extractor.js';
import { AgentFabricSchemaInfo, A2A_TERMINAL_STATES } from '../../../schema.js';
import { attachWarning, extractStringValue, type AstLike } from './shared.js';

const COMPLETED_STATE = 'TASK_STATE_COMPLETED';

/**
 * Adapted from "Proof-or-Stop: Don't Trust the Agent, Trust the Evidence"
 * (arxiv:2607.14890). The paper permits lifecycle transitions only when fresh,
 * mechanically verifiable evidence satisfies the relevant gate, and treats an
 * agent's "completed / DONE" output as a claim rather than lifecycle state.
 *
 * In AgentFabric the agent's terminal lifecycle claim is the
 * `a2a:status_update_event` echo carrying `TASK_STATE_COMPLETED`, and the
 * repo-native evidence gate is a router route's `when` predicate — surfaced as
 * `edge.predicate` by the graph extractor. This check flags the false-DONE
 * topology in which a node evidence-gates its non-completion outcomes
 * (failed / canceled / rejected) but reaches "completed" only through unguarded
 * edges: the one lifecycle claim not bound to verifiable evidence is the
 * success claim.
 *
 * Mode 2 (adapted port): the core gate-admissibility check is kept at full
 * fidelity (a terminal transition is either gated by a `when` predicate or it
 * is not); the paper's signed receipt / tracked-source-state binding is
 * substituted by the static `when` predicate as the mechanically-verifiable
 * gate, and the runtime control-policy ablation is intentionally out of scope
 * (this is a static lint pass, not a lifecycle engine).
 */
export function checkEvidenceGateRules(root: Record<string, unknown>): void {
  const { edges } = extractGraph(root, AgentFabricSchemaInfo);
  if (edges.length === 0) return;

  const terminalEchoStates = collectTerminalEchoStates(root);
  if (terminalEchoStates.size === 0) return;

  // Trigger entry points declare completion directly as the agent's response;
  // their unconditional transitions are not false-DONE claims, so exclude the
  // trigger sources (whose outgoing edges are tagged `via: 'trigger'`).
  const triggerSources = new Set<string>();
  for (const edge of edges) {
    if (edge.via === 'trigger') triggerSources.add(edge.from);
  }

  // Bucket each non-trigger source's outgoing edges to terminal echoes by
  // (gated?) x (completion?). A gated edge carries a non-empty `predicate`.
  const bySource = new Map<string, SourceBuckets>();
  for (const edge of edges) {
    if (triggerSources.has(edge.from)) continue;
    const state = terminalEchoStates.get(edge.to);
    if (state === undefined) continue; // target is not a terminal echo
    const buckets = bySource.get(edge.from) ?? emptyBuckets();
    bySource.set(edge.from, buckets);
    const gated =
      edge.predicate !== undefined && edge.predicate.trim().length > 0;
    if (state === COMPLETED_STATE) {
      if (gated) buckets.hasGatedCompletion = true;
      else buckets.ungatedCompletionEdges.push(edge);
    } else if (gated) {
      buckets.hasGatedNonCompletion = true;
    }
  }

  for (const [sourceId, buckets] of bySource) {
    // Fire only on the asymmetry: failure/cancellation is evidenced, but
    // completion is reachable solely through unguarded edges.
    if (!buckets.hasGatedNonCompletion) continue;
    if (buckets.hasGatedCompletion) continue;
    if (buckets.ungatedCompletionEdges.length === 0) continue;

    const astNode = findAstNode(root, sourceId);
    if (!astNode) continue;
    const shortName = sourceId.split('.').pop() ?? sourceId;
    attachWarning(
      astNode,
      `Node '${shortName}' reaches the terminal "completed" state only through ` +
        `unguarded transitions, while its failure/cancellation outcomes are ` +
        `gated by a "when" condition. Gate the completion transition too ` +
        `(add a "when" route to the completed echo) so the lifecycle cannot ` +
        `claim "done" without verifiable evidence.`,
      'terminal-completion-requires-evidence-gate'
    );
  }
}

interface SourceBuckets {
  hasGatedCompletion: boolean;
  hasGatedNonCompletion: boolean;
  ungatedCompletionEdges: GraphEdge[];
}

function emptyBuckets(): SourceBuckets {
  return {
    hasGatedCompletion: false,
    hasGatedNonCompletion: false,
    ungatedCompletionEdges: [],
  };
}

/** Map terminal-echo id -> A2A state for echoes emitting a terminal status. */
function collectTerminalEchoStates(
  root: Record<string, unknown>
): Map<string, string> {
  const states = new Map<string, string>();
  const echoEntries = root.echo;
  if (!isNamedMap(echoEntries)) return states;

  for (const [name, entry] of echoEntries) {
    if (entry == null || typeof entry !== 'object') continue;
    const echoEntry = entry as Record<string, unknown>;
    const kind = extractStringValue(echoEntry.kind);
    if (kind !== 'a2a:status_update_event') continue;
    const state = extractStringValue(echoEntry.state);
    if (state !== undefined && A2A_TERMINAL_STATES.has(state)) {
      states.set(`echo.${name}`, state);
    }
  }
  return states;
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
