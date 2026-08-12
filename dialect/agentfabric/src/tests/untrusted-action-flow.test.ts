/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseAndLintSource } from './test-utils.js';

// Exercises the wiring of `checkUntrustedActionFlow` into the AgentFabric
// semantic lint pass (parseAndLintSource -> agentfabricDialect -> defaultRules
// -> AgentFabricSemanticPass.finalize). The `untrusted-action-input` warning
// is only produced when that chain-level pass runs, so these assertions prove
// the integration end-to-end, not just the rule in isolation.

describe('untrusted-action-input rule (chain-level taint)', () => {
  function taintDiagnostics(result: ReturnType<typeof parseAndLintSource>) {
    return result.diagnostics.filter(d => d.code === 'untrusted-action-input');
  }

  it('flags trigger payload relayed by an LLM carrier into an action', () => {
    const source = `
config:
  agent_name: "taint-chain"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  send:
    target: "a2a://send"
    kind: "a2a:send_message"

trigger ingest:
  kind: "a2a"
  target: "brokers://taint-chain/a2a"
  on_message: ->
    transition to @generator.summarize

generator summarize:
  llm: @llm.g
  prompt: -> summarize the message
  on_exit: ->
    transition to @executor.send

executor send:
  do: ->
    run @actions.send
      with message = @generator.summarize.output
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    const taint = taintDiagnostics(result);
    expect(taint).toHaveLength(1);
    const message = String(taint[0]!.message);
    // The chain must name the trigger source, the carrier, and the sink.
    expect(message).toContain('@generator.summarize');
    expect(message).toContain('@trigger.ingest');
    expect(message).toContain('@executor.send');
  });

  it('flags a direct @request.* action input', () => {
    const source = `
config:
  agent_name: "taint-direct"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  send:
    target: "a2a://send"
    kind: "a2a:send_message"

trigger ingest:
  kind: "a2a"
  target: "brokers://taint-direct/a2a"
  on_message: ->
    transition to @executor.send

executor send:
  do: ->
    run @actions.send
      with message = @request.body
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    const taint = taintDiagnostics(result);
    expect(taint).toHaveLength(1);
    expect(String(taint[0]!.message)).toContain('@request.*');
  });

  it('does not flag an action input with no untrusted source', () => {
    const source = `
config:
  agent_name: "taint-benign"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  send:
    target: "a2a://send"
    kind: "a2a:send_message"

trigger ingest:
  kind: "a2a"
  target: "brokers://taint-benign/a2a"
  on_message: ->
    transition to @executor.send

executor send:
  do: ->
    run @actions.send
      with message = "hardcoded summary"
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(taintDiagnostics(result)).toHaveLength(0);
  });

  it('does not flag a carrier that is unreachable from any trigger', () => {
    // The trigger drives echo.done directly; the generator -> executor
    // subgraph is orphaned (no trigger reaches the carrier), so even though
    // the executor reads a carrier output, no untrusted source can flow in.
    const source = `
config:
  agent_name: "taint-orphan"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  send:
    target: "a2a://send"
    kind: "a2a:send_message"

trigger ingest:
  kind: "a2a"
  target: "brokers://taint-orphan/a2a"
  on_message: ->
    transition to @echo.done

generator summarize:
  llm: @llm.g
  prompt: -> summarize
  on_exit: ->
    transition to @executor.send

executor send:
  do: ->
    run @actions.send
      with message = @generator.summarize.output
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(taintDiagnostics(result)).toHaveLength(0);
  });
});
