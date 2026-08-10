/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import type { Diagnostic } from '@agentscript/language';
import { parseAndLintSource } from './test-utils.js';

describe('untrusted-data-to-control-flow rule', () => {
  function infoFlowDiagnostics(diagnostics: Diagnostic[]): Diagnostic[] {
    return diagnostics.filter(d => d.code === 'untrusted-data-to-control-flow');
  }

  it('flags a control-flow node reached directly from an external-action node', () => {
    // orchestrator.A ingests unvetted external data (calls an mcp tool) and
    // transitions straight into subagent.B — an LLM-reasoning node. With no
    // deterministic node in between, this is a prompt-injection surface.
    const source = `
config:
  agent_name: "info-flow-flagged"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  fetch:
    target: "mcp://knowledge"
    kind: "mcp:tool"
    tool_name: "fetch"

trigger t:
  kind: "a2a"
  target: "brokers://info-flow-flagged/a2a"
  on_message: ->
    transition to @orchestrator.A

orchestrator A:
  llm: @llm.g
  reasoning:
    instructions: ->
      | fetch and forward
    actions:
      kb: @actions.fetch
  on_exit: ->
    transition to @subagent.B

subagent B:
  llm: @llm.g
  reasoning:
    instructions: ->
      | reason over data
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    const found = infoFlowDiagnostics(result.diagnostics);
    expect(found).toHaveLength(1);
    expect(found[0].source).toBe('agentfabric-lint');
    expect(found[0].message).toContain('@orchestrator.A');
    expect(found[0].message).toContain('@subagent.B');
  });

  it('does not flag when a deterministic executor sits between them (sanitizer)', () => {
    // Same external ingestion in orchestrator.A, but it now routes through a
    // deterministic executor before reaching the control-flow node. The
    // executor breaks the taint chain (APPA's confinement-boundary analog),
    // so no control-flow node receives unvetted data directly.
    const source = `
config:
  agent_name: "info-flow-sanitized"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  fetch:
    target: "mcp://knowledge"
    kind: "mcp:tool"
    tool_name: "fetch"

trigger t:
  kind: "a2a"
  target: "brokers://info-flow-sanitized/a2a"
  on_message: ->
    transition to @orchestrator.A

orchestrator A:
  llm: @llm.g
  reasoning:
    instructions: ->
      | fetch and forward
    actions:
      kb: @actions.fetch
  on_exit: ->
    transition to @executor.E

executor E:
  do: ->
    set @variables.checked = True
  on_exit: ->
    transition to @subagent.B

subagent B:
  llm: @llm.g
  reasoning:
    instructions: ->
      | reason over bounded data
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(infoFlowDiagnostics(result.diagnostics)).toHaveLength(0);
  });

  it('does not flag when the external-action node transitions to a non-control-flow node', () => {
    // orchestrator.A forwards unvetted data straight to an echo (terminal,
    // non-reasoning) — no control-flow node is put at risk, so no flag.
    const source = `
config:
  agent_name: "info-flow-to-echo"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  fetch:
    target: "mcp://knowledge"
    kind: "mcp:tool"
    tool_name: "fetch"

trigger t:
  kind: "a2a"
  target: "brokers://info-flow-to-echo/a2a"
  on_message: ->
    transition to @orchestrator.A

orchestrator A:
  llm: @llm.g
  reasoning:
    instructions: ->
      | fetch and emit
    actions:
      kb: @actions.fetch
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(infoFlowDiagnostics(result.diagnostics)).toHaveLength(0);
  });
});
