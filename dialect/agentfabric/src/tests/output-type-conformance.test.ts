/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseAndLintSource } from './test-utils.js';

const conformanceCodes = (diagnostics: { code?: unknown }[]) =>
  diagnostics.filter(
    d =>
      typeof d.code === 'string' && d.code.startsWith('output-type-conformance')
  );

describe('output-type-conformance rules', () => {
  it('flags output-type-conformance-enum when enum members contradict the declared type', () => {
    const source = `
config:
  agent_name: "enum-type-clash"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://enum-type-clash/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  llm: @llm.g
  reasoning:
    instructions: -> do work
    outputs:
      properties:
        status:
          type: "string"
          enum: [1, 2, 3]
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.some(d => d.code === 'output-type-conformance-enum')
    ).toBe(true);
    expect(
      result.diagnostics.some(
        d =>
          typeof d.message === 'string' &&
          d.message.includes("declared as 'string'")
      )
    ).toBe(true);
  });

  it('flags output-type-conformance-enum when enum members mix types', () => {
    const source = `
config:
  agent_name: "enum-mixed"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://enum-mixed/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  llm: @llm.g
  reasoning:
    instructions: -> do work
    outputs:
      properties:
        flag:
          type: "string"
          enum: ["open", 1]
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.some(d => d.code === 'output-type-conformance-enum')
    ).toBe(true);
  });

  it('flags output-type-conformance-default when default contradicts the declared type', () => {
    const source = `
config:
  agent_name: "default-clash"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://default-clash/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  llm: @llm.g
  reasoning:
    instructions: -> do work
    outputs:
      properties:
        count:
          type: "integer"
          default: "many"
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.some(d => d.code === 'output-type-conformance-default')
    ).toBe(true);
  });

  it('reports enum conformance inside array items (recursion)', () => {
    const source = `
config:
  agent_name: "items-clash"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://items-clash/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  llm: @llm.g
  reasoning:
    instructions: -> do work
    outputs:
      properties:
        tags:
          type: "array"
          items:
            type: "string"
            enum: [7, 8]
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.some(d => d.code === 'output-type-conformance-enum')
    ).toBe(true);
    expect(
      result.diagnostics.some(
        d =>
          d.code === 'output-type-conformance-enum' &&
          typeof d.message === 'string' &&
          d.message.includes('.items')
      )
    ).toBe(true);
  });

  it('reports no conformance diagnostics for a conforming schema', () => {
    const source = `
config:
  agent_name: "conforming"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://conforming/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  llm: @llm.g
  reasoning:
    instructions: -> do work
    outputs:
      properties:
        status:
          type: "string"
          enum: ["open", "closed"]
        retries:
          type: "integer"
          default: 0
        ratio:
          type: "number"
          default: 5
        tags:
          type: "array"
          items:
            type: "string"
            enum: ["a", "b"]
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(conformanceCodes(result.diagnostics)).toEqual([]);
  });

  it('flags enum conformance on a generator outputs schema', () => {
    const source = `
config:
  agent_name: "generator-clash"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://generator-clash/a2a"
  on_message: -> transition to @generator.summary

generator summary:
  llm: @llm.g
  prompt: -> summarize
  outputs:
    properties:
      sentiment:
        type: "string"
        enum: [1, -1]
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.some(d => d.code === 'output-type-conformance-enum')
    ).toBe(true);
  });
});
