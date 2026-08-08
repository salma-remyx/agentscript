/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Output type-conformance lint rules for agentic nodes.
 *
 * AgentFabric agentic nodes (orchestrator, subagent, generator) declare
 * `outputs` schemas that constrain what an LLM emits — the LLM is made to
 * "play by the type rules" declared on each property. This pass checks
 * that the *values* a property advertises are consistent with the `type`
 * it declares, so a downstream consumer never receives an LLM output that
 * contradicts the schema it was validated against:
 *   - `enum` members must be assignable to the declared `type`
 *     (e.g. `type: string` with `enum: [1, 2, 3]` is a contradiction).
 *   - `default` must be assignable to the declared `type`.
 *
 * Adapted from "Play by the Type Rules: Inferring Constraints for LLM
 * Functions in Declarative Programs" (arXiv:2509.20208), which infers the
 * type implied by an LLM function's constraints and flags where it
 * contradicts the type the surrounding program expects. The paper
 * propagates constraints through a BlendSQL query plan at runtime; this
 * pass performs the equivalent inference statically over the dialect's
 * `outputs` schema (AgentFabric has no SQL query plan, so that auxiliary
 * is substituted with output-schema analysis).
 *
 * Complements `output-structure-rules.ts`, which validates the *shape* of
 * each schema in isolation. This pass validates *value/type conformance*
 * and additionally descends into `array.items` (which the structure pass
 * does not), so item sub-schemas receive the same conformance check.
 */
import {
  BooleanLiteral,
  DictLiteral,
  isNamedMap,
  ListLiteral,
  NumberLiteral,
  StringLiteral,
  UnaryExpression,
} from '@agentscript/language';
import { attachError, extractStringValue, type AstLike } from './shared.js';

type ScalarType = 'string' | 'number' | 'integer' | 'boolean';

interface EnumInference {
  /** `true` when members carry more than one scalar type. */
  mixed: boolean;
  /** Single scalar type carried by every member; undefined when `mixed`. */
  type?: ScalarType;
}

/** Resolve an expression-valued schema field to its underlying AST node. */
function exprNode(field: unknown): unknown {
  if (field == null || typeof field !== 'object') return undefined;
  if (typeof (field as { __kind?: unknown }).__kind === 'string') return field;
  const inner = (field as { value?: unknown }).value;
  if (
    inner != null &&
    typeof inner === 'object' &&
    typeof (inner as { __kind?: unknown }).__kind === 'string'
  ) {
    return inner;
  }
  return undefined;
}

/** Infer the scalar type a literal expression node represents. */
function scalarTypeOf(node: unknown): ScalarType | undefined {
  if (node instanceof StringLiteral) return 'string';
  if (node instanceof BooleanLiteral) return 'boolean';
  if (node instanceof NumberLiteral) {
    return Number.isInteger(node.value) ? 'integer' : 'number';
  }
  // Numeric sign prefix (e.g. `-1`) parses as a UnaryExpression wrapping a
  // NumberLiteral; preserve the inner type so signed enum members infer.
  if (node instanceof UnaryExpression) {
    if (node.operator !== '-' && node.operator !== '+') return undefined;
    return scalarTypeOf(node.operand);
  }
  // NoneLiteral (null) and non-literal expressions are not statically
  // inferable; returning undefined makes callers skip (never false-flag).
  return undefined;
}

/**
 * Infer the common scalar type carried by a static `enum` list.
 * Returns undefined when not inferable (not a list, empty, or containing a
 * non-literal member) so the caller can skip soundly.
 */
function enumImpliedType(node: unknown): EnumInference | undefined {
  if (!(node instanceof ListLiteral)) return undefined;
  if (node.elements.length === 0) return undefined;
  const types = new Set<ScalarType>();
  for (const element of node.elements) {
    const inferred = scalarTypeOf(exprNode(element) ?? element);
    if (inferred === undefined) return undefined;
    types.add(inferred);
  }
  if (types.size !== 1) return { mixed: true };
  return { mixed: false, type: types.values().next().value };
}

/** True when an inferred type is assignable to the declared type. */
function assignable(inferred: string, declared: string): boolean {
  if (inferred === declared) return true;
  // Integer values are valid wherever a number is declared.
  if (inferred === 'integer' && declared === 'number') return true;
  return false;
}

function validateProperty(
  prop: Record<string, unknown>,
  node: AstLike,
  path: string
): void {
  const declared = extractStringValue(prop.type);
  // A missing/invalid `type` is already reported by output-structure-rules;
  // nothing to conform against here.
  if (!declared) return;

  const enumNode = exprNode(prop.enum);
  if (enumNode) {
    const implied = enumImpliedType(enumNode);
    if (implied) {
      if (implied.mixed) {
        attachError(
          node,
          `${path}: 'enum' mixes value types; all members must conform to declared type '${declared}'.`,
          'output-type-conformance-enum'
        );
      } else if (implied.type && !assignable(implied.type, declared)) {
        attachError(
          node,
          `${path}: 'enum' members are of type '${implied.type}' but property is declared as '${declared}'.`,
          'output-type-conformance-enum'
        );
      }
    }
  }

  const defaultNode = exprNode(prop.default);
  if (defaultNode instanceof ListLiteral) {
    if (!assignable('array', declared)) {
      attachError(
        node,
        `${path}: 'default' is a list but property is declared as '${declared}'.`,
        'output-type-conformance-default'
      );
    }
  } else if (defaultNode instanceof DictLiteral) {
    if (!assignable('object', declared)) {
      attachError(
        node,
        `${path}: 'default' is a mapping but property is declared as '${declared}'.`,
        'output-type-conformance-default'
      );
    }
  } else {
    const inferred = scalarTypeOf(defaultNode);
    if (inferred && !assignable(inferred, declared)) {
      attachError(
        node,
        `${path}: 'default' is of type '${inferred}' but property is declared as '${declared}'.`,
        'output-type-conformance-default'
      );
    }
  }

  if (declared === 'array') {
    const items = prop.items;
    if (items && typeof items === 'object') {
      validateProperty(items as Record<string, unknown>, node, `${path}.items`);
    }
  } else if (declared === 'object') {
    const properties = prop.properties;
    if (isNamedMap(properties)) {
      for (const [childName, childDef] of properties) {
        if (childDef && typeof childDef === 'object') {
          validateProperty(
            childDef as Record<string, unknown>,
            node,
            `${path}.properties.${childName}`
          );
        }
      }
    }
  }
}

export function checkOutputTypeConformanceRules(
  root: Record<string, unknown>
): void {
  const validateGroup = (
    group: unknown,
    outputSelector: (rec: Record<string, unknown>) => unknown,
    pathPrefix: string
  ): void => {
    if (!isNamedMap(group)) return;
    for (const [, entry] of group) {
      if (entry == null || typeof entry !== 'object') continue;
      const rec = entry as Record<string, unknown>;
      const outputs = outputSelector(rec);
      if (outputs == null || typeof outputs !== 'object') continue;
      const properties = (outputs as Record<string, unknown>).properties;
      if (!isNamedMap(properties)) continue;
      for (const [propName, propDef] of properties) {
        if (propDef && typeof propDef === 'object') {
          validateProperty(
            propDef as Record<string, unknown>,
            entry as AstLike,
            `${pathPrefix}.${propName}`
          );
        }
      }
    }
  };

  validateGroup(
    root.orchestrator,
    rec => (rec.reasoning as Record<string, unknown> | undefined)?.outputs,
    'reasoning.outputs'
  );
  validateGroup(
    root.subagent,
    rec => (rec.reasoning as Record<string, unknown> | undefined)?.outputs,
    'reasoning.outputs'
  );
  validateGroup(root.generator, rec => rec.outputs, 'outputs');
}
