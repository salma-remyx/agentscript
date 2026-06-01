---
'@agentscript/agentfabric-dialect': patch
'@agentscript/agentforce-dialect': patch
'@agentscript/agentscript-dialect': patch
'@agentscript/agentforce': patch
'@agentscript/compiler': patch
'@agentscript/language': patch
'@agentscript/lsp-browser': patch
'@agentscript/lsp-server': patch
'@agentscript/lsp': patch
'@agentscript/monaco': patch
'@agentscript/parser-javascript': patch
'@agentscript/parser-tree-sitter': patch
'@agentscript/parser': patch
'@agentscript/types': patch
---

Fix publish: rewrite `@agentscript/*` → `@sf-agentscript/*` in `dist/` and `src/`, not just `package.json`.

Previously, `scripts/publish.mjs` only rewrote `package.json` files at publish time. The compiled JavaScript in `dist/` and the shipped TypeScript in `src/` still contained `import ... from '@agentscript/*'`, so consumers installing `@sf-agentscript/*` packages from npm hit `ERR_MODULE_NOT_FOUND: Cannot find package '@agentscript/...'` at runtime.

`scripts/publish.mjs` now also rewrites `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.cts`, `.mts`, and `.map` files inside each package's `dist/` and `src/` directories, so published artifacts resolve cleanly under the `@sf-agentscript` scope.
