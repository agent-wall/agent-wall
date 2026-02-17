# PolicyEngine

The core policy evaluation engine. Takes a policy config and evaluates tool calls against it.

## Constructor

```typescript
const engine = new PolicyEngine(config: PolicyConfig);
```

### `PolicyConfig`

```typescript
interface PolicyConfig {
  version: number;
  defaultAction: RuleAction;  // "allow" | "deny" | "prompt"
  globalRateLimit?: RateLimitConfig;
  responseScanning?: ResponseScannerPolicyConfig;
  rules: PolicyRule[];
}
```

## Methods

### `evaluate(toolName, args)`

Evaluate a tool call against the policy rules.

```typescript
const verdict = engine.evaluate(toolName: string, args: Record<string, unknown>);
```

Returns a `PolicyVerdict`:

```typescript
interface PolicyVerdict {
  action: RuleAction;       // "allow" | "deny" | "prompt"
  rule?: string;            // Name of the matching rule
  message?: string;         // Custom deny message
  rateLimited?: boolean;    // Whether the call was rate-limited
}
```

### Example

```typescript
import { PolicyEngine, loadPolicy } from "@agent-wall/core";

const { config } = loadPolicy();
const engine = new PolicyEngine(config);

// Test a tool call
const verdict = engine.evaluate("read_file", { path: "/home/.ssh/id_rsa" });

if (verdict.action === "deny") {
  console.log(`Blocked by rule: ${verdict.rule}`);
  console.log(`Reason: ${verdict.message}`);
}
```

## Types

### `PolicyRule`

```typescript
interface PolicyRule {
  name?: string;
  tool: string;           // Glob pattern or pipe-separated alternatives
  match?: RuleMatch;
  action: RuleAction;
  message?: string;
  rateLimit?: RateLimitConfig;
}
```

### `RuleMatch`

```typescript
interface RuleMatch {
  arguments?: Record<string, string>;  // Glob patterns for argument values
}
```

### `RateLimitConfig`

```typescript
interface RateLimitConfig {
  maxCalls: number;
  windowSeconds: number;
}
```
