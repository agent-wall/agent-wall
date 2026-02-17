# ResponseScanner API

The `ResponseScanner` class scans MCP server responses for secrets, PII, oversized content, and custom patterns before they reach the AI agent.

```typescript
import { ResponseScanner, createDefaultScanner } from "@agent-wall/core";
```

## `ResponseScanner`

### Constructor

```typescript
new ResponseScanner(config?: ResponseScannerConfig)
```

Creates a scanner with the given config. All fields are optional with sensible defaults.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config.enabled` | `boolean` | `true` | Enable/disable scanning |
| `config.maxResponseSize` | `number` | `0` | Max response bytes (0 = no limit) |
| `config.oversizeAction` | `"block" \| "redact"` | `"redact"` | Action for oversized responses |
| `config.detectSecrets` | `boolean` | `true` | Enable built-in secret detection (14 patterns) |
| `config.detectPII` | `boolean` | `false` | Enable built-in PII detection (5 patterns) |
| `config.patterns` | `ResponsePattern[]` | `[]` | Custom patterns to match |

### Methods

#### `scan(text: string): ScanResult`

Scan a plaintext string for sensitive content. Returns findings and an overall action.

```typescript
const result = scanner.scan("my-password=hunter2");
// { clean: false, action: "redact", findings: [...], originalSize: 19 }
```

#### `scanMcpResponse(result: unknown): ScanResult`

Scan the content of an MCP `tools/call` response. Extracts text from the standard MCP shape (`{ content: [{ type: "text", text: "..." }] }`) and runs all patterns.

```typescript
const mcpResult = {
  content: [{ type: "text", text: "DB_URL=postgres://user:pass@host/db" }],
};
const result = scanner.scanMcpResponse(mcpResult);
// { clean: false, action: "redact", findings: [{ pattern: "database-url", ... }] }
```

#### `getConfig(): ResponseScannerConfig`

Returns a copy of the current scanner configuration.

#### `getPatternCount(): number`

Returns the total number of compiled patterns (built-in + custom).

```typescript
const scanner = new ResponseScanner({ detectSecrets: true, detectPII: true });
scanner.getPatternCount(); // 19 (14 secret + 5 PII)
```

#### `updateConfig(config: ResponseScannerConfig): void`

Replace the scanner configuration and recompile all patterns. Useful for hot-reloading after a policy file change.

```typescript
scanner.updateConfig({ detectSecrets: true, detectPII: true });
```

## `createDefaultScanner()`

```typescript
function createDefaultScanner(): ResponseScanner
```

Factory function that creates a scanner with production defaults:

| Setting | Value |
|---------|-------|
| `enabled` | `true` |
| `maxResponseSize` | `5,242,880` (5 MB) |
| `oversizeAction` | `"redact"` |
| `detectSecrets` | `true` |
| `detectPII` | `false` |

## Types

### `ResponseAction`

```typescript
type ResponseAction = "pass" | "redact" | "block";
```

### `ResponsePattern`

```typescript
interface ResponsePattern {
  name: string;          // Unique identifier
  pattern: string;       // Regex pattern
  flags?: string;        // Regex flags (default: "gi")
  action: ResponseAction;
  message?: string;      // Human-readable message
  category?: string;     // Grouping key for audit logs
}
```

### `ResponseScannerConfig`

```typescript
interface ResponseScannerConfig {
  enabled?: boolean;
  maxResponseSize?: number;
  oversizeAction?: "block" | "redact";
  detectSecrets?: boolean;
  detectPII?: boolean;
  patterns?: ResponsePattern[];
}
```

### `ScanResult`

```typescript
interface ScanResult {
  clean: boolean;             // True if no findings
  action: ResponseAction;     // Overall action (highest severity)
  findings: ScanFinding[];    // All pattern matches
  redactedText?: string;      // Present when action is "redact"
  originalSize: number;       // Response size in bytes
}
```

### `ScanFinding`

```typescript
interface ScanFinding {
  pattern: string;      // Pattern name that matched
  category: string;     // Category (secrets, pii, custom, size)
  action: ResponseAction;
  message: string;      // Human-readable description
  matchCount: number;   // Number of matches found
  preview?: string;     // Redacted preview of matched content
}
```

## Built-in Patterns Reference

### Secret Patterns (14)

| Name | Category | Default Action |
|------|----------|---------------|
| `aws-access-key` | secrets | redact |
| `aws-secret-key` | secrets | redact |
| `github-token` | secrets | redact |
| `openai-api-key` | secrets | redact |
| `generic-api-key` | secrets | redact |
| `bearer-token` | secrets | redact |
| `jwt-token` | secrets | redact |
| `private-key` | secrets | **block** |
| `certificate` | secrets | redact |
| `database-url` | secrets | redact |
| `password-assignment` | secrets | redact |
| `large-base64-blob` | exfiltration | pass |
| `hex-dump` | exfiltration | pass |

::: info
`large-base64-blob` and `hex-dump` are informational (action: `pass`). They appear in findings but don't trigger redaction or blocking.
:::

### PII Patterns (5)

| Name | Category | Default Action |
|------|----------|---------------|
| `email-address` | pii | redact |
| `phone-number` | pii | redact |
| `ssn` | pii | **block** |
| `credit-card` | pii | **block** |
| `ip-address` | pii | pass |
