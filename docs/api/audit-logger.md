# AuditLogger

Structured JSON audit logger with sensitive value redaction.

## Constructor

```typescript
const logger = new AuditLogger(options?: AuditLoggerOptions);
```

### `AuditLoggerOptions`

```typescript
interface AuditLoggerOptions {
  stdout?: boolean;       // Log to stderr (default: false)
  filePath?: string;      // Log to file (JSON lines)
  redact?: boolean;       // Redact sensitive values (default: true)
}
```

## Methods

### `log(entry)`

Log an audit entry.

```typescript
logger.log(entry: AuditEntry);
```

### `AuditEntry`

```typescript
interface AuditEntry {
  timestamp: string;
  tool: string;
  arguments: Record<string, unknown>;
  action: "allowed" | "denied" | "prompted";
  rule?: string;
  message?: string;
}
```

## Example

```typescript
import { AuditLogger } from "@agent-wall/core";

const logger = new AuditLogger({
  stdout: true,
  filePath: "./audit.log",
  redact: true,
});

logger.log({
  timestamp: new Date().toISOString(),
  tool: "read_file",
  arguments: { path: "/home/.ssh/id_rsa" },
  action: "denied",
  rule: "block-ssh-keys",
  message: "SSH key access blocked",
});
```

## Redaction

When `redact: true`, the logger automatically masks values that match sensitive patterns:

- Values containing `key`, `secret`, `token`, `password`, `credential`
- Long alphanumeric strings that look like API keys
- Environment variable values

Redacted values appear as `[REDACTED]` in the log output.
