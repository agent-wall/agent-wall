# @agent-wall/core

Core proxy engine and security modules for [Agent Wall](https://github.com/agent-wall/agent-wall) — a security firewall for AI agents.

[![npm](https://img.shields.io/npm/v/@agent-wall/core)](https://www.npmjs.com/package/@agent-wall/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/agent-wall/agent-wall/blob/main/LICENSE)

> **Most users should install [`@agent-wall/cli`](https://www.npmjs.com/package/@agent-wall/cli) (the CLI) instead.** This package is for programmatic usage — embedding Agent Wall into your own tools.

## Install

```bash
npm install @agent-wall/core
```

## What's Inside

| Module | Description |
|--------|-------------|
| `StdioProxy` | Two-way MCP protocol interception proxy |
| `PolicyEngine` | First-match-wins rule evaluator (glob, rate limiting, strict mode) |
| `ResponseScanner` | Secret/PII detection with ReDoS protection |
| `InjectionDetector` | 30+ prompt injection patterns |
| `EgressControl` | URL/SSRF protection (RFC1918, metadata, IP obfuscation) |
| `KillSwitch` | Emergency deny-all (file, signal, programmatic) |
| `ChainDetector` | Multi-step attack pattern detection |
| `AuditLogger` | HMAC-SHA256 signed JSON lines with rotation |
| `PolicyLoader` | YAML config with Zod validation and hot-reload |
| `DashboardServer` | WebSocket + HTTP server for real-time dashboard |

## Usage

```typescript
import {
  StdioProxy,
  PolicyEngine,
  ResponseScanner,
  InjectionDetector,
  EgressControl,
  KillSwitch,
  ChainDetector,
  AuditLogger,
  loadPolicy,
} from "@agent-wall/core";

// Load policy from YAML
const { config } = loadPolicy("./agent-wall.yaml");

// Create security modules
const policyEngine = new PolicyEngine(config);
const scanner = new ResponseScanner(config.responseScanning);
const injectionDetector = new InjectionDetector();
const egressControl = new EgressControl();
const killSwitch = new KillSwitch();
const chainDetector = new ChainDetector();

// Create proxy
const proxy = new StdioProxy({
  command: "npx",
  args: ["@modelcontextprotocol/server-filesystem", "/home/user"],
  policyEngine,
  responseScanner: scanner,
  injectionDetector,
  egressControl,
  killSwitch,
  chainDetector,
});

await proxy.start();
```

## Documentation

Full docs: [agent-wall.github.io/agent-wall](https://agent-wall.github.io/agent-wall/)

API reference: [agent-wall.github.io/agent-wall/api/core](https://agent-wall.github.io/agent-wall/api/core)

## License

[MIT](https://github.com/agent-wall/agent-wall/blob/main/LICENSE)
