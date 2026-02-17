# Contributing to Agent Wall

Thank you for considering contributing to Agent Wall! Every contribution helps make AI agent security better for everyone.

## Philosophy

Agent Wall is built on 3 principles:

1. **Defense in depth** — Multiple security layers (kill switch, injection detection, egress control, policy engine, chain detection, response scanning) ensure nothing gets through
2. **Zero config, full control** — Sensible defaults out of the box, YAML policies for full customization
3. **Protocol-level, not SDK-level** — Works with any MCP client/server by intercepting JSON-RPC, no code changes required

## Project Structure

```
agent-wall/
├── packages/
│   ├── core/          # @agent-wall/core — Proxy engine, policy, security modules
│   ├── cli/           # agent-wall — CLI commands (wrap, init, test, audit, scan, validate, doctor)
│   └── dashboard/     # @agent-wall/dashboard — React SPA for real-time monitoring
├── docs/              # VitePress documentation
└── turbo.json         # Turborepo build config
```

## Getting Started

### Prerequisites

- Node.js >= 18
- pnpm >= 9

### Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/agent-wall.git
cd agent-wall

# 2. Install dependencies
pnpm install

# 3. Build all packages
pnpm build

# 4. Run tests
pnpm test
```

### Development Workflow

```bash
# Watch mode (rebuilds on change)
pnpm dev

# Run tests for a specific package
pnpm -F @agent-wall/core test
pnpm -F agent-wall test

# Format code
pnpm format
```

## Contributing Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b type/description
   ```

   Branch prefixes:
   | Prefix | Purpose |
   |--------|---------|
   | `feat/` | New features |
   | `fix/` | Bug fixes |
   | `docs/` | Documentation |
   | `refactor/` | Code restructuring |
   | `test/` | Tests |
   | `chore/` | Maintenance |

2. **Make changes** — keep PRs focused and small

3. **Test thoroughly**:
   ```bash
   pnpm test        # All tests
   pnpm build       # Ensure build passes
   ```

4. **Commit** with [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat: add custom injection pattern support"
   git commit -m "fix: kill switch file watcher race condition"
   git commit -m "docs: update response scanning configuration"
   ```

5. **Open a PR** against `main`

## Where to Contribute

### Good First Issues

- Improve error messages in policy validation
- Add more MCP client detection paths to `doctor` and `scan`
- Add examples for different MCP server configurations
- Improve CLI output formatting

### Security Module Development

Creating a new security module is a great way to contribute:

```typescript
// packages/core/src/my-detector.ts
import type { ToolCallParams } from "./types.js";

export interface MyDetectorConfig {
  enabled?: boolean;
  // ... your config
}

export class MyDetector {
  constructor(config?: MyDetectorConfig) {
    // ...
  }

  check(tool: string, args: Record<string, unknown>): {
    blocked: boolean;
    reason?: string;
  } {
    // Your detection logic
    return { blocked: false };
  }
}
```

Then wire it into the proxy pipeline in `proxy.ts`.

### Policy Rule Patterns

Contributing new default rules to `policy-loader.ts` helps protect more users out of the box. Good candidates:
- New exfiltration vectors
- Framework-specific dangerous operations
- Cloud provider credential patterns

## Code Quality

- All code must be TypeScript with strict mode
- Use meaningful names — avoid abbreviations
- Functions should do one thing
- Handle errors explicitly — no silent failures
- Write tests for new features and bug fixes
- Keep security modules consistent in API design
- Use `process.stderr.write` for output (stdout is the MCP protocol pipe)

## Testing

```bash
# Run all tests
pnpm test

# Core tests (security modules, policy engine, proxy)
pnpm -F @agent-wall/core test

# CLI tests (commands)
pnpm -F agent-wall test
```

## Documentation

Docs live in `/docs` and use [VitePress](https://vitepress.dev/).

```bash
# Run docs locally
pnpm docs:dev
```

When adding features, update:
1. The relevant guide in `docs/guide/`
2. API reference in `docs/api/`
3. CLI reference in `docs/cli/` (if applicable)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
