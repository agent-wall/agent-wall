import { defineConfig } from "vitepress";

export default defineConfig({
  base: '/agent-wall/',
  title: "Agent Wall",
  description: "Security firewall for AI agents — intercept MCP tool calls, enforce policies, block attacks",

  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/logo.svg" }],
  ],

  themeConfig: {
    logo: "/logo.svg",

    nav: [
      { text: "Guide", link: "/guide/getting-started" },
      { text: "CLI Reference", link: "/cli/overview" },
      { text: "API", link: "/api/core" },
      {
        text: "v0.1.0",
        items: [
          { text: "Changelog", link: "/changelog" },
          { text: "GitHub", link: "https://github.com/agent-wall/agent-wall" },
        ],
      },
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Introduction",
          items: [
            { text: "What is Agent Wall?", link: "/guide/what-is-agent-wall" },
            { text: "Getting Started", link: "/guide/getting-started" },
            { text: "How It Works", link: "/guide/how-it-works" },
          ],
        },
        {
          text: "Configuration",
          items: [
            { text: "Policy File", link: "/guide/policy-file" },
            { text: "Rules", link: "/guide/rules" },
            { text: "Rate Limiting", link: "/guide/rate-limiting" },
            { text: "Default Policy", link: "/guide/default-policy" },
          ],
        },
        {
          text: "Integrations",
          items: [
            { text: "Claude Code", link: "/guide/claude-code" },
            { text: "Claude Desktop", link: "/guide/claude-desktop" },
            { text: "Cursor", link: "/guide/cursor" },
            { text: "VS Code / Copilot", link: "/guide/vscode" },
            { text: "Windsurf", link: "/guide/windsurf" },
            { text: "Any MCP Client", link: "/guide/any-mcp-client" },
          ],
        },
        {
          text: "Advanced",
          items: [
            { text: "Audit Logging", link: "/guide/audit-logging" },
            { text: "Response Scanning", link: "/guide/response-scanning" },
            { text: "Security Scanning", link: "/guide/scanning" },
            { text: "Real-Time Dashboard", link: "/guide/dashboard" },
          ],
        },
      ],
      "/cli/": [
        {
          text: "CLI Reference",
          items: [
            { text: "Overview", link: "/cli/overview" },
            { text: "wrap", link: "/cli/wrap" },
            { text: "init", link: "/cli/init" },
            { text: "test", link: "/cli/test" },
            { text: "audit", link: "/cli/audit" },
            { text: "scan", link: "/cli/scan" },
            { text: "validate", link: "/cli/validate" },
            { text: "doctor", link: "/cli/doctor" },
          ],
        },
      ],
      "/api/": [
        {
          text: "API Reference",
          items: [
            { text: "@agent-wall/core", link: "/api/core" },
            { text: "PolicyEngine", link: "/api/policy-engine" },
            { text: "StdioProxy", link: "/api/stdio-proxy" },
            { text: "ResponseScanner", link: "/api/response-scanner" },
            { text: "AuditLogger", link: "/api/audit-logger" },
            { text: "DashboardServer", link: "/api/dashboard-server" },
            { text: "Types", link: "/api/types" },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: "github", link: "https://github.com/agent-wall/agent-wall" },
      { icon: 'npm', link: 'https://npmjs.com/package/agent-wall' },
    ],

    footer: {
      message: "Released under the MIT License.",
      copyright: "Copyright © 2026 Agent Wall",
    },

    search: {
      provider: "local",
    },
  },
});
