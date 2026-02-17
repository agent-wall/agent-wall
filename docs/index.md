---
layout: home

hero:
  name: Agent Wall
  text: Security Firewall for AI Agents
  tagline: Intercept MCP tool calls, enforce policies, block attacks. Zero-config protection for any MCP server.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/agent-wall/agent-wall

features:
  - icon: 🛡️
    title: Two-Way Firewall
    details: Inspects tool calls going IN and responses coming OUT. Blocks secrets, private keys, and PII before they reach the agent.
  - icon: ⚡
    title: Zero Config
    details: Sensible built-in defaults block credential access, exfiltration, and dangerous shell commands out of the box.
  - icon: 🔍
    title: Any MCP Server
    details: Works with every MCP server — official, third-party, or custom. Protocol-level proxy means zero code changes.
  - icon: 📊
    title: Audit Logging
    details: Structured JSON logging of every tool call and response scan with sensitive value redaction. Full audit trail.
  - icon: 🔬
    title: Response Scanning
    details: Detects leaked API keys, tokens, private keys, database URLs, and PII in server responses. Block or redact automatically.
  - icon: 🚦
    title: Rate Limiting
    details: Global and per-rule rate limits prevent runaway agents from hammering your infrastructure.
  - icon: 📡
    title: Real-Time Dashboard
    details: Browser-based security dashboard with live event feed, attack panel, kill switch, and rule hit tracking. One flag to enable.
  - icon: 🧬
    title: Defense in Depth
    details: Five-step inbound pipeline — kill switch, injection detection, SSRF/egress control, policy rules, chain detection. Nothing gets through.
---
