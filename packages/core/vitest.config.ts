import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    // Live integration tests spawn real MCP servers and share filesystem
    // state (kill switch file at cwd). Must run sequentially to prevent
    // cross-contamination between test files.
    fileParallelism: false,
  },
});
