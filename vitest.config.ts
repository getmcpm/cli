import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    coverage: {
      provider: "v8",
      thresholds: {
        lines: 80,
        branches: 75,
      },
      exclude: [
        "node_modules",
        "dist",
        "**/*.config.*",
        "**/*.d.ts",
        // Barrel re-export files have no executable statements
        "**/registry/index.ts",
        "**/config/index.ts",
        "**/config/adapters/index.ts",
        "**/scanner/index.ts",
        // Type-only files have no runtime code
        "**/registry/types.ts",
        // MCP server wiring (tool registration + transport setup) — logic tested via handlers.test.ts
        "**/server/index.ts",
        "**/server/tools.ts",
      ],
    },
  },
});
