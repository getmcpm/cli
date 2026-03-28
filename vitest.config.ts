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
        // Type-only files have no runtime code
        "**/registry/types.ts",
      ],
    },
  },
});
