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
      ],
    },
  },
});
