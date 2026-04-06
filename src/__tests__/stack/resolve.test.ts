import { describe, it, expect } from "vitest";
import { resolveVersion, resolveWithSingleVersion } from "../../stack/resolve.js";

describe("resolveVersion", () => {
  const available = ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "2.0.0"];

  it("resolves exact version match", () => {
    const result = resolveVersion("test-server", "1.2.0", available);
    expect(result.resolved).toBe("1.2.0");
  });

  it("resolves caret range to highest matching minor/patch", () => {
    const result = resolveVersion("test-server", "^1.0.0", available);
    expect(result.resolved).toBe("1.3.0");
  });

  it("resolves tilde range to highest matching patch", () => {
    const versions = ["1.2.0", "1.2.1", "1.2.5", "1.3.0"];
    const result = resolveVersion("test-server", "~1.2.0", versions);
    expect(result.resolved).toBe("1.2.5");
  });

  it("throws when no version satisfies the range", () => {
    expect(() => resolveVersion("test-server", "^3.0.0", available)).toThrow(
      'No version satisfies "^3.0.0" for "test-server"'
    );
  });

  it("throws for exact version not in available list", () => {
    expect(() => resolveVersion("test-server", "1.5.0", available)).toThrow(
      'Version "1.5.0" not found for "test-server"'
    );
  });

  it("resolves 'latest' alias to highest available version", () => {
    const result = resolveVersion("test-server", "latest", available);
    expect(result.resolved).toBe("2.0.0");
  });

  it("throws when 'latest' is requested but no versions available", () => {
    expect(() => resolveVersion("test-server", "latest", [])).toThrow(
      "No versions available"
    );
  });

  it("filters out non-semver version strings", () => {
    const mixed = ["1.0.0", "latest", "1.2.0", "beta", "2.0.0"];
    const result = resolveVersion("test-server", "^1.0.0", mixed);
    expect(result.resolved).toBe("1.2.0");
  });

  it("includes available versions in error message", () => {
    expect.assertions(2);
    try {
      resolveVersion("test-server", "^5.0.0", available);
    } catch (e) {
      expect((e as Error).message).toContain("2.0.0");
      expect((e as Error).message).toContain("1.3.0");
    }
  });
});

describe("resolveWithSingleVersion", () => {
  it("matches exact version", () => {
    const result = resolveWithSingleVersion("test-server", "1.0.0", "1.0.0");
    expect(result.resolved).toBe("1.0.0");
  });

  it("matches caret range against single version", () => {
    const result = resolveWithSingleVersion("test-server", "^1.0.0", "1.5.0");
    expect(result.resolved).toBe("1.5.0");
  });

  it("accepts 'latest' alias with single version", () => {
    const result = resolveWithSingleVersion("test-server", "latest", "1.0.0");
    expect(result.resolved).toBe("1.0.0");
  });

  it("throws when single version does not satisfy range", () => {
    expect(() =>
      resolveWithSingleVersion("test-server", "^2.0.0", "1.5.0")
    ).toThrow("does not satisfy");
  });

  it("throws when exact version does not match", () => {
    expect(() =>
      resolveWithSingleVersion("test-server", "2.0.0", "1.5.0")
    ).toThrow("not found");
  });
});
