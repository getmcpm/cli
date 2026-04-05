import { describe, it, expect } from "vitest";
import { parseEnvString, parseEnvFile } from "../../stack/env.js";

describe("parseEnvString", () => {
  it("parses KEY=VALUE pairs", () => {
    const content = "API_KEY=abc123\nDB_HOST=localhost\nPORT=3000";
    const result = parseEnvString(content);
    expect(result.vars).toEqual({
      API_KEY: "abc123",
      DB_HOST: "localhost",
      PORT: "3000",
    });
    expect(result.warnings).toHaveLength(0);
  });

  it("skips comments and empty lines", () => {
    const content = [
      "# This is a comment",
      "",
      "KEY=value",
      "  # Another comment",
      "",
      "OTHER=stuff",
    ].join("\n");
    const result = parseEnvString(content);
    expect(result.vars).toEqual({ KEY: "value", OTHER: "stuff" });
    expect(result.warnings).toHaveLength(0);
  });

  it("handles malformed lines with warnings", () => {
    const content = "GOOD=value\nno_equals_sign\nALSO_GOOD=yes";
    const result = parseEnvString(content);
    expect(result.vars).toEqual({ GOOD: "value", ALSO_GOOD: "yes" });
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("Line 2");
    expect(result.warnings[0]).toContain("no = sign");
  });

  it("strips surrounding quotes from values", () => {
    const content = [
      'DOUBLE="hello world"',
      "SINGLE='hello world'",
      "NONE=hello world",
    ].join("\n");
    const result = parseEnvString(content);
    expect(result.vars.DOUBLE).toBe("hello world");
    expect(result.vars.SINGLE).toBe("hello world");
    expect(result.vars.NONE).toBe("hello world");
  });

  it("strips inline comments only when preceded by space (dotenv standard)", () => {
    const content = [
      "KEY=value # this is a comment",
      'QUOTED="value # not a comment"',
      "URL=http://example.com/path#fragment",
    ].join("\n");
    const result = parseEnvString(content);
    expect(result.vars.KEY).toBe("value");
    expect(result.vars.QUOTED).toBe("value # not a comment");
    expect(result.vars.URL).toBe("http://example.com/path#fragment");
  });

  it("handles empty values", () => {
    const content = "EMPTY=\nALSO_EMPTY=  ";
    const result = parseEnvString(content);
    expect(result.vars.EMPTY).toBe("");
    expect(result.vars.ALSO_EMPTY).toBe("");
  });

  it("warns on empty key", () => {
    const content = "=value";
    const result = parseEnvString(content);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("empty key");
  });

  it("rejects __proto__ and other unsafe keys with warning", () => {
    const content = "__proto__=malicious\nGOOD_KEY=safe";
    const result = parseEnvString(content);
    expect(result.vars.GOOD_KEY).toBe("safe");
    expect(result.vars).not.toHaveProperty("__proto__");
    expect(Object.keys(result.vars)).toEqual(["GOOD_KEY"]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("invalid key");
  });

  it("rejects keys with special characters", () => {
    const content = "my-key=value\nmy.key=value\nGOOD_KEY=safe";
    const result = parseEnvString(content);
    expect(Object.keys(result.vars)).toEqual(["GOOD_KEY"]);
    expect(result.warnings).toHaveLength(2);
  });
});

describe("parseEnvFile", () => {
  it("returns empty result when file does not exist", async () => {
    const result = await parseEnvFile("/nonexistent/.env");
    expect(result.vars).toEqual({});
    expect(result.warnings).toHaveLength(0);
  });
});
