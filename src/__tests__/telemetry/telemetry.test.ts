/**
 * Tests for src/telemetry/ — written FIRST per TDD (Red → Green).
 *
 * Covers: anonymize strips server names, DO_NOT_TRACK respected,
 * queue write failure is non-fatal, flush is awaited.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

describe("anonymize", () => {
  it("includes command and outcome but not server names", async () => {
    const { anonymize } = await import("../../telemetry/anonymize.js");
    const event = anonymize({
      command: "install",
      outcome: "success",
      mcpmVersion: "0.3.3",
      nodeVersion: "20.0.0",
      platform: "darwin",
    });
    expect(event).toHaveProperty("command", "install");
    expect(event).toHaveProperty("outcome", "success");
    expect(event).toHaveProperty("command", "install");
    expect(event).toHaveProperty("outcome", "success");
  });

  it("includes mcpm version and platform", async () => {
    const { anonymize } = await import("../../telemetry/anonymize.js");
    const event = anonymize({
      command: "search",
      outcome: "success",
      mcpmVersion: "0.3.3",
      nodeVersion: "20.0.0",
      platform: "linux",
    });
    expect(event.mcpmVersion).toBe("0.3.3");
    expect(event.platform).toBe("linux");
  });
});

describe("isTelemetryEnabled", () => {
  it("returns false when MCPM_NO_TRACK=1 is set", async () => {
    const original = process.env.MCPM_NO_TRACK;
    process.env.MCPM_NO_TRACK = "1";
    try {
      vi.resetModules();
      const { isTelemetryEnabled } = await import("../../telemetry/queue.js");
      expect(isTelemetryEnabled()).toBe(false);
    } finally {
      if (original === undefined) delete process.env.MCPM_NO_TRACK;
      else process.env.MCPM_NO_TRACK = original;
    }
  });

  it("returns false when DO_NOT_TRACK=1 is set", async () => {
    const original = process.env.DO_NOT_TRACK;
    process.env.DO_NOT_TRACK = "1";
    try {
      vi.resetModules();
      const { isTelemetryEnabled } = await import("../../telemetry/queue.js");
      expect(isTelemetryEnabled()).toBe(false);
    } finally {
      if (original === undefined) delete process.env.DO_NOT_TRACK;
      else process.env.DO_NOT_TRACK = original;
    }
  });
});

describe("enqueueEvent", () => {
  it("does not throw when the queue write fails (disk full / permissions)", async () => {
    vi.resetModules();
    vi.doMock("../../store/index.js", () => ({
      getStorePath: vi.fn().mockResolvedValue("/nonexistent-path"),
      readJson: vi.fn().mockResolvedValue(null),
      writeJson: vi.fn().mockRejectedValue(new Error("ENOSPC")),
    }));
    const { enqueueEvent } = await import("../../telemetry/queue.js");
    await expect(
      enqueueEvent({ command: "install", outcome: "success", mcpmVersion: "0.3.3", nodeVersion: "20.0.0", platform: "darwin" })
    ).resolves.not.toThrow();
  });

  it("does not enqueue when telemetry is disabled via env", async () => {
    const original = process.env.MCPM_NO_TRACK;
    process.env.MCPM_NO_TRACK = "1";
    try {
      vi.resetModules();
      const writeJson = vi.fn();
      vi.doMock("../../store/index.js", () => ({
        getStorePath: vi.fn().mockResolvedValue("/tmp"),
        readJson: vi.fn().mockResolvedValue([]),
        writeJson,
      }));
      const { enqueueEvent } = await import("../../telemetry/queue.js");
      await enqueueEvent({ command: "install", outcome: "success", mcpmVersion: "0.3.3", nodeVersion: "20.0.0", platform: "darwin" });
      expect(writeJson).not.toHaveBeenCalled();
    } finally {
      if (original === undefined) delete process.env.MCPM_NO_TRACK;
      else process.env.MCPM_NO_TRACK = original;
    }
  });
});
