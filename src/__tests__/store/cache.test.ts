/**
 * Tests for src/store/cache.ts
 *
 * TDD — RED phase.
 * Mocks store/index.js. Uses vi.useFakeTimers for TTL tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../../store/index.js", () => ({
  getStorePath: vi.fn(async () => "/home/alice/.mcpm"),
  readJson: vi.fn(),
  writeJson: vi.fn(),
}));

import { readJson, writeJson } from "../../store/index.js";
import {
  getCachedResponse,
  setCachedResponse,
  DEFAULT_CACHE_TTL_MS,
} from "../../store/cache.js";

const mockReadJson = readJson as ReturnType<typeof vi.fn>;
const mockWriteJson = writeJson as ReturnType<typeof vi.fn>;

describe("DEFAULT_CACHE_TTL_MS", () => {
  it("is 1 hour (3600000ms)", () => {
    expect(DEFAULT_CACHE_TTL_MS).toBe(3_600_000);
  });
});

describe("setCachedResponse", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteJson.mockResolvedValue(undefined);
  });

  it("writes an object with data + timestamp", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-28T10:00:00.000Z"));

    await setCachedResponse("search:filesystem", { results: ["a", "b"] });

    expect(mockWriteJson).toHaveBeenCalledOnce();
    const [filename, entry] = mockWriteJson.mock.calls[0] as [
      string,
      { data: unknown; timestamp: number },
    ];
    expect(filename).toMatch(/cache\//);
    expect(entry.data).toEqual({ results: ["a", "b"] });
    expect(entry.timestamp).toBe(new Date("2026-03-28T10:00:00.000Z").getTime());

    vi.useRealTimers();
  });

  it("uses a filename derived from the cache key", async () => {
    await setCachedResponse("my:cache:key", {});
    const [filename] = mockWriteJson.mock.calls[0] as [string, unknown];
    expect(filename).toMatch(/my/);
  });

  it("produces a safe filename when key contains path traversal characters", async () => {
    await setCachedResponse("../evil", {});
    const [filename] = mockWriteJson.mock.calls[0] as [string, unknown];
    // Must not contain ".." segments
    expect(filename).not.toContain("..");
    // Must be under cache/ prefix
    expect(filename).toMatch(/^cache\//);
  });

  it("does not mutate data passed in", async () => {
    const data = { nested: { value: 42 } };
    const copy = structuredClone(data);
    await setCachedResponse("key", data);
    expect(data).toEqual(copy);
  });
});

describe("getCachedResponse", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteJson.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns cached data when within TTL", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-03-28T10:00:00.000Z").getTime();
    vi.setSystemTime(now);

    const cachedEntry = {
      data: { items: [1, 2, 3] },
      timestamp: now - 1000, // 1 second ago
    };
    mockReadJson.mockResolvedValue(cachedEntry);

    const result = await getCachedResponse<{ items: number[] }>("my-key");
    expect(result).toEqual({ items: [1, 2, 3] });
  });

  it("returns null when cache entry is expired (past TTL)", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-03-28T10:00:00.000Z").getTime();
    vi.setSystemTime(now);

    const cachedEntry = {
      data: { stale: true },
      timestamp: now - DEFAULT_CACHE_TTL_MS - 1, // 1ms past TTL
    };
    mockReadJson.mockResolvedValue(cachedEntry);

    const result = await getCachedResponse("my-key");
    expect(result).toBeNull();
  });

  it("returns null when no cached entry exists", async () => {
    mockReadJson.mockResolvedValue(null);
    const result = await getCachedResponse("missing-key");
    expect(result).toBeNull();
  });

  it("respects custom TTL parameter", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-03-28T10:00:00.000Z").getTime();
    vi.setSystemTime(now);

    const customTtl = 5000; // 5 seconds
    const cachedEntry = {
      data: { fresh: true },
      timestamp: now - 4000, // 4 seconds ago — within 5s TTL
    };
    mockReadJson.mockResolvedValue(cachedEntry);

    const result = await getCachedResponse("key", customTtl);
    expect(result).toEqual({ fresh: true });
  });

  it("expires with custom TTL when past it", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-03-28T10:00:00.000Z").getTime();
    vi.setSystemTime(now);

    const customTtl = 5000;
    const cachedEntry = {
      data: { fresh: false },
      timestamp: now - 6000, // 6 seconds ago — past 5s TTL
    };
    mockReadJson.mockResolvedValue(cachedEntry);

    const result = await getCachedResponse("key", customTtl);
    expect(result).toBeNull();
  });

  it("returns null when cache entry has no timestamp", async () => {
    mockReadJson.mockResolvedValue({ data: { broken: true } });
    const result = await getCachedResponse("broken-key");
    expect(result).toBeNull();
  });

  it("returns null when file read throws EACCES", async () => {
    const err = Object.assign(new Error("EACCES"), { code: "EACCES" });
    mockReadJson.mockRejectedValue(err);
    const result = await getCachedResponse("key");
    expect(result).toBeNull();
  });
});
