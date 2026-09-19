/**
 * No hand-written SGR colour escape may reach an output path.
 *
 * `mcpm install`'s success line was built as a raw escape template, so it
 * bypassed chalk's TTY detection entirely and emitted colour into pipes, log
 * files and CI transcripts while every other line around it came out plain.
 * Eight more sites in install.ts and guard/cli.ts had the same shape, found by
 * grepping when the first one was reported.
 *
 * This is a SOURCE invariant rather than an output assertion on one command,
 * because the defect is a habit, not a location: the next hand-written escape
 * would be in whichever file someone is editing next, and an output test only
 * covers the lines it happens to exercise. chalk already answers "is this a
 * TTY?" correctly and honours NO_COLOR / FORCE_COLOR; a literal answers nothing.
 *
 * Stripping, detecting and describing escapes is a different job, so the three
 * modules whose subject matter IS the escape sequence are exempt by path.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const SRC = path.resolve(process.cwd(), "src");

/** Modules that legitimately contain escape sequences: they strip or classify them. */
const EXEMPT = new Set([
  path.join("guard", "sanitize.ts"), // the stripper itself
  path.join("guard", "patterns.ts"), // classifies a codepoint as ANSI-ESC
  path.join("errors", "publish-errors.ts"), // strips ANSI out of registry error text
]);

function tsFiles(dir: string, acc: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name === "__tests__") continue;
      tsFiles(full, acc);
    } else if (name.endsWith(".ts")) {
      acc.push(full);
    }
  }
  return acc;
}

/**
 * An SGR colour/reset introducer written by hand, in either escape spelling.
 * Assembled from parts so this file holds no escape literal of its own, and so
 * the invariant below does not flag its own detector.
 */
const BS = String.fromCharCode(92);
const RAW_SGR = new RegExp(BS + BS + "(?:u001[bB]|x1[bB])" + BS + "[[0-9;]*m");

/** The two spellings, built the same way, for the detector's own self-check. */
const SAMPLE_U = BS + "u001b[32m";
const SAMPLE_X = BS + "x1b[33m";

describe("source invariant: colour goes through chalk, never a literal escape", () => {
  it("has no hand-written SGR escape outside the escape-handling modules", () => {
    const offenders: string[] = [];
    for (const file of tsFiles(SRC)) {
      const rel = path.relative(SRC, file);
      if (EXEMPT.has(rel)) continue;
      readFileSync(file, "utf-8")
        .split("\n")
        .forEach((line, i) => {
          // Comments may describe an escape (e.g. an example of a hostile name).
          if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
          if (RAW_SGR.test(line)) offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
        });
    }
    expect(offenders).toEqual([]);
  });

  it("the detector matches both spellings, so an empty result means something", () => {
    // Without this the test above passes just as happily against a broken regex.
    expect(RAW_SGR.test(`output("${SAMPLE_U}hi")`)).toBe(true);
    expect(RAW_SGR.test(`output("${SAMPLE_X}hi")`)).toBe(true);
    expect(RAW_SGR.test(`output(chalk.green("hi"))`)).toBe(false);
  });
});
