/**
 * mcpm-guard relay (v0.5.0 spike) — minimal stdio MITM using SDK framing helpers.
 *
 * Closes Open Question 1 in the v0.5.0 design doc by measuring whether the
 * SDK's ReadBuffer + serializeMessage primitives (line-delimited JSON-RPC,
 * not Content-Length framing — MCP doesn't use Content-Length) can hit the
 * < 5ms p99 small-message budget after parse+reserialize on the hot path.
 */

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

export interface RelayOptions {
  readonly command: string;
  readonly args: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly parentIn: Readable;
  readonly parentOut: Writable;
  readonly onParentMessage?: (msg: JSONRPCMessage) => void;
  readonly onChildMessage?: (msg: JSONRPCMessage) => void;
}

export interface RelayHandle {
  readonly child: ChildProcess;
  readonly exit: Promise<number>;
}

export function startRelay(opts: RelayOptions): RelayHandle {
  const child = spawn(opts.command, [...opts.args], {
    env: opts.env ?? process.env,
    stdio: ["pipe", "pipe", "inherit"],
  });

  const parentBuffer = new ReadBuffer();
  opts.parentIn.on("data", (chunk: Buffer) => {
    parentBuffer.append(chunk);
    let msg = parentBuffer.readMessage();
    while (msg !== null) {
      opts.onParentMessage?.(msg);
      child.stdin?.write(serializeMessage(msg));
      msg = parentBuffer.readMessage();
    }
  });
  opts.parentIn.on("end", () => {
    child.stdin?.end();
  });

  const childBuffer = new ReadBuffer();
  child.stdout?.on("data", (chunk: Buffer) => {
    childBuffer.append(chunk);
    let msg = childBuffer.readMessage();
    while (msg !== null) {
      opts.onChildMessage?.(msg);
      opts.parentOut.write(serializeMessage(msg));
      msg = childBuffer.readMessage();
    }
  });

  const exit = new Promise<number>((resolve) => {
    child.on("exit", (code) => resolve(code ?? 0));
  });

  return { child, exit };
}

/**
 * In-process relay (no subprocess) — for measuring the parse+reserialize cost
 * of the SDK helpers without the noise of stdio + process spawn overhead.
 * Wires a fake "child" via two PassThrough pairs: parent writes go through
 * the parse+reserialize path before reaching the synthetic responder.
 */
export interface InProcessRelayOptions {
  readonly parentIn: Readable;
  readonly parentOut: Writable;
  readonly respond: (msg: JSONRPCMessage) => JSONRPCMessage | null;
  readonly onParentMessage?: (msg: JSONRPCMessage) => void;
  readonly onChildMessage?: (msg: JSONRPCMessage) => void;
}

export function startInProcessRelay(opts: InProcessRelayOptions): void {
  const buffer = new ReadBuffer();
  opts.parentIn.on("data", (chunk: Buffer) => {
    buffer.append(chunk);
    let msg = buffer.readMessage();
    while (msg !== null) {
      opts.onParentMessage?.(msg);
      const response = opts.respond(msg);
      if (response !== null) {
        opts.onChildMessage?.(response);
        opts.parentOut.write(serializeMessage(response));
      }
      msg = buffer.readMessage();
    }
  });
}
