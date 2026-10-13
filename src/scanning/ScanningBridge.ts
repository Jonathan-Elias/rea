/**
 * Subprocess bridge for YARA and capa scanning tools.
 *
 * Follows the same request/reply JSON file protocol as existing REA bridges
 * (pwntools, pwndbg). Each scan spawns a Python subprocess, passes input via
 * a temporary JSON file, and reads the structured reply.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const BRIDGE_ROOT = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "bridge",
);

export interface ScanRequest {
  readonly targetPath: string;
  readonly rulesPath?: string;
  readonly format?: "default" | "verbose";
}

export interface ScanResult {
  readonly ok: boolean;
  readonly value?: Record<string, unknown>;
  readonly reason?: string;
  readonly message?: string;
}

async function runBridge(
  bridgePath: string,
  requestData: Record<string, unknown>,
  timeoutMs: number = 120_000,
): Promise<ScanResult> {
  const workDir = await mkdtemp(join(tmpdir(), "rea-scan-"));
  const requestPath = join(workDir, "request.json");
  const replyPath = join(workDir, "reply.json");

  try {
    await writeFile(
      requestPath,
      JSON.stringify({ ...requestData, reply_path: replyPath }),
      "utf-8",
    );

    await new Promise<void>((resolve, reject) => {
      const child = execFile(
        "python3",
        ["-I", bridgePath, requestPath],
        { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 },
        (error) => {
          if (error) reject(error);
          else resolve();
        },
      );
      child.unref?.();
    });

    const replyRaw = await readFile(replyPath, "utf-8");
    return JSON.parse(replyRaw) as ScanResult;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, reason: "bridge-process", message };
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

export async function scanYara(request: ScanRequest): Promise<ScanResult> {
  return runBridge(join(BRIDGE_ROOT, "yara", "scan.py"), {
    target_path: request.targetPath,
    rules_path: request.rulesPath ?? null,
  });
}

export async function scanCapa(request: ScanRequest): Promise<ScanResult> {
  return runBridge(
    join(BRIDGE_ROOT, "capa", "scan.py"),
    {
      target_path: request.targetPath,
      format: request.format ?? "default",
    },
    300_000,
  );
}
