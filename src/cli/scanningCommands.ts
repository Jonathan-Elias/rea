import { z } from "incur";
import { resolve } from "node:path";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { scanYara, scanCapa } from "../scanning/ScanningBridge.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

export const registerScanningCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.scanYara, {
    description:
      "Scan a binary with YARA rules for malware indicators, crypto patterns, and evasion techniques",
    args: z.object({
      path: z.string().describe("Local binary path to scan; never executed"),
    }),
    options: z.object({
      rules: z
        .string()
        .optional()
        .describe(
          "Path to custom YARA rules file; uses built-in offensive security rules when absent",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(() =>
        logCliCommand(logger, CLI_COMMANDS.scanYara, async () => {
          const result = await scanYara({
            targetPath: resolve(args.path),
            rulesPath: options.rules ? resolve(options.rules) : undefined,
          });
          if (!result.ok) {
            return {
              error: "YARA scan failed",
              code: result.reason,
              message: result.message,
            };
          }
          return {
            evidence_id: `ev_yara_${Date.now().toString(36)}`,
            provider: { id: "yara", name: "YARA", version: "4.x" },
            predicate_type: "rea.analysis",
            operation: "scan_yara",
            ...result.value,
          };
        }),
      ),
  });

  cli.command(CLI_COMMANDS.scanCapa, {
    description:
      "Detect binary capabilities, ATT&CK techniques, and malware behaviors with capa",
    args: z.object({
      path: z
        .string()
        .describe("Local PE or ELF binary to analyze; never executed"),
    }),
    options: z.object({
      verbose: z
        .boolean()
        .default(false)
        .describe("Include all capabilities instead of the top 50"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(() =>
        logCliCommand(logger, CLI_COMMANDS.scanCapa, async () => {
          const result = await scanCapa({
            targetPath: resolve(args.path),
            format: options.verbose ? "verbose" : "default",
          });
          if (!result.ok) {
            return {
              error: "capa analysis failed",
              code: result.reason,
              message: result.message,
            };
          }
          return {
            evidence_id: `ev_capa_${Date.now().toString(36)}`,
            predicate_type: "rea.analysis",
            operation: "scan_capa",
            ...result.value,
          };
        }),
      ),
  });
};
