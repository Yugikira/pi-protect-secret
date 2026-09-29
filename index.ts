import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { resolveConfig } from "./config.js";
import { evaluateWithJev } from "./evaluator.js";
import {
	isAllowedExistenceCheck,
	isObviousSecretDump,
	isSensitiveFilePath,
	isSuspiciousCommand,
} from "./heuristics.js";

const STATUS_KEY = "protect-secret";

export type JevEvaluatorFn = typeof evaluateWithJev;

export interface ProtectSecretOptions {
	evaluator?: JevEvaluatorFn;
}

export default function (pi: ExtensionAPI, options?: ProtectSecretOptions) {
	let disabled = false;
	const evaluatorFn = options?.evaluator || evaluateWithJev;

	const stats = {
		totalToolCalls: 0,
		whitelistedExistenceChecks: 0,
		benignPassThroughs: 0,
		hardBlockedReads: 0,
		hardBlockedCommands: 0,
		jevEvaluated: 0,
		jevBlocked: 0,
		jevPassed: 0,
		userBypassed: 0,
	};

	// Register CLI flags
	pi.registerFlag("protect-secret-disabled", {
		description: "Start the session with secret credential protection disabled.",
		type: "boolean",
		default: false,
	});

	pi.registerFlag("protect-secret-threshold", {
		description: "Override probability threshold (0.0 - 1.0) for Jev secret risk evaluation (default: 0.75).",
		type: "string",
	});

	// Helper to get threshold from flag
	function getThresholdFromFlag(): number | undefined {
		const raw = pi.getFlag("protect-secret-threshold") as string | undefined;
		if (raw !== undefined && raw !== null && raw !== "") {
			const parsed = parseFloat(raw);
			if (!isNaN(parsed) && parsed >= 0 && parsed <= 1) {
				return parsed;
			}
		}
		return undefined;
	}

	function updateStatusBadge(ctx: any) {
		if (!ctx?.ui) return;
		if (disabled) {
			const { theme } = ctx.ui;
			const badge = theme?.bg
				? theme.bg("toolErrorBg", theme.bold(theme.fg("error", " ⚠ SECRET-GUARD OFF ")))
				: " [SECRET-GUARD OFF] ";
			ctx.ui.setStatus(STATUS_KEY, badge);
		} else {
			ctx.ui.setStatus(STATUS_KEY, undefined);
		}
	}

	pi.on("session_start", async (event, ctx) => {
		if (pi.getFlag("protect-secret-disabled") === true) {
			disabled = true;
		}
		updateStatusBadge(ctx);
	});

	// Register /protect-secret slash command
	pi.registerCommand("protect-secret", {
		description: "View status, stats, or toggle secret protection (usage: /protect-secret [toggle|status])",
		handler: async (args, ctx) => {
			const action = args?.trim().toLowerCase();

			if (action === "toggle" || action === "on" || action === "off") {
				if (action === "on") disabled = false;
				else if (action === "off") disabled = true;
				else disabled = !disabled;

				updateStatusBadge(ctx);
				ctx.ui.notify(
					disabled
						? "Secret protection is now DISABLED for this session."
						: "Secret protection is now ACTIVE.",
					disabled ? "warning" : "info",
				);
				return;
			}

			// Display status
			const config = resolveConfig({
				thresholdOverride: getThresholdFromFlag(),
			});

			const keyStatus = config.apiKey ? "Configured" : "MISSING (Set in settings.json or env)";
			const info = [
				`🛡️ **pi-protect-secret status**:`,
				`• State: ${disabled ? "DISABLED" : "ACTIVE"}`,
				`• Provider: ${config.provider}`,
				`• Model: ${config.model}`,
				`• Risk Threshold: ${config.threshold}`,
				`• API Key: ${keyStatus}`,
				`• Stats:`,
				`  - Total tool calls checked: ${stats.totalToolCalls}`,
				`  - Whitelisted existence checks: ${stats.whitelistedExistenceChecks}`,
				`  - Benign commands bypassed (0ms): ${stats.benignPassThroughs}`,
				`  - Hard-blocked file reads: ${stats.hardBlockedReads}`,
				`  - Hard-blocked commands: ${stats.hardBlockedCommands}`,
				`  - Jev evaluations: ${stats.jevEvaluated} (Blocked: ${stats.jevBlocked}, Passed: ${stats.jevPassed})`,
				`  - User manual approvals: ${stats.userBypassed}`,
			].join("\n");

			if (ctx.hasUI) {
				ctx.ui.notify(info, "info");
			}
		},
	});

	// Main tool interception hook
	pi.on("tool_call", async (event, ctx) => {
		if (disabled) return undefined;

		const config = resolveConfig({
			thresholdOverride: getThresholdFromFlag(),
		});

		stats.totalToolCalls++;

		// Case 1: "read" tool
		if (event.toolName === "read") {
			const filePath = (event.input as { path?: string })?.path;
			if (filePath && isSensitiveFilePath(filePath)) {
				stats.hardBlockedReads++;
				if (ctx.hasUI) {
					ctx.ui.notify(`Blocked read to sensitive file: ${filePath}`, "warning");
				}
				return {
					block: true,
					reason: config.blockMessage,
				};
			}
			return undefined;
		}

		// Case 2: "bash" tool
		if (event.toolName === "bash") {
			const command = (event.input as { command?: string })?.command;
			if (!command || typeof command !== "string") {
				return undefined;
			}

			// 1. Whitelist check: Harmless environment variable existence check (anchored)
			if (isAllowedExistenceCheck(command)) {
				stats.whitelistedExistenceChecks++;
				return undefined;
			}

			// 2. Regex check: Is this command or referenced script suspicious at all?
			if (!isSuspiciousCommand(command, ctx.cwd)) {
				stats.benignPassThroughs++;
				return undefined;
			}

			// 3. Fast-path hard block: Obvious direct credential dump
			if (isObviousSecretDump(command)) {
				stats.hardBlockedCommands++;
				if (ctx.hasUI) {
					ctx.ui.notify(`Blocked direct credential dump command`, "warning");
				}
				return {
					block: true,
					reason: config.blockMessage,
				};
			}

			// 4. Jev System One Model Evaluation
			stats.jevEvaluated++;
			const result = await evaluatorFn(
				command,
				config,
				ctx,
				ctx.cwd,
				(ctx as any).signal,
			);

			if (result.bypassedByUser) {
				stats.userBypassed++;
				return undefined;
			}

			if (result.block) {
				stats.jevBlocked++;
				if (ctx.hasUI) {
					const probStr =
						result.probability !== undefined
							? ` (risk: ${(result.probability * 100).toFixed(0)}%)`
							: "";
					ctx.ui.notify(`Blocked command revealing secret credentials${probStr}`, "warning");
				}
				return {
					block: true,
					reason: result.reason || config.blockMessage,
				};
			}

			stats.jevPassed++;
			return undefined;
		}

		return undefined;
	});
}
