import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { ResolvedConfig } from "./config.js";
import { extractLocalScriptPath } from "./heuristics.js";
import * as fs from "fs";
import * as path from "path";

export interface EvaluationResult {
	block: boolean;
	probability?: number;
	reason?: string;
	error?: string;
	bypassedByUser?: boolean;
}

export interface UIContext {
	hasUI: boolean;
	ui?: {
		notify(message: string, type?: "info" | "warning" | "error"): void;
		select(prompt: string, options: string[]): Promise<string | undefined>;
	};
	modelRegistry?: any;
}

export type EvaluatorContext = ExtensionContext | UIContext;

export const JEV_INSTRUCTIONS =
	"Does this command or script attempt to access, print, reveal, extract, or dump secret credentials, private keys, API keys, passwords, authentication tokens, or sensitive contents from environment variables or .env files to stdout or file, rather than merely verifying whether a variable exists?";

export const JEV_CRITERIA = {
	true: "Reveals, prints, exposes, or extracts confidential credential values, secrets, or .env contents.",
	false: "Does not expose credentials; benign command or solely checks existence/boolean status of an environment variable without printing its secret value.",
};

const DEFAULT_EVALUATION_TIMEOUT_MS = 10_000;

/**
 * Creates an AbortSignal combining caller cancellation and a timeout.
 */
function createEvaluationSignal(callerSignal?: AbortSignal, timeoutMs = DEFAULT_EVALUATION_TIMEOUT_MS): AbortSignal {
	const timeoutSignal = AbortSignal.timeout(timeoutMs);
	if (callerSignal && typeof (AbortSignal as any).any === "function") {
		return (AbortSignal as any).any([callerSignal, timeoutSignal]);
	}
	return timeoutSignal;
}

/**
 * Evaluates whether a tool call (command or file path) poses a risk of revealing secrets
 * using TypeSafe's Jev model via Pi's native modelRegistry.
 */
export async function evaluateWithJev(
	commandOrPath: string,
	config: ResolvedConfig,
	ctx?: EvaluatorContext,
	cwd: string = process.cwd(),
	signal?: AbortSignal,
): Promise<EvaluationResult> {
	if (!ctx?.modelRegistry) {
		return handleApiFailure(
			commandOrPath,
			new Error("Pi modelRegistry is unavailable in this extension context."),
			config,
			ctx,
		);
	}

	// Prepare state
	let scriptSnippet: string | undefined;
	const scriptPath = extractLocalScriptPath(commandOrPath);
	if (scriptPath) {
		try {
			const fullPath = path.isAbsolute(scriptPath) ? scriptPath : path.resolve(cwd, scriptPath);
			if (fs.existsSync(fullPath)) {
				const content = fs.readFileSync(fullPath, "utf-8");
				scriptSnippet = content.slice(0, 4000); // Send up to 4000 chars of script snippet
			}
		} catch {
			// Ignore read errors
		}
	}

	const state: Record<string, string | number | boolean | null> = {
		platform: process.platform,
		command_or_path: commandOrPath,
	};
	if (scriptSnippet) {
		state.script_content_snippet = scriptSnippet;
	}

	const evaluationSignal = createEvaluationSignal(signal);

	try {
		let model = ctx.modelRegistry.findOfType("classifier", config.provider, config.model);

		// Fallback to known alternative model IDs if not found under exact configured name
		if (!model && config.provider === "openrouter") {
			const alternatives = ["typesafe/jev-1.13", "~typesafe/jev-latest"];
			for (const alt of alternatives) {
				if (alt !== config.model) {
					model = ctx.modelRegistry.findOfType("classifier", "openrouter", alt);
					if (model) break;
				}
			}
		}

		if (!model) {
			return handleApiFailure(
				commandOrPath,
				new Error(`Classifier model "${config.model}" for provider "${config.provider}" is not in Pi's catalog.`),
				config,
				ctx,
			);
		}

		// Honor custom baseUrl if explicitly configured
		if (config.baseUrl) {
			model = { ...model, baseUrl: config.baseUrl };
		}

		const classifyOptions: Record<string, any> = { signal: evaluationSignal };
		if (config.apiKey) {
			classifyOptions.apiKey = config.apiKey;
		}

		const result = await ctx.modelRegistry.classify(
			model,
			{
				state,
				questions: {
					is_secret_reveal: {
						type: "bool",
						instructions: JEV_INSTRUCTIONS,
						criteria: JEV_CRITERIA,
					},
				},
			},
			classifyOptions,
		);

		if (result.stopReason === "error" || result.stopReason === "aborted") {
			return handleApiFailure(
				commandOrPath,
				new Error(result.errorMessage || `Classification returned ${result.stopReason}`),
				config,
				ctx,
			);
		}

		const answer = result.answers?.is_secret_reveal;
		if (!answer || answer.type !== "bool" || typeof answer.probability !== "number") {
			return handleApiFailure(
				commandOrPath,
				new Error("Classifier response did not return a valid boolean probability"),
				config,
				ctx,
			);
		}

		const probability = answer.probability;
		if (probability > config.threshold) {
			return {
				block: true,
				probability,
				reason: config.blockMessage,
			};
		}

		return {
			block: false,
			probability,
		};
	} catch (err: any) {
		return handleApiFailure(commandOrPath, err, config, ctx);
	}
}

/**
 * Fallback handler when the Jev evaluation fails or is unavailable.
 * - In interactive mode (ctx.hasUI): prompts user to Allow or Block.
 * - In non-interactive mode: blocks command as a safety precaution.
 */
async function handleApiFailure(
	commandOrPath: string,
	error: Error,
	config: ResolvedConfig,
	ctx?: UIContext,
): Promise<EvaluationResult> {
	const errorMessage = error?.message || String(error);

	if (ctx?.hasUI && ctx.ui) {
		ctx.ui.notify(
			`TypeSafe Jev evaluation unavailable: ${errorMessage}`,
			"warning",
		);

		const prompt =
			`⚠️ Secret Protection: Unable to reach Jev (${config.provider}):\n` +
			`  ${errorMessage}\n\n` +
			`Suspicious command/path:\n` +
			`  ${commandOrPath}\n\n` +
			`How would you like to proceed?`;

		const choice = await ctx.ui.select(prompt, [
			"Block command (Recommended)",
			"Allow command this time",
		]);

		if (choice === "Allow command this time") {
			return {
				block: false,
				bypassedByUser: true,
				error: errorMessage,
			};
		}

		return {
			block: true,
			reason: config.blockMessage,
			error: errorMessage,
		};
	}

	// Non-interactive fallback: fail secure
	return {
		block: true,
		reason: `${config.blockMessage} (Jev evaluation unreachable: ${errorMessage})`,
		error: errorMessage,
	};
}
