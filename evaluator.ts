import type { EntryType } from "@typesafe-ai/sdk";
import { noul, TypeSafeClient } from "@typesafe-ai/sdk";
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
}

const JEV_INSTRUCTIONS =
	"Does this command or script attempt to access, print, reveal, extract, or dump secret credentials, private keys, API keys, passwords, authentication tokens, or sensitive contents from environment variables or .env files to stdout or file, rather than merely verifying whether a variable exists?";

const JEV_CRITERIA = {
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
 * using TypeSafe's Jev model (either directly or via OpenRouter).
 */
export async function evaluateWithJev(
	commandOrPath: string,
	config: ResolvedConfig,
	ctx?: UIContext,
	cwd: string = process.cwd(),
	signal?: AbortSignal,
): Promise<EvaluationResult> {
	// If API key is missing entirely, handle as API failure
	if (!config.apiKey) {
		return handleApiFailure(
			commandOrPath,
			new Error(`Missing API key for provider "${config.provider}".`),
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
		let probability: number;

		if (config.provider === "typesafe") {
			probability = await callTypeSafeDirect(state, config, evaluationSignal);
		} else {
			probability = await callOpenRouterDecisions(state, config, evaluationSignal);
		}

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
 * Calls TypeSafe direct System One API.
 */
async function callTypeSafeDirect(
	state: EntryType,
	config: ResolvedConfig,
	signal?: AbortSignal,
): Promise<number> {
	const client = new TypeSafeClient({
		apiKey: config.apiKey,
		baseURL: config.baseUrl,
		timeout: DEFAULT_EVALUATION_TIMEOUT_MS,
	});

	const response = await client.systemOne(
		{
			model: config.model || "jev-latest",
			state,
			questions: {
				is_secret_reveal: noul(JEV_INSTRUCTIONS, JEV_CRITERIA),
			},
		},
		{
			signal,
			timeout: DEFAULT_EVALUATION_TIMEOUT_MS,
		},
	);

	const answer = response.answers.is_secret_reveal;
	return answer.noul;
}

/**
 * Calls OpenRouter Decisions API (POST /api/alpha/decisions).
 */
async function callOpenRouterDecisions(
	state: EntryType,
	config: ResolvedConfig,
	signal?: AbortSignal,
): Promise<number> {
	const baseUrl = config.baseUrl || "https://openrouter.ai/api/alpha";
	const endpoint = baseUrl.endsWith("/decisions") ? baseUrl : `${baseUrl}/decisions`;

	const payload = {
		model: config.model || "typesafe/jev-1.13",
		state,
		questions: {
			is_secret_reveal: {
				type: "noul",
				instructions: JEV_INSTRUCTIONS,
				criteria: JEV_CRITERIA,
			},
		},
	};

	const response = await fetch(endpoint, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${config.apiKey}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify(payload),
		signal,
	});

	if (!response.ok) {
		const text = await response.text();
		throw new Error(
			`OpenRouter decisions API failed (${response.status} ${response.statusText}): ${text}`,
		);
	}

	const data = (await response.json()) as any;
	if (data.answers?.is_secret_reveal?.noul !== undefined) {
		return data.answers.is_secret_reveal.noul;
	}

	throw new Error(`Invalid response structure from OpenRouter decisions API: ${JSON.stringify(data)}`);
}

/**
 * Fallback handler when the TypeSafe / OpenRouter API is unavailable or fails.
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
