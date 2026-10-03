import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export type ProviderType = "typesafe" | "openrouter";

export interface ProtectSecretSettings {
	provider?: ProviderType;
	apiKey?: string;
	model?: string;
	threshold?: number;
	baseUrl?: string;
}

export interface ResolvedConfig {
	provider: ProviderType;
	apiKey: string;
	model: string;
	threshold: number;
	baseUrl?: string;
	blockMessage: string;
}

export const DEFAULT_BLOCK_MESSAGE =
	"Do **NOT** read any credentials by yourself, ask the user and state why you would like to check the credentials.";

export const DEFAULT_THRESHOLD = 0.75;

export const DEFAULT_MODELS: Record<ProviderType, string> = {
	typesafe: "jev-latest",
	openrouter: "typesafe/jev-1.13",
};

export const DEFAULT_BASE_URLS: Record<ProviderType, string> = {
	typesafe: "https://api.typesafe.ai/v1",
	openrouter: "https://openrouter.ai/api/v1",
};

/**
 * Reads ~/.pi/agent/settings.json safely if it exists.
 */
export function loadPiSettings(): { protectsecret?: ProtectSecretSettings } {
	try {
		const settingsPath = path.join(os.homedir(), ".pi", "agent", "settings.json");
		if (fs.existsSync(settingsPath)) {
			const raw = fs.readFileSync(settingsPath, "utf-8");
			return JSON.parse(raw);
		}
	} catch {
		// Ignore parse errors or missing file
	}
	return {};
}

/**
 * Resolves configuration from settings.json, environment variables, and CLI overrides.
 */
export function resolveConfig(options?: {
	thresholdOverride?: number;
	ctx?: { modelRegistry?: any };
}): ResolvedConfig {
	const settings = loadPiSettings().protectsecret ?? {};

	// Determine provider
	let provider: ProviderType;
	if (settings.provider === "openrouter" || settings.provider === "typesafe") {
		provider = settings.provider;
	} else {
		// Auto-detect based on Pi credentials or available env keys
		const hasTypeSafeAuth =
			Boolean(process.env.TYPESAFE_API_KEY || process.env.typesafe_api_key) ||
			Boolean(options?.ctx?.modelRegistry?.getProviderAuthStatus?.("typesafe")?.configured);
		const hasOpenRouterAuth =
			Boolean(process.env.OPENROUTER_API_KEY || process.env.openrouter_api_key) ||
			Boolean(options?.ctx?.modelRegistry?.getProviderAuthStatus?.("openrouter")?.configured);

		if (hasTypeSafeAuth) {
			provider = "typesafe";
		} else if (hasOpenRouterAuth) {
			provider = "openrouter";
		} else {
			provider = "typesafe"; // default
		}
	}

	// Resolve API Key
	// Priority 1: settings.json protectsecret.apiKey
	// Priority 2: environment variables
	let apiKey = settings.apiKey || "";
	if (!apiKey) {
		if (provider === "typesafe") {
			apiKey = process.env.TYPESAFE_API_KEY || process.env.typesafe_api_key || "";
		} else {
			apiKey = process.env.OPENROUTER_API_KEY || process.env.openrouter_api_key || "";
		}
	}

	// Resolve model
	const model = settings.model || DEFAULT_MODELS[provider];

	// Resolve threshold
	let threshold = DEFAULT_THRESHOLD;
	if (typeof options?.thresholdOverride === "number" && !isNaN(options.thresholdOverride)) {
		threshold = options.thresholdOverride;
	} else if (typeof settings.threshold === "number" && !isNaN(settings.threshold)) {
		threshold = settings.threshold;
	}

	// Resolve baseUrl
	const baseUrl = settings.baseUrl || DEFAULT_BASE_URLS[provider];

	return {
		provider,
		apiKey,
		model,
		threshold,
		baseUrl,
		blockMessage: DEFAULT_BLOCK_MESSAGE,
	};
}
