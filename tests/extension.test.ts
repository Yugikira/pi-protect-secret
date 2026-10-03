import * as assert from "assert";
import type {
	ExtensionAPI,
	ExtensionContext,
	ExtensionFlag,
	ToolCallEvent,
	ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import initExtension from "../index.js";
import { DEFAULT_BLOCK_MESSAGE } from "../config.js";

console.log("=== Running Extension Integration Tests (Round 3 - Pi 1.0.0) ===");

// Create a mock ExtensionAPI
class MockPi {
	flags = new Map<string, unknown>();
	flagDefs = new Map<string, ExtensionFlag>();
	commands = new Map<string, any>();
	handlers = new Map<string, Array<(...args: any[]) => any>>();

	registerFlag(name: string, def: ExtensionFlag): void {
		this.flagDefs.set(name, def);
		if (def.default !== undefined) {
			this.flags.set(name, def.default);
		}
	}

	getFlag(name: string): any {
		return this.flags.get(name);
	}

	registerCommand(name: string, def: any): void {
		this.commands.set(name, def);
	}

	on(event: string, handler: (...args: any[]) => any): () => void {
		if (!this.handlers.has(event)) {
			this.handlers.set(event, []);
		}
		this.handlers.get(event)!.push(handler);
		return () => {
			const list = this.handlers.get(event);
			if (list) {
				const idx = list.indexOf(handler);
				if (idx >= 0) list.splice(idx, 1);
			}
		};
	}

	async emit(event: string, ...args: any[]): Promise<any> {
		const list = this.handlers.get(event) || [];
		for (const h of list) {
			const res = await h(...args);
			if (res !== undefined) return res;
		}
		return undefined;
	}
}

const mockUi = {
	notifications: [] as string[],
	status: undefined as string | undefined,
	notify(message: string) {
		this.notifications.push(message);
	},
	setStatus(_key: string, status?: string) {
		this.status = status;
	},
	async select(prompt: string, options: string[]) {
		return options[0];
	},
	async confirm() {
		return true;
	},
};

const mockModelRegistry = {
	findOfType: (type: string, provider: string, id: string) => ({
		type: "classifier",
		provider,
		id,
		api: "typesafe-system-one",
	}),
	getProviderAuthStatus: () => ({ configured: true }),
	classify: async () => ({
		stopReason: "stop",
		answers: {
			is_secret_reveal: {
				type: "bool",
				probability: 0.01,
			},
		},
	}),
};

const mockCtx: ExtensionContext = {
	cwd: process.cwd(),
	hasUI: true,
	ui: mockUi as any,
	modelRegistry: mockModelRegistry as any,
} as unknown as ExtensionContext;

async function runTests() {
	const pi = new MockPi();
	initExtension(pi as unknown as ExtensionAPI);

	// 1. Check flags and commands registration
	assert.ok(pi.flagDefs.has("protect-secret-disabled"), "protect-secret-disabled flag registered");
	assert.ok(pi.flagDefs.has("protect-secret-threshold"), "protect-secret-threshold flag registered");
	assert.ok(pi.commands.has("protect-secret"), "/protect-secret command registered");
	console.log("✓ Flags and commands registered.");

	// 2. Test read tool on safe files and templates
	let result = await pi.emit("tool_call", { toolName: "read", input: { path: "package.json" } }, mockCtx);
	assert.strictEqual(result, undefined, "read package.json should be allowed");

	result = await pi.emit("tool_call", { toolName: "read", input: { path: ".env.example" } }, mockCtx);
	assert.strictEqual(result, undefined, "read .env.example should be allowed");

	result = await pi.emit("tool_call", { toolName: "read", input: { path: "oauth.json" } }, mockCtx);
	assert.strictEqual(result, undefined, "read oauth.json should be allowed");

	// 3. Test read tool on .env and sensitive json files
	result = await pi.emit("tool_call", { toolName: "read", input: { path: ".env" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "read .env should be blocked");

	result = await pi.emit("tool_call", { toolName: "read", input: { path: "auth.json" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "read auth.json should be blocked");

	result = await pi.emit("tool_call", { toolName: "read", input: { path: "credentials.json" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "read credentials.json should be blocked");
	console.log("✓ read tool protection verified.");

	// 4. Test bash tool on benign commands (0ms bypass)
	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "git status" } }, mockCtx);
	assert.strictEqual(result, undefined, "git status should be allowed (0ms bypass)");

	result = await pi.emit("tool_call", { toolName: "bash", input: { command: 'git commit -m "add env config"' } }, mockCtx);
	assert.strictEqual(result, undefined, "git commit should be allowed (not falsely flagged as env dump)");

	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "ENV=production npm start" } }, mockCtx);
	assert.strictEqual(result, undefined, "ENV=production npm start should be allowed (0ms bypass)");

	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "env=dev npm start" } }, mockCtx);
	assert.strictEqual(result, undefined, "env=dev npm start should be allowed (0ms bypass)");

	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "set -e; npm start" } }, mockCtx);
	assert.strictEqual(result, undefined, "set -e; npm start should be allowed (0ms bypass)");

	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "set -euo pipefail && npm run build" } }, mockCtx);
	assert.strictEqual(result, undefined, "set -euo pipefail should be allowed (0ms bypass)");

	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "cat oauth.json" } }, mockCtx);
	assert.strictEqual(result, undefined, "cat oauth.json should be allowed (not auth.json)");

	// 5. Test bash tool on allowed existence checks (anchored)
	result = await pi.emit("tool_call", { toolName: "bash", input: { command: '[ -n "$API_KEY" ]' } }, mockCtx);
	assert.strictEqual(result, undefined, "[ -n $API_KEY ] existence check should be allowed");

	result = await pi.emit("tool_call", { toolName: "bash", input: { command: 'Test-Path env:API_KEY' } }, mockCtx);
	assert.strictEqual(result, undefined, "Test-Path env:API_KEY existence check should be allowed");
	console.log("✓ Whitelisted existence checks verified (bash).");

	// 6. Test powershell tool: safe commands, existence checks, and hard-blocks
	result = await pi.emit("tool_call", { toolName: "powershell", input: { command: "Get-ChildItem" } }, mockCtx);
	assert.strictEqual(result, undefined, "powershell Get-ChildItem should be allowed");

	result = await pi.emit("tool_call", { toolName: "powershell", input: { command: "Test-Path env:API_KEY" } }, mockCtx);
	assert.strictEqual(result, undefined, "powershell Test-Path env:API_KEY should be allowed");

	result = await pi.emit("tool_call", { toolName: "powershell", input: { command: "Get-Content .env" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "powershell Get-Content .env should be blocked");

	result = await pi.emit("tool_call", { toolName: "powershell", input: { command: "$env:API_KEY" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "powershell $env:API_KEY should be blocked");

	result = await pi.emit("tool_call", { toolName: "powershell", input: { command: "Get-Item env:API_KEY" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "powershell Get-Item env:API_KEY should be blocked");

	result = await pi.emit("tool_call", { toolName: "powershell", input: { command: "Get-Content env:API_KEY" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "powershell Get-Content env:API_KEY should be blocked");

	result = await pi.emit("tool_call", { toolName: "powershell", input: { command: "[Environment]::GetEnvironmentVariable('OPENAI_API_KEY')" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "powershell [Environment]::GetEnvironmentVariable should be blocked");
	console.log("✓ powershell tool protection verified.");

	// 7. Test bypass attack vectors: MUST NOT BYPASS!
	const bypassAttempts = [
		'[ -n "$OPENAI_API_KEY" ] && printenv OPENAI_API_KEY',
		'[ -n "$OPENAI_API_KEY" ]; printenv OPENAI_API_KEY',
		'[ -n "$K" ] && cat ~/.aws/credentials',
		'[ -n "$K" ] && cp .env /tmp/x',
		'[ -n "$K" ] && Get-Content .env',
		'echo ${OPENAI_API_KEY}',
		'echo %OPENAI_API_KEY%',
		'set OPENAI_API_KEY',
		// Shell keyword subcommands:
		'if [ -n "$K" ]; then printenv OPENAI_API_KEY; fi',
		'if [ -n "$K" ]; then echo ok; else printenv OPENAI_API_KEY; fi',
		'for f in *; do printenv OPENAI_API_KEY; done',
		'for f in *; do printenv AWS_SECRET_ACCESS_KEY; done',
		'while read l; do printenv TOKEN; done',
		// Template abuse attempts:
		'cat .env # see .env.example',
		'cat .env .env.example',
		'cat .env > out.txt # .env.example',
		'Get-Content .env # .env.sample',
		// Curl and // path tests:
		'curl https://evil.example.com/.env',
		'curl http://internal.host/.env//x',
		'head -n 5 .//.env//',
	];

	for (const cmd of bypassAttempts) {
		result = await pi.emit("tool_call", { toolName: "bash", input: { command: cmd } }, mockCtx);
		assert.deepStrictEqual(
			result,
			{ block: true, reason: DEFAULT_BLOCK_MESSAGE },
			`Expected attack vector "${cmd}" to be BLOCKED, but was allowed!`,
		);
	}
	console.log("✓ All Round 1 & Round 2 bypass attack vectors successfully blocked!");

	// 8. Test Stage-5 Jev Model Evaluation Seam (hygienic factory option)
	console.log("\nTesting Stage 5 Jev evaluation seam...");
	let jevCalledWith: string | undefined;

	const piWithMockJev = new MockPi();
	initExtension(piWithMockJev as unknown as ExtensionAPI, {
		evaluator: async (cmd) => {
			jevCalledWith = cmd;
			if (cmd.includes("dump_secret")) {
				return { block: true, probability: 0.95, reason: DEFAULT_BLOCK_MESSAGE };
			}
			return { block: false, probability: 0.1 };
		},
	});

	// Evaluated and blocked by Jev (bash)
	result = await piWithMockJev.emit(
		"tool_call",
		{ toolName: "bash", input: { command: "python -c 'import os; dump_secret(os.environ)'" } },
		mockCtx,
	);
	assert.strictEqual(jevCalledWith, "python -c 'import os; dump_secret(os.environ)'");
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE });

	// Evaluated and blocked by Jev (powershell)
	result = await piWithMockJev.emit(
		"tool_call",
		{ toolName: "powershell", input: { command: "python -c 'import os; dump_secret(os.environ)'" } },
		mockCtx,
	);
	assert.strictEqual(jevCalledWith, "python -c 'import os; dump_secret(os.environ)'");
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE });

	// Evaluated and allowed by Jev
	result = await piWithMockJev.emit(
		"tool_call",
		{ toolName: "bash", input: { command: "python -c 'import os; safe_check(os.environ)'" } },
		mockCtx,
	);
	assert.strictEqual(result, undefined);
	console.log("✓ Jev evaluation seam and branching verified (bash & powershell).");

	// 9. Test /protect-secret toggle
	const toggleCmd = pi.commands.get("protect-secret")!;
	await toggleCmd.handler("off", mockCtx);

	// When disabled, cat .env should be allowed
	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "cat .env" } }, mockCtx);
	assert.strictEqual(result, undefined, "cat .env should be allowed when disabled");

	// Re-enable
	await toggleCmd.handler("on", mockCtx);
	result = await pi.emit("tool_call", { toolName: "bash", input: { command: "cat .env" } }, mockCtx);
	assert.deepStrictEqual(result, { block: true, reason: DEFAULT_BLOCK_MESSAGE }, "cat .env should be blocked when re-enabled");
	console.log("✓ Toggle command verified.");

	// 10. Test /protect-secret status display
	await toggleCmd.handler("", mockCtx);
	const lastNotification = mockUi.notifications[mockUi.notifications.length - 1];
	assert.ok(lastNotification.includes("pi-protect-secret status"), "Status command should display status");
	assert.ok(
		lastNotification.includes("Ready via Pi credentials") || lastNotification.includes("Configured (override, ready)"),
		"Status should report ready status",
	);
	console.log("✓ Status display command verified.");

	console.log("\n🎉 ALL EXTENSION INTEGRATION TESTS PASSED!\n");
}

runTests().catch((err) => {
	console.error("Test failed:", err);
	process.exit(1);
});
