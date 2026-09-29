declare module "@earendil-works/pi-coding-agent" {
	export interface ExtensionUI {
		notify(message: string, type?: "info" | "warning" | "error"): void;
		setStatus(key: string, status?: string): void;
		select(prompt: string, options: string[]): Promise<string | undefined>;
		confirm(title: string, message: string): Promise<boolean>;
		theme?: {
			bg(style: string, text: string): string;
			fg(style: string, text: string): string;
			bold(text: string): string;
		};
	}

	export interface ExtensionContext {
		cwd: string;
		hasUI: boolean;
		ui: ExtensionUI;
	}

	export interface ToolCallEvent {
		toolName: string;
		input: Record<string, unknown>;
	}

	export interface ToolCallResult {
		block?: boolean;
		reason?: string;
	}

	export interface CommandDefinition {
		description: string;
		handler: (args: string, ctx: ExtensionContext) => Promise<void> | void;
	}

	export interface FlagDefinition {
		description: string;
		type: "boolean" | "string";
		default?: boolean | string;
	}

	export interface ExtensionAPI {
		registerCommand(name: string, def: CommandDefinition): void;
		registerFlag(name: string, def: FlagDefinition): void;
		getFlag(name: string): unknown;
		on(
			event: "session_start",
			handler: (event: any, ctx: ExtensionContext) => Promise<void> | void,
		): () => void;
		on(
			event: "tool_call",
			handler: (
				event: ToolCallEvent,
				ctx: ExtensionContext,
			) => Promise<ToolCallResult | undefined> | ToolCallResult | undefined,
		): () => void;
		on(event: string, handler: (...args: any[]) => any): () => void;
	}
}

declare module "@mariozechner/pi-coding-agent" {
	export * from "@earendil-works/pi-coding-agent";
}
