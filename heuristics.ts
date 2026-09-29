import * as fs from "fs";
import * as path from "path";

/**
 * Patterns matching sensitive files that contain credentials.
 */
export const SENSITIVE_FILE_PATTERNS = [
	/(?:^|[\\/])\.env(?:\.[a-zA-Z0-9_.-]+)*$/i,
	/(?:^|[\\/])id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?$/i,
	/(?:^|[\\/]).*\.(?:pem|key|pfx|p12|pkcs12)$/i,
	/(?:^|[\\/])(?:credentials|\.git-credentials|\.netrc|\.npmrc)$/i,
	/(?:^|[\\/])(?:secrets?|credentials|auth|client_secret.*|service_account.*)\.json$/i,
	/(?:^|[\\/])\.aws[\\/]credentials$/i,
];

/**
 * Patterns for non-secret template/example files that should not be blocked.
 */
export const NON_SECRET_TEMPLATE_PATTERNS = [
	/(?:^|[\\/\s"'])\.env\.(?:example|sample|template|dist|defaults)(?:$|[\s"'])/i,
];

/**
 * Sensitive keyword substrings commonly used in credential environment variables.
 * Single source of truth across all heuristic checks.
 */
export const SENSITIVE_KEYWORDS = [
	"KEY",
	"SECRET",
	"TOKEN",
	"AUTH",
	"PASS",
	"PASSWORD",
	"CREDENTIAL",
	"PRIVATE",
	"BEARER",
	"API",
] as const;

export const SENSITIVE_KEYWORDS_PATTERN = SENSITIVE_KEYWORDS.join("|");

// Precompiled regular expressions built from the single source of truth
const SENSITIVE_KEYWORD_REGEX = new RegExp(
	String.raw`(?:${SENSITIVE_KEYWORDS_PATTERN})`,
	"i",
);

const ECHO_BASH_SENSITIVE_REGEX = new RegExp(
	String.raw`\b(?:echo|printf)\s+["']?\$(\{?[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*\}?)`,
	"i",
);

const ECHO_CMD_SENSITIVE_REGEX = new RegExp(
	String.raw`\becho\s+["']?%[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*%`,
	"i",
);

const SET_CMD_SENSITIVE_REGEX = new RegExp(
	String.raw`\bset\s+["']?[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*(?:=|\s|$)`,
	"i",
);

const PRINTENV_SENSITIVE_REGEX = new RegExp(
	String.raw`\bprintenv\s+["']?[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*`,
	"i",
);

const PWSH_DIRECT_DUMP_REGEX = new RegExp(
	String.raw`(?:\$env:[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*|\bGet-(?:Item|ChildItem)\s+["']?env:[A-Za-z0-9_*]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_*]*["']?)`,
	"i",
);

const SUSPICIOUS_VAR_MENTION_REGEX = new RegExp(
	String.raw`\$(?:\{[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*\}|[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*)` +
		String.raw`|%[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*%` +
		String.raw`|\$env:[A-Za-z0-9_]*` +
		String.raw`|\bprintenv\s+["']?[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*` +
		String.raw`|\bset\s+["']?[A-Za-z0-9_]*?(?:${SENSITIVE_KEYWORDS_PATTERN})[A-Za-z0-9_]*` +
		String.raw`|\bGet-(?:Item|ChildItem)\s+["']?env:`,
	"i",
);

/**
 * Strips comments and non-secret template file references (.env.example, .env.sample, etc.)
 * from a command or script string before checking for sensitive .env references.
 *
 * lineComments: if true (for script source code), strips // comments (ignoring :// in URLs).
 * In shell commands, lineComments is omitted so URLs like https://host/.env are NOT truncated!
 */
export function stripTemplateReferences(
	text: string,
	opts?: { lineComments?: boolean },
): string {
	let out = text
		// '#' starts a comment only at the start of a line or after whitespace
		.replace(/(?:^|\s)#.*$/gm, " ")
		// Remove template names e.g. .env.example
		.replace(/\.env\.(?:example|sample|template|dist|defaults)\b/gi, " ");

	if (opts?.lineComments) {
		// `//` is a comment in JS/TS/C source code only; never let it truncate a URL (require not preceded by :)
		out = out.replace(/(?<!:)\/\/.*$/gm, " ");
	}

	return out;
}

/**
 * Checks whether a file path requested by the `read` tool points to a sensitive credential file.
 */
export function isSensitiveFilePath(targetPath: string): boolean {
	const normalized = targetPath.trim().replace(/\\/g, "/");
	if (NON_SECRET_TEMPLATE_PATTERNS.some((p) => p.test(normalized))) {
		return false;
	}
	return SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(normalized));
}

/**
 * Checks if a command is explicitly a harmless environment variable existence check.
 * These commands confirm existence or non-emptiness without outputting the secret value.
 *
 * NOTE: Patterns MUST be strictly whole-command anchored (^...$). Chained commands (&&, ||, ;, |)
 * are NEVER whitelisted so downstream stages cannot be bypassed.
 */
export function isAllowedExistenceCheck(command: string): boolean {
	const trimmed = command.trim();

	// Bash bracket test: [ -n "$VAR" ], [ -z "$VAR" ], [[ -n "$VAR" ]], [[ -z "$VAR" ]], [ -v VAR ], [[ -v VAR ]]
	if (/^\[{1,2}\s+-(?:n|z|v)\s+["']?\$?[A-Za-z_][A-Za-z0-9_]*["']?\s*\]{1,2}$/i.test(trimmed)) {
		return true;
	}

	// Bash test command: test -n "$VAR", test -z "$VAR", test -v VAR
	if (/^test\s+-(?:n|z|v)\s+["']?\$?[A-Za-z_][A-Za-z0-9_]*["']?$/i.test(trimmed)) {
		return true;
	}

	// Empty if statement: if [ -n "$VAR" ]; then :; fi or if [ -n "$VAR" ]; then true; fi
	if (
		/^if\s+\[{1,2}\s+-(?:n|z|v)\s+["']?\$?[A-Za-z_][A-Za-z0-9_]*["']?\s*\]{1,2}\s*;\s*then\s*(?::|true)?\s*;?\s*fi$/i.test(
			trimmed,
		)
	) {
		return true;
	}

	// Bash: parameter expansion that replaces value with literal string:
	// echo ${VAR:+exists} or printf "${VAR:+set}"
	if (
		/^(?:echo|printf)\s+["']?\$\{[A-Za-z_][A-Za-z0-9_]*:\+[A-Za-z0-9_-]+\}["']?$/i.test(
			trimmed,
		)
	) {
		return true;
	}

	// Bash: printenv VAR >/dev/null or printenv VAR > /dev/null (strictly anchored)
	if (/^printenv\s+[A-Za-z_][A-Za-z0-9_]*\s*>\s*\/dev\/null$/i.test(trimmed)) {
		return true;
	}

	// Bash: env | grep -q VAR (strictly anchored)
	if (
		/^env\s*\|\s*grep\s+-(?:q|-quiet)\s+["']?\^?[A-Za-z_][A-Za-z0-9_]*=?["']?$/i.test(
			trimmed,
		)
	) {
		return true;
	}

	// PowerShell / pwsh: Test-Path env:VAR
	if (/^Test-Path\s+["']?env:[A-Za-z0-9_]+["']?$/i.test(trimmed)) {
		return true;
	}

	// PowerShell / pwsh: [bool]$env:VAR or [boolean]$env:VAR or [string]::IsNullOrEmpty($env:VAR)
	if (
		/^\[bool(?:ean)?\]\$env:[A-Za-z0-9_]+$/i.test(trimmed) ||
		/^\[string\]::IsNullOr(?:Empty|WhiteSpace)\(\$env:[A-Za-z0-9_]+\)$/i.test(trimmed) ||
		/^\$null\s+-(?:ne|eq)\s+\$env:[A-Za-z0-9_]+$/i.test(trimmed) ||
		/^\$env:[A-Za-z0-9_]+\s+-(?:ne|eq)\s+\$null$/i.test(trimmed)
	) {
		return true;
	}

	return false;
}

/**
 * Fast-path check for obvious, blatant secret dumps.
 * Returns true if the command is directly attempting to dump secret files or credentials.
 */
export function isObviousSecretDump(command: string): boolean {
	const trimmed = command.trim();

	// Direct read of .env or secret files via shell tools
	// e.g. cat .env, type .env, Get-Content .env, head -n 20 .env, tail .env, cp .env /tmp, curl .../.env
	const sanitizedForEnv = stripTemplateReferences(trimmed);
	const fileReadCmds =
		/\b(?:cat|type|Get-Content|gc|head|tail|more|less|grep|awk|sed|cp|curl|wget)\b.*?(?:[\\/]?\.env(?:\.[a-zA-Z0-9_.-]+)*)/i;
	if (fileReadCmds.test(sanitizedForEnv)) {
		return true;
	}

	// Reading private ssh keys
	const sshKeyRead =
		/\b(?:cat|type|Get-Content|gc|head|tail|cp)\b.*?id_(?:rsa|ed25519|ecdsa|dsa)/i;
	if (sshKeyRead.test(trimmed)) {
		return true;
	}

	// Reading aws credentials
	if (
		/\b(?:cat|type|Get-Content|gc|head|tail|cp)\b.*?(?:[\\/]\.aws[\\/]credentials)/i.test(
			trimmed,
		)
	) {
		return true;
	}

	// Direct echo / printf of sensitive environment variables
	// Bash: echo $API_KEY, echo ${API_KEY}
	if (ECHO_BASH_SENSITIVE_REGEX.test(trimmed) && !isAllowedExistenceCheck(trimmed)) {
		return true;
	}

	// Windows cmd.exe: echo %API_KEY%
	if (ECHO_CMD_SENSITIVE_REGEX.test(trimmed)) {
		return true;
	}

	// Windows cmd.exe: set API_KEY (prints value)
	if (SET_CMD_SENSITIVE_REGEX.test(trimmed)) {
		return true;
	}

	// printenv of sensitive env vars (e.g. printenv OPENAI_API_KEY)
	if (
		PRINTENV_SENSITIVE_REGEX.test(trimmed) &&
		!trimmed.includes(">/dev/null") &&
		!trimmed.includes("> /dev/null")
	) {
		return true;
	}

	// PowerShell / pwsh direct dump of sensitive env vars
	// e.g. $env:OPENAI_API_KEY, Write-Output $env:SECRET, Get-Item env:*KEY*
	if (PWSH_DIRECT_DUMP_REGEX.test(trimmed) && !isAllowedExistenceCheck(trimmed)) {
		return true;
	}

	return false;
}

/**
 * Checks whether a command or its referenced local script file contains any suspicious patterns
 * that warrant evaluation by the TypeSafe Jev model.
 */
export function isSuspiciousCommand(command: string, cwd: string = process.cwd()): boolean {
	const trimmed = command.trim();

	// 1. Direct command line mentions of .env or sensitive file patterns (excluding .env.example)
	const sanitizedForEnv = stripTemplateReferences(trimmed);
	if (
		/\.env(?:\.[a-zA-Z0-9_.-]+)*/i.test(sanitizedForEnv) ||
		/\bid_(?:rsa|ed25519|ecdsa|dsa)\b/i.test(trimmed) ||
		/\b(?:credentials|\.git-credentials|\.netrc|\.npmrc)\b/i.test(trimmed) ||
		/\.(?:pem|key|pfx|p12|pkcs12)\b/i.test(trimmed) ||
		/(?:^|[\\/\s"'])(?:secrets?|credentials|auth|client_secret.*|service_account.*)\.json(?:$|[\\/\s"'])/i.test(
			trimmed,
		) ||
		/\.aws[\\/]credentials/i.test(trimmed)
	) {
		return true;
	}

	// 2. Mentions of sensitive env var keywords ($...KEY..., ${...KEY...}, %...KEY...%, $env:..., printenv KEY, set KEY)
	if (SUSPICIOUS_VAR_MENTION_REGEX.test(trimmed)) {
		return true;
	}

	// 3. Mentions of env listing / dumping tools as commands (segmented to catch compound commands, if/else/for/do sub-commands)
	const SEGMENT_SPLIT = /[|;&()\n]|\b(?:then|else|elif|do|done|time)\b/i;
	const segments = trimmed.split(SEGMENT_SPLIT);

	for (const seg of segments) {
		const s = seg.trim();
		// printenv (without redirect to /dev/null)
		if (/^printenv\b/i.test(s) && !s.includes(">/dev/null") && !s.includes("> /dev/null")) {
			return true;
		}
		// env (standalone or with options, but not variable assignments like ENV=production or env=dev)
		if (/^env\b/i.test(s) && !/^[a-zA-Z_][a-zA-Z0-9_]*=/i.test(s)) {
			return true;
		}
		// set (dumps all env vars in cmd.exe/bash, but NOT shell option flags like set -e or set +x)
		if (/^set\b/i.test(s)) {
			// If set is followed by shell flags (-e, -euo, +x, -o, etc.), it's setting shell options, not dumping env
			if (!/^set\s+[-+][a-zA-Z]/i.test(s)) {
				return true;
			}
		}
		// PowerShell env dump tools or export -p / declare -p
		if (
			/\b(?:export\s+-p|declare\s+-p|Get-ChildItem\s+env:|dir\s+env:|ls\s+env:)\b/i.test(s)
		) {
			return true;
		}
	}

	// 4. Inlined script with credential APIs
	// Python: os.environ, os.getenv, dotenv
	if (
		/\b(?:os\.environ|os\.getenv|dotenv|load_dotenv)\b/i.test(trimmed) ||
		/\bprocess\.env\b/i.test(trimmed) ||
		/\[System\.Environment\]::GetEnvironmentVariable/i.test(trimmed)
	) {
		return true;
	}

	// 5. Script execution inspection:
	// If the command is running a local script file (python script.py, bash run.sh, pwsh deploy.ps1),
	// inspect the file content on disk.
	const scriptPath = extractLocalScriptPath(trimmed);
	if (scriptPath) {
		const fullPath = path.isAbsolute(scriptPath) ? scriptPath : path.resolve(cwd, scriptPath);
		try {
			if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
				// Only read reasonable sized files (< 2MB)
				const size = fs.statSync(fullPath).size;
				if (size < 2 * 1024 * 1024) {
					const content = fs.readFileSync(fullPath, "utf-8");
					if (isScriptContentSuspicious(content)) {
						return true;
					}
				}
			}
		} catch {
			// If file read fails, do not crash; fallback to command-only evaluation
		}
	}

	return false;
}

/**
 * Checks if the content of a script file contains suspicious credential retrieval patterns.
 */
export function isScriptContentSuspicious(content: string): boolean {
	// Strip comments and template references first (with lineComments enabled for source code)
	const sanitized = stripTemplateReferences(content, { lineComments: true });

	// Mentions .env or credential file names
	if (/\.env(?:\.[a-zA-Z0-9_.-]+)*/i.test(sanitized)) {
		return true;
	}
	if (/id_(?:rsa|ed25519|ecdsa|dsa)/i.test(content)) return true;
	if (
		/(?:^|[\\/\s"'])(?:secrets?|credentials|auth|client_secret.*|service_account.*)\.json(?:$|[\\/\s"'])/i.test(
			content,
		)
	) {
		return true;
	}

	// Python env/dotenv
	if (/\b(?:os\.environ|os\.getenv|dotenv|load_dotenv)\b/i.test(content)) return true;

	// Node process.env
	if (/\bprocess\.env\b/i.test(content)) return true;

	// PowerShell $env:
	if (/\$env:[A-Za-z0-9_]+/i.test(content)) return true;

	// Environment variable names with sensitive keywords
	if (
		SENSITIVE_KEYWORD_REGEX.test(content) &&
		/(?:environ|getenv|process\.env|\$env:|\.env)/i.test(content)
	) {
		return true;
	}

	return false;
}

/**
 * Extracts a candidate script file path from a runner command.
 * e.g.:
 *   "python script.py" -> "script.py"
 *   "python3 ./tools/test.py --arg" -> "./tools/test.py"
 *   "node run.js" -> "run.js"
 *   "bash ./script.sh" -> "./script.sh"
 *   "pwsh -File deploy.ps1" -> "deploy.ps1"
 */
export function extractLocalScriptPath(command: string): string | null {
	// Patterns for runner + script path
	const runners = [
		/^(?:python[0-9.]*|py)\s+(?:-u\s+)?([^\s-][^\s]*\.(?:py|pyw))\b/i,
		/^node\s+([^\s-][^\s]*\.(?:js|mjs|cjs|ts))\b/i,
		/^(?:bash|sh)\s+([^\s-][^\s]*\.(?:sh|bash))\b/i,
		/^(?:pwsh|powershell)(?:\.exe)?\s+(?:-File\s+)?([^\s-][^\s]*\.(?:ps1|psm1))\b/i,
		/^\.\/([^\s]+\.(?:sh|py|js|ts|ps1))\b/i,
	];

	for (const pattern of runners) {
		const match = command.match(pattern);
		if (match && match[1]) {
			return match[1].replace(/["']/g, "");
		}
	}

	return null;
}
