"""
Autonomous agent loop for CTF solving — v2.

Upgrades over v1:
- MAX_ITERATIONS: 20 → 40 → 80
- Working memory: session.memory_block() injected into system prompt every iteration
- Context compression: long histories are trimmed before each LLM call
- Global memory: past challenge experience loaded at startup, saved at the end
- New tools: think, update_memory
- Stronger system prompt: never give up, mandatory think after failures, finish gate

Backends: claude (Anthropic tool_use) | azure (Azure OpenAI function calling)
"""

import json
import os
import queue
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Generator

import anthropic
from dotenv import load_dotenv
from openai import AzureOpenAI, BadRequestError
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule

from ctf_rag.session import Session, GLOBAL_MEMORY_PATH
from ctf_rag.tools import TOOL_SCHEMAS, execute_tool
from ctf_rag.orchestrator import auto_detect_and_prompt

load_dotenv()

console = Console()
MAX_ITERATIONS = 500
_DISABLED_TOOLS: frozenset[str] = frozenset()  # tools blocked for current run

# ---------------------------------------------------------------------------
# Shell activity tracker — drives the statusline counter
# ---------------------------------------------------------------------------

_shell_lock = threading.Lock()
_active_shells: int = 0       # currently running shell_exec / bg_shell calls
_total_shells: int = 0        # lifetime count this session
_statusline_stop = threading.Event()


def _inc_shells() -> None:
    global _active_shells, _total_shells
    with _shell_lock:
        _active_shells += 1
        _total_shells += 1


def _dec_shells() -> None:
    global _active_shells
    with _shell_lock:
        _active_shells = max(0, _active_shells - 1)


def _statusline_worker(iteration_ref: list, backend_ref: list) -> None:
    """Background thread: redraws a one-line status bar every 0.3 s."""
    SHELL_ICON = "⬡"
    spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    frame = 0
    while not _statusline_stop.is_set():
        with _shell_lock:
            active = _active_shells
            total = _total_shells
        spin = spinner_frames[frame % len(spinner_frames)]
        frame += 1
        it = iteration_ref[0] if iteration_ref else "?"
        backend = backend_ref[0] if backend_ref else "?"

        if active > 0:
            shell_part = f"\033[33m{SHELL_ICON} {active} shell{'s' if active != 1 else ''} running\033[0m"
        else:
            shell_part = f"\033[2m{SHELL_ICON} 0 shells\033[0m"

        line = (
            f"\r\033[K"                              # CR + erase line
            f"\033[2m[{spin} iter {it} · {backend} · {shell_part}"
            f"\033[2m · {total} total shells]\033[0m"
        )
        sys.stderr.write(line)
        sys.stderr.flush()
        time.sleep(0.3)
    # Clear the statusline when stopped
    sys.stderr.write("\r\033[K")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Parallelism helpers
# ---------------------------------------------------------------------------

# Tools that are safe to run concurrently (pure reads / isolated processes)
_PARALLEL_SAFE = frozenset({
    "shell_exec", "bg_shell", "search_writeups", "get_attack_tree",
    "get_template", "http_get", "http_post", "think", "r2_analyze",
    "ghidra_analyze", "gdb_analyze", "ltrace_run", "strace_run",
    "cyclic_offset", "one_gadget", "find_gadget", "checksec",
    "strings_search", "angr_solve", "web_search", "read_file",
    "verify_crypto", "exploit_crash_analyze",
})

# Tools that MUST run alone (stateful / terminate the loop)
_SEQUENTIAL_ONLY = frozenset({
    "finish", "save_state", "revert_state", "note_failure",
    "update_memory", "save_skill", "delegate_task",
})


# ---------------------------------------------------------------------------
# Automated crash hint injection
# ---------------------------------------------------------------------------

_CRASH_PATTERNS = {
    # MOVAPS alignment — most common crash, highest priority
    "movaps":               "SELF-HEAL: MOVAPS alignment crash → add `ret` gadget BEFORE system(). Use exploit_crash_analyze(crash_output=<above>) for full diagnosis.",
    "sigsegv":              "SELF-HEAL: SIGSEGV detected → call exploit_crash_analyze(crash_output=<above>) to get specific fix recommendations. Do NOT call note_failure first.",
    "segmentation fault":   "SELF-HEAL: Segfault → call exploit_crash_analyze(crash_output=<above>) immediately.",
    "sigill":               "SELF-HEAL: Illegal instruction → likely wrong address or architecture mismatch. Call exploit_crash_analyze(crash_output=<above>).",
    "__stack_chk_fail":     "SELF-HEAL: Stack canary detected! Leak canary first via format string (%N$p) or off-by-one. Call exploit_crash_analyze(crash_output=<above>).",
    "stack smashing":       "SELF-HEAL: Stack canary detected! Call exploit_crash_analyze(crash_output=<above>) for bypass strategy.",
    "double free":          "SELF-HEAL: Heap double-free detected → check glibc version, use House of Botcake for glibc 2.29+. Call exploit_crash_analyze(crash_output=<above>).",
    "malloc(): corrupted":  "SELF-HEAL: Heap corruption → call exploit_crash_analyze(crash_output=<above>) for version-specific bypass.",
    "invalid next size":    "SELF-HEAL: Heap metadata corruption → call exploit_crash_analyze(crash_output=<above>).",
    "seccomp":              "SELF-HEAL: Seccomp filter! execve is likely blocked. Switch to ORW chain: rop_chain_synthesis(binary, goal='orw_flag', offset=N). Call exploit_crash_analyze(crash_output=<above>).",
    "bad syscall":          "SELF-HEAL: Seccomp blocked a syscall → call exploit_crash_analyze(crash_output=<above>) for ORW chain guidance.",
    "kernel panic":         "SELF-HEAL: Kernel panic → KPTI trampoline needed. Call exploit_crash_analyze(crash_output=<above>) for kernel ROP fix.",
    "general protection":   "SELF-HEAL: GPF in kernel → likely SMEP/SMAP/KPTI issue. Call exploit_crash_analyze(crash_output=<above>).",
}


def _inject_crash_hint(shell_result: str) -> str:
    """
    Scan shell_exec output for crash patterns and append a self-healing hint.
    This is a lightweight triage — for detailed diagnosis use exploit_crash_analyze.
    Only appends ONE hint (highest priority match).
    """
    if not shell_result:
        return shell_result
    lo = shell_result.lower()
    for pattern, hint in _CRASH_PATTERNS.items():
        if pattern in lo:
            return shell_result + f"\n\n⚠️  [AUTO-TRIAGE] {hint}"
    return shell_result


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

BASE_SYSTEM_PROMPT = """\
You are an elite, fully autonomous CTF (Capture The Flag) expert agent. \
You NEVER give up until you've exhausted every reasonable approach. \
You have {max_iter} iterations — use them all if you need to.

## Workflow
1. **Analyse first** — read the challenge description and recon output carefully before acting.
   Call `update_memory(category=...)` and `update_memory(hypothesis=...)` immediately.
2. **Search informed** — call search_writeups() with specific technical terms from your analysis.
3. **Get a plan** — if search returns nothing useful, call get_attack_tree(category).
4. **Execute iteratively** — get_template → write_file → shell_exec → observe → fix or move on.
5. **Think before pivoting** — after EVERY note_failure, call think() to reason about next steps.
6. **Record state** — use update_memory() to track partial results, extracted values, hypotheses.
7. **Finish decisively** — when you find the flag call finish(). \
   You may only call finish(NOT_FOUND) after ≥{min_fail} distinct failures AND after consulting \
   get_attack_tree AND after calling think at least once.

## Strict Rules
- NEVER retry an approach listed under "ALREADY TRIED" below.
- NEVER guess a flag — find it through execution.
- After every note_failure → MUST call think() next.
- **[SCRIPT FAILED — exit code N]** = your CODE has a bug. Fix the script immediately. \
  Read the traceback, find the exact line causing the crash, and rewrite the script. \
  Do NOT call note_failure on the attack method just because your python syntax failed.
- **[exit 0 — script ran but produced no output]** = add print() to debug intermediate values.
- Use update_memory to preserve all important values (n, e, c, partial results) so you never lose them.
- If one implementation fails, try a different implementation of the same attack before abandoning it.

## MANDATORY EXECUTION REQUIREMENT
- ALWAYS write and run actual Python/bash code. Reasoning alone counts for nothing.
- get_template → write_file → shell_exec is the minimum loop per attack attempt.
- "I need SageMath" is not valid — implement math in pure Python (sympy, gmpy2, from scratch).
- NEVER ask the user to run a script for you. YOU are running the scripts.
- NEVER instruct the user to "Use a real computer". YOU must execute the tool.
- NEVER ask the user whether to try approach A vs B — choose yourself.
- NEVER ask the user to run commands and paste back results — YOU run the commands.
- `ask_human` is ONLY for physically unreachable resources (e.g., a flag on a live machine you have no shell on). It requires ≥{min_fail} distinct note_failure() calls first.

## POWER TOOLS — use these proactively
- **delegate_task**: Offload a subtask to a Haiku sub-agent (e.g. fuzz binary while you analyse, crack hash in parallel). Use when you have two independent paths to explore simultaneously.
- **run_afl**: When pwn vulnerability type is unknown — fuzz first, then analyse crashes.
- **cyclic_offset**: ALWAYS use this at the start of pwn challenges to find the exact overflow offset.
- **ltrace_run**: Try BEFORE angr for rev challenges — flags often leak in strcmp/memcmp calls in plain text.
- **ghidra_analyze**: More accurate decompilation than r2ghidra for complex binaries.
- **one_gadget**: After libc leak, find single-gadget RCE address — no full ROP chain needed.
- **nmap_scan**: For network/nc challenges, always scan the service first.
- **crypto_identify**: Run on any unknown hash/encoding to classify it before attempting attacks.
- **angr_solve**: Use for symbolic execution on hard rev/pwn challenges. Check the Capabilities Manifest in Working Memory for availability — if listed as available, use it freely for path exploration and constraint solving.

## SELF-IMPROVEMENT (SKILL LIBRARY)
- You have access to a persistent skill library. All scripts in `data/agent_skills/` can be imported \
  in any python script you write (e.g., `from agent_skills.aes_padding import exploit`).
- When you successfully write a robust, reusable exploit/script (like a generic RSA attack, format string \
  leak, etc.), use the `save_skill` tool to save it so you can reuse it in future challenges.

- **gdb_analyze**: For native x86/x86_64 crash analysis. For ARM: use qemu_gdb or unicorn_emulate.
- **unicorn_emulate**: YOUR KEY TOOL FOR ARM CRACKMES. Emulates any ARM/x86 function in isolation — \
no OS needed. Give it the function address from r2/ghidra, the input registers, and it returns \
the output registers. Runs in 0.5s. Use for: PRNG cracking, hash functions, validation logic. \
To bruteforce a PRNG: call shell_exec with a Python loop that calls unicorn_emulate logic inline.
- **qemu_gdb**: ARM/MIPS tracing via qemu built-in strace/asm logging (gdb-multiarch not installed). \
Use: qemu_gdb(binary="./vault_app", gdb_cmds=["strace"], stdin_input="2\\n123456\\n", rootfs="...") \
to see every syscall (read/write) and the exact bytes compared — often reveals the expected token directly.

## NEVER CLAIM MISSING TOOLS OR UNFEASIBILITY
You have: unicorn_emulate, qemu_gdb, gdb_analyze, ghidra_analyze, r2_analyze, ltrace_run, z3_solve, shell_exec.
The following phrases are FORBIDDEN — writing them wastes iterations and is never accurate:
  ✗ "I don't have symbolic execution" / "I lack GDB" / "I cannot run qemu"
  ✗ "not feasible here" / "not feasible in this environment"
  ✗ "tool constraints prevent" / "given tool constraints"
  ✗ "cannot be done through this interface"
  ✗ "fully reconstructing ... isn't feasible"
  ✗ "I don't have access to" [any tool you can see in your tool list]
If a tool errors → read the error, fix the parameters, retry. If Ghidra fails → r2 auto-fallback runs.
If unicorn_emulate fails on a function → try a smaller func_size or different arch (arm vs arm_thumb).
There is ALWAYS another approach. Your job is to find it.

## ARM / EMBEDDED CRACKME PROTOCOL
For ARM ELF crackmes and embedded challenges (vault_app, crackme, etc.):
1. `r2_analyze` the binary: find the validation function (look for strcmp, memcmp, custom compare loop).
2. Run it with `qemu-arm -L <rootfs> ./binary` with stdin_input to explore the menu.
3. For PRNG-seeded tokens: use `unicorn_emulate` on the PRNG/token function with different seed values \
   to find which seed produces the observed token, then predict the response code.
4. For strcmp/memcmp: set a breakpoint with `qemu_gdb` at the compare, read r0/r1 to see both sides.
5. For hash functions: use `unicorn_emulate` to compute the expected hash for candidate inputs.

## BACKGROUND SHELLS (bg_shell)
You have multiple independent shells. Use bg_shell when you need two things running at once:
  • Start a server/service before attacking it:
      bg_shell(action='start', shell_id='srv', command='python3 -m http.server 8080')
      shell_exec(command='curl http://localhost:8080/')
      bg_shell(action='read', shell_id='srv')   ← check server logs
      bg_shell(action='kill', shell_id='srv')
  • Run qemu in background while reversing:
      bg_shell(action='start', shell_id='vm', command='qemu-arm -L rootfs ./binary', stdin_input='\\n')
      r2_analyze(binary='./binary', command='afl')  ← reverse in parallel
      bg_shell(action='read', shell_id='vm')
  • Netcat listener + exploit sender:
      bg_shell(action='start', shell_id='nc', command='nc -lvp 4444')
      shell_exec(command='python3 exploit.py')
      bg_shell(action='read', shell_id='nc')

## INTERACTIVE BINARIES (menus, prompts)
When running a binary that shows a menu or waits for input, you MUST use stdin_input:
  ✓ shell_exec(command="qemu-arm -L rootfs ./vault_app", stdin_input="1\\n123456\\n3\\n", timeout=10)
  ✗ shell_exec(command="qemu-arm -L rootfs ./vault_app", timeout=120)   ← WILL ALWAYS HANG/TIMEOUT
The binary output up to the first prompt is shown in stdout_before_timeout — read it to understand the menu.
For exploration (just to see the menu), use stdin_input="\\n" so it exits cleanly instead of hanging.

## NETWORK UNREACHABILITY PROTOCOL
If the target host is unreachable (HTTP timeout AND/OR nmap timeout both fail):
1. Call `ask_human` IMMEDIATELY with message: "Target <IP> is unreachable from this environment. Check VPN/routing. I need network access to proceed."
2. Do NOT loop. Do NOT run echo placeholders. Do NOT waste iterations echoing status messages.
3. NEVER use shell_exec to echo strings like 'tool call placeholder' or 'complying with requirements' — these are blocked and waste iterations.
4. One timeout = try a different port/protocol. TWO different tool timeouts = target is unreachable, escalate to human.

## LOOP PREVENTION — MANDATORY
The system tracks every tool call you make. If you call the same tool with the same arguments more than once:
- 2nd call: you receive the **cached result** with a warning. Re-reading will NOT give new information.
- 3rd call: final warning before a hard block.
- 4th+ call: **BLOCKED** — the call is cancelled, you receive an error. The result WILL NOT CHANGE.

If you see a `[DUPLICATE CALL]` or `[BLOCKED — LOOP DETECTED]` message:
1. **Stop immediately.** Do not call that tool again.
2. Call `think()` to reason about a completely different approach.
3. Call `note_failure()` to log the exhausted path.
4. Try a different tool, different arguments, or a different attack angle entirely.

**Calling the same analysis tool 3+ times on the same target is ALWAYS a bug in your reasoning, not a tool failure.**

## RAG / WRITEUP RESULTS — Anti-Contamination Rule
`search_writeups` and `get_attack_tree` return examples from **completely different past challenges**.
**NEVER extract or use a flag string from a search_writeups result as your answer.**
A flag like `FLAG{{...}}` or `AKASEC{{...}}` in a writeup result is from another CTF — it is WRONG for this challenge.
Only accept a flag as valid when it comes directly from a shell_exec, binary output, file content, or the binary itself.

## CONTEXT GROUNDING — Anti-Hallucination Rules
Confabulation (stating facts you haven't verified) wastes iterations and leads to dead ends.

1. **Confirmed vs hypothesis memory keys:**
   - Use `confirmed_<name>` keys for values extracted from actual tool output.
     e.g. `update_memory(key="confirmed_binary_path", value="/home/.../vault_app")`
     e.g. `update_memory(key="confirmed_prng_seed", value="1775949504")`
   - Use plain keys for working hypotheses:
     e.g. `update_memory(key="hypothesis", value="PRNG seeded from clock_gettime64")`
   The Working Memory block labels confirmed facts as GROUND TRUTH. Trust them. Never contradict them.

2. **Update memory after EVERY significant tool output:**
   After shell_exec, r2_analyze, ghidra_analyze, qemu_gdb, or unicorn_emulate returns output:
   - Extract key addresses, values, strings, or conclusions
   - Call update_memory with confirmed_ keys for each fact
   This ensures context compression never destroys your findings.

3. **Quote before claiming:** Before stating "the binary does X", you must have a tool output
   visible in your context that shows X. If you don't, run the tool first.

4. **Verify before re-running:** Check Working Memory before calling the same tool twice
   with the same arguments. If you already ran `file binary` and stored the result, don't run it again.

5. **[USER INSTRUCTION] messages are highest priority:** If you see a [USER INSTRUCTION] in
   the conversation, act on it immediately before continuing your current plan.

## ABSOLUTE PATHS — Non-Negotiable Rule
Each shell_exec runs in a **fresh, stateless bash shell** — `cd` commands do NOT persist between calls.
The output always starts with `[CWD: /absolute/path]` — that is your base.

**Rules:**
- ALWAYS use ABSOLUTE paths: `/home/work/ctf-tool-enset/workdir/file.bin`, NOT `./file.bin` or `file.bin`.
- After extracting/finding a file, IMMEDIATELY call `update_memory(key="confirmed_<name>_path", value="/absolute/path/to/it")`.
- Before any file operation, check Working Memory for the stored absolute path instead of re-listing.
- Pattern: `ls /abs/path/` → store absolute path → use `/abs/path/file` next. NEVER drop the prefix.
- Your `confirmed_workdir` memory key holds the base working directory — use it as prefix when unsure.

## CHALLENGE FILE DISCOVERY — MANDATORY FOR PWN/REV/FORENSICS
The first message includes a **"Challenge Files Found in Workdir"** section listing all discovered artifacts.
**Use those paths immediately.** Do NOT ignore that list. Do NOT search `outputs/` for previous runs.

If no file list was provided OR the binary is not found at the listed path:
```bash
find <confirmed_workdir> -maxdepth 4 -type f \
  ! -path "*/outputs/*" ! -path "*/.venv/*" ! -path "*/__pycache__/*" \
  ! -name "*.pyc" ! -name "*.log" 2>/dev/null | head -30
```
Challenge binaries are commonly in subdirectories like `challenges/`, `bin/`, `dist/`, or `src/`.
**NEVER assume the binary does not exist without running this find command first.**

## SPECIAL CHARACTERS IN PATHS — Mandatory Sanitisation
If any file, directory, or binary name contains **`'` (apostrophe), spaces, `(`, `)`, or other shell-special characters**, you MUST sanitise it BEFORE doing anything else:

```bash
# Step 1 — create a symlink to a clean path (no special chars)
ln -sf "/the/path/with'quote/binary" /tmp/ctf_bin
ln -sf "/the/dir/with'quote" /tmp/ctf_dir

# Step 2 — use ONLY the clean symlink for ALL subsequent operations
file /tmp/ctf_bin
checksec --file=/tmp/ctf_bin
LD_LIBRARY_PATH=/tmp/ctf_dir /tmp/ctf_bin
```

Store the clean path immediately: `update_memory(key="confirmed_binary_path", value="/tmp/ctf_bin")`
**NEVER attempt to quote or escape a path with a single quote in bash** — it is impossible to do reliably.
Use Python `subprocess.run([exe_path, ...], ...)` (list form, not shell=True) when shell quoting is unavoidable.
This rule applies to r2_analyze, ltrace_run, ghidra_analyze — pass the SYMLINKED path, not the original.

## PARALLEL TOOL CALLS — Speed Rule
You can call **multiple tools in a single response**. Use this aggressively for independent tasks:
- Analyse a file AND search writeups at the same time.
- Run a shell command AND call think() in the same turn.
- Check two different attack vectors simultaneously.
Every iteration that calls only ONE tool when two are independent is wasted time.

## SELF-HEALING EXPLOIT LOOP
**PRIMARY ACTION**: When shell_exec returns a crash, call `exploit_crash_analyze(crash_output=<output>)` IMMEDIATELY.
It gives you specific fix instructions. Do NOT call note_failure before calling exploit_crash_analyze first.
Auto-triage hints starting with ⚠️ [AUTO-TRIAGE] are injected automatically — follow them.

When your exploit crashes or produces wrong output, apply these fixes automatically — do NOT call note_failure:

**Crash: SIGSEGV / Illegal instruction near system()**
→ Add a bare `ret` gadget BEFORE system()/execve() in your ROP chain (16-byte stack alignment fix)
→ Find with: find_gadget(binary, 'ret')
→ Fix in pwntools: `rop.raw(ret_gadget); rop.system(binsh_addr)`

**Crash: SIGSEGV at wrong address / RIP corrupted**
→ Recalculate offset: run cyclic_offset again with larger max_length
→ Verify with gdb_analyze: the crash RIP should match your cyclic pattern
→ Check for SSP (stack canary): if crash is in __stack_chk_fail, you must leak canary first

**Crash: EOF / Connection reset**
→ Padding is wrong length — re-run cyclic_offset with gdb_analyze to confirm exact offset
→ Check architecture (32 vs 64-bit): 32-bit uses 4-byte addresses, 64-bit uses 8-byte
→ Verify binary is not expecting additional input (interactive) — check with ltrace

**Crash: SIGSEGV reading libc function**
→ Wrong libc base: re-examine the leaked address, check alignment
→ Use web_search(query='puts=0xXXX', intent='libc') to identify correct libc version + offsets
→ Try one_gadget(libc_path) — single-gadget RCE avoids offset calculation errors

**Crash: Heap assertion / abort() in malloc/free**
→ glibc version mismatch — detect exact version: `ldd --version; strings ./libc.so.6 | grep 'version'`
→ For double-free: use House of Botcake pattern instead of naive double-free
→ For tcache (glibc ≥2.32): encode fd with PROTECT_PTR: `fd_enc = target ^ (chunk_addr >> 12)`
→ For no hooks (glibc ≥2.34): switch to _IO_FILE / FSOP exploitation path

**Exploit produces output but wrong / no flag**
→ Check seccomp: `seccomp-tools dump ./binary` — may need ORW (open-read-write) chain, not execve
→ Check if flag is in file: use shell_exec('cat /flag /root/flag.txt /home/*/flag.txt 2>/dev/null')
→ Verify flag format: validate_flag() before submitting
→ Try different shell: /bin/bash, /bin/dash, /bin/sh — use `ls -la /bin/*sh`

## CRYPTO SELF-VERIFICATION RULE
For ANY crypto challenge, call `verify_crypto` BEFORE reporting the flag. This catches:
- Wrong XOR key order (encrypt then base64 ≠ base64 then encrypt)
- Off-by-one in multi-step encodings (base64→hex→ascii chain)
- Wrong RSA parameters (wrong n, wrong exponent)
- Morse code ambiguities (N=.-  vs  D=-..  vs  K=-.-  etc.)
- Vigenere key recovery errors

**verify_crypto modes:**
- `xor_base64`: re-decode base64 then XOR; compare to your plaintext
- `rsa_encrypt`: pow(m, e, n) == c?
- `cube_encrypt`: m^e == c (no mod, small e)
- `vigenere_encrypt`: re-encrypt your plaintext with recovered key == original ciphertext?
- `morse_decode`: decode the Morse to confirm your reading
- `base64_chain`: re-encode through multi-layer chain

**MANDATORY**: Call verify_crypto whenever you recover a crypto plaintext. Only submit the flag after PASS.

**Kernel exploit crashes / kernel panic**
→ Use KPTI trampoline (swapgs_restore_regs_and_return_to_usermode+22), NOT bare swapgs+iretq
→ Ensure all saved registers (cs, ss, rflags, rsp) are correct user-space values
→ Save user context BEFORE entering kernel exploit: `save_state()` → restore on panic

## MULTI-AGENT PLANNER PROTOCOL
For complex multi-stage exploits, split work between roles:

**PLANNER role (you):** Determine overall attack path, track state, synthesize results
**EXECUTOR role (delegate_task):** Run specific subtasks in parallel

Example delegation patterns:
```
# While you analyse the binary, delegate hash cracking
delegate_task(task='Crack this MD5 hash: 5f4dcc3b5aa765d61d8327deb882cf99', category='crypto')

# While you build the ROP chain, delegate libc version detection
delegate_task(task='Identify libc version from leaked address: puts @ 0x7f...d90',
              category='pwn', tools_hint='web_search')

# Parallel exploration of two heap paths
delegate_task(task='Test if tcache poisoning works on ./heap_binary: double-free chunk,
              write 0x4141414141 as fd, malloc twice, check if second malloc returns 0x4141...',
              category='pwn', tools_hint='shell_exec, gdb_analyze')
```

Use delegate_task whenever you have two independent things to verify simultaneously.
"""


def _build_system(session: Session, specialist_prompt: str = "") -> str:
    """Inject specialist prompt + current failure memory + working memory into system prompt."""
    from ctf_rag.tools import MIN_FAILURES_BEFORE_GIVING_UP
    prompt = BASE_SYSTEM_PROMPT.format(
        max_iter=MAX_ITERATIONS,
        min_fail=MIN_FAILURES_BEFORE_GIVING_UP,
    )
    if specialist_prompt:
        prompt = specialist_prompt  # Specialist prompt already includes base
    prompt += session.memory_block()
    prompt += session.failed_methods_block()

    # Inject capabilities manifest if it exists (built by `python -m ctf_rag.cli probe_tools`)
    _caps_path = Path("outputs/capabilities.json")
    if _caps_path.exists():
        try:
            _caps = json.loads(_caps_path.read_text(encoding="utf-8"))
            avail = [k for k, v in _caps.items() if v.get("status") == "available"]
            missing = [k for k, v in _caps.items() if v.get("status") != "available"]
            prompt += (
                "\n\n## Tool Capabilities Manifest (verified at startup)\n"
                f"**Available** ({len(avail)}): {', '.join(avail)}\n"
                f"**Missing** ({len(missing)}): {', '.join(missing) if missing else 'none'}\n"
                "Do NOT claim a tool is missing if it appears in the Available list above.\n"
            )
        except Exception:
            pass

    return prompt




# ---------------------------------------------------------------------------
# Global memory loader
# ---------------------------------------------------------------------------

def _load_past_experience(challenge: str, category: str | None) -> str:
    """
    Load relevant past experience from global_memory.json.
    Returns a formatted ## Past Experience block or empty string.
    """
    if not GLOBAL_MEMORY_PATH.exists():
        return ""
    try:
        records: list[dict] = json.loads(GLOBAL_MEMORY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return ""

    if not records:
        return ""

    # Match by category (primary) and keyword overlap (secondary)
    challenge_lower = challenge.lower()
    challenge_words = set(challenge_lower.split())

    scored = []
    for rec in records:
        score = 0
        rec_cat = rec.get("category", "").lower()
        if category and rec_cat == category.lower():
            score += 3
        elif rec_cat in challenge_lower:
            score += 1
        # keyword overlap with past challenge snippet
        past_words = set(rec.get("challenge_snippet", "").lower().split())
        overlap = len(challenge_words & past_words)
        score += min(overlap, 5)
        if score > 0:
            scored.append((score, rec))

    if not scored:
        return ""

    # Take top 3 by score
    top = sorted(scored, key=lambda x: -x[0])[:3]

    lines = ["\n\n## Past Experience (from previous sessions — learn from this)"]
    for score, rec in top:
        outcome = rec.get("outcome", "?")
        ts = rec.get("timestamp", "?")[:10]
        snippet = rec.get("challenge_snippet", "")[:100]
        failed = rec.get("failed_methods", [])
        thought = rec.get("thoughts_summary", "")[:200]
        lesson = rec.get("lesson_learned", "")
        
        entry = (
            f"\n**[{ts}] {outcome}** — {snippet}...\n"
            f"  Failed approaches: {'; '.join(failed[:3]) or 'none'}\n"
            f"  Last reasoning: {thought or 'n/a'}"
        )
        if lesson:
            entry += f"\n  [bold red]CRITICAL LESSON FROM THIS FAILURE:[/bold red] {lesson}"
            
        lines.append(entry)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Preemptive tool-output sanitizer — prevent Azure content policy violations
# ---------------------------------------------------------------------------

import re as _re

# Regex patterns that commonly trigger Azure's content policy on CTF content
_POLICY_PATTERNS = [
    # Large C++ hex arrays like {0x800000cd, 0x600000c6, ...} (obfuscated strings)
    (_re.compile(r'\{(?:\s*0x[0-9a-fA-F]+\s*,\s*){4,}[^}]*\}'), '[hex_array]'),
    # Long hex literals (shellcode, encoded data) > 8 chars
    (_re.compile(r'0x[0-9a-fA-F]{9,}'), lambda m: m.group(0)[:10] + '...'),
    # isBeingDebugged / anti-debugging function names
    (_re.compile(r'isBeingDebugged\s*\(\)', _re.IGNORECASE), 'isAntiDebug()'),
    # Very long single lines (> 400 chars) in source code — likely obfuscated data
    (_re.compile(r'[^\n]{400,}'), lambda m: m.group(0)[:200] + ' ...[line truncated]'),
]

# Cap for any single tool result added to message history
_TOOL_RESULT_MAX_CHARS = 6000


def _presanitize_tool_result(result: str) -> str:
    """
    Preemptively sanitize tool output before it enters the Azure message history.
    Strips patterns (large hex arrays, anti-debug strings, very long lines) that
    reliably trigger Azure content policy on CTF source code and binary analysis.
    """
    if len(result) <= 200:
        return result  # short results are never the problem

    sanitized = result
    for pattern, replacement in _POLICY_PATTERNS:
        if callable(replacement):
            sanitized = pattern.sub(replacement, sanitized)
        else:
            sanitized = pattern.sub(replacement, sanitized)

    # Hard cap on total length
    if len(sanitized) > _TOOL_RESULT_MAX_CHARS:
        sanitized = sanitized[:_TOOL_RESULT_MAX_CHARS] + "\n...[output truncated for context window]"

    return sanitized


# ---------------------------------------------------------------------------
# Backend adapters
# ---------------------------------------------------------------------------

def _clean_message(m: dict, max_chars: int = 200) -> dict:
    """Return a copy of message with tool/assistant content truncated to max_chars."""
    m2 = dict(m)
    role = m.get("role", "")
    if role == "tool":
        m2["content"] = "[tool output redacted]"
    elif role == "assistant":
        content = str(m.get("content", "") or "")
        m2["content"] = content[:max_chars] + "...[truncated]" if len(content) > max_chars else content
        # Strip tool_calls from assistant messages — they reference content we're wiping
        m2.pop("tool_calls", None)
    return m2


def _sanitize_messages_for_policy(messages: list[dict], level: int = 1) -> list[dict]:
    """
    Strip policy-flagged content from Azure message history.

    level=1 (default): redact middle tool outputs, sanitize tail too
    level=2 (escalated): redact ALL tool outputs and assistant content
    level=3 (nuclear):   keep only system + first user + neutral pivot
    """
    # Level 3: nuclear — minimal context, zero risk of re-triggering filter
    if level >= 3:
        system_msgs = [m for m in messages if m.get("role") == "system"]
        first_user = next((m for m in messages if m.get("role") == "user"), None)
        result = system_msgs[:]
        if first_user:
            result.append(first_user)
        result.append({"role": "user", "content": "Continue with the next step."})
        return result

    # Level 2: wipe all tool outputs and truncate all assistant messages
    if level == 2:
        sanitized = []
        for m in messages:
            sanitized.append(_clean_message(m, max_chars=100))
        # Drop orphaned tool messages (no preceding tool_call reference)
        final = []
        for m in sanitized:
            if m.get("role") == "tool" and (not final or final[-1].get("role") != "assistant"):
                continue
            final.append(m)
        return final

    # Level 1: redact middle + sanitize tail (fix: tail was previously unsanitized)
    head = messages[:2]   # system + first user
    rest = messages[2:]

    sanitized = []
    for m in rest:
        sanitized.append(_clean_message(m, max_chars=200))

    # Drop tool messages that would be orphaned (no tool_calls in preceding assistant)
    final = []
    for m in sanitized:
        if m.get("role") == "tool":
            if not final or final[-1].get("role") != "assistant":
                continue
        final.append(m)

    return head + final


def _is_policy_error(e: BadRequestError) -> bool:
    err_str = str(e)
    err_body = getattr(e, "body", {}) or {}
    err_obj = err_body.get("error", {}) if isinstance(err_body, dict) else {}
    err_code = err_obj.get("code", "") or ""
    return (
        "invalid_prompt" in err_str
        or err_code in ("invalid_prompt", "content_filter")
        or "content management policy" in err_str
        or "ResponsibleAI" in err_str
        or "role 'tool' must be a response" in err_str
        or "tool_calls" in err_str
    )


def _azure_call_with_retry_and_policy(client, deployment, messages, tools, console, msg_list, session=None):
    """
    Call Azure OpenAI with:
    - 429 rate-limit: exponential backoff (20s / 40s / 80s, 3 retries)
    - Content policy / orphaned message: escalating sanitization (level 1→2→3)
      Level 1: redact all tool outputs + truncate assistant content
      Level 2: wipe everything except head + tail assistant text
      Level 3: nuclear — system + first user only
    Returns response or None (caller should `continue` the iteration loop).
    """
    import time as _time

    def _do_call(msgs):
        return client.chat.completions.create(
            model=deployment, messages=msgs, tools=tools,
            tool_choice="auto", max_completion_tokens=8192,
        )

    # --- First attempt with rate-limit retry ---
    for _attempt in range(4):
        try:
            return _do_call(messages)
        except BadRequestError as e:
            if not _is_policy_error(e):
                raise
            # Policy error — fall through to escalating sanitize block below
            break
        except Exception as _err:
            _estr = str(_err)
            if "429" in _estr or "too_many_requests" in _estr.lower():
                if _attempt == 3:
                    console.print("[red]✗ Rate limit persists after 3 retries. Skipping.[/red]")
                    return None
                _wait = 20 * (2 ** _attempt)
                console.print(f"[yellow]⚠ Rate limited — waiting {_wait}s ({_attempt+1}/3)...[/yellow]")
                _time.sleep(_wait)
            else:
                raise

    # --- Escalating sanitization (policy errors) ---
    for level in (1, 2, 3):
        console.print(f"[yellow]⚠ Azure content policy — sanitizing level {level}/3...[/yellow]")
        sanitized = _sanitize_messages_for_policy(messages, level=level)
        try:
            return _do_call(sanitized)
        except BadRequestError as e:
            if not _is_policy_error(e):
                raise
            if level == 3:
                # Completely exhausted — inject pivot and skip iteration
                console.print("[red]✗ Blocked at all sanitization levels. Injecting pivot.[/red]")
                # Build a context-aware pivot using current working memory
                pivot_lines = [
                    "⚠ Context was wiped due to content policy. Your working memory is preserved "
                    "in the system prompt above — check it before doing anything.",
                ]
                if session is not None and hasattr(session, "working_memory"):
                    mem = session.working_memory
                    if mem:
                        already_set = ", ".join(
                            f"{k}={v[:40]}" for k, v in list(mem.items())[:6]
                        )
                        pivot_lines.append(
                            f"Already recorded in memory: {already_set}. "
                            f"Do NOT call update_memory for any of these keys — they are already set. "
                            f"Proceed to the NEXT task: write and run code, read a file, or analyse the challenge."
                        )
                    if session.failed_methods:
                        pivot_lines.append(
                            f"Already tried (do NOT repeat): "
                            + "; ".join(session.failed_methods[-3:])
                        )
                pivot_lines.append(
                    "Take a new concrete action (shell_exec, write_file, read_file, etc.) "
                    "— do NOT just update memory."
                )
                msg_list.append({
                    "role": "user",
                    "content": " ".join(pivot_lines),
                })
                return None
            # else: escalate to next level
        except Exception as _err:
            _estr = str(_err)
            if "429" in _estr or "too_many_requests" in _estr.lower():
                console.print("[yellow]⚠ Rate limited during sanitized retry — waiting 30s...[/yellow]")
                _time.sleep(30)
            else:
                raise

    return None


def _get_nvidia_client():
    """OpenAI-compatible client pointed at NVIDIA NIM."""
    from openai import OpenAI
    key = os.getenv("NVIDIA_API_KEY")
    if not key or key == "your-nvidia-key-here":
        raise ValueError("NVIDIA_API_KEY not set in .env")
    return OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=key,
    )


def _get_openrouter_client():
    """OpenAI-compatible client pointed at OpenRouter."""
    from openai import OpenAI
    key = os.getenv("OPENROUTER_API_KEY")
    if not key or key == "your-openrouter-key-here":
        raise ValueError("OPENROUTER_API_KEY not set in .env")
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=key,
    )


def _get_deepseek_client():
    """OpenAI-compatible client pointed at DeepSeek API."""
    from openai import OpenAI
    key = os.getenv("DEEPSEEK_API_KEY")
    if not key or key == "your-deepseek-key-here":
        raise ValueError("DEEPSEEK_API_KEY not set in .env")
    return OpenAI(
        base_url="https://api.deepseek.com",
        api_key=key,
    )


def _get_anthropic_client() -> anthropic.Anthropic:
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key or key == "sk-ant-your-key-here":
        raise ValueError("ANTHROPIC_API_KEY not set in .env")
    return anthropic.Anthropic(api_key=key)


def _get_azure_client() -> AzureOpenAI:
    key = os.getenv("AZURE_OPENAI_API_KEY")
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "https://graphopen.openai.azure.com/")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
    if not key or key == "your-azure-key-here":
        raise ValueError("AZURE_OPENAI_API_KEY not set in .env")
    return AzureOpenAI(api_key=key, azure_endpoint=endpoint, api_version=api_version)


def _anthropic_tools() -> list[dict]:
    return [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
            for t in TOOL_SCHEMAS if t["name"] not in _DISABLED_TOOLS]


def _azure_tools() -> list[dict]:
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
             "parameters": t["parameters"]}} for t in TOOL_SCHEMAS if t["name"] not in _DISABLED_TOOLS]


# ---------------------------------------------------------------------------
# Shared event renderer
# ---------------------------------------------------------------------------

# Tools whose output is worth showing to the user
_SHOW_RESULT_TOOLS = frozenset({
    "shell_exec", "bg_shell", "http_get", "http_post",
    "search_writeups", "nmap_scan", "r2_analyze", "ghidra_analyze",
    "gdb_analyze", "ltrace_run", "strace_run", "angr_solve",
    "unicorn_emulate", "qemu_gdb", "verify_crypto", "web_search",
})

# Tools shown only as a dim one-liner (no result panel)
_SILENT_TOOLS = frozenset({
    "update_memory", "save_state", "revert_state", "read_file",
    "write_file", "get_template", "save_skill", "cyclic_offset",
    "one_gadget", "find_gadget", "checksec", "strings_search",
    "crypto_identify", "z3_solve",
})

_TOOL_COLORS = {
    "note_failure":   "red",
    "finish":         "bold magenta",
    "shell_exec":     "yellow",
    "bg_shell":       "yellow",
    "http_get":       "cyan",
    "http_post":      "cyan",
    "search_writeups":"blue",
    "get_attack_tree":"blue",
    "get_template":   "green",
    "write_file":     "green",
    "think":          "bright_blue",
    "delegate_task":  "magenta",
}


def _tool_summary(name: str, args: dict) -> str:
    """One-line human-readable summary of a tool call."""
    if name == "shell_exec":
        cmd = args.get("command", "")
        return f'"{cmd}"'[:100]
    if name == "bg_shell":
        action = args.get("action", "")
        sid = args.get("shell_id", "?")
        if action == "start":
            return f"[{sid}] start: {args.get('command', '')[:60]}"
        return f"[{sid}] {action}"
    if name in ("http_get",):
        return args.get("url", "")[:90]
    if name == "http_post":
        url = args.get("url", "")[:50]
        data = args.get("data", args.get("json", args.get("body", "")))
        if isinstance(data, dict):
            data = " ".join(f"{k}={v}" for k, v in list(data.items())[:3])
        return f"{url}  {str(data)[:40]}"
    if name == "finish":
        flag = args.get("flag", "?")
        return f"flag = {flag}"
    if name == "note_failure":
        return args.get("method", "")[:80]
    if name == "update_memory":
        return f"{args.get('key','?')} = {str(args.get('value',''))[:50]}"
    if name == "think":
        return args.get("reasoning", "")[:80]
    if name == "write_file":
        return args.get("path", args.get("filename", "?"))
    if name == "read_file":
        return args.get("path", args.get("filename", "?"))
    if name in ("search_writeups", "get_attack_tree", "get_template"):
        return str(next(iter(args.values()), ""))[:70]
    if name == "delegate_task":
        return args.get("task", "")[:70]
    # Generic: first string value
    for v in args.values():
        if isinstance(v, str) and v:
            return v[:70]
    return ""


def _render_event(event: dict):
    etype = event["type"]

    if etype == "iteration":
        n, backend = event["n"], event["backend"]
        console.print(f"\n[dim]{'─' * 40}  {n}  [/dim][dim]{backend}[/dim]")

    elif etype == "thought":
        text = event["text"].strip()
        # Strip thinking-mode prefixes
        for prefix in ("[DeepSeek thinking]\n", "[Nemotron thinking]\n"):
            if text.startswith(prefix):
                text = text[len(prefix):]
        if len(text) < 20:
            return
        if len(text) > 400:
            text = text[:400] + "…"
        console.print(f"[dim italic]  {text}[/dim italic]")

    elif etype == "tool_call":
        name = event["name"]
        summary = _tool_summary(name, event["args"])
        color = _TOOL_COLORS.get(name, "white")
        parallel = f" [dim]×{event['parallel_count']}[/dim]" if event.get("parallel") else ""
        console.print(f"  [bold {color}]→ {name}[/bold {color}]{parallel}  [dim]{summary}[/dim]")

    elif etype == "tool_result":
        name = event["name"]
        if name in _SILENT_TOOLS:
            return
        if name not in _SHOW_RESULT_TOOLS:
            return
        result = event["result"]
        if len(result) > 1800:
            result = result[:1800] + "\n[…]"
        console.print(Panel(result, title=f"[dim]{name}[/dim]",
                            border_style="dim", padding=(0, 1)))

    elif etype == "failure_noted":
        console.print(f"  [red]✗[/red] [dim]{event['method'][:90]}[/dim]")

    elif etype == "memory_updated":
        # Only surface confirmed_ keys — others are bookkeeping noise
        key = event["key"]
        if key.startswith("confirmed_") or key in ("category", "hypothesis"):
            val = str(event["value"])[:60]
            console.print(f"  [dim cyan]◈[/dim cyan] [dim]{key} = {val}[/dim]")

    elif etype == "think":
        reasoning = event["reasoning"][:300]
        console.print(f"  [bright_blue]💭[/bright_blue]  [dim]{reasoning}[/dim]")

    elif etype == "finish":
        flag = event["data"].get("flag", "NOT_FOUND")
        if flag not in ("NOT_FOUND", "NOT_FOUND\n", ""):
            console.print(f"\n  [bold green]✓ Flag found:[/bold green] [bold]{flag}[/bold]")
        else:
            console.print(f"\n  [bold red]✗ Flag not found[/bold red]")

    elif etype == "_checkpoint":
        pass  # silent


# ---------------------------------------------------------------------------
# Startup file discovery
# ---------------------------------------------------------------------------

_SCAN_EXCLUDE_DIRS = frozenset({
    "outputs", ".venv", "venv", "__pycache__", ".git", "node_modules",
    "chroma_db", ".cache", ".idea", ".mypy_cache", "dist", "build",
    # The tool's own source and runtime dirs — never challenge files
    "ctf_rag", "agent_skills",
    # Previous-session extraction artifacts
    "workdir", "data",
})

_SCAN_INTERESTING_EXT = frozenset({
    # Binaries / firmware
    ".bin", ".elf", ".ko", ".so", ".exe", ".dll",
    # Mobile
    ".apk", ".ipa", ".dex",
    # Archives / disk images
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".iso", ".img",
    # Network
    ".pcap", ".pcapng", ".cap",
    # Crypto / data
    ".pem", ".key", ".crt", ".der", ".p12",
    # Code
    ".py", ".js", ".ts", ".rb", ".php", ".c", ".cpp", ".go", ".rs", ".sol",
    # Documents / config
    ".json", ".yaml", ".yml", ".txt", ".md",
    # Compiled
    ".pyc", ".class", ".jar",
})


def _scan_challenge_files(cwd: Path) -> list[str]:
    """
    Scan `cwd` (depth ≤ 4) for files that look like challenge artifacts.

    Prioritisation order:
      1. Executables / binaries (ELF, PE, scripts with executable bit)
      2. Non-Python files in challenge-named subdirs (challenges/, bin/, dist/, src/)
      3. Data files: pcap, zip, apk, txt, json, sol, c, etc.
      4. Python/Ruby/JS source files in challenge subdirs
      5. Root-level Python files (solve scripts — lowest priority)

    Excludes: outputs/, .venv/, ctf_rag/ (tool source), __pycache__, etc.
    Returns a list of absolute paths, capped at 40 files.
    """
    import stat as _stat

    # Priority buckets: 0 = highest priority
    buckets: dict[int, list[str]] = {0: [], 1: [], 2: [], 3: [], 4: []}

    _CHALLENGE_SUBDIRS = {"challenges", "challenge", "bin", "dist", "src",
                           "attachments", "files", "chall", "task", "prob"}

    try:
        for p in cwd.rglob("*"):
            try:
                rel = p.relative_to(cwd)
                if len(rel.parts) > 4:
                    continue
            except ValueError:
                continue

            # Skip excluded dirs
            if any(part in _SCAN_EXCLUDE_DIRS for part in rel.parts):
                continue

            if not p.is_file():
                continue

            in_challenge_subdir = bool(
                rel.parts and rel.parts[0].lower() in _CHALLENGE_SUBDIRS
            )
            ext = p.suffix.lower()
            path_str = str(p)

            # Bucket 0: executables without extension (ELF, PE, shebang)
            if not ext:
                try:
                    mode = p.stat().st_mode
                    if mode & (_stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH):
                        with open(p, "rb") as _fh:
                            magic = _fh.read(4)
                        if magic in (b'\x7fELF', b'MZ\x90\x00',
                                     b'#!\x2f', b'\xca\xfe\xba\xbe'):
                            buckets[0].append(path_str)
                            continue
                except Exception:
                    pass
                # No extension, not executable → skip
                continue

            # Bucket 0: binary/firmware files (always interesting)
            if ext in (".bin", ".elf", ".ko", ".so", ".exe", ".dll",
                       ".apk", ".ipa", ".dex"):
                buckets[0].append(path_str)
                continue

            # Bucket 1: archive/network/crypto artifacts
            if ext in (".pcap", ".pcapng", ".cap",
                       ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
                       ".iso", ".img", ".pem", ".key", ".crt", ".der"):
                buckets[1].append(path_str)
                continue

            # Bucket 2: data / config in challenge subdirs
            if ext in (".txt", ".json", ".yaml", ".yml", ".xml",
                       ".sol", ".c", ".cpp", ".go", ".rs",
                       ".jar", ".class"):
                buckets[2].append(path_str)
                continue

            # Bucket 3: source code files in challenge subdirs
            if ext in (".py", ".js", ".ts", ".rb", ".php") and in_challenge_subdir:
                buckets[3].append(path_str)
                continue

            # Bucket 4: root-level .py solve scripts (previous attempt artifacts)
            # Include only .txt/.md/data files at root, skip root .py
            if ext in (".txt", ".md") and len(rel.parts) == 1:
                buckets[4].append(path_str)
                continue

        # Merge in priority order, sorting within each bucket
        merged: list[str] = []
        for pri in sorted(buckets):
            merged.extend(sorted(buckets[pri]))
    except Exception:
        merged = []

    return merged[:40]


# ---------------------------------------------------------------------------
# Stagnation / anti-loop helpers
# ---------------------------------------------------------------------------

_STAGNATION_WINDOW = 4  # consecutive duplicate calls before forcing a pivot


def _maybe_inject_stagnation_pivot(session: "Session", messages: list[dict],
                                    iteration: int) -> bool:
    """
    If the session reports stagnation (no unique new tool calls in the last
    _STAGNATION_WINDOW turns), inject a hard pivot message into the conversation.

    Returns True if a pivot was injected (caller should `continue` the iteration).
    """
    if not session.is_stagnating(_STAGNATION_WINDOW):
        return False

    failed = "\n".join(f"  ✗ {m}" for m in session.failed_methods[-8:])
    pivot_msg = (
        f"[EMERGENCY PIVOT — STAGNATION DETECTED AT ITERATION {iteration}]\n\n"
        f"You have called the same tools with the same arguments repeatedly for the last "
        f"{_STAGNATION_WINDOW}+ turns. This is a loop. You are not making progress.\n\n"
        f"MANDATORY ACTIONS — do ALL of these right now:\n"
        f"1. Call think() — reason about WHY your current approach is not working\n"
        f"2. Call note_failure() — log the exhausted approach\n"
        f"3. Pick a COMPLETELY DIFFERENT attack angle:\n"
        f"   - If you have been doing static analysis → try dynamic (run the binary, strace, ltrace)\n"
        f"   - If you have been running the binary → try symbolic execution (angr) or SMT (z3)\n"
        f"   - If you have been decompiling → try a different tool (ghidra vs r2 vs objdump)\n"
        f"   - If stuck on one function → step back, look at the full program flow from main\n"
        f"   - If all analysis fails → get_attack_tree to reset your strategy\n\n"
        f"Already failed approaches:\n{failed or '(none logged yet)'}\n\n"
        f"Do NOT call any tool you have already called with the same arguments."
    )
    console.print(f"\n[bold red]⚠ Stagnation detected at iter {iteration} — forcing pivot[/bold red]")
    messages.append({"role": "user", "content": pivot_msg})

    # Reset stagnation counter so we don't spam every iteration
    session._stagnation_counter = 0
    session._last_unique_iteration = iteration
    return True


# ---------------------------------------------------------------------------
# Claude loop
# ---------------------------------------------------------------------------

_CHECKPOINT_INTERVAL = 5   # save checkpoint every N iterations


def _run_claude(challenge: str, session: Session, past_experience: str, specialist_prompt: str = "",
                inject_queue: "queue.Queue | None" = None,
                initial_messages: "list[dict] | None" = None,
                start_iteration: int = 1) -> Generator[dict, None, None]:
    client = _get_anthropic_client()
    tools = _anthropic_tools()

    if initial_messages is not None:
        messages = initial_messages
    else:
        first_content = challenge
        if past_experience:
            first_content = past_experience + "\n\n" + challenge
        messages = [{"role": "user", "content": first_content}]

    for iteration in range(start_iteration, MAX_ITERATIONS + 1):
        # Drain any user-injected instructions before calling the LLM
        if inject_queue:
            while not inject_queue.empty():
                try:
                    injected = inject_queue.get_nowait()
                    console.print(f"\n[bold yellow]📩 User instruction injected:[/bold yellow] {injected}")
                    messages.append({"role": "user", "content": f"[USER INSTRUCTION — act on this immediately] {injected}"})
                except Exception:
                    pass

        yield {"type": "iteration", "n": iteration, "backend": "claude"}
        session._current_iteration = iteration
        if _maybe_inject_stagnation_pivot(session, messages, iteration):
            continue

        # Compress context if growing large
        messages = session.compress_history(messages, max_chars=80_000)

        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            system=_build_system(session, specialist_prompt),
            tools=tools,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        tool_results = []
        finished = False
        finish_data = None

        # Split blocks into text thoughts + tool calls
        tool_blocks = [b for b in response.content if b.type == "tool_use"]
        for block in response.content:
            if block.type == "text" and block.text.strip():
                yield {"type": "thought", "text": block.text}

        # --- Parallel execution when multiple independent tools are called ---
        # Sequential-only tools are run one-by-one after parallel batch completes.
        parallel_blocks = [b for b in tool_blocks if b.name in _PARALLEL_SAFE]
        sequential_blocks = [b for b in tool_blocks if b.name not in _PARALLEL_SAFE]

        results_map: dict[str, str] = {}  # block.id → result

        def _run_one(blk) -> tuple[str, str]:
            """Execute a single tool call, tracking shell activity."""
            is_shell = blk.name in ("shell_exec", "bg_shell")
            if is_shell:
                _inc_shells()
            try:
                res = execute_tool(blk.name, blk.input, session)
                if blk.name == "shell_exec":
                    res = _inject_crash_hint(res)
                return blk.id, res
            finally:
                if is_shell:
                    _dec_shells()

        if len(parallel_blocks) > 1:
            # Announce all parallel calls before running them
            for blk in parallel_blocks:
                yield {"type": "tool_call", "name": blk.name, "args": blk.input,
                       "parallel": True, "parallel_count": len(parallel_blocks)}
            with ThreadPoolExecutor(max_workers=min(len(parallel_blocks), 8)) as pool:
                futures = {pool.submit(_run_one, blk): blk for blk in parallel_blocks}
                for fut in as_completed(futures):
                    blk_id, res = fut.result()
                    results_map[blk_id] = res
        else:
            for blk in parallel_blocks:
                yield {"type": "tool_call", "name": blk.name, "args": blk.input}
                _, res = _run_one(blk)
                results_map[blk.id] = res

        for blk in sequential_blocks:
            yield {"type": "tool_call", "name": blk.name, "args": blk.input}
            _, res = _run_one(blk)
            results_map[blk.id] = res

        # Process results in original block order
        for block in tool_blocks:
            result = results_map[block.id]

            if block.name == "note_failure":
                yield {"type": "failure_noted", "method": block.input.get("method", "")}
            elif block.name == "think":
                yield {"type": "think", "reasoning": block.input.get("reasoning", "")}
            elif block.name == "update_memory":
                yield {"type": "memory_updated",
                       "key": block.input.get("key", ""),
                       "value": block.input.get("value", "")}
            elif block.name == "finish" and not result.startswith("[FINISH REJECTED]"):
                finished = True
                finish_data = block.input

            yield {"type": "tool_result", "name": block.name, "result": result}
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result,
            })

            # Checkpoint tracking logic for Claude
            if block.name == "save_state":
                session.working_memory["_checkpoint_messages_" + block.input.get("checkpoint_name", "")] = str(len(messages))
            elif block.name == "revert_state" and not result.startswith("[error]"):
                rollback_idx = session.working_memory.get("_checkpoint_messages_" + block.input.get("checkpoint_name", ""))
                if rollback_idx and rollback_idx.isdigit():
                    idx = int(rollback_idx)
                    if idx < len(messages):
                        messages = messages[:idx]
                        result += " [Context history rolled back correctly.]"
                        tool_results[-1]["content"] = result

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

        # Auto-save checkpoint every N iterations
        if iteration % _CHECKPOINT_INTERVAL == 0:
            session.save_checkpoint(messages, "claude", specialist_prompt, iteration)
            yield {"type": "_checkpoint", "iteration": iteration, "path": str(session.dir / "checkpoint_latest.json")}

        if finished:
            yield {"type": "finish", "data": finish_data}
            return

        if response.stop_reason == "end_turn" and not tool_results:
            messages.append({"role": "user", "content": "[SYSTEM] You stopped without calling a tool. You CANNOT give up. You MUST call a tool (e.g., shell_exec, ask_human, or finish)."})
            continue

    yield {"type": "finish", "data": {"report": f"Hit {MAX_ITERATIONS} iterations.", "flag": "NOT_FOUND"}}


# ---------------------------------------------------------------------------
# Azure loop
# ---------------------------------------------------------------------------

def _run_azure(challenge: str, session: Session, past_experience: str, specialist_prompt: str = "",
               inject_queue: "queue.Queue | None" = None,
               initial_messages: "list[dict] | None" = None,
               start_iteration: int = 1) -> Generator[dict, None, None]:
    client = _get_azure_client()
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1")
    tools = _azure_tools()

    if initial_messages is not None:
        messages = initial_messages
    else:
        first_content = challenge
        if past_experience:
            first_content = past_experience + "\n\n" + challenge
        messages = [
            {"role": "system", "content": _build_system(session)},
            {"role": "user", "content": first_content},
        ]

    for iteration in range(start_iteration, MAX_ITERATIONS + 1):
        # Drain any user-injected instructions before calling the LLM
        if inject_queue:
            while not inject_queue.empty():
                try:
                    injected = inject_queue.get_nowait()
                    console.print(f"\n[bold yellow]📩 User instruction injected:[/bold yellow] {injected}")
                    messages.append({"role": "user", "content": f"[USER INSTRUCTION — act on this immediately] {injected}"})
                except Exception:
                    pass

        yield {"type": "iteration", "n": iteration, "backend": "azure"}
        session._current_iteration = iteration
        if _maybe_inject_stagnation_pivot(session, messages, iteration):
            continue

        # Rebuild system prompt with latest memory + failure memory every iteration
        messages[0]["content"] = _build_system(session, specialist_prompt)

        # Compress context if growing too large
        messages_to_send = session.compress_history(list(messages), max_chars=80_000)

        response = _azure_call_with_retry_and_policy(
            client, deployment, messages_to_send, tools,
            console, messages, session=session,
        )
        if response is None:
            continue  # rate-limit exhausted or policy blocked — already handled

        msg = response.choices[0].message
        msg_dict = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            msg_dict["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        messages.append(msg_dict)

        if msg.content:
            yield {"type": "thought", "text": msg.content}

        finished = False
        finish_data = None

        if msg.tool_calls:
            # Parse all tool calls first
            parsed_tcs = []
            for tc in msg.tool_calls:
                try:
                    tool_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}
                parsed_tcs.append((tc, tc.function.name, tool_args))

            parallel_tcs = [(tc, n, a) for tc, n, a in parsed_tcs if n in _PARALLEL_SAFE]
            sequential_tcs = [(tc, n, a) for tc, n, a in parsed_tcs if n not in _PARALLEL_SAFE]

            az_results: dict[str, str] = {}  # tc.id → result

            def _run_az(tc_name_args) -> tuple[str, str]:
                tc, tname, targs = tc_name_args
                is_shell = tname in ("shell_exec", "bg_shell")
                if is_shell:
                    _inc_shells()
                try:
                    res = execute_tool(tname, targs, session)
                    if tname == "shell_exec":
                        res = _inject_crash_hint(res)
                    return tc.id, res
                finally:
                    if is_shell:
                        _dec_shells()

            if len(parallel_tcs) > 1:
                for tc, tname, targs in parallel_tcs:
                    yield {"type": "tool_call", "name": tname, "args": targs,
                           "parallel": True, "parallel_count": len(parallel_tcs)}
                with ThreadPoolExecutor(max_workers=min(len(parallel_tcs), 8)) as pool:
                    futures = {pool.submit(_run_az, item): item for item in parallel_tcs}
                    for fut in as_completed(futures):
                        tid, res = fut.result()
                        az_results[tid] = res
            else:
                for item in parallel_tcs:
                    tc, tname, targs = item
                    yield {"type": "tool_call", "name": tname, "args": targs}
                    tid, res = _run_az(item)
                    az_results[tid] = res

            for item in sequential_tcs:
                tc, tname, targs = item
                yield {"type": "tool_call", "name": tname, "args": targs}
                tid, res = _run_az(item)
                az_results[tid] = res

            # Process in original order
            for tc, tool_name, tool_args in parsed_tcs:
                result = az_results[tc.id]

                if tool_name == "note_failure":
                    yield {"type": "failure_noted", "method": tool_args.get("method", "")}
                elif tool_name == "think":
                    yield {"type": "think", "reasoning": tool_args.get("reasoning", "")}
                elif tool_name == "update_memory":
                    yield {"type": "memory_updated",
                           "key": tool_args.get("key", ""),
                           "value": tool_args.get("value", "")}
                elif tool_name == "finish" and not result.startswith("[FINISH REJECTED]"):
                    finished = True
                    finish_data = tool_args

                yield {"type": "tool_result", "name": tool_name, "result": result}

                # Checkpoint tracking logic for Azure
                if tool_name == "save_state":
                    session.working_memory["_checkpoint_messages_" + tool_args.get("checkpoint_name", "")] = str(len(messages))
                elif tool_name == "revert_state" and not result.startswith("[error]"):
                    rollback_idx = session.working_memory.get("_checkpoint_messages_" + tool_args.get("checkpoint_name", ""))
                    if rollback_idx and rollback_idx.isdigit():
                        idx = int(rollback_idx)
                        if idx < len(messages):
                            messages = messages[:idx]
                            result += " [Context history rolled back correctly.]"

                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": _presanitize_tool_result(result)})

        # Auto-save checkpoint every N iterations
        if iteration % _CHECKPOINT_INTERVAL == 0:
            session.save_checkpoint(messages, "azure", specialist_prompt, iteration)
            yield {"type": "_checkpoint", "iteration": iteration, "path": str(session.dir / "checkpoint_latest.json")}

        if finished:
            yield {"type": "finish", "data": finish_data}
            return

        if response.choices[0].finish_reason == "stop" and not msg.tool_calls:
            messages.append({"role": "user", "content": "[SYSTEM] You stopped without calling a tool. You CANNOT give up. You MUST call a tool (e.g., shell_exec, ask_human, or finish)."})
            continue

    yield {"type": "finish", "data": {"report": f"Hit {MAX_ITERATIONS} iterations.", "flag": "NOT_FOUND"}}


# ---------------------------------------------------------------------------
# NVIDIA NIM / DeepSeek-V3 loop
# ---------------------------------------------------------------------------

def _run_nvidia(challenge: str, session: Session, past_experience: str, specialist_prompt: str = "",
                inject_queue: "queue.Queue | None" = None,
                initial_messages: "list[dict] | None" = None,
                start_iteration: int = 1) -> Generator[dict, None, None]:
    """
    Agent loop for NVIDIA NIM (DeepSeek-V3 with extended thinking).

    Uses the OpenAI-compatible NVIDIA endpoint.  Tool calling works the same
    as the Azure loop.  Extra feature: reasoning_content tokens from
    DeepSeek's extended thinking are yielded as "thought" events so they
    appear in the UI — this lets you watch the model's chain-of-thought live.
    """
    import time as _time
    from openai import OpenAI

    client = _get_nvidia_client()
    model = os.getenv("NVIDIA_MODEL", "deepseek-ai/deepseek-v3.2")
    tools = _azure_tools()  # same OpenAI function format

    if initial_messages is not None:
        messages = initial_messages
    else:
        first_content = challenge
        if past_experience:
            first_content = past_experience + "\n\n" + challenge
        messages = [
            {"role": "system", "content": _build_system(session, specialist_prompt)},
            {"role": "user", "content": first_content},
        ]

    for iteration in range(start_iteration, MAX_ITERATIONS + 1):
        # Drain user-injected instructions
        if inject_queue:
            while not inject_queue.empty():
                try:
                    injected = inject_queue.get_nowait()
                    console.print(f"\n[bold yellow]📩 User instruction injected:[/bold yellow] {injected}")
                    messages.append({"role": "user", "content": f"[USER INSTRUCTION — act on this immediately] {injected}"})
                except Exception:
                    pass

        # Refresh system prompt with latest memory every iteration
        messages[0]["content"] = _build_system(session, specialist_prompt)

        yield {"type": "iteration", "n": iteration, "backend": "nvidia/deepseek"}
        session._current_iteration = iteration
        if _maybe_inject_stagnation_pivot(session, messages, iteration):
            continue

        # Compress context if growing too large
        messages_to_send = session.compress_history(list(messages), max_chars=80_000)

        # ── Call NVIDIA with streaming to capture thinking tokens live ──
        try:
            stream = client.chat.completions.create(
                model=model,
                messages=messages_to_send,
                tools=tools,
                tool_choice="auto",
                max_tokens=8192,
                temperature=0.6,
                top_p=0.95,
                extra_body={"chat_template_kwargs": {"thinking": True}},
                stream=True,
            )
        except Exception as err:
            estr = str(err)
            if "429" in estr or "too_many_requests" in estr.lower():
                wait = 30
                console.print(f"[yellow]⚠ NVIDIA rate limit — waiting {wait}s...[/yellow]")
                _time.sleep(wait)
                continue
            raise

        # Collect streamed chunks
        reasoning_buf: list[str] = []
        content_buf: list[str] = []
        tool_calls_raw: dict[int, dict] = {}  # index → {id, name, arguments}
        finish_reason = None

        for chunk in stream:
            if not getattr(chunk, "choices", None):
                continue
            delta = chunk.choices[0].delta
            finish_reason = chunk.choices[0].finish_reason or finish_reason

            # Extended thinking tokens
            reasoning = getattr(delta, "reasoning_content", None)
            if reasoning:
                reasoning_buf.append(reasoning)

            # Regular content
            if delta.content:
                content_buf.append(delta.content)

            # Tool call deltas (streamed incrementally per OpenAI spec)
            if delta.tool_calls:
                for tc_delta in delta.tool_calls:
                    idx = tc_delta.index
                    if idx not in tool_calls_raw:
                        tool_calls_raw[idx] = {"id": "", "name": "", "arguments": ""}
                    if tc_delta.id:
                        tool_calls_raw[idx]["id"] = tc_delta.id
                    if tc_delta.function:
                        if tc_delta.function.name:
                            tool_calls_raw[idx]["name"] += tc_delta.function.name
                        if tc_delta.function.arguments:
                            tool_calls_raw[idx]["arguments"] += tc_delta.function.arguments

        # Emit reasoning as a thought block
        if reasoning_buf:
            reasoning_text = "".join(reasoning_buf)
            yield {"type": "thought", "text": f"[DeepSeek thinking]\n{reasoning_text}"}

        # Emit content as a thought block
        content_text = "".join(content_buf)
        if content_text.strip():
            yield {"type": "thought", "text": content_text}

        # Build the assistant message for history
        msg_dict: dict = {"role": "assistant", "content": content_text or ""}
        tool_calls_list = []
        if tool_calls_raw:
            for idx in sorted(tool_calls_raw):
                tc = tool_calls_raw[idx]
                tool_calls_list.append({
                    "id": tc["id"] or f"call_{idx}",
                    "type": "function",
                    "function": {"name": tc["name"], "arguments": tc["arguments"]},
                })
            msg_dict["tool_calls"] = tool_calls_list
        messages.append(msg_dict)

        finished = False
        finish_data = None

        for tc in tool_calls_list:
            tool_name = tc["function"]["name"]
            try:
                tool_args = json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                tool_args = {}

            yield {"type": "tool_call", "name": tool_name, "args": tool_args}

            result = execute_tool(tool_name, tool_args, session)

            if tool_name == "note_failure":
                yield {"type": "failure_noted", "method": tool_args.get("method", "")}
            elif tool_name == "think":
                yield {"type": "think", "reasoning": tool_args.get("reasoning", "")}
            elif tool_name == "update_memory":
                yield {"type": "memory_updated",
                       "key": tool_args.get("key", ""),
                       "value": tool_args.get("value", "")}
            elif tool_name == "finish" and not result.startswith("[FINISH REJECTED]"):
                finished = True
                finish_data = tool_args

            yield {"type": "tool_result", "name": tool_name, "result": result}

            # Checkpoint tracking
            if tool_name == "save_state":
                session.working_memory["_checkpoint_messages_" + tool_args.get("checkpoint_name", "")] = str(len(messages))
            elif tool_name == "revert_state" and not result.startswith("[error]"):
                rollback_idx = session.working_memory.get("_checkpoint_messages_" + tool_args.get("checkpoint_name", ""))
                if rollback_idx and rollback_idx.isdigit():
                    idx = int(rollback_idx)
                    if idx < len(messages):
                        messages = messages[:idx]
                        result += " [Context history rolled back correctly.]"

            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})

        # Auto-save checkpoint every N iterations
        if iteration % _CHECKPOINT_INTERVAL == 0:
            session.save_checkpoint(messages, "nvidia", specialist_prompt, iteration)
            yield {"type": "_checkpoint", "iteration": iteration, "path": str(session.dir / "checkpoint_latest.json")}

        if finished:
            yield {"type": "finish", "data": finish_data}
            return

        if finish_reason == "stop" and not tool_calls_list:
            messages.append({
                "role": "user",
                "content": "[SYSTEM] You stopped without calling a tool. You CANNOT give up. You MUST call a tool."
            })
            continue

    yield {"type": "finish", "data": {"report": f"Hit {MAX_ITERATIONS} iterations.", "flag": "NOT_FOUND"}}


# ---------------------------------------------------------------------------
# OpenRouter / Nemotron loop
# ---------------------------------------------------------------------------

def _run_openrouter(challenge: str, session: Session, past_experience: str, specialist_prompt: str = "",
                    inject_queue: "queue.Queue | None" = None,
                    initial_messages: "list[dict] | None" = None,
                    start_iteration: int = 1) -> Generator[dict, None, None]:
    """
    Agent loop for OpenRouter (Nemotron-3-Super-120B with reasoning).

    Key differences from other backends:
    - Uses `extra_body={"reasoning": {"enabled": True}}` (OpenRouter's format)
    - Reasoning is returned as `response.reasoning_details` (not streaming chunks)
    - For multi-turn coherence, `reasoning_details` is passed BACK in the
      assistant message — the model continues reasoning from where it left off.
    - Non-streaming so reasoning_details is preserved correctly.
    """
    import time as _time

    client = _get_openrouter_client()
    model = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
    tools = _azure_tools()  # same OpenAI function format

    if initial_messages is not None:
        messages: list[dict] = initial_messages
    else:
        first_content = challenge
        if past_experience:
            first_content = past_experience + "\n\n" + challenge
        # OpenRouter messages carry reasoning_details on assistant turns.
        messages = [
            {"role": "system", "content": _build_system(session, specialist_prompt)},
            {"role": "user", "content": first_content},
        ]

    for iteration in range(start_iteration, MAX_ITERATIONS + 1):
        # Drain user-injected instructions
        if inject_queue:
            while not inject_queue.empty():
                try:
                    injected = inject_queue.get_nowait()
                    console.print(f"\n[bold yellow]📩 User instruction injected:[/bold yellow] {injected}")
                    messages.append({"role": "user", "content": f"[USER INSTRUCTION — act on this immediately] {injected}"})
                except Exception:
                    pass

        # Refresh system prompt every iteration
        messages[0]["content"] = _build_system(session, specialist_prompt)

        yield {"type": "iteration", "n": iteration, "backend": f"openrouter/{model.split('/')[-1]}"}
        session._current_iteration = iteration
        if _maybe_inject_stagnation_pivot(session, messages, iteration):
            continue

        # Compress context (strip reasoning_details fields before sending to avoid bloat)
        messages_to_send = session.compress_history(list(messages), max_chars=80_000)

        # ── Non-streaming call with reasoning enabled ──
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages_to_send,
                tools=tools,
                tool_choice="auto",
                max_tokens=8192,
                extra_body={"reasoning": {"enabled": True}},
            )
        except Exception as err:
            estr = str(err)
            if "429" in estr or "rate" in estr.lower():
                wait = 30
                console.print(f"[yellow]⚠ OpenRouter rate limit — waiting {wait}s...[/yellow]")
                _time.sleep(wait)
                continue
            raise

        # OpenRouter sometimes returns choices=None on model errors (empty 200 response)
        if not response or not response.choices:
            err_body = getattr(response, "error", None) or getattr(response, "body", None)
            console.print(f"[yellow]⚠ OpenRouter returned empty choices (model may have errored): {err_body} — retrying...[/yellow]")
            _time.sleep(5)
            continue

        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        # ── Emit reasoning as a live thought ──
        reasoning_details = getattr(msg, "reasoning_details", None)
        reasoning_text = ""
        if reasoning_details:
            # reasoning_details is a list of {type, text, format, index} blocks
            if isinstance(reasoning_details, list):
                reasoning_text = "".join(
                    (b.get("text") or b.get("thinking") or "") if isinstance(b, dict) else str(b)
                    for b in reasoning_details
                )
            else:
                reasoning_text = str(reasoning_details)

        if reasoning_text.strip():
            yield {"type": "thought", "text": f"[Nemotron thinking]\n{reasoning_text}"}

        content_text = msg.content or ""
        if content_text.strip():
            yield {"type": "thought", "text": content_text}

        # ── Build assistant message — include reasoning_details for continuity ──
        msg_dict: dict = {"role": "assistant", "content": content_text}
        if reasoning_details is not None:
            msg_dict["reasoning_details"] = reasoning_details  # pass back unmodified
        if msg.tool_calls:
            msg_dict["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ]
        messages.append(msg_dict)

        finished = False
        finish_data = None

        if msg.tool_calls:
            for tc in msg.tool_calls:
                tool_name = tc.function.name
                try:
                    tool_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                yield {"type": "tool_call", "name": tool_name, "args": tool_args}

                result = execute_tool(tool_name, tool_args, session)

                if tool_name == "note_failure":
                    yield {"type": "failure_noted", "method": tool_args.get("method", "")}
                elif tool_name == "think":
                    yield {"type": "think", "reasoning": tool_args.get("reasoning", "")}
                elif tool_name == "update_memory":
                    yield {"type": "memory_updated",
                           "key": tool_args.get("key", ""),
                           "value": tool_args.get("value", "")}
                elif tool_name == "finish" and not result.startswith("[FINISH REJECTED]"):
                    finished = True
                    finish_data = tool_args

                yield {"type": "tool_result", "name": tool_name, "result": result}

                # Checkpoint tracking
                if tool_name == "save_state":
                    session.working_memory["_checkpoint_messages_" + tool_args.get("checkpoint_name", "")] = str(len(messages))
                elif tool_name == "revert_state" and not result.startswith("[error]"):
                    rollback_idx = session.working_memory.get("_checkpoint_messages_" + tool_args.get("checkpoint_name", ""))
                    if rollback_idx and rollback_idx.isdigit():
                        idx = int(rollback_idx)
                        if idx < len(messages):
                            messages = messages[:idx]
                            result += " [Context history rolled back correctly.]"

                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

        # Auto-save checkpoint every N iterations
        if iteration % _CHECKPOINT_INTERVAL == 0:
            session.save_checkpoint(messages, "openrouter", specialist_prompt, iteration)
            yield {"type": "_checkpoint", "iteration": iteration, "path": str(session.dir / "checkpoint_latest.json")}

        if finished:
            yield {"type": "finish", "data": finish_data}
            return

        if finish_reason == "stop" and not (msg.tool_calls):
            messages.append({
                "role": "user",
                "content": "[SYSTEM] You stopped without calling a tool. You CANNOT give up. You MUST call a tool.",
            })
            continue

    yield {"type": "finish", "data": {"report": f"Hit {MAX_ITERATIONS} iterations.", "flag": "NOT_FOUND"}}


# ---------------------------------------------------------------------------
# Multi-LLM support helpers — used by the hybrid backend
# ---------------------------------------------------------------------------

_PYTHON_TRACEBACK_RE = None  # initialised lazily below

def _has_python_error(result: str) -> bool:
    """Return True if a tool result contains a Python traceback or error."""
    global _PYTHON_TRACEBACK_RE
    if _PYTHON_TRACEBACK_RE is None:
        import re as _re
        _PYTHON_TRACEBACK_RE = _re.compile(
            r'(Traceback \(most recent call last\)|SyntaxError|IndentationError'
            r'|NameError|TypeError|AttributeError|ImportError|ValueError'
            r'|ModuleNotFoundError|ZeroDivisionError|RecursionError)',
            _re.MULTILINE,
        )
    return bool(_PYTHON_TRACEBACK_RE.search(result))


def _gemini_fix_code(command: str, error: str) -> "str | None":
    """
    Ask Gemini Flash to fix a failing Python/bash command.
    Returns the corrected command string, or None if Gemini is unavailable.
    """
    try:
        import google.genai as genai
        client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY", ""))
        _gemini_model = os.getenv("GEMINI_AUTOFIX_MODEL", "gemini-2.0-flash")
        prompt = (
            "You are a Python/bash expert fixing a CTF exploit command.\n"
            "The command below failed with the shown error. "
            "Return ONLY the corrected command (one line or a short heredoc), "
            "no explanation, no markdown fences.\n\n"
            f"COMMAND:\n{command[:1500]}\n\n"
            f"ERROR:\n{error[-1200:]}\n\n"
            "FIXED COMMAND:"
        )
        resp = client.models.generate_content(
            model=_gemini_model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(max_output_tokens=1024, temperature=0.0),
        )
        fixed = resp.text.strip()
        # Strip accidental markdown fences
        for fence in ("```bash\n", "```sh\n", "```python\n", "```\n", "```"):
            fixed = fixed.replace(fence, "")
        return fixed.strip() or None
    except Exception:
        return None


def _deepseek_initial_plan(challenge: str, session: "Session", specialist_prompt: str) -> str:
    """
    Call DeepSeek (R1 or V3) once at the start of a hybrid session to produce
    an initial attack strategy. Runs in a separate thread so it doesn't block
    the UI while initializing.
    Returns a formatted string to prepend to the first user message.
    """
    try:
        client = _get_deepseek_client()
        # Prefer deepseek-reasoner for the advisory role; fall back to V3
        advisor_model = os.getenv("DEEPSEEK_ADVISOR_MODEL",
                                   os.getenv("DEEPSEEK_MODEL", "deepseek-reasoner"))
        category = session.working_memory.get("category", "unknown")
        prompt = (
            f"You are an elite CTF solver doing initial triage. Category: {category}\n\n"
            f"Challenge:\n{challenge[:3000]}\n\n"
            "In 150 words or fewer: (1) most likely vulnerability/approach, "
            "(2) the EXACT first tool call to make, (3) what successful output looks like. "
            "Be specific — name algorithms, parameters, expected output format."
        )
        resp = client.chat.completions.create(
            model=advisor_model,
            messages=[
                {"role": "system", "content": (specialist_prompt[:800] if specialist_prompt
                                                else "You are a world-class CTF expert.")},
                {"role": "user", "content": prompt},
            ],
            max_tokens=700,
            temperature=0.0,
        )
        msg = resp.choices[0].message
        thinking = getattr(msg, "reasoning_content", "") or ""
        answer = (msg.content or "").strip()
        if thinking and len(thinking) > 50:
            return (f"[DeepSeek R1 Reasoning (condensed)]\n{thinking[:600]}\n\n"
                    f"[Action Plan]\n{answer}")
        return f"[DeepSeek Initial Analysis]\n{answer}"
    except Exception as exc:
        return f"[DeepSeek unavailable: {exc}]"


def _deepseek_advise_stuck(challenge: str, session: "Session", messages: list) -> str:
    """
    Called when the agent has been stuck (4+ consecutive note_failure calls).
    Returns a short strategic pivot from DeepSeek R1.
    """
    try:
        client = _get_deepseek_client()
        advisor_model = os.getenv("DEEPSEEK_ADVISOR_MODEL",
                                   os.getenv("DEEPSEEK_MODEL", "deepseek-reasoner"))
        failed = "\n".join(f"  ✗ {m}" for m in session.failed_methods[-10:])
        memory = session.memory_block()
        # Collect last 3 assistant thoughts for context
        recent_thoughts = []
        for m in reversed(messages[-20:]):
            if m["role"] == "assistant" and m.get("content"):
                recent_thoughts.insert(0, m["content"][:200])
                if len(recent_thoughts) >= 3:
                    break
        prompt = (
            f"CTF challenge (agent is STUCK):\n{challenge[:1500]}\n\n"
            f"Agent memory:\n{memory[:500]}\n\n"
            f"Tried & failed:\n{failed or '(none logged)'}\n\n"
            f"Recent agent thoughts:\n{'---'.join(recent_thoughts)}\n\n"
            "In 100 words MAX: what specific approach has NOT been tried and "
            "is most likely to work? Name the exact tool, technique, and key parameter."
        )
        resp = client.chat.completions.create(
            model=advisor_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=450,
            temperature=0.0,
        )
        msg = resp.choices[0].message
        thinking = getattr(msg, "reasoning_content", "") or ""
        answer = (msg.content or "").strip()
        if thinking and len(thinking) > 30:
            return f"[R1 Reasoning] {thinking[:300]}\n\n[Recommended Action] {answer}"
        return answer
    except Exception as exc:
        return f"[DeepSeek advisor error: {exc}]"


def _gemini_enrich_report(challenge: str, raw_report: str, flag: str,
                           session: "Session") -> str:
    """
    Post-solve: ask Gemini to write a clean, structured CTF writeup.
    Falls back to raw_report if Gemini is unavailable.
    """
    try:
        import google.genai as genai
        client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY", ""))
        _gemini_model = os.getenv("GEMINI_AUTOFIX_MODEL", "gemini-2.0-flash")
        failed = "\n".join(f"✗ {m}" for m in session.failed_methods)
        memory = session.memory_block()
        prompt = (
            "Write a concise CTF writeup in markdown. "
            "Sections: ## Summary, ## Vulnerability, ## Solution Steps (numbered), "
            "## Flag, ## Lessons Learned. Technical and precise.\n\n"
            f"CHALLENGE:\n{challenge[:1000]}\n\n"
            f"AGENT MEMORY:\n{memory[:500]}\n\n"
            f"FAILED APPROACHES:\n{failed[:400] or 'None'}\n\n"
            f"RAW AGENT REPORT:\n{raw_report[:2000]}\n\n"
            f"FLAG: `{flag}`"
        )
        resp = client.models.generate_content(
            model=_gemini_model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(max_output_tokens=2048, temperature=0.3),
        )
        enriched = resp.text.strip()
        return enriched if enriched else raw_report
    except Exception:
        return raw_report


# ---------------------------------------------------------------------------
# Hybrid multi-LLM agent loop
# ---------------------------------------------------------------------------

def _run_hybrid(challenge: str, session: Session, past_experience: str, specialist_prompt: str = "",
                inject_queue: "queue.Queue | None" = None,
                initial_messages: "list[dict] | None" = None,
                start_iteration: int = 1) -> Generator[dict, None, None]:
    """
    Hybrid multi-LLM agent loop — each model plays to its strength:

    • DeepSeek R1  — "brain": initial attack plan + strategic advisor when stuck
    • Azure GPT    — "hands": primary executor for all structured tool calls
    • Gemini Flash — "medic": inline Python error auto-fixer + final report writer

    DeepSeek and Gemini are consulted only on specific triggers, so per-iteration
    latency stays close to the Azure-only baseline.
    """
    client = _get_azure_client()
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1")
    tools_list = _azure_tools()

    consecutive_failures = 0
    advisor_cooldown = 0  # iterations until next DeepSeek advice is allowed

    if initial_messages is not None:
        messages = initial_messages
    else:
        # ── Phase 0: DeepSeek initial strategy (non-blocking spinner) ──────────
        console.print("[dim]  🧠 DeepSeek analyzing...[/dim]", end="", highlight=False)
        plan = _deepseek_initial_plan(challenge, session, specialist_prompt)
        console.print(" ✓")

        first_content = (past_experience + "\n\n" + challenge) if past_experience else challenge
        # Prepend DeepSeek's plan as context enrichment for Azure
        first_content = f"{plan}\n\n---\n\n{first_content}"

        messages = [
            {"role": "system", "content": _build_system(session, specialist_prompt)},
            {"role": "user", "content": first_content},
        ]

    for iteration in range(start_iteration, MAX_ITERATIONS + 1):
        # Drain user-injected instructions
        if inject_queue:
            while not inject_queue.empty():
                try:
                    injected = inject_queue.get_nowait()
                    console.print(f"\n[bold yellow]📩 User instruction:[/bold yellow] {injected}")
                    messages.append({"role": "user",
                                     "content": f"[USER INSTRUCTION — act on this immediately] {injected}"})
                except Exception:
                    pass

        yield {"type": "iteration", "n": iteration, "backend": "hybrid"}
        session._current_iteration = iteration
        if _maybe_inject_stagnation_pivot(session, messages, iteration):
            continue

        messages[0]["content"] = _build_system(session, specialist_prompt)
        messages_to_send = session.compress_history(list(messages), max_chars=80_000)

        response = _azure_call_with_retry_and_policy(
            client, deployment, messages_to_send, tools_list, console, messages,
            session=session)
        if response is None:
            continue

        msg = response.choices[0].message
        msg_dict = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            msg_dict["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        messages.append(msg_dict)

        if msg.content:
            yield {"type": "thought", "text": msg.content}

        finished = False
        finish_data = None

        if msg.tool_calls:
            parsed_tcs = []
            for tc in msg.tool_calls:
                try:
                    tool_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}
                parsed_tcs.append((tc, tc.function.name, tool_args))

            parallel_tcs = [(tc, n, a) for tc, n, a in parsed_tcs if n in _PARALLEL_SAFE]
            sequential_tcs = [(tc, n, a) for tc, n, a in parsed_tcs if n not in _PARALLEL_SAFE]
            az_results: dict[str, str] = {}

            def _run_az_hybrid(tc_name_args: tuple) -> tuple[str, str]:
                tc, tname, targs = tc_name_args
                is_shell = tname in ("shell_exec", "bg_shell")
                if is_shell:
                    _inc_shells()
                try:
                    res = execute_tool(tname, targs, session)
                    if tname == "shell_exec":
                        res = _inject_crash_hint(res)
                        # ── Gemini auto-fixer: fix Python errors inline ───────
                        cmd = targs.get("command", "")
                        if _has_python_error(res) and cmd and (
                                "python" in cmd.lower() or cmd.strip().endswith(".py")):
                            fixed_cmd = _gemini_fix_code(cmd, res)
                            if fixed_cmd and fixed_cmd.strip() != cmd.strip():
                                console.print("[dim]  🩹 Gemini auto-fix → re-running...[/dim]",
                                              end="", highlight=False)
                                fixed_res = execute_tool("shell_exec", {"command": fixed_cmd}, session)
                                if not _has_python_error(fixed_res):
                                    console.print(" ✓")
                                    res = (
                                        f"[GEMINI AUTO-FIXED] Python error corrected and re-executed.\n"
                                        f"Fixed command:\n{fixed_cmd[:400]}\n\n"
                                        f"Output:\n{fixed_res}"
                                    )
                                else:
                                    console.print(" ✗ still failing")
                                    res += (f"\n\n[GEMINI FIX SUGGESTION — still has errors, "
                                            f"review manually]\n{fixed_cmd[:400]}")
                    return tc.id, res
                finally:
                    if is_shell:
                        _dec_shells()

            # Run parallel-safe tools concurrently, sequential ones in order
            if len(parallel_tcs) > 1:
                for tc, tname, targs in parallel_tcs:
                    yield {"type": "tool_call", "name": tname, "args": targs,
                           "parallel": True, "parallel_count": len(parallel_tcs)}
                with ThreadPoolExecutor(max_workers=min(len(parallel_tcs), 8)) as pool:
                    futures = {pool.submit(_run_az_hybrid, item): item for item in parallel_tcs}
                    for fut in as_completed(futures):
                        tid, res = fut.result()
                        az_results[tid] = res
            else:
                for item in parallel_tcs:
                    tc, tname, targs = item
                    yield {"type": "tool_call", "name": tname, "args": targs}
                    tid, res = _run_az_hybrid(item)
                    az_results[tid] = res

            for item in sequential_tcs:
                tc, tname, targs = item
                yield {"type": "tool_call", "name": tname, "args": targs}
                tid, res = _run_az_hybrid(item)
                az_results[tid] = res

            # ── Track consecutive failures → DeepSeek advisor ─────────────────
            if advisor_cooldown > 0:
                advisor_cooldown -= 1
            for _, tool_name, _ in parsed_tcs:
                if tool_name == "note_failure":
                    consecutive_failures += 1
                elif tool_name not in ("think", "update_memory"):
                    consecutive_failures = 0

            if consecutive_failures >= 4 and advisor_cooldown == 0:
                console.print("[dim]  🧠 Agent stuck → DeepSeek advisor...[/dim]",
                              end="", highlight=False)
                advice = _deepseek_advise_stuck(challenge, session, messages)
                console.print(" ✓")
                yield {"type": "thought", "text": f"[DeepSeek Strategic Advisor]\n{advice}"}
                messages.append({
                    "role": "user",
                    "content": (
                        "[STRATEGIC ADVISOR — DeepSeek R1] The agent is stuck. "
                        "Independent analysis of the challenge suggests:\n\n"
                        f"{advice}\n\n"
                        "Immediately pivot to the approach above. "
                        "Do NOT retry previously failed methods."
                    ),
                })
                consecutive_failures = 0
                advisor_cooldown = 6  # don't advise again for 6 iterations

            # ── Process tool results ──────────────────────────────────────────
            for tc, tool_name, tool_args in parsed_tcs:
                result = az_results[tc.id]

                if tool_name == "note_failure":
                    yield {"type": "failure_noted", "method": tool_args.get("method", "")}
                elif tool_name == "think":
                    yield {"type": "think", "reasoning": tool_args.get("reasoning", "")}
                elif tool_name == "update_memory":
                    yield {"type": "memory_updated",
                           "key": tool_args.get("key", ""),
                           "value": tool_args.get("value", "")}
                elif tool_name == "finish" and not result.startswith("[FINISH REJECTED]"):
                    finished = True
                    raw_report = tool_args.get("report", "")
                    flag = tool_args.get("flag", "NOT_FOUND")
                    # ── Gemini report enrichment ──────────────────────────────
                    if raw_report and flag and flag != "NOT_FOUND":
                        console.print("[dim]  📝 Gemini writing report...[/dim]",
                                      end="", highlight=False)
                        enriched = _gemini_enrich_report(challenge, raw_report, flag, session)
                        console.print(" ✓")
                        finish_data = {**tool_args, "report": enriched}
                    else:
                        finish_data = tool_args

                yield {"type": "tool_result", "name": tool_name, "result": result}

                if tool_name == "save_state":
                    session.working_memory["_checkpoint_messages_" + tool_args.get("checkpoint_name", "")] = str(len(messages))
                elif tool_name == "revert_state" and not result.startswith("[error]"):
                    rollback_idx = session.working_memory.get("_checkpoint_messages_" + tool_args.get("checkpoint_name", ""))
                    if rollback_idx and rollback_idx.isdigit():
                        idx = int(rollback_idx)
                        if idx < len(messages):
                            messages = messages[:idx]
                            result += " [Context rolled back.]"

                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": _presanitize_tool_result(result)})

        if iteration % _CHECKPOINT_INTERVAL == 0:
            session.save_checkpoint(messages, "hybrid", specialist_prompt, iteration)
            yield {"type": "_checkpoint", "iteration": iteration,
                   "path": str(session.dir / "checkpoint_latest.json")}

        if finished:
            yield {"type": "finish", "data": finish_data}
            return

        if response.choices[0].finish_reason == "stop" and not msg.tool_calls:
            messages.append({
                "role": "user",
                "content": "[SYSTEM] You stopped without calling a tool. You MUST call a tool.",
            })
            continue

    yield {"type": "finish", "data": {"report": f"Hit {MAX_ITERATIONS} iterations.", "flag": "NOT_FOUND"}}


def _run_deepseek(challenge: str, session: Session, past_experience: str, specialist_prompt: str = "",
                  inject_queue: "queue.Queue | None" = None,
                  initial_messages: "list[dict] | None" = None,
                  start_iteration: int = 1) -> Generator[dict, None, None]:
    """
    Agent loop for DeepSeek API (deepseek-chat = V3.2, deepseek-reasoner = R1).

    Uses the OpenAI-compatible DeepSeek endpoint.  deepseek-reasoner returns
    reasoning_content tokens which are displayed as thought blocks.
    """
    import time as _time

    client = _get_deepseek_client()
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    tools = _azure_tools()  # same OpenAI function format

    if initial_messages is not None:
        messages = initial_messages
    else:
        first_content = challenge
        if past_experience:
            first_content = past_experience + "\n\n" + challenge
        messages = [
            {"role": "system", "content": _build_system(session, specialist_prompt)},
            {"role": "user", "content": first_content},
        ]

    for iteration in range(start_iteration, MAX_ITERATIONS + 1):
        if inject_queue:
            while not inject_queue.empty():
                try:
                    injected = inject_queue.get_nowait()
                    console.print(f"\n[bold yellow]📩 User instruction injected:[/bold yellow] {injected}")
                    messages.append({"role": "user", "content": f"[USER INSTRUCTION — act on this immediately] {injected}"})
                except Exception:
                    pass

        messages[0]["content"] = _build_system(session, specialist_prompt)
        yield {"type": "iteration", "n": iteration, "backend": f"deepseek/{model}"}
        session._current_iteration = iteration
        if _maybe_inject_stagnation_pivot(session, messages, iteration):
            continue

        messages_to_send = session.compress_history(list(messages), max_chars=80_000)

        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages_to_send,
                tools=tools,
                tool_choice="auto",
                max_tokens=8192,
            )
        except Exception as err:
            estr = str(err)
            if "429" in estr or "rate" in estr.lower() or "quota" in estr.lower():
                wait = 60
                console.print(f"[yellow]⚠ DeepSeek rate limit — waiting {wait}s...[/yellow]")
                _time.sleep(wait)
                continue
            raise

        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        # deepseek-reasoner returns reasoning_content (chain-of-thought)
        reasoning_content = getattr(msg, "reasoning_content", None)
        if reasoning_content and str(reasoning_content).strip():
            yield {"type": "thought", "text": f"[DeepSeek thinking]\n{reasoning_content}"}

        content_text = msg.content or ""
        if content_text.strip():
            yield {"type": "thought", "text": content_text}

        msg_dict: dict = {"role": "assistant", "content": content_text}
        if msg.tool_calls:
            msg_dict["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        messages.append(msg_dict)

        finished = False
        finish_data = None

        if msg.tool_calls:
            parsed_tcs = []
            for tc in msg.tool_calls:
                try:
                    tool_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}
                parsed_tcs.append((tc, tc.function.name, tool_args))

            parallel_tcs = [(tc, n, a) for tc, n, a in parsed_tcs if n in _PARALLEL_SAFE]
            sequential_tcs = [(tc, n, a) for tc, n, a in parsed_tcs if n not in _PARALLEL_SAFE]

            ds_results: dict[str, str] = {}

            def _run_ds(tc_name_args) -> tuple[str, str]:
                tc, tname, targs = tc_name_args
                is_shell = tname in ("shell_exec", "bg_shell")
                if is_shell:
                    _inc_shells()
                try:
                    res = execute_tool(tname, targs, session)
                    if tname == "shell_exec":
                        res = _inject_crash_hint(res)
                    return tc.id, res
                finally:
                    if is_shell:
                        _dec_shells()

            if len(parallel_tcs) > 1:
                for tc, tname, targs in parallel_tcs:
                    yield {"type": "tool_call", "name": tname, "args": targs,
                           "parallel": True, "parallel_count": len(parallel_tcs)}
                with ThreadPoolExecutor(max_workers=min(len(parallel_tcs), 8)) as pool:
                    futures = {pool.submit(_run_ds, item): item for item in parallel_tcs}
                    for fut in as_completed(futures):
                        tid, res = fut.result()
                        ds_results[tid] = res
            else:
                for item in parallel_tcs:
                    tc, tname, targs = item
                    yield {"type": "tool_call", "name": tname, "args": targs}
                    tid, res = _run_ds(item)
                    ds_results[tid] = res

            for item in sequential_tcs:
                tc, tname, targs = item
                yield {"type": "tool_call", "name": tname, "args": targs}
                tid, res = _run_ds(item)
                ds_results[tid] = res

            for tc, tool_name, tool_args in parsed_tcs:
                result = ds_results[tc.id]

                if tool_name == "note_failure":
                    yield {"type": "failure_noted", "method": tool_args.get("method", "")}
                elif tool_name == "think":
                    yield {"type": "think", "reasoning": tool_args.get("reasoning", "")}
                elif tool_name == "update_memory":
                    yield {"type": "memory_updated",
                           "key": tool_args.get("key", ""),
                           "value": tool_args.get("value", "")}
                elif tool_name == "finish" and not result.startswith("[FINISH REJECTED]"):
                    finished = True
                    finish_data = tool_args

                yield {"type": "tool_result", "name": tool_name, "result": result}

                if tool_name == "save_state":
                    session.working_memory["_checkpoint_messages_" + tool_args.get("checkpoint_name", "")] = str(len(messages))
                elif tool_name == "revert_state" and not result.startswith("[error]"):
                    rollback_idx = session.working_memory.get("_checkpoint_messages_" + tool_args.get("checkpoint_name", ""))
                    if rollback_idx and rollback_idx.isdigit():
                        idx = int(rollback_idx)
                        if idx < len(messages):
                            messages = messages[:idx]
                            result += " [Context history rolled back correctly.]"

                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

        if iteration % _CHECKPOINT_INTERVAL == 0:
            session.save_checkpoint(messages, "deepseek", specialist_prompt, iteration)
            yield {"type": "_checkpoint", "iteration": iteration, "path": str(session.dir / "checkpoint_latest.json")}

        if finished:
            yield {"type": "finish", "data": finish_data}
            return

        if finish_reason == "stop" and not msg.tool_calls:
            messages.append({
                "role": "user",
                "content": "[SYSTEM] You stopped without calling a tool. You CANNOT give up. You MUST call a tool.",
            })
            continue

    yield {"type": "finish", "data": {"report": f"Hit {MAX_ITERATIONS} iterations.", "flag": "NOT_FOUND"}}


def _run_reflection(backend: str, challenge: str, report: str) -> "str | None":
    """Post-mortem reflection loop to extract strict lessons from failed runs."""
    try:
        import google.genai as genai
        import os
        client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY", ""))
        _gemini_model = os.getenv("GEMINI_AUTOFIX_MODEL", "gemini-2.0-flash")
        prompt = (
            "You are an elite CTF coach reviewing a failed autonomous AI run.\n"
            "Analyze the challenge and the agent's final report/tracebacks.\n"
            "Identify EXACTLY why the agent failed (e.g., python syntax error, missed an underscore in flag format, wrong endianness, used shell=True incorrectly, etc).\n"
            "Write a SINGLE strictly actionable rule that the agent must adhere to next time so it never makes this exact technical mistake again.\n"
            "Start your reply directly with the rule, e.g., 'When doing X, always use Y.' Keep it under 2 sentences.\n\n"
            f"CHALLENGE:\n{challenge}\n\nREPORT (snippet):\n{report[-12000:]}"
        )
        response = client.models.generate_content(
            model=_gemini_model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(max_output_tokens=200, temperature=0.0),
        )
        return response.text.strip()
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Pre-flight shortcut engine — zero-iteration deterministic solves
# ---------------------------------------------------------------------------

def _preflight_shortcuts(challenge: str, session: "Session") -> "str | None":
    """
    Attempt fast deterministic shortcuts BEFORE the first LLM call.
    Returns a flag string if found, or None to proceed with the full agent.

    Covers:
    - RSA small-e: integer nth root of c with e=3,5,17
    - Vigenere KPA: direct key recovery when plaintext fragment visible
    - Caesar brute: try all 26 shifts, return if one looks like readable English
    - Morse code: decode obvious dot-dash strings
    - Base64/hex nested encoding chains (up to 5 layers)
    - Common flag patterns directly in challenge text
    """
    import re as _re
    import base64 as _b64

    text = challenge

    # ── 0. Flag already in challenge text ────────────────────────────────────
    flag_re = _re.compile(r'(?<![A-Za-z0-9_])[A-Za-z0-9_]{2,15}\{[^}\s]{3,80}\}')
    for m in flag_re.finditer(text):
        candidate = m.group(0)
        prefix = candidate.split("{")[0]
        if prefix.upper() not in {"BLOCKED", "REJECTED", "ERROR", "MEMORY", "NOTE", "HINT",
                                   "EXAMPLE", "FORMAT", "OUTPUT", "INPUT", "ASSERT",
                                   "WARNING", "FIXED", "DESCRIPTION"}:
            console.print(f"[bold green][PREFLIGHT][/bold green] Flag found directly in challenge: [yellow]{candidate}[/yellow]")
            session.update_memory("candidate_flag", candidate)
            return candidate

    # ── 1. RSA small-e iroot ─────────────────────────────────────────────────
    _rsa_c = _re.search(r'(?:c|ct|ciphertext)\s*[=:]\s*(\d{10,})', text, _re.IGNORECASE)
    _rsa_e = _re.search(r'\be\s*[=:]\s*(\d+)\b', text)
    if _rsa_c and _rsa_e:
        c_val = int(_rsa_c.group(1))
        e_val = int(_rsa_e.group(1))
        if e_val in (3, 5, 7, 17):
            try:
                import gmpy2  # type: ignore
                root, exact = gmpy2.iroot(c_val, e_val)
                if exact:
                    raw = int(root).to_bytes((int(root).bit_length() + 7) // 8, 'big')
                    try:
                        decoded = raw.decode('utf-8', errors='replace')
                    except Exception:
                        decoded = raw.hex()
                    console.print(f"[bold green][PREFLIGHT][/bold green] RSA iroot(c,{e_val}) exact! m = [yellow]{decoded[:120]}[/yellow]")
                    flag_hits = flag_re.findall(decoded)
                    if flag_hits:
                        session.update_memory("candidate_flag", flag_hits[0])
                        session.update_memory("confirmed_flag", flag_hits[0])
                        return flag_hits[0]
                    session.update_memory("confirmed_rsa_plaintext", decoded[:500])
            except ImportError:
                pass  # gmpy2 not installed — skip, let agent do it

    # ── 2. Base64 / Hex decoding chains (up to 5 layers) ────────────────────
    _b64_re = _re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    _hex_re = _re.compile(r'(?:0x)?[0-9a-fA-F]{20,}')

    def _try_decode_chain(data: str, depth: int = 0) -> "str | None":
        if depth > 5 or len(data) < 4:
            return None
        # Check for flag in current data
        hits = flag_re.findall(data)
        if hits:
            return hits[0]
        # Try base64
        stripped = data.strip().rstrip('=')
        try:
            pad = stripped + '=' * ((4 - len(stripped) % 4) % 4)
            decoded = _b64.b64decode(pad).decode('utf-8', errors='replace')
            if decoded.isprintable() or any(c.isalpha() for c in decoded[:20]):
                result = _try_decode_chain(decoded, depth + 1)
                if result:
                    return result
        except Exception:
            pass
        # Try hex
        if _hex_re.fullmatch(data.strip().replace(' ', '').replace('0x', '')):
            try:
                decoded = bytes.fromhex(data.strip().replace(' ', '').replace('0x', '')).decode('utf-8', errors='replace')
                result = _try_decode_chain(decoded, depth + 1)
                if result:
                    return result
            except Exception:
                pass
        return None

    # Find longest base64 or hex blob in challenge
    for match in _b64_re.finditer(text):
        blob = match.group(0)
        if len(blob) >= 24:
            result = _try_decode_chain(blob)
            if result:
                console.print(f"[bold green][PREFLIGHT][/bold green] Flag found via encoding chain: [yellow]{result}[/yellow]")
                session.update_memory("candidate_flag", result)
                return result

    # ── 3. Morse code decode ─────────────────────────────────────────────────
    _morse_re = _re.compile(r'(?:[.\-]{1,6}\s+){4,}[.\-]{1,6}')
    morse_map = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z',
        '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '/{3}': ' ', '/': ' ',
    }
    morse_match = _morse_re.search(text)
    if morse_match:
        try:
            morse_str = morse_match.group(0).strip()
            words = morse_str.split('   ')
            decoded_words = []
            for word in words:
                chars = [morse_map.get(tok.strip(), '?') for tok in word.split() if tok.strip()]
                decoded_words.append(''.join(chars))
            decoded = ' '.join(decoded_words)
            console.print(f"[bold green][PREFLIGHT][/bold green] Morse decoded: [yellow]{decoded[:120]}[/yellow]")
            flag_hits = flag_re.findall(decoded)
            if flag_hits:
                session.update_memory("candidate_flag", flag_hits[0])
                return flag_hits[0]
            session.update_memory("confirmed_morse_decode", decoded[:200])
        except Exception:
            pass

    # ── 4. Caesar / ROT brute-force (text-only ciphertext) ──────────────────
    _caesar_re = _re.compile(r'ciphertext[^\n]*:\s*([A-Za-z ]{20,})', _re.IGNORECASE)
    c_match = _caesar_re.search(text)
    if c_match:
        ctext = c_match.group(1).strip()
        def _caesar_score(s: str) -> float:
            freq = {c: 0.0 for c in 'ETAOINSHRDLU'}
            total = sum(1 for c in s.upper() if c.isalpha())
            if total == 0:
                return 0.0
            for c in s.upper():
                if c in freq:
                    freq[c] += 1
            return sum(freq.values()) / total
        best_score, best_shift, best_text = 0.0, 0, ctext
        for shift in range(26):
            shifted = ''.join(
                chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97))
                if c.isalpha() else c
                for c in ctext
            )
            score = _caesar_score(shifted)
            if score > best_score:
                best_score, best_shift, best_text = score, shift, shifted
        if best_score > 0.35 and best_shift != 0:
            console.print(f"[bold green][PREFLIGHT][/bold green] Caesar shift={best_shift}: [yellow]{best_text[:80]}[/yellow]")
            flag_hits = flag_re.findall(best_text)
            if flag_hits:
                session.update_memory("candidate_flag", flag_hits[0])
                return flag_hits[0]
            session.update_memory("confirmed_caesar_decode", f"shift={best_shift}: {best_text[:200]}")

    return None  # no shortcut found — proceed with agent


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_agent(
    challenge: str,
    backend: str = "claude",
    category: str = None,
    recon_context: str = "",
    resume_from: "str | None" = None,
    disabled_tools: "list[str] | None" = None,
) -> dict:
    """
    Run the autonomous agent.
    - recon_context: pre-computed output from recon.auto_recon(), prepended to the challenge.
    - resume_from: path to a checkpoint_latest.json file (or its parent session dir) to resume.
    - disabled_tools: tool names to remove from the agent's toolbox for this run.
    Returns the finish dict {report, flag}.
    """
    global _DISABLED_TOOLS
    _orig_disabled = _DISABLED_TOOLS
    _DISABLED_TOOLS = frozenset(disabled_tools) if disabled_tools else frozenset()

    # ── Resume path ────────────────────────────────────────────
    initial_messages = None
    start_iteration = 1
    specialist_prompt = ""
    resolved_category = category

    if resume_from:
        ckpt_path = Path(resume_from)
        if ckpt_path.is_dir():
            ckpt_path = ckpt_path / "checkpoint_latest.json"
        if not ckpt_path.exists():
            console.print(f"[red]✗ Checkpoint not found: {ckpt_path}[/red]")
            raise FileNotFoundError(str(ckpt_path))

        session, state = Session.load_checkpoint(ckpt_path)
        challenge = state["challenge"]
        backend = state.get("backend", backend)
        specialist_prompt = state.get("specialist_prompt", "")
        start_iteration = state.get("iteration", 0) + 1
        initial_messages = state["messages"]
        resolved_category = session.working_memory.get("category", category)
        past_experience = _load_past_experience(challenge, resolved_category)

        # Inject a resume notice so the agent knows where it is
        initial_messages.append({
            "role": "user",
            "content": (
                f"[SESSION RESUMED at iteration {start_iteration}] "
                f"You were working on: {challenge[:200]}. "
                f"Your memory and failed methods have been restored. "
                f"Continue exactly where you left off."
            ),
        })

        console.print(
            f"\n[bold magenta]Resuming[/bold magenta]  "
            f"[dim]iter {start_iteration} · {backend} · {resolved_category}[/dim]  "
            f"[dim]{ckpt_path}[/dim]"
        )

    else:
        # ── Fresh session ──────────────────────────────────────
        session = Session(challenge)

        if recon_context:
            session.save_recon(recon_context)

        # AUTO-DETECT category + build specialist system prompt
        detected_category, specialist_prompt = auto_detect_and_prompt(
            challenge_text=challenge,
            base_prompt=BASE_SYSTEM_PROMPT.format(
                max_iter=MAX_ITERATIONS,
                min_fail=5,
            ),
            explicit_category=category,
        )
        resolved_category = category or detected_category

        # Seed working memory with known facts
        session.update_memory("category", resolved_category)
        session.update_memory("detected_automatically", str(category is None))
        # Anchor the absolute working directory so the agent always has a path reference
        session.update_memory("confirmed_workdir", str(Path.cwd().resolve()))

        # ── Pre-flight shortcut engine ────────────────────────────────────────
        # Run deterministic checks BEFORE the first LLM call. If a flag is found,
        # we skip the agent entirely and return immediately.
        preflight_flag = _preflight_shortcuts(challenge, session)
        if preflight_flag:
            console.print(f"\n[bold green]✓ Pre-flight solve![/bold green] Flag: [yellow]{preflight_flag}[/yellow]")
            _DISABLED_TOOLS = _orig_disabled
            return {
                "report": f"Pre-flight deterministic solve. Flag recovered without LLM iterations.\n\nFlag: {preflight_flag}",
                "flag": preflight_flag,
                "session_dir": str(session.dir),
            }

        # Take a t=0 snapshot of the workdir so reset_environment can restore it later.
        # This is a shallow copy of the current directory (challenge files only — no
        # subdirs deeper than the agent usually touches).  Stored out-of-band in session dir.
        try:
            import shutil as _shutil
            import os as _os
            _snap_src = Path.cwd().resolve()
            
            # Disk space safeguard: don't snapshot if directory > 50MB
            def _get_size(start_path):
                total_size = 0
                for dirpath, dirnames, filenames in _os.walk(start_path):
                    for f in filenames:
                        fp = _os.path.join(dirpath, f)
                        if not _os.path.islink(fp):
                            total_size += _os.path.getsize(fp)
                return total_size
            
            if _get_size(str(_snap_src)) > 50 * 1024 * 1024:
                session._workdir_snapshot = None
            else:
                _snap_dst = session.dir / "_initial_snapshot"
                _shutil.copytree(str(_snap_src), str(_snap_dst), dirs_exist_ok=True,
                                 ignore=_shutil.ignore_patterns(
                                     "chroma_db", "data", "outputs", "*.pyc", "__pycache__",
                                     ".git", "node_modules", "*.log", "workdir", "repo"
                                 ))
                session._workdir_snapshot = _snap_dst
        except Exception:
            session._workdir_snapshot = None  # reset_environment will warn gracefully


        # Load past experience from global memory
        past_experience = _load_past_experience(challenge, resolved_category)

        # Build the enriched first message: challenge + recon findings
        abs_cwd = str(Path.cwd().resolve())
        cwd_path = Path(abs_cwd)

        # ── Auto-scan for challenge files ─────────────────────────────────────
        discovered_files = _scan_challenge_files(cwd_path)
        # Filter out infrastructure files (requirements.txt, *.py from the tool itself, etc.)
        _infra_names = {"requirements.txt", "start.sh", "setup.py", "pyproject.toml"}
        _infra_dirs = {"ctf_rag", "agent_skills"}
        challenge_files = [
            f for f in discovered_files
            if Path(f).name not in _infra_names
            and not any(part in _infra_dirs for part in Path(f).relative_to(cwd_path).parts)
        ]

        first_message_parts = [
            f"## Challenge\n{challenge}",
            f"**Working directory (absolute):** `{abs_cwd}`",
        ]

        if challenge_files:
            file_list = "\n".join(f"  {p}" for p in challenge_files)
            first_message_parts.append(
                f"## Challenge Files Found in Workdir\n"
                f"These files were auto-discovered at startup — use them directly:\n"
                f"{file_list}"
            )
            console.print(f"[dim]  📁 {len(challenge_files)} challenge file(s) discovered[/dim]")
            # Also store in memory so the agent has them even after compression
            session.update_memory("confirmed_challenge_files",
                                  "; ".join(challenge_files[:10]))
        else:
            first_message_parts.append(
                "**No challenge artifacts auto-detected in the workdir.** "
                "If there are binary/archive files, use shell_exec to find them: "
                f"`find {abs_cwd} -maxdepth 3 -type f ! -path '*/outputs/*' ! -path '*/.venv/*'`"
            )

        if category:
            first_message_parts.append(f"**Category hint:** {category}")
            # Pre-populate memory so the agent never needs to call update_memory(category=...)
            session.update_memory("category", category)
        # Pre-populate workdir in memory so the agent has it from the start
        session.update_memory("confirmed_workdir", abs_cwd)
        if recon_context:
            first_message_parts.append(f"## Pre-run Recon Output\n{recon_context}")

        first_message_parts.append(
            "\nBegin by analysing the above. The challenge files listed above are your primary targets — "
            "start working on them immediately using their absolute paths. "
            "category and confirmed_workdir are already stored in memory — do NOT call update_memory "
            "for those. Use ABSOLUTE paths in all shell_exec commands."
        )
        first_message = "\n\n".join(first_message_parts)

        cat_str = f"  [dim]category:[/dim] [yellow]{resolved_category}[/yellow]" if resolved_category else ""
        console.print(
            f"\n[bold magenta]CTF Agent[/bold magenta]  "
            f"[dim]backend:[/dim] [cyan]{backend}[/cyan]{cat_str}"
            f"  [dim]{session.dir}[/dim]"
        )
        # Show challenge, truncated to avoid flooding the terminal
        chall_preview = challenge[:500] + ("…" if len(challenge) > 500 else "")
        console.print(Panel(chall_preview, title="[bold]Challenge[/bold]", border_style="blue", padding=(0, 1)))
        if past_experience:
            console.print(f"[dim]  📚 Past experience loaded[/dim]")
        if recon_context:
            console.print(Panel(recon_context[:600] + ("…" if len(recon_context) > 600 else ""),
                                title="[dim]Recon[/dim]", border_style="dim", padding=(0, 1)))

    if backend == "claude":
        runner = _run_claude
    elif backend == "nvidia":
        runner = _run_nvidia
    elif backend == "openrouter":
        runner = _run_openrouter
    elif backend == "deepseek":
        runner = _run_deepseek
    elif backend == "hybrid":
        runner = _run_hybrid
    else:
        runner = _run_azure
    finish_data = {"report": "No report generated.", "flag": "NOT_FOUND"}

    # ----------------------------------------------------------------
    # Interactive event loop — Ctrl+C pauses the agent so you can
    # inject instructions mid-solve (Claude Code style).
    # ----------------------------------------------------------------
    inject_queue: queue.Queue = queue.Queue()
    event_queue: queue.Queue = queue.Queue()
    _interrupted = threading.Event()

    def _sigint_handler(sig, frame):
        _interrupted.set()

    old_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _sigint_handler)

    # For fresh sessions, `first_message` is the challenge string passed to the runner.
    # For resumed sessions, `initial_messages` carries the full history and first_message is ignored.
    _runner_challenge = challenge if resume_from else first_message  # type: ignore[possibly-undefined]

    def _agent_thread():
        try:
            for event in runner(
                _runner_challenge, session, past_experience, specialist_prompt,
                inject_queue=inject_queue,
                initial_messages=initial_messages,
                start_iteration=start_iteration,
            ):
                event_queue.put(event)
        except Exception as exc:
            import traceback
            event_queue.put({"type": "_error", "error": str(exc), "tb": traceback.format_exc()})
        finally:
            event_queue.put({"type": "_done"})

    agent_thread = threading.Thread(target=_agent_thread, daemon=True)
    agent_thread.start()

    # ── Statusline thread ─────────────────────────────────────────────────────
    global _active_shells, _total_shells
    _active_shells = 0
    _total_shells = 0
    _statusline_stop.clear()
    _iter_ref = [start_iteration]   # mutable so statusline thread sees updates
    _backend_ref = [backend]
    _sl_thread = threading.Thread(
        target=_statusline_worker, args=(_iter_ref, _backend_ref), daemon=True
    )
    _sl_thread.start()

    try:
        while True:
            # ── Ctrl+C was pressed → enter pause mode ──
            if _interrupted.is_set():
                _interrupted.clear()

                # Stop statusline — it erases the line every 0.3s and wipes typed text
                _statusline_stop.set()
                _sl_thread.join(timeout=0.5)
                sys.stderr.write("\r\033[K")
                sys.stderr.flush()

                console.print(
                    "\n[bold yellow]⏸  Paused.[/bold yellow] "
                    "Type an instruction and Enter to inject, or Enter alone to resume. "
                    "[dim](Ctrl+C to quit)[/dim]"
                )

                # Restore default SIGINT so Ctrl+C during input() raises KeyboardInterrupt
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                try:
                    user_input = input("> ").strip()
                except KeyboardInterrupt:
                    console.print("\n[red]Aborted.[/red]")
                    break
                except EOFError:
                    user_input = ""
                finally:
                    # Reinstall custom handler and restart statusline
                    signal.signal(signal.SIGINT, _sigint_handler)
                    _interrupted.clear()
                    _statusline_stop.clear()
                    _sl_thread = threading.Thread(
                        target=_statusline_worker, args=(_iter_ref, _backend_ref), daemon=True
                    )
                    _sl_thread.start()

                if user_input:
                    inject_queue.put(user_input)
                    console.print(f"[dim green]✓ Queued[/dim green]")
                else:
                    console.print("[dim]Resuming...[/dim]")
                continue

            # ── Pull next event from the agent thread ──
            try:
                event = event_queue.get(timeout=0.15)
            except queue.Empty:
                continue

            if event["type"] == "_done":
                break
            elif event["type"] == "_error":
                console.print(f"[red]Agent thread error: {event['error']}[/red]")
                console.print(f"[dim red]{event.get('tb', '')}[/dim red]")
                break

            # Keep statusline iteration counter in sync
            if event["type"] == "iteration":
                _iter_ref[0] = event["n"]

            _render_event(event)
            if event["type"] == "finish":
                finish_data = event["data"]

    finally:
        _statusline_stop.set()
        _sl_thread.join(timeout=1)
        signal.signal(signal.SIGINT, old_sigint)

    agent_thread.join(timeout=2)

    report = finish_data.get("report", "")
    flag = finish_data.get("flag", "NOT_FOUND")

    if flag in ("NOT_FOUND", "NOT_FOUND\n", ""):
        import re
        match = re.search(r'[A-Za-z0-9_]+\{[^}]+\}', report)
        if match:
            flag = match.group(0)

    session.save_report(report, flag)
    session.generate_digest(flag, iterations=MAX_ITERATIONS)

    lesson_learned = None
    if flag in ("NOT_FOUND", "NOT_FOUND\n", ""):
        lesson_learned = _run_reflection(backend, challenge, report)

    session.save_global_memory(flag, lesson_learned=lesson_learned)

    # ── Final result ─────────────────────────────────────────────────────────
    console.print(Rule())
    if flag not in ("NOT_FOUND", "NOT_FOUND\n", ""):
        console.print(f"\n[bold green]  ✓  {flag}[/bold green]\n")
        if "search_writeups" not in _DISABLED_TOOLS:
            try:
                from ctf_rag.ingest import auto_ingest_solve, extract_and_store_technique
                _cat = category or session.working_memory.get("category", "misc")
                auto_ingest_solve(
                    challenge=challenge,
                    category=_cat,
                    report=report,
                    flag=flag,
                    tools_used=session.tools_used,
                )
                extract_and_store_technique(report=report, category=_cat)
            except Exception as e:
                console.print(f"[dim]Auto-ingest skipped: {e}[/dim]")
    else:
        console.print(f"\n[bold red]  ✗  Flag not found[/bold red]\n")
        # Show a condensed report (first 800 chars) so the user knows what happened
        if report:
            snippet = report.strip()[:800] + ("…" if len(report) > 800 else "")
            console.print(Panel(snippet, title="[dim]Report[/dim]", border_style="dim", padding=(0, 1)))

    console.print(f"[dim]  session: {session.dir}[/dim]\n")

    # Restore disabled tools to previous state (thread-safe for benchmark parallelism)
    _DISABLED_TOOLS = _orig_disabled

    return finish_data
