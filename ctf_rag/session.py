"""
Session: tracks everything that happens during one agent run.
- Maintains failed_methods so the LLM never repeats a dead end.
- Maintains working_memory: a persistent key/value scratchpad injected into every prompt.
- Persists all commands, tool calls, and the final report to outputs/.
- Appends a compact record to global_memory.json for cross-session learning.
"""

import json
import re
from datetime import datetime
from pathlib import Path

# Keys the agent uses for confirmed (tool-verified) facts — displayed first
_CONFIRMED_PREFIX = "confirmed_"

GLOBAL_MEMORY_PATH = Path("outputs/global_memory.json")


class Session:
    def __init__(self, challenge: str):
        slug = re.sub(r"[^\w]+", "_", challenge[:50].lower()).strip("_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.dir = Path(f"outputs/{slug}/{ts}")
        self.dir.mkdir(parents=True, exist_ok=True)

        self.challenge = challenge
        self.failed_methods: list[str] = []       # approaches tried and confirmed dead
        self.tools_used: list[str] = []            # every tool name called (for writeup)
        self.working_memory: dict[str, str] = {}   # agent-maintained scratchpad
        self.thoughts: list[str] = []              # reasoning log from `think` tool

        # ── Duplicate-call / loop detection ──────────────────────────────
        # Maps call_key → (call_count, first_iteration, result_snippet)
        self._tool_call_counts: dict[str, tuple[int, int, str]] = {}
        self._current_iteration: int = 0          # updated by the agent loop each turn
        self._stagnation_counter: int = 0         # consecutive duplicate/blocked calls
        self._last_unique_iteration: int = 0      # iteration of last genuinely new call

        self._commands_log = self.dir / "commands.log"
        self._commands_log.touch()

    # ------------------------------------------------------------------
    # Failed-method memory
    # ------------------------------------------------------------------

    def note_failure(self, method: str, reason: str) -> str:
        """Record an approach as failed. Returns confirmation string."""
        entry = f"{method} — {reason}"
        if entry not in self.failed_methods:
            self.failed_methods.append(entry)
        return f"[noted] '{method}' marked as failed."

    def failed_methods_block(self) -> str:
        """Returns a prompt block to inject so the LLM won't repeat failures."""
        if not self.failed_methods:
            return ""
        lines = "\n".join(f"  - {m}" for m in self.failed_methods)
        return f"\n\n## ALREADY TRIED — DO NOT REPEAT:\n{lines}\n"

    # ------------------------------------------------------------------
    # Duplicate-call / loop detection
    # ------------------------------------------------------------------

    # Tools that are safe to call repeatedly (state changes each time)
    _LOOP_EXEMPT = frozenset({
        "think", "update_memory", "note_failure", "finish",
        "ask_human", "delegate_task", "shell_exec", "bg_shell",
        "write_file", "save_state", "revert_state", "save_skill",
    })

    def check_tool_duplicate(self, name: str, args_key: str) -> "tuple[str, str] | None":
        """
        Check whether this (tool, args) combo has been called before.

        Returns:
          None                       — first time, proceed normally
          ("warn", message)          — called 2–3 times; return cached result + warning
          ("block", message)         — called 4+ times; hard-block, demand pivot
        """
        if name in self._LOOP_EXEMPT:
            return None

        key = f"{name}::{args_key}"
        entry = self._tool_call_counts.get(key)

        if entry is None:
            # First call — record it (result stored by record_tool_call)
            self._tool_call_counts[key] = (0, self._current_iteration, "")
            self._last_unique_iteration = self._current_iteration
            self._stagnation_counter = 0
            return None

        count, first_iter, cached_snippet = entry
        self._stagnation_counter += 1

        if count == 1:
            # Second call — allow but warn
            return ("warn",
                    f"[DUPLICATE CALL #{count + 1}] You already called `{name}` with these exact "
                    f"arguments at iteration {first_iter}. Here is the cached result — reading "
                    f"it again will give you nothing new:\n\n{cached_snippet}\n\n"
                    f"Use this cached result instead of re-running the tool.")

        elif count == 2:
            # Third call — strong warning
            return ("warn",
                    f"[DUPLICATE CALL #{count + 1} — LAST WARNING] `{name}` with these exact "
                    f"args has been called {count + 1} times (first at iter {first_iter}). "
                    f"Cached result:\n\n{cached_snippet}\n\n"
                    f"ONE MORE duplicate call will be hard-blocked. Try a DIFFERENT tool or "
                    f"different arguments.")

        else:
            # 4th call and beyond — hard block
            return ("block",
                    f"[BLOCKED — LOOP DETECTED] `{name}` with these exact arguments has been "
                    f"called {count + 1} times (first at iter {first_iter}). This call is "
                    f"CANCELLED. You are looping. The output will not change.\n\n"
                    f"MANDATORY: You MUST do ONE of the following right now:\n"
                    f"  1. Try a COMPLETELY DIFFERENT tool (not the same tool with same args)\n"
                    f"  2. Call note_failure() to log the approach as exhausted\n"
                    f"  3. Call think() to reason about an entirely new attack angle\n"
                    f"  4. Call finish() if you have collected enough information\n"
                    f"Do NOT retry `{name}` with the same arguments ever again.")

    def record_tool_call(self, name: str, args_key: str, result: str) -> None:
        """Record a completed tool call. Updates count and caches result snippet."""
        if name in self._LOOP_EXEMPT:
            return
        key = f"{name}::{args_key}"
        entry = self._tool_call_counts.get(key, (0, self._current_iteration, ""))
        count, first_iter, _ = entry
        snippet = result[:400] + ("…" if len(result) > 400 else "")
        self._tool_call_counts[key] = (count + 1, first_iter, snippet)

    def is_stagnating(self, window: int = 8) -> bool:
        """
        Return True if the agent has made no unique new tool calls in the
        last `window` calls — i.e., every recent call was a duplicate/blocked.
        """
        if self._current_iteration - self._last_unique_iteration >= window:
            return True
        return self._stagnation_counter >= window

    # ------------------------------------------------------------------
    # Working memory scratchpad
    # ------------------------------------------------------------------

    def update_memory(self, key: str, value: str) -> str:
        """Store a key/value in the agent's working memory scratchpad."""
        key = key.strip()
        value = value.strip()
        if self.working_memory.get(key) == value:
            # Same key + same value → noop, count as stagnation
            self._stagnation_counter += 1
            return (
                f"[memory] '{key}' is ALREADY set to this exact value — no change made. "
                f"Do NOT call update_memory again with the same key/value. "
                f"This key is stored: {value[:120]}. "
                f"Proceed to your next task (write/run code, call a tool, etc.)."
            )
        self.working_memory[key] = value
        # A genuinely new memory write resets stagnation
        self._last_unique_iteration = self._current_iteration
        self._stagnation_counter = 0
        return f"[memory] '{key}' updated."

    def memory_block(self) -> str:
        """Returns the current working memory formatted for prompt injection.

        Confirmed facts (keys starting with 'confirmed_') are rendered first in a
        GROUND TRUTH block so the agent treats them as authoritative and is less
        likely to contradict them.
        """
        if not self.working_memory and not self.thoughts:
            return ""

        confirmed = {k: v for k, v in self.working_memory.items()
                     if k.startswith(_CONFIRMED_PREFIX) and not k.startswith("_")}
        hypotheses = {k: v for k, v in self.working_memory.items()
                      if not k.startswith(_CONFIRMED_PREFIX) and not k.startswith("_")}

        parts = ["\n\n## Working Memory"]

        if confirmed:
            parts.append("### GROUND TRUTH — confirmed by tool output (treat as facts):")
            for k, v in confirmed.items():
                display_k = k[len(_CONFIRMED_PREFIX):]  # strip prefix for readability
                parts.append(f"  ✓ **{display_k}:** {v}")

        if hypotheses:
            parts.append("### Hypotheses & notes (unconfirmed — verify before acting on):")
            for k, v in hypotheses.items():
                parts.append(f"  ~ **{k}:** {v}")

        if self.thoughts:
            parts.append(f"\n  **last_thought:** {self.thoughts[-1][:300]}")

        return "\n".join(parts) + "\n"

    def add_thought(self, reasoning: str) -> str:
        """Log a reasoning step from the think tool."""
        self.thoughts.append(reasoning)
        # Persist last thought as memory key for context window visibility
        self.working_memory["_last_think"] = reasoning[:300]
        with self._commands_log.open("a") as f:
            f.write(f"\n{'='*60}\n[THINK @ {datetime.now().isoformat()}]\n{reasoning}\n")
        return "[think] Reasoning recorded. Now decide your next action based on this."

    # ------------------------------------------------------------------
    # Context window management
    # ------------------------------------------------------------------

    def compress_history(self, messages: list[dict], max_chars: int = 60_000) -> list[dict]:
        """
        Smart context compression — preserves critical information across compression:
          - Always keeps: system prompt + original challenge + last 8 messages
          - Middle section: extracts memory updates, failures, and key tool output snippets
            so the agent never loses discovered values (addresses, seeds, tokens, etc.)
        """
        if not messages:
            return messages

        total_chars = sum(
            len(str(m.get("content", ""))) + len(str(m.get("tool_calls", "")))
            for m in messages
        )
        if total_chars <= max_chars:
            return messages

        keep_head = 2   # system + original challenge
        keep_tail = 8   # most recent turns (increased from 6)

        if len(messages) <= keep_head + keep_tail:
            return messages

        head = messages[:keep_head]
        raw_tail = messages[-keep_tail:]
        middle = messages[keep_head:-keep_tail]

        # Trim leading tool messages from tail (would be orphaned)
        tail = list(raw_tail)
        while tail and tail[0].get("role") == "tool":
            tail.pop(0)

        # ----------------------------------------------------------------
        # Smart digest: extract high-value items from the dropped middle
        # ----------------------------------------------------------------
        digest_lines = ["[CONTEXT COMPRESSED — extracted key findings from dropped turns:]"]
        tool_output_snippets: list[str] = []   # collect recent tool outputs

        for m in middle:
            role = m.get("role", "?")
            content = m.get("content", "")

            # ── Azure format: assistant message with tool_calls list ──
            tool_calls = m.get("tool_calls", [])
            if tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    name = fn.get("name", "?")
                    try:
                        args = json.loads(fn.get("arguments", "{}"))
                    except Exception:
                        args = {}
                    if name == "update_memory":
                        k, v = args.get("key", ""), args.get("value", "")
                        digest_lines.append(f"  [memory set] {k} = {str(v)[:100]}")
                    elif name == "note_failure":
                        digest_lines.append(f"  [failed approach] {args.get('method','')[:100]}")
                    elif name == "think":
                        snippet = args.get("reasoning", "")[:120].replace("\n", " ")
                        digest_lines.append(f"  [think] {snippet}...")
                    else:
                        cmd = args.get("command", args.get("binary", args.get("query", "")))[:60]
                        digest_lines.append(f"  [called] {name}({cmd})")

            # ── Azure format: tool result ──
            elif role == "tool":
                c = str(content or "")
                if c and not c.startswith("[tool output redacted]"):
                    tool_output_snippets.append(c)

            # ── Claude format: content is a list of blocks ──
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type", "")
                    if btype == "tool_use":
                        name = block.get("name", "?")
                        inp = block.get("input", {})
                        if name == "update_memory":
                            k, v = inp.get("key", ""), inp.get("value", "")
                            digest_lines.append(f"  [memory set] {k} = {str(v)[:100]}")
                        elif name == "note_failure":
                            digest_lines.append(f"  [failed approach] {inp.get('method','')[:100]}")
                        elif name == "think":
                            snippet = inp.get("reasoning", "")[:120].replace("\n", " ")
                            digest_lines.append(f"  [think] {snippet}...")
                        else:
                            cmd_val = inp.get("command", inp.get("binary", inp.get("query", "")))[:60]
                            digest_lines.append(f"  [called] {name}({cmd_val})")
                    elif btype == "tool_result":
                        c = str(block.get("content", ""))
                        if c and not c.startswith("[tool output redacted]"):
                            tool_output_snippets.append(c)

            # ── Plain string content ──
            elif isinstance(content, str) and content.strip():
                snippet = content.replace("\n", " ")[:100]
                digest_lines.append(f"  [{role}]: {snippet}...")

        # Append last 3 tool output snippets (most recent findings matter most)
        if tool_output_snippets:
            digest_lines.append("  [last tool outputs — most recent 3, newest last:]")
            for out in tool_output_snippets[-3:]:
                snippet = out[:400].replace("\n", " | ")
                digest_lines.append(f"    >>> {snippet}")

        digest_msg = {
            "role": "user",
            "content": "\n".join(digest_lines),
        }

        # ── Pinned facts block — NEVER lost during compression ──────────────
        # Confirmed facts and recent failures are re-injected every time so the
        # agent always has access to discovered values regardless of how much
        # history was trimmed.
        pinned_lines: list[str] = []
        confirmed = {k: v for k, v in self.working_memory.items()
                     if k.startswith(_CONFIRMED_PREFIX) and not k.startswith("_")}
        if confirmed:
            pinned_lines.append("## PINNED FACTS — confirmed by tools (always authoritative):")
            for k, v in confirmed.items():
                display_k = k[len(_CONFIRMED_PREFIX):]
                pinned_lines.append(f"  ✓ {display_k} = {str(v)[:200]}")
        if self.failed_methods:
            pinned_lines.append("## ALREADY FAILED — do not retry these:")
            for m in self.failed_methods[-8:]:
                pinned_lines.append(f"  ✗ {m}")
        candidate = self.working_memory.get("candidate_flag", "")
        if candidate:
            pinned_lines.append(f"## CANDIDATE FLAG (auto-detected): {candidate}")

        if pinned_lines:
            pinned_msg = {"role": "user", "content": "\n".join(pinned_lines)}
            return head + [pinned_msg, digest_msg] + tail

        return head + [digest_msg] + tail

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Signal event log — compact structured record for digest
    # ------------------------------------------------------------------

    def _append_event(self, event: dict):
        """Append a structured signal event (low-noise digest building)."""
        if not hasattr(self, "_events"):
            self._events: list[dict] = []
        self._events.append(event)

    def log_tool(self, name: str, args: dict, result: str):
        if name not in self.tools_used:
            self.tools_used.append(name)
        with self._commands_log.open("a") as f:
            f.write(f"\n{'='*60}\n[{datetime.now().isoformat()}] {name}\n")
            if name == "shell_exec":
                f.write(f"CMD: {args.get('command', '')}\n")
            f.write(f"RESULT:\n{result[:2000]}\n")

        # Record signal events for digest (skip noisy read/write/think)
        SIGNAL_TOOLS = {
            "note_failure", "finish", "shell_exec", "search_writeups",
            "get_attack_tree", "get_template", "delegate_task", "run_afl",
            "allocate_oast_payload", "check_oast_logs", "angr_solve",
            "gdb_analyze", "cyclic_offset", "r2_analyze", "z3_solve",
            "gmpy2_compute", "crack_hash", "web_request", "ffuf_fuzz",
            "browser_exec", "decompile_function", "ltrace_run",
            "ghidra_analyze", "pcap_analyze_flows", "nmap_scan",
        }
        if name in SIGNAL_TOOLS:
            entry: dict = {"tool": name}
            if name == "shell_exec":
                cmd = args.get("command", "")
                entry["cmd"] = cmd[:120]
                if "[SCRIPT FAILED" in result:
                    entry["status"] = "FAILED"
                    err_line = next((l for l in result.splitlines() if "Error" in l or "error" in l), "")
                    entry["error"] = err_line[:100]
                elif "[auto-fixed" in result:
                    entry["status"] = "AUTO-FIXED"
                else:
                    entry["status"] = "OK"
            elif name == "note_failure":
                entry["method"] = args.get("method", "")[:80]
                entry["reason"] = args.get("reason", "")[:80]
            elif name == "finish":
                entry["flag"] = args.get("flag", "NOT_FOUND")
            elif name in ("get_template", "get_attack_tree"):
                entry["target"] = args.get("template") or args.get("category", "")
            elif name == "search_writeups":
                entry["query"] = args.get("query", "")[:80]
                entry["hits"] = 0 if "No matching" in result else result.count("[")
            else:
                # capture first meaningful line of result (skip CWD header injected by _shell_exec)
                first = next(
                    (l.strip() for l in result.splitlines()
                     if l.strip() and not l.startswith("[CWD:")),
                    ""
                )
                entry["result_snippet"] = first[:120]
            self._append_event(entry)

    def save_report(self, report: str, flag: str):
        (self.dir / "report.md").write_text(
            f"# CTF Agent Report\n\n**Flag:** `{flag}`\n\n{report}",
            encoding="utf-8",
        )

    def save_recon(self, recon_text: str):
        (self.dir / "recon.md").write_text(recon_text, encoding="utf-8")

    # ------------------------------------------------------------------
    # Cross-session global memory
    # ------------------------------------------------------------------

    def save_checkpoint(self, checkpoint_name: str) -> str:
        """Saves a checkpoint of the current session state."""
        import copy
        if not hasattr(self, "checkpoints"):
            self.checkpoints = {}
            
        self.checkpoints[checkpoint_name] = {
            "failed_methods": copy.deepcopy(self.failed_methods),
            "working_memory": copy.deepcopy(self.working_memory),
            "thoughts": copy.deepcopy(self.thoughts)
        }
        return f"[checkpoint] Saved state as '{checkpoint_name}'"

    def restore_checkpoint(self, checkpoint_name: str) -> str:
        """Restores a session state from a checkpoint."""
        import copy
        if not hasattr(self, "checkpoints") or checkpoint_name not in self.checkpoints:
            return f"[error] Checkpoint '{checkpoint_name}' not found."
            
        ckpt = self.checkpoints[checkpoint_name]
        self.failed_methods = copy.deepcopy(ckpt["failed_methods"])
        self.working_memory = copy.deepcopy(ckpt["working_memory"])
        self.thoughts = copy.deepcopy(ckpt["thoughts"])
        return f"[checkpoint] Restored state from '{checkpoint_name}'"

    # ------------------------------------------------------------------
    # Digest — compact session summary for Claude Code feedback
    # ------------------------------------------------------------------

    def generate_digest(self, flag: str, iterations: int = 0) -> Path:
        """
        Write a compact DIGEST.md — the only file you need to paste into
        Claude Code so it understands what happened and what to improve.
        Stays under ~800 tokens by design.
        """
        events = getattr(self, "_events", [])
        outcome = "SOLVED" if flag not in ("NOT_FOUND", "NOT_FOUND\n", "", None) else "FAILED"

        lines: list[str] = [
            f"# CTF Agent Session Digest",
            f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Challenge**: {self.challenge[:120].replace(chr(10), ' ')}",
            f"**Category**: {self.working_memory.get('category', 'unknown')}",
            f"**Outcome**: {outcome} {'— flag: `' + flag + '`' if outcome == 'SOLVED' else ''}",
            f"**Iterations**: {iterations}",
            f"**Session dir**: `{self.dir}`",
            "",
        ]

        # Attack sequence (signal events only)
        if events:
            lines.append("## Attack Sequence")
            for i, ev in enumerate(events, 1):
                tool = ev["tool"]
                if tool == "shell_exec":
                    status = ev.get("status", "")
                    cmd = ev.get("cmd", "")
                    err = f" → {ev['error']}" if ev.get("error") else ""
                    icon = "✗" if status == "FAILED" else ("⚡" if status == "AUTO-FIXED" else "✓")
                    lines.append(f"{i}. `shell_exec` {icon} `{cmd}`{err}")
                elif tool == "note_failure":
                    lines.append(f"{i}. **FAIL noted**: {ev.get('method','')} — {ev.get('reason','')}")
                elif tool == "finish":
                    lines.append(f"{i}. `finish` → flag={ev.get('flag','?')}")
                elif tool == "search_writeups":
                    lines.append(f"{i}. `search_writeups`: \"{ev.get('query','')}\" ({ev.get('hits',0)} hits)")
                elif tool in ("get_template", "get_attack_tree"):
                    lines.append(f"{i}. `{tool}`: {ev.get('target','')}")
                else:
                    snippet = ev.get("result_snippet", "")
                    lines.append(f"{i}. `{tool}`: {snippet}")
            lines.append("")

        # Errors
        errors = [ev for ev in events if ev.get("status") == "FAILED"]
        autofixes = [ev for ev in events if ev.get("status") == "AUTO-FIXED"]
        if errors:
            lines.append("## Script Errors")
            for ev in errors:
                lines.append(f"- `{ev.get('cmd','')[:80]}` → {ev.get('error','')}")
            lines.append("")
        if autofixes:
            lines.append(f"## Auto-Fixed by Gemini: {len(autofixes)}x")
            for ev in autofixes:
                lines.append(f"- `{ev.get('cmd','')[:80]}`")
            lines.append("")

        # Failed methods
        if self.failed_methods:
            lines.append("## Failed Methods (do not repeat)")
            for m in self.failed_methods:
                lines.append(f"- {m}")
            lines.append("")

        # Working memory snapshot
        mem = {k: v for k, v in self.working_memory.items() if not k.startswith("_")}
        if mem:
            lines.append("## Final Working Memory")
            for k, v in list(mem.items())[:12]:
                lines.append(f"- **{k}**: {str(v)[:100]}")
            lines.append("")

        # Tool usage stats
        tool_counts: dict[str, int] = {}
        for ev in events:
            tool_counts[ev["tool"]] = tool_counts.get(ev["tool"], 0) + 1
        if tool_counts:
            stats = ", ".join(f"{t}×{c}" for t, c in sorted(tool_counts.items(), key=lambda x: -x[1]))
            lines.append(f"## Tool Stats\n{stats}\n")

        # Last thought (usually the most insightful)
        if self.thoughts:
            lines.append("## Last Agent Thought")
            lines.append(f"> {self.thoughts[-1][:400]}")
            lines.append("")

        # Improvement hints (auto-generated heuristics)
        hints: list[str] = []
        n_fail = len(self.failed_methods)
        n_shell = tool_counts.get("shell_exec", 0)
        n_think = tool_counts.get("think", 0)
        n_search = tool_counts.get("search_writeups", 0)
        if n_fail > 4 and outcome == "FAILED":
            hints.append(f"Agent tried {n_fail} failed approaches — consider expanding attack tree or adding more templates.")
        if n_shell == 0 and outcome == "FAILED":
            hints.append("Agent never executed code — system prompt execution gate may need strengthening.")
        if n_think < n_fail:
            hints.append("Agent didn't think() after every failure — enforce think-after-fail rule.")
        if n_search == 0:
            hints.append("Agent skipped RAG search entirely — writeup database may need broader coverage.")
        if autofixes:
            hints.append(f"Gemini auto-fixed {len(autofixes)} script(s) — agent is writing buggy code; improve templates.")
        if hints:
            lines.append("## Improvement Hints")
            for h in hints:
                lines.append(f"- {h}")
            lines.append("")

        digest_path = self.dir / "DIGEST.md"
        digest_path.write_text("\n".join(lines), encoding="utf-8")
        return digest_path

    # ------------------------------------------------------------------
    # Session checkpoint — save/load for resumption
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_messages(messages: list[dict]) -> list[dict]:
        """Convert any Anthropic SDK objects inside messages to plain dicts."""
        result = []
        for msg in messages:
            m = dict(msg)
            content = m.get("content")
            if isinstance(content, list):
                serialized: list = []
                for block in content:
                    if hasattr(block, "model_dump"):        # Anthropic SDK pydantic model
                        serialized.append(block.model_dump())
                    elif hasattr(block, "__dict__") and not isinstance(block, dict):
                        serialized.append(vars(block))
                    else:
                        serialized.append(block)
                m["content"] = serialized
            result.append(m)
        return result

    def save_checkpoint(self, messages: list[dict], backend: str,
                        specialist_prompt: str = "", iteration: int = 0,
                        name: str = "latest") -> Path:
        """Persist full session state (messages + scratchpad) to disk.

        File: <session.dir>/checkpoint_<name>.json
        """
        state = {
            "schema_version": 2,
            "challenge": self.challenge,
            "backend": backend,
            "specialist_prompt": specialist_prompt,
            "iteration": iteration,
            "working_memory": self.working_memory,
            "failed_methods": self.failed_methods,
            "thoughts": self.thoughts,
            "tools_used": self.tools_used,
            "messages": self._serialize_messages(messages),
            # Loop-detection state — preserved across resume
            "tool_call_counts": {
                k: list(v) for k, v in self._tool_call_counts.items()
            },
        }
        path = self.dir / f"checkpoint_{name}.json"
        path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    @classmethod
    def load_checkpoint(cls, checkpoint_path: Path) -> tuple["Session", dict]:
        """Load a session from a checkpoint file.

        Returns (session, state) where state contains 'messages', 'backend', etc.
        The session.dir is set to the checkpoint's parent directory so all future
        logs append to the original session folder.
        """
        state: dict = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        challenge = state["challenge"]
        session = cls.__new__(cls)          # bypass __init__ to avoid creating a new dir
        session.challenge = challenge
        session.failed_methods = state.get("failed_methods", [])
        session.tools_used = state.get("tools_used", [])
        session.working_memory = state.get("working_memory", {})
        session.thoughts = state.get("thoughts", [])
        session._events = []                # rebuild from new run
        session.dir = checkpoint_path.parent
        session._commands_log = session.dir / "commands.log"
        # Restore loop-detection state so resumed sessions don't re-allow blocked calls
        raw_counts = state.get("tool_call_counts", {})
        session._tool_call_counts = {k: tuple(v) for k, v in raw_counts.items()}
        session._current_iteration = state.get("iteration", 0)
        session._stagnation_counter = 0
        session._last_unique_iteration = state.get("iteration", 0)
        return session, state

    def save_global_memory(self, flag: str, lesson_learned: str = None):
        """
        Append a compact record of this session to global_memory.json.
        Future sessions load this to benefit from past experience.
        """
        GLOBAL_MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)

        existing: list[dict] = []
        if GLOBAL_MEMORY_PATH.exists():
            try:
                existing = json.loads(GLOBAL_MEMORY_PATH.read_text(encoding="utf-8"))
            except Exception:
                existing = []

        record = {
            "timestamp": datetime.now().isoformat(),
            "challenge_snippet": self.challenge[:200],
            "category": self.working_memory.get("category", "unknown"),
            "outcome": "SOLVED" if flag not in ("NOT_FOUND", "NOT_FOUND\n", "") else "FAILED",
            "flag": flag if flag not in ("NOT_FOUND", "") else None,
            "failed_methods": self.failed_methods,
            "lesson_learned": lesson_learned,
            "thoughts_summary": self.thoughts[-1][:300] if self.thoughts else "",
            "working_memory": dict(self.working_memory),
            "tools_used": self.tools_used,
        }

        # Keep the last 100 records to avoid unbounded growth
        existing.append(record)
        existing = existing[-100:]

        GLOBAL_MEMORY_PATH.write_text(
            json.dumps(existing, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
