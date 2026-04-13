import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
def cli():
    """CTF RAG Agent — AI-powered CTF challenge solver with writeup knowledge base."""


@cli.command()
@click.option("--dir", "writeups_dir", default="data/writeups", show_default=True,
              help="Directory containing .md writeup files.")
def ingest(writeups_dir: str):
    """Ingest writeup files into ChromaDB vector store."""
    from ctf_rag.ingest import ingest_all
    console.print(Panel(f"[bold cyan]Ingesting writeups from:[/bold cyan] {writeups_dir}"))
    ingest_all(writeups_dir)


@cli.command()
@click.option("--challenge", "-c", default=None, help="Challenge description as a string.")
@click.option("--file", "-f", "challenge_file", default=None,
              type=click.Path(exists=True), help="Path to a text file with the challenge description.")
@click.option("--category", default=None,
              type=click.Choice(["web", "crypto", "pwn", "rev", "forensics", "misc"], case_sensitive=False),
              help="Challenge category for filtered retrieval.")
@click.option("--top-k", default=3, show_default=True, help="Number of similar writeups to retrieve.")
@click.option("--verbose", is_flag=True, help="Show raw retrieved writeup chunks.")
def solve(challenge: str, challenge_file: str, category: str, top_k: int, verbose: bool):
    """Solve a CTF challenge using RAG + Anthropic API."""
    if challenge_file:
        challenge = Path(challenge_file).read_text(encoding="utf-8").strip()
    elif not challenge:
        console.print("[red]Error:[/red] Provide --challenge or --file.")
        sys.exit(1)

    console.print(Panel(Markdown(f"**Challenge:**\n{challenge}"), title="[bold]Input[/bold]"))

    if category:
        console.print(f"[dim]Category filter: {category}[/dim]")

    console.print("[dim]Retrieving similar writeups and querying AI...[/dim]\n")

    try:
        from ctf_rag.agent import solve as agent_solve
        response_text, retrieved = agent_solve(challenge, category=category, top_k=top_k)
    except ValueError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)
    except RuntimeError as e:
        console.print(f"[red]API error:[/red] {e}")
        sys.exit(1)

    if verbose and retrieved:
        console.print(Panel("[bold yellow]Retrieved Context[/bold yellow]"))
        for i, r in enumerate(retrieved, 1):
            console.print(
                f"[{i}] [cyan]{r['title']}[/cyan] "
                f"([dim]{r['category']}[/dim], dist={r['distance']:.4f})\n"
                f"    Tools: {r['tools']}\n"
                f"    Key Insight: {r['key_insight']}\n"
            )

    console.print(Panel(Markdown(response_text), title="[bold green]CTF Agent Response[/bold green]"))

    if retrieved:
        titles = ", ".join(f"[cyan]{r['title']}[/cyan]" for r in retrieved)
        console.print(f"\n[dim]Retrieved context from: {titles}[/dim]")
    else:
        console.print("\n[dim yellow]No similar writeups found — answer based on general knowledge.[/dim yellow]")


@cli.command(name="list")
@click.option("--category", default=None,
              type=click.Choice(["web", "crypto", "pwn", "rev", "forensics", "misc"], case_sensitive=False),
              help="Filter by category.")
def list_writeups(category: str):
    """List all writeups stored in ChromaDB."""
    import chromadb

    client = chromadb.PersistentClient(path="./chroma_db")
    try:
        collection = client.get_collection("ctf_writeups")
    except Exception:
        console.print("[yellow]No writeups found. Run `ingest` first.[/yellow]")
        return

    results = collection.get(include=["metadatas"])
    metadatas = results["metadatas"]

    if category:
        metadatas = [m for m in metadatas if m.get("category", "").lower() == category.lower()]

    if not metadatas:
        msg = f"No writeups found for category '{category}'." if category else "No writeups found."
        console.print(f"[yellow]{msg}[/yellow]")
        return

    table = Table(title=f"CTF Writeups ({len(metadatas)} total)", show_lines=True)
    table.add_column("Title", style="cyan", no_wrap=False)
    table.add_column("Category", style="magenta")
    table.add_column("Difficulty", style="yellow")
    table.add_column("Event", style="green")
    table.add_column("Tags", style="dim")

    for m in sorted(metadatas, key=lambda x: (x.get("category", ""), x.get("title", ""))):
        table.add_row(
            m.get("title", "?"),
            m.get("category", "?"),
            m.get("difficulty", "?"),
            m.get("event", "?"),
            m.get("tags", ""),
        )

    console.print(table)


@cli.command()
@click.option("--challenge", "-c", default=None, help="Challenge description as a string.")
@click.option("--file", "-f", "challenge_file", default=None,
              type=click.Path(exists=True), help="Path to a text file with the challenge description.")
@click.option(
    "--backend", "-b",
    default=None, show_default=True,
    type=click.Choice(["claude", "azure", "nvidia", "openrouter", "deepseek", "hybrid"], case_sensitive=False),
    help=(
        "LLM backend to use:\n"
        "  claude     — Anthropic Claude Sonnet\n"
        "  azure      — Azure OpenAI GPT-5.1 (default)\n"
        "  nvidia     — NVIDIA NIM DeepSeek-V3 with extended thinking\n"
        "  openrouter — OpenRouter Nemotron-3-Super-120B with reasoning_details\n"
        "  deepseek   — DeepSeek API (deepseek-chat / deepseek-reasoner)\n"
        "  hybrid     — DeepSeek brain + Azure executor + Gemini healer (best quality)"
    ),
)
@click.option(
    "--category",
    default=None,
    type=click.Choice(["web", "crypto", "pwn", "rev", "forensics", "misc",
                       "blockchain", "android"], case_sensitive=False),
    help="Challenge category — helps the agent start with the right attack tree.",
)
@click.option(
    "--files", "artifact_files", multiple=True,
    help="Challenge artifact(s) to auto-recon before the first LLM call. Repeatable: --files a.bin --files b.png",
)
@click.option("--url", default=None, help="Target URL to auto-recon (curl, whatweb, common paths).")
@click.option("--nc", default=None, metavar="HOST:PORT", help="nc target to banner-grab and nmap. Format: host:port")
@click.option("--resume", "-r", default=None, metavar="PATH",
              help="Resume a previous session. Pass the session dir or checkpoint_latest.json path.")
def agent(challenge: str, challenge_file: str, backend: str, category: str,
          artifact_files: tuple, url: str, nc: str, resume: str):
    """
    Run the autonomous agent loop (up to 500 iterations, real tool use).

    Supports multiple LLM backends. Press Ctrl+C at any time to pause the agent
    and inject instructions — press Enter alone to resume.

    Run with no arguments to enter the interactive wizard (paste challenge, choose provider).

    \b
    Examples:
      python -m ctf_rag.cli agent --challenge "Login form, JWT auth" --category web --backend azure
      python -m ctf_rag.cli agent --challenge "pwn this" --files ./vuln --category pwn
      python -m ctf_rag.cli agent --challenge "web app" --url http://target.ctf --backend deepseek
      python -m ctf_rag.cli agent --file challenge.txt --nc chall.ctf.io:1337
      python -m ctf_rag.cli agent --challenge "ARM crackme" --files ./vault_app --backend nvidia
      python -m ctf_rag.cli agent   (interactive wizard)
    """
    _BACKENDS = ["claude", "azure", "nvidia", "openrouter", "deepseek", "hybrid"]
    _BACKEND_LABELS = {
        "claude":     "Anthropic Claude Sonnet",
        "azure":      "Azure OpenAI GPT-5.1",
        "nvidia":     "NVIDIA NIM DeepSeek-V3 (thinking)",
        "openrouter": "OpenRouter Nemotron-120B (reasoning)",
        "deepseek":   "DeepSeek API (V3.2 / R1)",
        "hybrid":     "DeepSeek brain + Azure executor + Gemini healer  ★ best",
    }

    if resume:
        challenge = challenge or (Path(challenge_file).read_text(encoding="utf-8").strip() if challenge_file else "")
        if backend is None:
            backend = "azure"
    elif challenge_file:
        challenge = Path(challenge_file).read_text(encoding="utf-8").strip()
        if backend is None:
            backend = "azure"
    elif challenge:
        if backend is None:
            backend = "azure"
    else:
        # ── Interactive wizard ──────────────────────────────────────────────
        console.print("\n[bold cyan]═══ CTF Agent Wizard ═══[/bold cyan]\n")

        # Provider selection
        console.print("[bold]Select provider:[/bold]")
        for i, b in enumerate(_BACKENDS, 1):
            console.print(f"  [cyan]{i}[/cyan]) {b:12s} — {_BACKEND_LABELS[b]}")
        console.print()
        while True:
            raw = input("Provider [1=claude, 2=azure, 5=deepseek, 6=hybrid, default=2]: ").strip()
            if raw == "":
                backend = "azure"
                break
            if raw.isdigit() and 1 <= int(raw) <= len(_BACKENDS):
                backend = _BACKENDS[int(raw) - 1]
                break
            if raw.lower() in _BACKENDS:
                backend = raw.lower()
                break
            console.print(f"[red]Invalid choice.[/red] Enter 1-{len(_BACKENDS)} or a backend name.")

        console.print(f"[dim]→ using [cyan]{backend}[/cyan][/dim]\n")

        # Category
        raw = input("Category [web/crypto/pwn/rev/forensics/misc/blockchain/android, Enter=auto-detect]: ").strip().lower()
        if raw in ("web", "crypto", "pwn", "rev", "forensics", "misc", "blockchain", "android"):
            category = raw

        # Artifact files
        raw = input("Challenge files (comma-separated paths, or Enter to skip): ").strip()
        if raw:
            artifact_files = tuple(p.strip() for p in raw.split(",") if p.strip())

        # URL
        raw = input("Target URL (or Enter to skip): ").strip()
        if raw:
            url = raw

        # nc target
        raw = input("nc target host:port (or Enter to skip): ").strip()
        if raw:
            nc = raw

        # Multi-line challenge paste
        console.print("\n[bold]Paste challenge description.[/bold] Type [cyan]END[/cyan] on its own line when done:\n")
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == "END":
                break
            lines.append(line)
        challenge = "\n".join(lines).strip()

        if not challenge:
            console.print("[red]No challenge provided — aborting.[/red]")
            sys.exit(1)

        console.print(f"\n[dim]Challenge ({len(challenge)} chars), backend=[cyan]{backend}[/cyan], "
                      f"category=[yellow]{category or 'auto'}[/yellow][/dim]\n")

    # Auto-recon phase — runs before any LLM call (skip on resume unless explicitly requested)
    recon_context = ""
    if (artifact_files or url or nc) and not resume:
        from ctf_rag.recon import auto_recon
        console.print("[dim cyan]Running pre-agent recon...[/dim cyan]")
        recon_context = auto_recon(
            files=list(artifact_files) if artifact_files else None,
            url=url,
            nc=nc,
        )

    try:
        from ctf_rag.autonomous import run_agent
        run_agent(
            challenge or "",
            backend=backend.lower(),
            category=category,
            recon_context=recon_context,
            resume_from=resume,
        )
    except ValueError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        console.print(f"[red]Checkpoint not found:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Agent error:[/red] {e}")
        raise



@cli.command()
@click.option("--last", "-n", default=10, show_default=True, help="Show the N most recent sessions.")
def sessions(last: int):
    """List recent sessions with resume commands.

    \b
    Examples:
      python -m ctf_rag.cli sessions
      python -m ctf_rag.cli sessions --last 5
    """
    checkpoints = sorted(
        Path("outputs").rglob("checkpoint_latest.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:last]

    if not checkpoints:
        console.print("[yellow]No resumable sessions found.[/yellow]")
        return

    from datetime import datetime
    table = Table(title=f"Resumable Sessions (newest first)", show_lines=True)
    table.add_column("N", style="dim", width=3)
    table.add_column("Date", style="green")
    table.add_column("Challenge", style="cyan", max_width=50)
    table.add_column("Backend", style="magenta")
    table.add_column("Iter", style="yellow")
    table.add_column("Category", style="blue")
    table.add_column("Resume command", style="dim")

    for i, ckpt in enumerate(checkpoints, 1):
        try:
            state = json.loads(ckpt.read_text(encoding="utf-8"))
        except Exception:
            continue
        mtime = datetime.fromtimestamp(ckpt.stat().st_mtime).strftime("%m-%d %H:%M")
        challenge_snippet = state.get("challenge", "?")[:48].replace("\n", " ")
        backend = state.get("backend", "?")
        iteration = state.get("iteration", "?")
        category = state.get("working_memory", {}).get("category", "?")
        resume_cmd = f"--resume {ckpt.parent}"
        table.add_row(str(i), mtime, challenge_snippet, backend, str(iteration), category, resume_cmd)

    console.print(table)
    console.print("\n[dim]Resume with:[/dim] [cyan]python -m ctf_rag.cli agent --resume <path>[/cyan]")
    console.print("[dim]Or via start.sh — choose 'Resume' at the challenge input prompt.[/dim]")


@cli.command()
@click.option("--max-per-repo", default=500, show_default=True,
              help="Max HackTricks pages to ingest per repo (full = ~4000 each).")
def hacktricks(max_per_repo: int):
    """Clone HackTricks + HackTricks Cloud and ingest all technique pages.

    \b
    This is the single highest-impact knowledge bootstrapping step.
    Adds ~4000 technique-first pages covering every CTF category.
    Run once after initial setup, then periodically to pick up new content.

    \b
    Example:
      python -m ctf_rag.cli hacktricks
      python -m ctf_rag.cli hacktricks --max-per-repo 1000
    """
    from ctf_rag.scraper import scrape_hacktricks
    console.print(Panel("[bold magenta]HackTricks knowledge base bootstrap[/bold magenta]"))
    total = scrape_hacktricks(max_per_repo=max_per_repo)
    console.print(f"[bold green]Done! {total} new technique pages added.[/bold green]")


@cli.command()
def probe_tools():
    """Detect installed tool versions and capabilities — builds the Capabilities Manifest.

    \b
    Run at initial setup and after any tooling changes. The manifest is stored to
    outputs/capabilities.json and injected into the agent system prompt at startup.
    This prevents the agent from claiming tools are missing when they are available.

    \b
    Examples:
      python -m ctf_rag.cli probe_tools
    """
    import json
    import shutil
    import subprocess

    console.print(Panel("[bold cyan]Tool Capability Probe[/bold cyan]"))

    def _run(cmd: str) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return (r.stdout.strip() or r.stderr.strip())[:200]
        except Exception as e:
            return f"ERROR: {e}"

    def _which(name: str) -> str:
        p = shutil.which(name)
        return p if p else "NOT_FOUND"

    results: dict = {}

    # ── Binary tools ──────────────────────────────────────────────────────
    tools_to_probe = [
        # (name_in_manifest, shell_command_to_get_version)
        ("python3",       "python3 --version"),
        ("pwntools",      "python3 -c 'import pwn; print(pwn.__version__)' 2>&1 || python3 -c 'import pwnlib; print(pwnlib.__version__)'"),
        ("gdb",           "gdb --version | head -1"),
        ("r2/radare2",    "r2 -v | head -1"),
        ("qemu-arm",      "qemu-arm --version | head -1"),
        ("qemu-aarch64",  "qemu-aarch64 --version | head -1"),
        ("qemu-mips",     "qemu-mips --version | head -1"),
        ("qemu-mipsel",   "qemu-mipsel --version | head -1"),
        # one_gadget is a Ruby gem — check with `which` to avoid shell 'not found' confusion
        ("one_gadget",    "which one_gadget 2>/dev/null && one_gadget --version 2>&1 || echo NOT_FOUND"),
        ("ropper",        "ropper --version 2>&1 | head -1"),
        ("z3",            "python3 -c 'import z3; print(z3.get_version_string())'"),
        ("gmpy2",         "python3 -c 'import gmpy2; print(gmpy2.version())'"),
        # sage may not be in PATH even when installed via conda/pip
        ("sage",          "which sage 2>/dev/null && sage --version 2>&1 | head -1 || echo NOT_FOUND"),
        ("hashcat",       "hashcat --version"),
        # john: use --help (--version not supported on this build)
        ("john",          "john 2>&1 | head -2 | tail -1"),
        ("sqlmap",        "sqlmap --version 2>&1 | head -1"),
        ("ffuf",          "ffuf -V 2>&1 | head -1"),
        # gobuster: use --version flag (not 'version' subcommand)
        ("gobuster",      "gobuster --version 2>&1 | head -1"),
        ("nmap",          "nmap --version | head -1"),
        ("wireshark/tshark", "tshark --version 2>&1 | head -1"),
        # binwalk ships a PATH binary — use --version (not --help)
        ("binwalk",       "binwalk --version 2>&1 | head -1 || python3 -c 'import binwalk; print(binwalk.__version__)'"),
        ("exiftool",      "exiftool -ver"),
        ("steghide",      "steghide --version 2>&1 | head -1"),
        ("openssl",       "openssl version"),
        ("curl",          "curl --version | head -1"),
        ("ghidra",        "which ghidra 2>/dev/null || which ghidraRun 2>/dev/null || echo NOT_FOUND"),
        ("rank_bm25",     "python3 -c 'import rank_bm25; print(\"installed\")'  2>&1"),
        ("angr",          "python3 -c 'import angr; print(angr.__version__)'"),
        ("unicorn",       "python3 -c 'import unicorn; print(unicorn.__version__)'"),
        ("pycryptodome",  "python3 -c 'import Crypto; print(Crypto.__version__)'"),
    ]

    from rich.table import Table
    table = Table(title="Tool Capability Manifest", show_lines=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Version Info", style="dim")

    # Phrases that indicate the tool output is an error, even if exit code 0
    _FAIL_SIGNATURES = (
        "NOT_FOUND", "ERROR:",
        "Traceback",         # Python import error
        ": not found",       # shell 'not found'
        "not found",         # shell 'not found' (no colon variant)
        "Unknown option",    # tool doesn't support the flag we used
        "No help topic",     # gobuster legacy 'version' subcommand
        "command not found", # bash fallback
        "No such file",      # path doesn't exist
    )

    for tool_name, cmd in tools_to_probe:
        output = _run(cmd)
        is_error = (
            not output
            or any(sig in output for sig in _FAIL_SIGNATURES)
        )
        available = "missing" if is_error else "available"
        results[tool_name] = {"status": available, "version_info": output[:120]}
        status_style = "[green]✓ installed[/green]" if available == "available" else "[red]✗ missing[/red]"
        table.add_row(tool_name, status_style, output[:80])

    console.print(table)

    # Save to outputs/capabilities.json
    Path("outputs").mkdir(exist_ok=True)
    caps_path = Path("outputs/capabilities.json")
    caps_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    console.print(f"\n[bold green]Capabilities manifest saved to: {caps_path}[/bold green]")
    console.print("[dim]The agent reads this file at startup to know exactly what tools are available.[/dim]")

    n_installed = sum(1 for v in results.values() if v["status"] == "available")
    console.print(f"\n[bold]{n_installed}/{len(results)} tools installed.[/bold]")
    console.print("\n[dim]Run this again after installing new tools to refresh the manifest.[/dim]")


@cli.command()
@click.option("--max-per-repo", default=200, show_default=True,
              help="Max writeups to ingest per repository.")
@click.option("--fallback/--no-fallback", default=True, show_default=True,
              help="Try raw URL fallback if repos fail to clone.")
def scrape(max_per_repo: int, fallback: bool):
    """Clone CTF writeup GitHub repos and ingest all writeups into ChromaDB.

    \b
    This command downloads thousands of CTF writeups from well-known repos
    and ingests them into the vector store. Run this once to bootstrap the KB.

    \b
    Example:
      python -m ctf_rag.cli scrape
      python -m ctf_rag.cli scrape --max-per-repo 100
    """
    from ctf_rag.scraper import scrape_and_ingest
    console.print(Panel("[bold cyan]Mass writeup scrape + ingest starting...[/bold cyan]"))
    total = scrape_and_ingest(max_per_repo=max_per_repo, use_fallback=fallback)
    console.print(f"[bold green]Done! Total new writeups added: {total}[/bold green]")


@cli.command()
@click.option(
    "--backend", "backend",
    type=click.Choice(["claude", "azure", "nvidia", "openrouter", "deepseek", "hybrid"], case_sensitive=False),
    default="azure", show_default=True,
    help="LLM backend: claude, azure, nvidia, openrouter, deepseek, or hybrid.",
)
@click.option("--max-iter", default=15, show_default=True,
              help="Max iterations per challenge.")
@click.option(
    "--category", "-C", multiple=True,
    type=click.Choice(["web", "crypto", "pwn", "rev", "forensics", "misc"], case_sensitive=False),
    help="Only run challenges in these categories. Repeatable: -C crypto -C web",
)
@click.option("--id", "challenge_ids", multiple=True,
              help="Run only specific challenge IDs. Repeatable.")
def benchmark(backend: str, max_iter: int, category: tuple, challenge_ids: tuple):
    """Run the agent against known CTF challenges and report the solve rate.

    \b
    This benchmarks the agent against 8+ built-in challenges with known flags,
    measures solve rate per category, and reports overall performance.

    \b
    Examples:
      python -m ctf_rag.cli benchmark --backend azure
      python -m ctf_rag.cli benchmark --backend azure --max-iter 10 -C crypto -C misc
      python -m ctf_rag.cli benchmark --id crypto_caesar_13 --id misc_morse
    """
    try:
        from ctf_rag.benchmark import run_benchmark
        run_benchmark(
            backend=backend.lower(),
            max_iterations=max_iter,
            categories=list(category) if category else None,
            challenge_ids=list(challenge_ids) if challenge_ids else None,
        )
    except ValueError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Benchmark error:[/red] {e}")
        raise


@cli.command()
@click.option("--last", "-n", default=1, show_default=True,
              help="Show the Nth most recent digest (1=latest).")
@click.option("--all", "show_all", is_flag=True,
              help="List all available digests instead of printing one.")
def digest(last: int, show_all: bool):
    """Print the latest session DIGEST.md — paste it into Claude Code for improvement hints.

    \b
    Examples:
      python -m ctf_rag.cli digest            # latest digest
      python -m ctf_rag.cli digest --last 2   # second most recent
      python -m ctf_rag.cli digest --all      # list all
    """
    from pathlib import Path
    digests = sorted(Path("outputs").rglob("DIGEST.md"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not digests:
        console.print("[yellow]No digests found. Run the agent first.[/yellow]")
        return

    if show_all:
        table = Table(title=f"Session Digests ({len(digests)} total)", show_lines=True)
        table.add_column("N", style="dim", width=3)
        table.add_column("Path", style="cyan")
        table.add_column("Modified", style="green")
        table.add_column("Outcome", style="magenta")
        for i, d in enumerate(digests, 1):
            text = d.read_text(encoding="utf-8")
            outcome = "SOLVED" if "Outcome**: SOLVED" in text else "FAILED"
            from datetime import datetime
            mtime = datetime.fromtimestamp(d.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            table.add_row(str(i), str(d), mtime, outcome)
        console.print(table)
        return

    idx = max(1, min(last, len(digests))) - 1
    chosen = digests[idx]
    console.print(Panel(
        Markdown(chosen.read_text(encoding="utf-8")),
        title=f"[bold cyan]DIGEST[/bold cyan] [dim]{chosen}[/dim]",
    ))
    console.print(f"\n[dim]Full path: {chosen.resolve()}[/dim]")
    console.print("[dim]Tip: copy the content above and paste it into Claude Code with: 'Based on this digest, improve the CTF agent.'[/dim]")


@cli.command()
@click.option("--max-techniques", default=200, show_default=True,
              help="Max how2heap technique files to ingest (full repo = ~40).")
def how2heap(max_techniques: int):
    """Clone shellphish/how2heap and ingest all heap exploitation techniques.

    \b
    how2heap is the definitive reference for glibc heap exploitation.
    Each .c file demonstrates a distinct technique with version annotations.
    Run this once to give the agent deep heap exploitation knowledge.

    \b
    Example:
      python -m ctf_rag.cli how2heap
    """
    import subprocess
    import tempfile
    from pathlib import Path

    console.print(Panel("[bold red]how2heap knowledge ingestion[/bold red]"))

    # Clone or update how2heap
    how2heap_dir = Path("data/how2heap")
    if how2heap_dir.exists():
        console.print("[dim]Updating existing how2heap clone...[/dim]")
        subprocess.run(["git", "-C", str(how2heap_dir), "pull", "--quiet"], check=False)
    else:
        console.print("[dim]Cloning shellphish/how2heap...[/dim]")
        try:
            subprocess.run(
                ["git", "clone", "--depth=1", "--quiet",
                 "https://github.com/shellphish/how2heap.git", str(how2heap_dir)],
                check=True, timeout=120,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            console.print(f"[red]Clone failed:[/red] {e}")
            console.print("[yellow]Falling back to embedded technique summaries...[/yellow]")
            _ingest_embedded_how2heap()
            return

    # Ingest each .c file as a technique writeup
    from ctf_rag.ingest import ingest_how2heap_dir
    c_files = sorted(how2heap_dir.glob("*.c"))[:max_techniques]
    if not c_files:
        c_files = sorted((how2heap_dir / "glibc_2.35").glob("*.c"))[:max_techniques]

    if not c_files:
        console.print("[yellow]No .c files found — ingesting readme/docs instead.[/yellow]")
        c_files = list(how2heap_dir.rglob("*.c"))[:max_techniques]

    console.print(f"[dim]Found {len(c_files)} technique files to ingest.[/dim]")
    total = ingest_how2heap_dir(c_files)
    console.print(f"[bold green]Done! {total} how2heap techniques ingested into knowledge base.[/bold green]")


@cli.command()
def pwncollegedocs():
    """Ingest pwn.college curriculum and technique summaries into the knowledge base.

    \b
    Creates structured writeups for pwn.college's core curriculum:
    exploitation primitives, ROP, format strings, heap, kernel, and more.
    This seeds the knowledge base with authoritative, structured content
    even without a live pwn.college connection.

    \b
    Example:
      python -m ctf_rag.cli pwncollegedocs
    """
    from ctf_rag.ingest import ingest_pwncollegedocs
    console.print(Panel("[bold cyan]pwn.college curriculum ingestion[/bold cyan]"))
    total = ingest_pwncollegedocs()
    console.print(f"[bold green]Done! {total} pwn.college technique documents ingested.[/bold green]")


def main():
    cli()


if __name__ == "__main__":
    main()
