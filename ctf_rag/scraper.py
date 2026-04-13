"""
CTF Writeup Scraper — mass ingestion from GitHub repositories.

Clones well-known CTF writeup repositories and converts them to
the internal writeup format, ready for ChromaDB ingestion.

Usage:
    python -m ctf_rag.scraper            # clone + ingest all sources
    python -m ctf_rag.scraper --list     # show configured sources
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import Iterator

from rich.console import Console
from rich.progress import track

console = Console()

# ---------------------------------------------------------------------------
# Known sources: GitHub repos with structured CTF writeups
# ---------------------------------------------------------------------------

WRITEUP_SOURCES = [
    # Format: (repo_url, branch, subdirs_to_scan, category_hint)
    # All verified to exist as of April 2026
    ("https://github.com/sajjadium/ctf-writeups", "master", [], None),
    ("https://github.com/pr0v3rbs/CTF", "master", [], None),
    ("https://github.com/VoidHack/write-ups", "master", [], None),
    ("https://github.com/4n86rakam1/writeup", "main", [], None),
    ("https://github.com/angstrom-ctf/angstromctf-2023", "main", ["writeups"], None),
    ("https://github.com/hxp-ctf/htb-challenges", "main", [], None),
    ("https://github.com/perfectblue/ctf-writeups", "master", [], None),
    ("https://github.com/TeamItaly/TeamItalyCTF-2023", "main", [], None),
    ("https://github.com/Legoclones/created-ctf-challenges", "main", [], None),
]

# HackTricks repos — technique-first knowledge base.
# Parsed separately: see parse_hacktricks_page() below.
HACKTRICKS_SOURCES = [
    ("https://github.com/carlospolop/hacktricks", "master"),
    ("https://github.com/carlospolop/hacktricks-cloud", "master"),
]

# HackTricks path prefixes that are enumeration-style (inform the Planner)
# vs exploit/technique pages (inform the Executor).
_HT_ENUMERATION_DIRS = {
    "network-services-pentesting",
    "generic-methodologies-and-resources",
    "reconnaissance",
    "misc",
    "physical-attacks",
    "todo",
    "README",
}
_HT_EXPLOIT_DIRS = {
    "pentesting-web",
    "binary-exploitation",
    "cryptography",
    "forensics",
    "reversing",
    "mobile-pentesting",
    "linux-hardening",
    "windows-hardening",
    "macos-hardening",
}

# Fallback: if network is unavailable, download individual writeup markdown
# files from raw.githubusercontent.com
FALLBACK_RAW_URLS = [
    # picoCTF writeups
    "https://raw.githubusercontent.com/HHousen/PicoCTF-2022/master/Cryptography/README.md",
    "https://raw.githubusercontent.com/HHousen/PicoCTF-2022/master/Reverse%20Engineering/README.md",
    "https://raw.githubusercontent.com/HHousen/PicoCTF-2022/master/Web%20Exploitation/README.md",
    "https://raw.githubusercontent.com/HHousen/PicoCTF-2022/master/Binary%20Exploitation/README.md",
    "https://raw.githubusercontent.com/HHousen/PicoCTF-2022/master/Forensics/README.md",
]

CLONE_BASE = Path("data/scraped_writeups")

# ---------------------------------------------------------------------------
# Category detection
# ---------------------------------------------------------------------------

CATEGORY_KEYWORDS = {
    "crypto": ["rsa", "aes", "xor", "encrypt", "decrypt", "cipher", "hash", "elliptic",
                "modular", "prime", "diffie", "polynomial", "sage", "lattice", "coppersmith",
                "cbc", "ecb", "gcm", "sha", "hmac", "vigenere", "frequency", "otp"],
    "pwn": ["buffer overflow", "ret2libc", "rop", "shellcode", "heap", "use after free",
             "format string", "libc", "gdb", "pwntools", "overwrite", "got", "plt", "canary"],
    "web": ["sql injection", "xss", "csrf", "ssrf", "lfi", "rfi", "ssti", "jwt", "cookie",
             "admin", "login", "flask", "php", "node", "express", "upload", "path traversal"],
    "rev": ["decompile", "disassemble", "radare", "ghidra", "ida", "angr", "crackme",
             "binary", "obfuscate", "anti-debug", "z3", "symbolic", "assembly", "reverse"],
    "forensics": ["pcap", "wireshark", "steganography", "exif", "metadata", "binwalk",
                   "file carving", "memory dump", "volatility", "steg", "png", "jpeg", "zip"],
    "misc": ["quiz", "programming", "osint", "morse", "base64", "qr", "barcode"],
}


def detect_category(text: str, hint: str | None = None) -> str:
    if hint:
        return hint
    text_lower = text.lower()
    scores = {cat: sum(1 for kw in words if kw in text_lower)
              for cat, words in CATEGORY_KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "misc"


# ---------------------------------------------------------------------------
# Writeup parser: extract structured data from markdown files
# ---------------------------------------------------------------------------

def parse_hacktricks_page(path: Path) -> dict | None:
    """
    Parse a HackTricks markdown page into the internal writeup format.

    Key differences from generic writeup parsing:
    - Distinguishes 'enumeration' vs 'exploit' page_type based on directory path.
    - Extracts ALL code blocks (often the most reusable part of HackTricks pages).
    - Prepends [HackTricks: <page-title>] to each chunk so vectors don't lose context
      when the payload text is short (e.g. "{{7*7}}").
    - Stores page_type in tags so search_writeups can filter by planner vs executor intent.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    if len(text) < 80:
        return None

    # --- Page type: enumeration (planner) vs exploit (executor) ---
    path_str = str(path).lower()
    page_type = "exploit"  # default
    for d in _HT_ENUMERATION_DIRS:
        if d in path_str:
            page_type = "enumeration"
            break

    # --- Title: first H1 or filename ---
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    raw_title = title_match.group(1).strip() if title_match else path.stem
    raw_title = re.sub(r"\s+", " ", raw_title)[:120]
    title = f"[HackTricks] {raw_title}"

    # --- Category ---
    category = detect_category(text)
    for cat in CATEGORY_KEYWORDS:
        if cat in path_str:
            category = cat
            break

    # --- Code blocks: the heart of HackTricks pages ---
    code_blocks = re.findall(r"```(?:[a-zA-Z0-9_+-]*)?\n(.*?)```", text, re.DOTALL)
    # Keep the top 6 most substantial blocks (skip one-liners)
    substantial_blocks = [cb.strip() for cb in code_blocks if len(cb.strip()) > 30][:6]
    reusable_code = "\n\n# ---\n".join(substantial_blocks)

    # --- Key insight: first substantial paragraph (usually the intro) ---
    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 60]
    key_insight = re.sub(r"[#`*!]|\[.*?\]\(.*?\)", "", paragraphs[0] if paragraphs else "")[:400]

    # --- Solution: full text minus images, capped at 4000 chars ---
    solution = re.sub(r"!\[.*?\]\(.*?\)", "", text)[:4000]

    # --- Searchable document: prefix prevents short payload vectors losing context ---
    # e.g. "{{7*7}}" alone won't match "SSTI Jinja2", but "[HackTricks: SSTI] {{7*7}}" will.
    context_prefix = f"[HackTricks: {raw_title}] {category} {page_type}"
    document = f"{context_prefix} {key_insight[:300]}".strip()

    tools_found = [t for t in [
        "python", "curl", "nmap", "sqlmap", "metasploit", "burpsuite",
        "openssl", "john", "hashcat", "ffuf", "gobuster", "wfuzz",
        "wireshark", "volatility", "binwalk", "ghidra", "pwntools", "z3",
    ] if t in text.lower()]

    return {
        "title": title,
        "category": category,
        "difficulty": "reference",
        "event": "hacktricks",
        "tags": f"{page_type}, " + ", ".join(tools_found[:5]),
        "tools": ", ".join(tools_found),
        "description": raw_title,
        "solution": solution,
        "key_insight": key_insight,
        "reusable_code": reusable_code[:3000],
        "document": document,
    }


def parse_markdown_writeup(path: Path, category_hint: str | None = None) -> dict | None:
    """
    Parse any CTF writeup markdown file into our internal format.
    Tries to extract: title, category, solution steps, key insight, flag.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    if len(text) < 100:
        return None

    # --- Title ---
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else path.stem

    # Clean up title
    title = re.sub(r"\s+", " ", title)[:120]

    # --- Category guess ---
    category = detect_category(text, category_hint)
    # Override if path contains category keyword
    for cat in CATEGORY_KEYWORDS:
        if cat in str(path).lower():
            category = cat
            break

    # --- Flag extraction ---
    flag_match = re.search(
        r"(picoCTF\{[^}]+\}|flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}|"
        r"HTB\{[^}]+\}|ENSA\{[^}]+\}|[A-Z]{2,10}\{[^}]{5,50}\})",
        text,
    )
    flag = flag_match.group(0) if flag_match else None

    # --- Extract code blocks as solution evidence ---
    code_blocks = re.findall(r"```(?:python|bash|sh|sage|text|)?\n(.*?)```", text, re.DOTALL)
    solution_code = "\n\n".join(cb[:500] for cb in code_blocks[:4])

    # --- Key insight: first substantial paragraph after intro ---
    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 80]
    key_insight = paragraphs[1] if len(paragraphs) > 1 else paragraphs[0] if paragraphs else ""
    key_insight = re.sub(r"[#`*]", "", key_insight)[:400]

    # --- Full solution: everything after first h2 ---
    solution_match = re.search(r"^##\s+.+$", text, re.MULTILINE)
    if solution_match:
        solution = text[solution_match.start():][:3000]
    else:
        solution = text[:3000]

    solution = re.sub(r"!\[.*?\]\(.*?\)", "", solution)  # remove images

    # --- Tools used ---
    tool_words = ["python", "sage", "pwntools", "z3", "angr", "ghidra", "radare2",
                  "sqlmap", "nmap", "curl", "ffuf", "binwalk", "exiftool", "steghide",
                  "wireshark", "volatility", "hashcat", "john", "openssl"]
    tools_found = [t for t in tool_words if t in text.lower()]

    document = f"{title} {category} {key_insight[:200]}".strip()

    return {
        "title": title,
        "category": category,
        "difficulty": "unknown",
        "event": path.parent.name or "unknown",
        "tags": ", ".join(tools_found[:6]),
        "tools": ", ".join(tools_found),
        "description": title,
        "solution": solution,
        "key_insight": key_insight,
        "flag_example": flag or "",
        "document": document,
    }


# ---------------------------------------------------------------------------
# Repo cloner
# ---------------------------------------------------------------------------

def _clone_or_update(repo_url: str, branch: str = "main") -> Path | None:
    """Clone repo if missing, pull if already exists. Returns local path."""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    dest = CLONE_BASE / repo_name

    CLONE_BASE.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        console.print(f"  [dim]↻ Updating {repo_name}...[/dim]")
        r = subprocess.run(
            ["git", "pull", "--depth=1"], cwd=dest,
            capture_output=True, text=True, timeout=60,
        )
    else:
        console.print(f"  [cyan]⤓ Cloning {repo_name}...[/cyan]")
        r = subprocess.run(
            ["git", "clone", "--depth=1", "--branch", branch, repo_url, str(dest)],
            capture_output=True, text=True, timeout=300,
        )

    if r.returncode != 0:
        console.print(f"  [red]✗ Failed:[/red] {r.stderr[:200]}")
        return None

    return dest


# ---------------------------------------------------------------------------
# Markdown file walker
# ---------------------------------------------------------------------------

def iter_writeup_files(base: Path, subdirs: list[str]) -> Iterator[Path]:
    """Yield all .md files under base (or specific subdirs)."""
    search_roots = [base / s for s in subdirs] if subdirs else [base]
    for root in search_roots:
        if not root.exists():
            continue
        for md_file in root.rglob("*.md"):
            # Skip root meta files but allow README.md deep in subfolders
            if md_file.name.lower() in ("contributing.md", "license.md"):
                continue
            if md_file.name.lower() == "readme.md" and md_file.parent == root:
                continue
            yield md_file


# ---------------------------------------------------------------------------
# Batch download fallback (raw URLs)
# ---------------------------------------------------------------------------

def _download_raw(url: str) -> Path | None:
    """Download a single markdown file to data/scraped_writeups/raw/."""
    import urllib.request
    raw_dir = CLONE_BASE / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    filename = url.split("/")[-1].replace("%20", "_")
    dest = raw_dir / filename
    try:
        urllib.request.urlretrieve(url, dest)
        return dest
    except Exception as e:
        console.print(f"  [red]✗ Download failed:[/red] {e}")
        return None


# ---------------------------------------------------------------------------
# Main scrape + ingest pipeline
# ---------------------------------------------------------------------------

def scrape_and_ingest(
    sources: list = None,
    max_per_repo: int = 200,
    use_fallback: bool = True,
) -> int:
    """
    Clone repos, parse writeups, ingest into ChromaDB.
    Returns total number of new writeups added.
    """
    from ctf_rag.ingest import _get_collection, embed_and_store
    import hashlib

    if sources is None:
        sources = WRITEUP_SOURCES

    collection = _get_collection()
    total_added = 0

    for repo_url, branch, subdirs, category_hint in sources:
        console.print(f"\n[bold cyan]◉ {repo_url.split('/')[-1]}[/bold cyan]")

        repo_path = _clone_or_update(repo_url, branch)
        if not repo_path:
            continue

        files = list(iter_writeup_files(repo_path, subdirs))
        console.print(f"  Found {len(files)} markdown files")

        added = 0
        for md_file in files[:max_per_repo]:
            writeup = parse_markdown_writeup(md_file, category_hint)
            if not writeup:
                continue
            try:
                stored = embed_and_store(writeup, collection)
                if stored:
                    added += 1
            except Exception:
                pass

        console.print(f"  [green]✓ Added {added} new writeups[/green]")
        total_added += added

    # Fallback: download raw files if nothing was added
    if total_added == 0 and use_fallback:
        console.print("\n[yellow]Repos failed — trying raw URL fallback...[/yellow]")
        for url in FALLBACK_RAW_URLS:
            path = _download_raw(url)
            if path:
                writeup = parse_markdown_writeup(path)
                if writeup:
                    try:
                        stored = embed_and_store(writeup, collection)
                        if stored:
                            total_added += 1
                    except Exception:
                        pass

    console.print(f"\n[bold green]Total new writeups ingested: {total_added}[/bold green]")
    console.print(f"[dim]KB size: {collection.count()} writeups[/dim]")
    return total_added


def scrape_hacktricks(max_per_repo: int = 500) -> int:
    """
    Clone HackTricks repos and ingest every page into ChromaDB.

    Pages are stored in the ctf_writeups collection with:
      - event='hacktricks'
      - tags containing 'enumeration' or 'exploit' so the agent can filter by intent

    Also triggers Layer-2 technique extraction for exploit pages (via ingest.extract_and_store_technique).
    Returns total new pages added.
    """
    from ctf_rag.ingest import _get_collection, embed_and_store

    collection = _get_collection()
    total_added = 0

    for repo_url, branch in HACKTRICKS_SOURCES:
        console.print(f"\n[bold magenta]◉ HackTricks: {repo_url.split('/')[-1]}[/bold magenta]")

        repo_path = _clone_or_update(repo_url, branch)
        if not repo_path:
            continue

        md_files = [
            p for p in repo_path.rglob("*.md")
            if p.name.lower() not in ("contributing.md", "license.md", "summary.md")
        ]
        console.print(f"  Found {len(md_files)} pages")

        added = 0
        for md_file in track(md_files[:max_per_repo], description=f"  Ingesting {repo_url.split('/')[-1]}..."):
            parsed = parse_hacktricks_page(md_file)
            if not parsed:
                continue
            try:
                stored = embed_and_store(parsed, collection)
                if stored:
                    added += 1
            except Exception as e:
                console.print(f"  [red]✗[/red] {md_file.name}: {e}")

        console.print(f"  [green]✓ Added {added} HackTricks pages[/green]")
        total_added += added

    console.print(f"\n[bold green]HackTricks total: {total_added} new pages[/bold green]")
    console.print(f"[dim]KB size: {collection.count()} entries total[/dim]")
    return total_added


if __name__ == "__main__":
    if "--list" in sys.argv:
        for url, branch, subdirs, cat in WRITEUP_SOURCES:
            print(f"  {url} [{branch}] cat={cat or 'auto'}")
    elif "--hacktricks" in sys.argv:
        scrape_hacktricks()
    else:
        scrape_and_ingest()
