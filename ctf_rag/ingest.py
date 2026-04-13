import hashlib
import json
import os
import re
from pathlib import Path

import chromadb
from google import genai
from rich.console import Console
from rich.progress import track
from sentence_transformers import SentenceTransformer

console = Console()

# Singleton embedding model
_model = None

def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


def _get_collection() -> chromadb.Collection:
    client = chromadb.PersistentClient(path="./chroma_db")
    return client.get_or_create_collection("ctf_writeups")


def _get_technique_collection() -> chromadb.Collection:
    client = chromadb.PersistentClient(path="./chroma_db")
    return client.get_or_create_collection("ctf_techniques")


def parse_writeup(filepath: str) -> dict:
    """
    Parse a markdown writeup file.
    Extracts frontmatter metadata and ## section content.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Parse YAML-like frontmatter between --- markers
    metadata = {}
    frontmatter_match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
    if frontmatter_match:
        frontmatter_text = frontmatter_match.group(1)
        for line in frontmatter_text.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                metadata[key.strip()] = value.strip()
        body = content[frontmatter_match.end():]
    else:
        body = content

    def extract_section(text: str, heading: str) -> str:
        pattern = rf"## {re.escape(heading)}\n(.*?)(?=\n## |\Z)"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""

    description = extract_section(body, "Challenge Description")
    solution = extract_section(body, "Solution")
    key_insight = extract_section(body, "Key Insight")

    title = metadata.get("title", Path(filepath).stem)
    category = metadata.get("category", "misc")

    document = f"{title} {category} {description} {key_insight}".strip()

    return {
        "title": title,
        "category": category,
        "difficulty": metadata.get("difficulty", "unknown"),
        "event": metadata.get("event", "unknown"),
        "tags": metadata.get("tags", ""),
        "tools": metadata.get("tools", ""),
        "description": description,
        "solution": solution,
        "key_insight": key_insight,
        "document": document,
    }


def embed_and_store(writeup: dict, collection: chromadb.Collection):
    """
    Embed the writeup's document field and store it in ChromaDB.
    """
    model = _get_model()
    doc_id = hashlib.md5(writeup["title"].encode()).hexdigest()

    # Check for duplicate
    existing = collection.get(ids=[doc_id])
    if existing["ids"]:
        return False  # already exists

    embedding = model.encode(writeup["document"]).tolist()

    collection.add(
        ids=[doc_id],
        embeddings=[embedding],
        documents=[writeup["document"]],
        metadatas=[{
            "title": writeup["title"],
            "category": writeup["category"],
            "difficulty": writeup["difficulty"],
            "event": writeup["event"],
            "tags": writeup["tags"],
            "tools": writeup["tools"],
            "solution": writeup["solution"],
            "key_insight": writeup["key_insight"],
        }],
    )
    return True


def auto_ingest_solve(challenge: str, category: str, report: str, flag: str, tools_used: list[str]):
    """
    After a successful agent solve, generate a writeup and add it to ChromaDB
    so the next time a similar challenge appears, the agent has first-hand experience.
    """
    title = f"[Auto] {challenge[:60].strip()}"

    # Extract the most information-dense section for the searchable document.
    # Priority: Conclusion > Key Insight > Solution > last non-trivial paragraph.
    def _extract_section(text: str, heading: str) -> str:
        pattern = rf"## {re.escape(heading)}\n(.*?)(?=\n## |\Z)"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""

    key_insight = (
        _extract_section(report, "Conclusion")
        or _extract_section(report, "Key Insight")
        or _extract_section(report, "Solution")
    )
    if not key_insight:
        # Fall back to last substantial paragraph (often the conclusion)
        paras = [p.strip() for p in report.split("\n\n") if len(p.strip()) > 40]
        key_insight = paras[-1] if paras else report[-600:]

    # The document field is what gets embedded and searched — pack it with
    # technical terms from the conclusion so future searches find it.
    document = " ".join(filter(None, [
        title, category, challenge[:200], key_insight[:600],
    ]))

    writeup = {
        "title": title,
        "category": category or "misc",
        "difficulty": "unknown",
        "event": "auto-ingested",
        "tags": ", ".join(tools_used[:6]),
        "tools": ", ".join(tools_used),
        "description": challenge,
        "solution": report[:4000],
        "key_insight": key_insight[:500],
        "document": document,
    }

    collection = _get_collection()
    stored = embed_and_store(writeup, collection)
    if stored:
        console.print(f"[dim green]Auto-ingested solve into knowledge base: {title}[/dim green]")
    else:
        # Already exists — update the entry with the better content
        model = _get_model()
        doc_id = hashlib.md5(title.encode()).hexdigest()
        embedding = model.encode(document).tolist()
        collection.update(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[document],
            metadatas=[{
                "title": writeup["title"],
                "category": writeup["category"],
                "difficulty": writeup["difficulty"],
                "event": writeup["event"],
                "tags": writeup["tags"],
                "tools": writeup["tools"],
                "solution": writeup["solution"],
                "key_insight": writeup["key_insight"],
            }],
        )
        console.print(f"[dim green]Updated existing auto-ingested entry: {title}[/dim green]")
    return True


# ---------------------------------------------------------------------------
# Layer 2: abstract technique extraction + storage
# ---------------------------------------------------------------------------

_TECHNIQUE_EXTRACTION_PROMPT = """\
You are a CTF knowledge engineer. Read this solve report and extract reusable knowledge.

Respond with a single JSON object and nothing else — no markdown fences, no explanation.

Fields:
- technique_name: short kebab-case slug (e.g. "elf-packer-xor-memfd", "arm-crackme-strcmp", "rsa-crt-fault")
- recognition: list of 3 bullet strings — fast identifiers that tell you THIS technique applies
- steps: list of numbered strings describing the GENERIC solution steps (no challenge-specific paths/values)
- reusable_code: string — a complete, parameterized Python/bash snippet usable on similar challenges (empty string if none)
- caveats: list of strings — conditions that must hold for this technique to work
- novelty: "new" if this is a technique not commonly known, "common" if it is a well-known pattern

REPORT (category: {category}):
{report}
"""

_TEMPLATE_DIR = Path("data/templates")


def extract_technique(report: str, category: str) -> dict | None:
    """
    Call Gemini Flash to extract a structured technique from a solve report.
    Returns a dict with technique_name, recognition, steps, reusable_code, caveats, novelty.
    Returns None on any error (non-fatal — raw report still stored in Layer 1).
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None

    prompt = _TECHNIQUE_EXTRACTION_PROMPT.format(
        category=category,
        report=report[:5000],
    )
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        raw = response.text.strip()
        # Strip markdown fences if the model added them anyway
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw).rstrip("`").strip()
        return json.loads(raw)
    except Exception as e:
        console.print(f"[dim yellow]Technique extraction failed: {e}[/dim yellow]")
        return None


def store_technique(technique: dict, category: str) -> bool:
    """
    Embed and store an extracted technique in the ctf_techniques collection.
    Auto-saves reusable_code as a template file when novelty=="new" and code is substantial.
    Returns True if newly stored, False if already exists.
    """
    name = technique.get("technique_name", "unknown")
    recognition = "\n".join(technique.get("recognition", []))
    steps = "\n".join(technique.get("steps", []))
    reusable_code = technique.get("reusable_code", "")
    caveats = "\n".join(technique.get("caveats", []))
    novelty = technique.get("novelty", "common")

    # The searchable document: name + recognition cues + steps
    document = f"{name} {category} {recognition} {steps}".strip()

    model = _get_model()
    collection = _get_technique_collection()
    doc_id = hashlib.md5(name.encode()).hexdigest()

    existing = collection.get(ids=[doc_id])
    is_new_entry = not existing["ids"]

    embedding = model.encode(document).tolist()
    metadata = {
        "technique_name": name,
        "category": category,
        "recognition": recognition,
        "steps": steps,
        "reusable_code": reusable_code[:3000],
        "caveats": caveats,
        "novelty": novelty,
    }

    if is_new_entry:
        collection.add(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[document],
            metadatas=[metadata],
        )
        console.print(f"[dim green]Stored technique: {name} ({novelty})[/dim green]")
    else:
        collection.update(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[document],
            metadatas=[metadata],
        )
        console.print(f"[dim green]Updated technique: {name}[/dim green]")

    # Auto-save reusable code as template when genuinely novel and substantial
    if novelty == "new" and len(reusable_code.strip()) > 30:
        _TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
        slug = name.replace("-", "_")
        # Prefix with category so it doesn't collide with hand-written templates
        tpl_path = _TEMPLATE_DIR / f"{category}_{slug}.py"
        if not tpl_path.exists():
            tpl_path.write_text(reusable_code, encoding="utf-8")
            console.print(f"[dim green]Auto-saved template: {tpl_path}[/dim green]")

    return is_new_entry


def extract_and_store_technique(report: str, category: str) -> bool:
    """
    High-level helper: extract then store. Returns True on success.
    """
    technique = extract_technique(report, category)
    if not technique:
        return False
    store_technique(technique, category)
    return True


def ingest_all(writeups_dir: str = "data/writeups"):
    """
    Walk writeups_dir, parse every .md file, embed and store each one.
    """
    writeups_path = Path(writeups_dir)
    if not writeups_path.exists():
        console.print(f"[red]Directory not found: {writeups_dir}[/red]")
        return

    md_files = list(writeups_path.glob("**/*.md"))
    if not md_files:
        console.print(f"[yellow]No .md files found in {writeups_dir}[/yellow]")
        return

    collection = _get_collection()
    ingested = 0
    skipped = 0

    for filepath in track(md_files, description="Ingesting writeups..."):
        try:
            writeup = parse_writeup(str(filepath))
            stored = embed_and_store(writeup, collection)
            if stored:
                ingested += 1
                console.print(f"  [green]✓[/green] {writeup['title']}")
            else:
                skipped += 1
                console.print(f"  [yellow]~[/yellow] {writeup['title']} (duplicate, skipped)")
        except Exception as e:
            console.print(f"  [red]✗[/red] {filepath.name}: {e}")

    console.print(f"\n[bold green]Done.[/bold green] Ingested: {ingested}, Skipped: {skipped}")
    console.print(f"Collection size: [cyan]{collection.count()}[/cyan] writeups total")


# ---------------------------------------------------------------------------
# how2heap ingestion
# ---------------------------------------------------------------------------

def ingest_how2heap_dir(c_files: list) -> int:
    """
    Parse shellphish/how2heap .c files and ingest each as a technique writeup.
    Returns number of new techniques added.
    """
    collection = _get_collection()
    model = _get_model()
    total = 0

    _GLIBC_VERSIONS = {
        "glibc_2.23": "2.23", "glibc_2.27": "2.27", "glibc_2.29": "2.29",
        "glibc_2.31": "2.31", "glibc_2.34": "2.34", "glibc_2.35": "2.35",
        "glibc_2.36": "2.36", "glibc_2.39": "2.39",
    }

    for c_file in track(c_files, description="Ingesting how2heap..."):
        c_file = Path(c_file)
        technique_name = c_file.stem  # e.g. "house_of_botcake"

        # Detect glibc version from parent directory
        glibc_ver = "unknown"
        for part in c_file.parts:
            if part in _GLIBC_VERSIONS:
                glibc_ver = _GLIBC_VERSIONS[part]

        try:
            code = c_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Extract description from top-level comments
        desc_lines = []
        for line in code.splitlines()[:40]:
            stripped = line.strip().lstrip("/*").strip()
            if stripped and not stripped.startswith("#include") and not stripped.startswith("int "):
                desc_lines.append(stripped)
            if len(desc_lines) >= 8:
                break
        description = " ".join(desc_lines)[:500]

        title = technique_name.replace("_", " ").title()
        tags = technique_name.replace("_", ",").lower()

        writeup = {
            "title": f"how2heap: {title} (glibc {glibc_ver})",
            "category": "pwn",
            "difficulty": "hard",
            "event": "how2heap",
            "tags": f"heap,glibc,{glibc_ver},{tags}",
            "tools": "pwntools,gdb,pwndbg",
            "solution": f"Technique: {technique_name}\nGlibc version: {glibc_ver}\n\n{description}\n\nSource:\n```c\n{code[:6000]}\n```",
            "key_insight": description[:300] or f"Advanced heap exploitation technique: {technique_name}",
            "document": (
                f"[how2heap] {title} glibc {glibc_ver} heap exploitation "
                f"{technique_name.replace('_', ' ')} {description[:300]}"
            ),
        }

        try:
            stored = embed_and_store(writeup, collection)
            if stored:
                total += 1
        except Exception as e:
            console.print(f"  [red]✗[/red] {c_file.name}: {e}")

    console.print(f"[bold green]how2heap: {total} new techniques added.[/bold green]")
    return total


# ---------------------------------------------------------------------------
# pwn.college curriculum ingestion
# ---------------------------------------------------------------------------

_PWNCOLLEGEDOCS = [
    # (title, category, difficulty, key_insight, solution_steps)
    ("Buffer Overflow Fundamentals", "pwn", "easy",
     "Stack overflows overwrite the saved return address to redirect execution",
     """## Concepts
- Stack layout: locals, saved rbp, saved rip
- Overflow: write past buffer end to overwrite rip
- Find offset with cyclic pattern (cyclic_offset tool)

## Steps
1. checksec — check protections
2. cyclic_offset — find exact offset to rip
3. ret2win — if win function exists, use its address
4. ret2libc — if NX enabled: leak puts GOT → compute libc base → system('/bin/sh')

## Key Tools
- pwntools: cyclic(), cyclic_find(), ELF(), ROP()
- ROPgadget: find 'pop rdi; ret', 'ret'
- one_gadget: single-gadget RCE in libc"""),

    ("ROP Chain Construction", "pwn", "medium",
     "Return-Oriented Programming chains short gadget sequences to build arbitrary computation without injecting code",
     """## Concepts
- Gadget: instruction sequence ending in 'ret'
- Chain: sequence of [gadget_addr, arg1, ...] on stack
- MOVAPS alignment: add bare 'ret' before system() on Ubuntu ≥18.04

## Common gadgets
- pop rdi; ret — set first argument
- pop rsi; ret — set second argument (pop rsi; pop r15; ret common)
- pop rdx; ret — set third argument (often missing; use ret2csu)
- syscall; ret — raw Linux syscall

## Strategies
1. execve_binsh: pop rdi → /bin/sh; system() [needs libc leak]
2. orw_flag: open(path,0) → read(fd,buf,n) → write(1,buf,n) [for seccomp]
3. ret2syscall: rax=0x3b, rdi=/bin/sh, rsi=0, rdx=0; syscall
4. ret2csu: use __libc_csu_init gadgets when pop rdx missing"""),

    ("Format String Exploitation", "pwn", "medium",
     "printf(user_input) allows reading/writing arbitrary memory via %p/%n format specifiers",
     """## Read primitive: %p chain
- Send: '%p.%p.%p...%p' (20-40 times)
- Leaks: canary, PIE base, libc base from stack

## Write primitive: %n writes count of chars printed
- %Nc%M$n — write N as 4-byte int at stack[M]
- %Nc%M$hn — write N as 2-byte short at stack[M]
- %Nc%M$hhn — write N as 1-byte char at stack[M]

## Find format offset
- Send 'AAAA%p.%p.%p...' until you see '0x41414141' in output
- That position N is your fmt_offset (%N$p reads your buffer)

## Multi-stage attack
1. Leak: %p chain → extract libc/PIE base
2. Overwrite: %hhn × 8 to write 8-byte value byte-by-byte
3. Target: __free_hook (glibc < 2.34) or _IO_list_all (glibc 2.34+)"""),

    ("Heap Exploitation: Tcache Poisoning", "pwn", "hard",
     "Corrupting tcache fd pointer to make malloc() return an arbitrary address",
     """## Requirements
- Heap overflow or UAF write primitive
- Free + malloc control to manipulate freelist

## glibc 2.27-2.28 (no key)
1. free(A); free(B)  — B.fd = A
2. write B.fd = target
3. malloc() → returns B
4. malloc() → returns target  (arbitrary alloc!)
5. write target → overwrite __free_hook with system

## glibc 2.29+ (tcache key prevents naive double-free)
- Use House of Botcake: consolidate chunks via unsorted bin first
- get_template('pwn_heap_tcache') for full implementation

## glibc 2.32+ (PROTECT_PTR safe-link)
- Stored fd = real_ptr ^ (chunk_addr >> 12)
- Must leak heap base first via UAF read on first freed chunk
- Encode: encoded_target = target ^ (chunk_addr >> 12)

## glibc 2.34+ (no hooks)
- __malloc_hook and __free_hook removed
- Use _IO_FILE / FSOP: overwrite _IO_list_all → fake FILE struct
- get_template('pwn_io_file') for implementation"""),

    ("Heap Exploitation: House of X Techniques", "pwn", "hard",
     "Advanced heap exploitation techniques from the 'House of X' family for bypassing glibc protections",
     """## House of Botcake (glibc 2.29+)
- Bypass tcache double-free detection via unsorted bin consolidation
- Steps: fill tcache → free prev+victim (unsorted bin merge) → drain tcache → free victim again → overlap write → arbitrary alloc

## House of Tangerine (glibc 2.35+)
- Corrupt tcache_perthread_struct entries[] array directly
- Requires write primitive to heap base + 0x10
- Write target addr into entries[idx] + set counts[idx] = 1
- Next malloc(size_for_idx) returns target

## House of Force (old glibc, top-chunk overflow)
- Overwrite top-chunk size to 0xffffffffffffffff (-1)
- malloc(offset_to_target) → top-chunk moves to target - 2*SIZE_SZ
- Very old technique; patched in modern glibc

## Largebin Attack (glibc 2.30+)
- Overwrite bk_nextsize of large chunk in largebin
- Achieves arbitrary write on next malloc consolidation
- Use to corrupt: mp_.tcache_bins, _IO_list_all, global_max_fast

## Unsorted Bin Attack (glibc < 2.30)
- Overwrite bk of unsorted chunk → arbitrary write of main_arena address
- Classic target: global_max_fast (makes all sizes go to fastbins)"""),

    ("IO_FILE Exploitation (FSOP)", "pwn", "expert",
     "_IO_FILE structure exploitation bypasses glibc 2.34+ which removed __malloc_hook/__free_hook",
     """## Background
- Every FILE* in glibc has _IO_FILE struct with vtable pointer
- _IO_list_all: linked list of all open FILE structures
- On exit(): _IO_cleanup() walks _IO_list_all calling vtable methods

## _IO_str_overflow FSOP
1. Build fake _IO_FILE at controlled memory
2. Set fake.vtable = _IO_str_jumps (pointer arithmetic: _IO_str_jumps - 0x20)
3. Set fake._IO_write_ptr > fake._IO_buf_end (triggers _IO_str_overflow)
4. _IO_str_overflow calls: ((char*)fp->_IO_buf_base)(fp) [i.e. system("/bin/sh")]
5. Overwrite _IO_list_all with &fake_file
6. Trigger: call exit() or return from main

## House of Apple2 (_IO_wfile_overflow)
- Abuse _IO_wfile_overflow → calls fp->_wide_data->_IO_write_base
- Set _wide_data to point to fake vtable → arbitrary call

## House of Emma (_IO_cookie_file)
- Forge _IO_cookie_file with custom cookie_read/write function pointers
- Requires heap and libc base leak

## get_template('pwn_io_file') for ready-to-use implementation"""),

    ("Kernel Exploitation: Linux CTF Challenges", "pwn", "expert",
     "Linux kernel module exploitation for CTF challenges requiring ring-0 privilege escalation",
     """## Challenge Identification
- /dev/xxx device file → kernel module present
- .ko file provided → loadable kernel module
- Runs in VM/QEMU → full kernel exploit environment

## Common Vulnerability Types
1. UAF: pipe_buffer → corrupt pipe_buf_operations → arbitrary ops
2. OOB: kernel heap OOB → overwrite adjacent object
3. Type confusion: kernel struct field misinterpretation
4. Race condition: ioctl TOCTOU

## Exploitation Goals
1. commit_creds(prepare_kernel_cred(0)) → set uid=0 (most common)
2. modprobe_path overwrite → execute as root without commit_creds
3. cred structure overwrite → direct privilege escalation

## KASLR Bypass
- /proc/kallsyms (if readable): cat /proc/kallsyms | grep ' T '
- dmesg (if accessible): crash logs contain kernel addresses
- Side-channel: cache timing (theoretical in CTF)

## KPTI Bypass
- NEVER use bare swapgs + iretq — crashes with KPTI enabled
- Use swapgs_restore_regs_and_return_to_usermode trampoline
- Chain: [trampoline, 0, 0, user_rip, user_cs, user_rflags, user_rsp, user_ss]

## get_template('pwn_kernel_rop') for full kernel ROP skeleton"""),

    ("Symbolic Execution with angr", "rev", "medium",
     "angr performs symbolic execution to find inputs that reach a target address or print success string",
     """## When to Use
- Binary takes input and checks a condition (correct/wrong)
- Logic too complex to reverse manually
- Custom hash/checksum with many branches

## Basic Usage (angr_solve tool)
- find_str='Correct' — reaches any state printing this
- avoid_str='Wrong' — prune paths printing this
- flag_length=40 — expected input size in bytes

## Path Explosion Mitigation (built into angr_solve)
- Strategy 1: veritesting=True (merges similar paths)
- Strategy 2: max_active=64 (prune excess states)
- Strategy 3: shorter flag_length (tries smaller input)

## When angr Fails
- Binary has very deep loops (e.g. millions of iterations)
- Fix: use unicorn_emulate for function-level brute-force instead
- Fix: use ltrace_run first — many crackmes leak the answer in strcmp

## Advanced: Custom Hook
```python
# Hook a slow function to speed up exploration
@p.hook(loop_func_addr, length=5)
def skip_loop(state):
    pass  # bypass expensive computation"""),

    ("RSA Cryptography Attacks", "crypto", "medium",
     "Common RSA vulnerability patterns in CTF challenges with attack implementations",
     """## Small e (e=3 or e=5)
- If m^e < n (no modular reduction): flag = iroot(c, e)
- Use gmpy2: m, exact = gmpy2.iroot(c, e)

## Wiener's Attack (large e relative to n)
- When d < n^0.25, recover d from continued fractions of e/n
- Use owiener library: d = owiener.attack(e, n)

## Franklin-Reiter Related Message Attack
- Two ciphertexts with related plaintexts: m2 = a*m1 + b
- Compute gcd of polynomials over Z/nZ → reveals m
- get_template('crypto_franklin_reiter')

## Hastad's Broadcast Attack
- Same message encrypted with same e for k different n values
- CRT to combine → k-th root
- Requires k ≥ e recipients

## Fermat Factoring (p, q close together)
- When |p - q| is small: a = isqrt(n), then check a^2 - n
- Use: p = gmpy2.isqrt(n) + 1; while not gmpy2.is_perfect_square(p*p - n): p+=1

## Common Modulus Attack
- Two ciphertexts c1, c2 with same (n, m) but different e1, e2
- If gcd(e1, e2) = 1: use extended Euclidean to recover m"""),

    ("Web: JWT Attacks", "web", "easy",
     "JSON Web Tokens (JWT) are frequently misconfigured in CTF web challenges",
     """## JWT Structure
header.payload.signature (base64url encoded, dot-separated)

## Attack 1: alg:none
- Change header {"alg":"HS256"} → {"alg":"none"}
- Remove signature (keep trailing dot)
- Server skips verification → forge any claims

## Attack 2: RS256 → HS256 confusion
- Server uses RS256 public key. Attack: treat public key as HS256 secret.
- Sign payload with HMAC-SHA256 using the public key as secret
- get_template('web_jwt_forge') for implementation

## Attack 3: Weak HS256 secret
- Brute-force with hashcat: hashcat -a 0 -m 16500 <jwt> wordlist.txt
- Common secrets: 'secret', 'password', service name

## Attack 4: kid header injection
- kid parameter used in SQL or path lookup
- SQL: {"kid":"x' UNION SELECT 'secret'--"}
- Path: {"kid":"../../dev/null"} with null-byte secret"""),
]


def ingest_pwncollegedocs() -> int:
    """
    Ingest curated pwn.college curriculum content into the knowledge base.
    Returns number of documents added.
    """
    collection = _get_collection()
    total = 0

    for title, category, difficulty, key_insight, solution in track(
        _PWNCOLLEGEDOCS, description="Ingesting pwn.college docs..."
    ):
        writeup = {
            "title": f"pwn.college: {title}",
            "category": category,
            "difficulty": difficulty,
            "event": "pwn.college",
            "tags": f"{category},curriculum,technique",
            "tools": "pwntools,gdb,python3",
            "solution": solution,
            "key_insight": key_insight,
        }
        try:
            stored = embed_and_store(writeup, collection)
            if stored:
                total += 1
        except Exception as e:
            console.print(f"  [red]✗[/red] {title}: {e}")

    console.print(f"[bold green]pwn.college: {total} documents ingested.[/bold green]")
    return total
