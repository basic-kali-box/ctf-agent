# CTF RAG Agent — Claude Code Instructions

## Project Goal
Build a local CTF assistant tool that uses Retrieval-Augmented Generation (RAG) to help solve CTF challenges.
It ingests past CTF writeups (challenge + solution + tools), embeds them into a ChromaDB vector store,
and at query time retrieves the most relevant past writeups to feed into an Anthropic API call that
reasons about the new challenge and suggests an attack path or solution.

All LLM calls go through the **Anthropic API directly** using `ANTHROPIC_API_KEY` from `.env`.
Do NOT use the Claude Code built-in model for inference — only for code generation during setup.

---

## Stack
- **Language:** Python 3.11+
- **LLM:** Anthropic API (`claude-sonnet-4-5` via `anthropic` SDK)
- **Embeddings:** `sentence-transformers` (`all-MiniLM-L6-v2`, runs locally, no API needed)
- **Vector DB:** ChromaDB (local persistent storage)
- **CLI:** `click` or `argparse`
- **Env:** `python-dotenv`

---

## Project Structure to Create

```
ctf-rag/
├── CLAUDE.md                  ← this file
├── .env                       ← ANTHROPIC_API_KEY=sk-ant-...
├── .gitignore                 ← ignore .env, chroma_db/, __pycache__/
├── requirements.txt
├── README.md
│
├── data/
│   └── writeups/              ← raw writeup files (.md or .json)
│       └── example_writeup.md ← create one sample writeup
│
├── ctf_rag/
│   ├── __init__.py
│   ├── ingest.py              ← load & embed writeups into ChromaDB
│   ├── retriever.py           ← query ChromaDB, return top-k similar writeups
│   ├── agent.py               ← call Anthropic API with challenge + context
│   └── cli.py                 ← entry point: `python -m ctf_rag.cli`
│
└── chroma_db/                 ← auto-created by ChromaDB (gitignored)
```

---

## Step-by-Step Implementation

### 1. `requirements.txt`
```
anthropic>=0.28.0
chromadb>=0.5.0
sentence-transformers>=3.0.0
python-dotenv>=1.0.0
click>=8.1.0
rich>=13.0.0
```

### 2. `.env` template
```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### 3. Sample Writeup Format (`data/writeups/example_writeup.md`)
Each writeup must follow this exact schema:

```markdown
---
title: SQL Injection in Login Form
category: web
difficulty: easy
event: PicoCTF 2024
tags: sqli, authentication, bypass
tools: sqlmap, burpsuite, curl
---

## Challenge Description
The login form at /login accepts username and password. Source code shows direct string
concatenation into SQL query. No WAF detected.

## Solution
1. Tested `' OR '1'='1` in username field — got logged in as admin
2. Used sqlmap: `sqlmap -u "http://target/login" --data="user=a&pass=b" --dbs`
3. Dumped users table, found flag column
4. Flag was base64-encoded in the flag column

## Flag
`picoCTF{sql_1nj3ct10n_1s_3asy_abc123}`

## Key Insight
No input sanitization + error messages leaking table names = easy blind sqli escalation.
```

Create at least 5 sample writeups covering: web, crypto, rev, pwn, forensics.

---

### 4. `ctf_rag/ingest.py`

Implement the following functions:

```python
def parse_writeup(filepath: str) -> dict:
    """
    Parse a markdown writeup file.
    Extract: title, category, difficulty, event, tags, tools,
             description, solution, key_insight.
    Return as dict. Use frontmatter for metadata, parse ## sections for content.
    The 'document' field for embedding = title + category + description + key_insight
    concatenated as a single string.
    """

def embed_and_store(writeup: dict, collection: chromadb.Collection):
    """
    Embed the writeup's 'document' field using SentenceTransformer('all-MiniLM-L6-v2').
    Store in ChromaDB with:
      - id: md5 hash of title
      - embedding: list[float] from model.encode()
      - document: the concatenated text
      - metadata: {category, difficulty, event, tags, tools, title}
    """

def ingest_all(writeups_dir: str = "data/writeups"):
    """
    Walk the writeups_dir, parse every .md file, embed and store each one.
    Print progress with rich. Skip duplicates (check by id).
    Initialize ChromaDB with: chromadb.PersistentClient(path="./chroma_db")
    Collection name: "ctf_writeups"
    """
```

---

### 5. `ctf_rag/retriever.py`

```python
def retrieve(query: str, category: str = None, top_k: int = 3) -> list[dict]:
    """
    Embed the query using the same SentenceTransformer model.
    Query ChromaDB collection "ctf_writeups".
    If category is provided, filter: where={"category": category}
    Return top_k results as list of dicts with keys:
      {title, category, tools, solution, key_insight, distance}
    Parse the full solution and key_insight from the stored document field.
    """
```

---

### 6. `ctf_rag/agent.py`

This is the core — calls the Anthropic API with RAG context.

```python
import anthropic
from dotenv import load_dotenv
import os

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are an expert CTF (Capture The Flag) solver with deep knowledge in:
- Web exploitation (SQLi, XSS, SSTI, LFI, SSRF, deserialization)
- Binary exploitation / Pwn (buffer overflow, ROP chains, heap exploits)
- Reverse engineering (static/dynamic analysis, decompilation)
- Cryptography (classical ciphers, RSA, AES, hash cracking)
- Forensics (steganography, file carving, memory analysis, pcap analysis)
- OSINT and Misc

You reason step by step. You suggest specific tools and commands.
You do NOT hallucinate flags — if you don't know, say so clearly.
Format your response as:
1. **Challenge Type Analysis** — what category/subcategory is this
2. **Similar Past Challenges** — what the retrieved writeups teach us
3. **Attack Plan** — numbered steps with exact commands where possible
4. **Tools** — list with install command if non-standard
5. **Expected Flag Format** — based on event naming convention if known
"""

def build_user_prompt(challenge: str, retrieved: list[dict]) -> str:
    """
    Build the user message combining the challenge description + retrieved writeups.
    Format retrieved writeups as a numbered list showing title, tools, key_insight, solution summary.
    Keep each retrieved writeup under 300 tokens to save context space.
    """

def solve(challenge: str, category: str = None, top_k: int = 3) -> str:
    """
    1. Call retrieve() to get top_k similar writeups
    2. Build the prompt
    3. Call client.messages.create() with:
       - model: "claude-sonnet-4-5"  (NOT claude-3-5-sonnet — use this exact string)
       - max_tokens: 2048
       - system: SYSTEM_PROMPT
       - messages: [{"role": "user", "content": user_prompt}]
    4. Return response.content[0].text
    5. If no writeups retrieved, still call the API but note "No similar writeups found in knowledge base."
    """
```

---

### 7. `ctf_rag/cli.py`

Build a clean CLI with two commands:

**Command 1: `ingest`**
```
python -m ctf_rag.cli ingest [--dir data/writeups]
```
- Calls `ingest_all()`
- Shows count of writeups ingested
- Shows ChromaDB collection stats after ingestion

**Command 2: `solve`**
```
python -m ctf_rag.cli solve --challenge "..." [--category web] [--top-k 3]
```
- Accepts `--challenge` as a string OR `--file path/to/challenge.txt`
- Calls `agent.solve()`
- Prints output with `rich` formatting (panels, markdown rendering)
- At the bottom, shows "Retrieved context from: [writeup1 title, writeup2 title]"

**Command 3: `list`**
```
python -m ctf_rag.cli list [--category web]
```
- Lists all writeups in ChromaDB with title, category, event, tags

---

## Implementation Rules

1. **Always load `.env` first** — every module that calls the API must call `load_dotenv()` at the top
2. **Singleton embedding model** — instantiate `SentenceTransformer` once at module level, not per call
3. **ChromaDB client** — use `PersistentClient`, not in-memory, so writeups survive between sessions
4. **Error handling** — wrap API calls in try/except, print clear errors if `ANTHROPIC_API_KEY` is missing
5. **No hardcoded keys** — never put the API key in source code
6. **Rich output** — use `rich.console`, `rich.panel`, `rich.markdown` for all CLI output
7. **Verbose flag** — add `--verbose` to `solve` command to show raw retrieved chunks

---

## After Building

1. Run `pip install -r requirements.txt`
2. Run `python -m ctf_rag.cli ingest` to populate ChromaDB with sample writeups
3. Test with: `python -m ctf_rag.cli solve --challenge "Login form with JWT authentication, RS256 algorithm. We have the public key." --category web`
4. Expected behavior: retrieves similar auth/JWT writeups, suggests algorithm confusion attack (RS256→HS256)

---

## Optional Extensions (build if time allows)

- `--interactive` mode: multi-turn conversation keeping challenge context
- `--import-ctftime URL`: scrape and auto-ingest a CTFtime.org writeup URL
- `--export`: save the agent's response as a markdown file in `outputs/`
- Category auto-detection: if `--category` not provided, classify the challenge automatically with a quick API call before retrieval
