# CTF RAG Agent

An autonomous CTF solver powered by a hybrid multi-LLM architecture and a RAG knowledge base of past writeups.

```
  ██████╗████████╗███████╗
  ██╔════╝╚══██╔══╝██╔══���═╝
  ██║        ██║   █████╗
  ██║        ██║   ██╔══╝
  ╚██████╗   ██║   ██║
   ╚═���═══╝   ╚═╝   ╚═╝     RAG Agent
```

## How it works

- **DeepSeek R1** — reads the challenge, produces an initial attack plan
- **Azure GPT-4** — executes the plan (tool calls, shell commands, file I/O)
- **Gemini Flash** — fixes broken Python/bash scripts inline, writes the final writeup
- **ChromaDB** — vector database of past CTF writeups, queried at runtime for similar challenges
- Loop prevention, stagnation detection, and session checkpointing built in

---

## Requirements

- Python 3.10+
- `radare2`, `gdb`, `ltrace`, `strace`, `binwalk`, `file`, `strings` (standard RE/forensics tools)
- `g++` / `gcc` (for compiling challenge helpers)
- `netcat` (`nc`) for daemon/network challenges

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/basic-kali-box/ctf-agent.git
cd ctf-agent
```

### 2. Create a virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure API keys

Create a `.env` file in the project root:

```env
# Required for hybrid / azure backend
AZURE_OPENAI_API_KEY=your_azure_key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-4o          # or your deployment name

# Required for DeepSeek (hybrid backend — brain)
DEEPSEEK_API_KEY=your_deepseek_key

# Required for Gemini (hybrid backend — healer + reporter)
GOOGLE_API_KEY=your_google_ai_key

# Optional — Anthropic (claude backend)
ANTHROPIC_API_KEY=your_anthropic_key

# Optional — override Gemini model (default: gemini-2.0-flash)
GEMINI_AUTOFIX_MODEL=gemini-2.0-flash
```

> You only need the keys for the backend you plan to use.
> The **hybrid** backend (recommended) requires Azure + DeepSeek + Google keys.

### 4. Launch

```bash
./start.sh
```

This opens an interactive menu. Pick a command or pass arguments directly:

```bash
./start.sh agent "your challenge description here" --category rev --backend hybrid
./start.sh solve  "one-shot RAG solve without agent loop"
./start.sh ingest /path/to/writeups/
```

---

## Backends

| Flag | Model | Notes |
|------|-------|-------|
| `hybrid` | DeepSeek R1 + Azure GPT-4 + Gemini Flash | Recommended — best results |
| `azure` | Azure GPT-4 | Fast, reliable executor |
| `claude` | Claude (Anthropic) | Best reasoning, no content policy issues |
| `deepseek` | DeepSeek | Good for crypto/math |
| `nvidia` / `openrouter` | Various | Configurable via env |

---

## RAG knowledge base

The repo ships with a pre-built `chroma_db/` containing CTF writeups.
To expand it with your own writeups:

```bash
./start.sh ingest /path/to/your/writeups/
```

To pull in shellphish/how2heap (heap exploitation reference):

```bash
./start.sh how2heap
```

To pull in HackTricks:

```bash
./start.sh hacktricks
```

---

## Categories

`pwn` · `rev` · `crypto` · `forensics` · `web` · `misc` · `blockchain` · `android`

---

## Session outputs

Every run saves to `outputs/<challenge-slug>/<timestamp>/`:
- `commands.log` — every tool call and result
- `report.md` — Gemini-generated writeup
- `checkpoint_latest.json` — resume with `--resume <path>`

To resume a session:

```bash
./start.sh agent --resume outputs/my_challenge/20260413_153338
```
