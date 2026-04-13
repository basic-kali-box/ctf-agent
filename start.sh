#!/usr/bin/env bash
# CTF RAG Agent — entrypoint
# Usage:
#   ./start.sh                          interactive menu
#   ./start.sh agent "desc" [--category pwn] [--backend azure]
#   ./start.sh benchmark [--backend azure]
#   ./start.sh solve "challenge text"
#   ./start.sh ingest /path/to/writeups/
#   ./start.sh <any cli command> [args...]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
die()     { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ── python / venv ────────────────────────────────────────────────────────────
PYTHON="${PYTHON:-python3}"

if [[ -d "$SCRIPT_DIR/.venv" ]]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
    PYTHON="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    die "python3 not found. Install it or set PYTHON=/path/to/python3"
fi

# ── verify ctf_rag is importable ─────────────────────────────────────────────
if ! "$PYTHON" -c "import ctf_rag" 2>/dev/null; then
    warn "ctf_rag not installed — running: pip install -r requirements.txt"
    "$PYTHON" -m pip install -r requirements.txt -q || die "pip install failed"
fi

# ── pass-through: any args → run directly ────────────────────────────────────
if [[ $# -gt 0 ]]; then
    exec "$PYTHON" -m ctf_rag.cli "$@"
fi

# ── interactive menu ─────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ██████╗████████╗███████╗"
echo "  ██╔════╝╚══██╔══╝██╔════╝"
echo "  ██║        ██║   █████╗  "
echo "  ██║        ██║   ██╔══╝  "
echo "  ╚██████╗   ██║   ██║     "
echo "   ╚═════╝   ╚═╝   ╚═╝     RAG Agent"
echo -e "${RESET}"

echo -e "${BOLD}Commands:${RESET}"
echo "  1) agent      — run autonomous solver on a challenge"
echo "  2) benchmark  — run benchmark suite"
echo "  3) solve      — one-shot RAG solve (no agent loop)"
echo "  4) ingest     — ingest writeup files into ChromaDB"
echo "  5) how2heap   — clone + ingest shellphish/how2heap"
echo "  6) hacktricks — clone + ingest HackTricks"
echo "  7) sessions   — list recent sessions"
echo "  8) list       — list all stored writeups"
echo "  9) probe      — detect installed tool versions"
echo "  q) quit"
echo

while true; do
    read -rp "$(echo -e "${CYAN}ctf>${RESET} ")" choice
    case "$choice" in
        1|agent)
            # Drop into the Python interactive wizard (handles multi-line paste + provider menu)
            "$PYTHON" -m ctf_rag.cli agent
            ;;
        2|benchmark)
            read -rp "Backend [claude/azure/deepseek/nvidia/openrouter/hybrid, blank=azure]: " backend
            read -rp "Max iterations per challenge [blank=default]: " maxiter
            args=("benchmark")
            [[ -n "$backend" ]] && args+=(--backend "$backend")
            [[ -n "$maxiter" ]] && args+=(--max-iter "$maxiter")
            "$PYTHON" -m ctf_rag.cli "${args[@]}"
            ;;
        3|solve)
            read -rp "Challenge description: " desc
            read -rp "Category [blank=auto]: " cat
            args=("solve" "--challenge" "$desc")
            [[ -n "$cat" ]] && args+=(--category "$cat")
            "$PYTHON" -m ctf_rag.cli "${args[@]}"
            ;;
        4|ingest)
            read -rp "Path to writeup file(s) or directory: " path
            "$PYTHON" -m ctf_rag.cli ingest "$path"
            ;;
        5|how2heap)
            "$PYTHON" -m ctf_rag.cli how2heap
            ;;
        6|hacktricks)
            "$PYTHON" -m ctf_rag.cli hacktricks
            ;;
        7|sessions)
            "$PYTHON" -m ctf_rag.cli sessions
            ;;
        8|list)
            "$PYTHON" -m ctf_rag.cli list
            ;;
        9|probe)
            "$PYTHON" -m ctf_rag.cli probe-tools
            ;;
        q|quit|exit)
            echo "bye"
            exit 0
            ;;
        "")
            ;;
        *)
            warn "Unknown choice '$choice' — pass any CLI command directly or pick 1-9"
            ;;
    esac
    echo
done
