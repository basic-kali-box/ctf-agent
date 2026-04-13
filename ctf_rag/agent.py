import os

import anthropic
from dotenv import load_dotenv

from ctf_rag.retriever import retrieve

load_dotenv()

_client = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key or api_key == "sk-ant-your-key-here":
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. Add it to your .env file."
            )
        _client = anthropic.Anthropic(api_key=api_key)
    return _client


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
    Build the user message combining challenge description + retrieved writeups.
    """
    parts = [f"## New Challenge\n{challenge}\n"]

    if retrieved:
        parts.append("## Retrieved Writeups from Knowledge Base\n")
        for i, r in enumerate(retrieved, 1):
            # Truncate solution to keep context reasonable (~300 tokens ≈ 1200 chars)
            solution_summary = r["solution"][:1000] + "..." if len(r["solution"]) > 1000 else r["solution"]
            parts.append(
                f"### [{i}] {r['title']}\n"
                f"- **Category:** {r['category']}\n"
                f"- **Tools:** {r['tools']}\n"
                f"- **Key Insight:** {r['key_insight']}\n"
                f"- **Solution Summary:** {solution_summary}\n"
            )
    else:
        parts.append("*No similar writeups found in knowledge base.*\n")

    parts.append("Based on the above, analyze the new challenge and provide a detailed attack plan.")
    return "\n".join(parts)


def solve(challenge: str, category: str = None, top_k: int = 3) -> tuple[str, list[dict]]:
    """
    Retrieve similar writeups and call the Anthropic API to generate a solution.
    Returns (response_text, retrieved_writeups).
    """
    retrieved = retrieve(query=challenge, category=category, top_k=top_k)
    user_prompt = build_user_prompt(challenge, retrieved)

    try:
        client = _get_client()
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text, retrieved
    except ValueError as e:
        raise
    except anthropic.APIError as e:
        raise RuntimeError(f"Anthropic API error: {e}") from e
