"""
Auto-recon pipeline — runs before the first LLM call.
Detects input type and runs appropriate tools to produce a rich context blob.
This replaces vague challenge text with concrete technical facts.
"""

import os
import subprocess
from pathlib import Path


def _run(cmd: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr).strip()
        return out if out else "(no output)"
    except subprocess.TimeoutExpired:
        return f"(timed out after {timeout}s)"
    except Exception as e:
        return f"(error: {e})"


def _tool_exists(name: str) -> bool:
    return _run(f"which {name}") != "(no output)"


# ---------------------------------------------------------------------------
# File recon
# ---------------------------------------------------------------------------

def recon_files(paths: list[str]) -> str:
    sections = ["# File Recon\n"]
    for path in paths:
        path = os.path.expanduser(path)   # expand ~ properly
        p = Path(path)
        if not p.exists():
            sections.append(f"## {path}\n[NOT FOUND]\n")
            continue

        sections.append(f"## {p.name}\n")
        sections.append(f"**file:** {_run(f'file {path}')}")
        sections.append(f"**size:** {p.stat().st_size} bytes")

        # Executable-specific
        file_out = _run(f"file {path}").lower()
        is_elf = "elf" in file_out

        if is_elf:
            sections.append(f"\n**checksec:**\n```\n{_run(f'checksec --file={path} 2>/dev/null || checksec {path} 2>/dev/null')}\n```")
            sections.append(f"\n**strings (interesting):**\n```\n{_run(f'strings -a {path} | grep -iE \"flag|ctf|htb|pico|win|shell|password|secret|key\" | head -30')}\n```")
            sections.append(f"\n**imported functions:**\n```\n{_run(f'nm -D {path} 2>/dev/null | grep -v \"^$\" | head -40')}\n```")
            sections.append(f"\n**hexdump head:**\n```\n{_run(f'xxd {path} | head -20')}\n```")

        # Image files
        elif any(x in file_out for x in ["png", "jpeg", "jpg", "gif", "bmp", "tiff"]):
            sections.append(f"\n**exiftool:**\n```\n{_run(f'exiftool {path} 2>/dev/null | head -40')}\n```")
            if _tool_exists("zsteg") and "png" in file_out:
                sections.append(f"\n**zsteg (LSB check):**\n```\n{_run(f'zsteg {path} 2>/dev/null | head -20')}\n```")
            sections.append(f"\n**binwalk:**\n```\n{_run(f'binwalk {path} | head -20')}\n```")
            sections.append(f"\n**strings (suspicious):**\n```\n{_run(f'strings -a {path} | grep -iE \"flag|ctf|htb|pico\" | head -20')}\n```")

        # PCAP
        elif "pcap" in file_out or p.suffix.lower() in [".pcap", ".pcapng"]:
            sections.append(f"\n**tshark summary:**\n```\n{_run(f'tshark -r {path} -q -z io,phs 2>/dev/null | head -30')}\n```")
            sections.append(f"\n**HTTP objects:**\n```\n{_run(f'tshark -r {path} -Y http -T fields -e http.request.uri 2>/dev/null | head -20')}\n```")
            sections.append(f"\n**strings search:**\n```\n{_run(f'strings -a {path} | grep -iE \"flag|ctf|htb|pico\" | head -20')}\n```")

        # Archive
        elif any(x in file_out for x in ["zip", "gzip", "tar", "7-zip"]):
            sections.append(f"\n**binwalk:**\n```\n{_run(f'binwalk -e {path} 2>/dev/null | head -30')}\n```")

        # Generic fallback
        else:
            sections.append(f"\n**strings (all):**\n```\n{_run(f'strings -a {path} | head -50')}\n```")
            sections.append(f"\n**hexdump head:**\n```\n{_run(f'xxd {path} | head -20')}\n```")
            sections.append(f"\n**exiftool:**\n```\n{_run(f'exiftool {path} 2>/dev/null | head -20')}\n```")

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# URL recon
# ---------------------------------------------------------------------------

def recon_url(url: str) -> str:
    base = url.rstrip("/")
    sections = [f"# URL Recon: {url}\n"]

    sections.append(f"**HTTP headers:**\n```\n{_run('curl -si ' + url + ' | head -40')}\n```")
    sections.append(f"\n**robots.txt:**\n```\n{_run('curl -s ' + base + '/robots.txt | head -20')}\n```")
    sections.append(f"\n**Page source (head):**\n```\n{_run('curl -s ' + url + ' | head -60')}\n```")

    # Check for common endpoints
    for path in ["/admin", "/.git/HEAD", "/api", "/login", "/register", "/.env", "/config.php"]:
        code = _run(f'curl -so /dev/null -w "%{{http_code}}" {base}{path}')
        if code not in ["404", "(error", "(timed"]:
            sections.append(f"\n**{path}:** HTTP {code}")

    if _tool_exists("whatweb"):
        sections.append(f"\n**whatweb:**\n```\n{_run(f'whatweb {url} 2>/dev/null')}\n```")

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# NC / raw socket recon
# ---------------------------------------------------------------------------

def recon_nc(host: str, port: int) -> str:
    sections = [f"# Service Recon: {host}:{port}\n"]
    sections.append(f"**nmap:**\n```\n{_run(f'nmap -sV -p {port} {host} 2>/dev/null', timeout=30)}\n```")
    sections.append(f"\n**banner grab:**\n```\n{_run(f'echo -e \"\\n\" | nc -w 3 {host} {port} 2>/dev/null | head -10')}\n```")
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def auto_recon(
    files: list[str] | None = None,
    url: str | None = None,
    nc: str | None = None,  # "host:port"
) -> str:
    """
    Run appropriate recon and return a structured markdown report.
    Returns empty string if no inputs provided.
    """
    parts = []

    if files:
        parts.append(recon_files(files))

    if url:
        parts.append(recon_url(url))

    if nc:
        try:
            host, port_str = nc.rsplit(":", 1)
            parts.append(recon_nc(host, int(port_str)))
        except ValueError:
            parts.append(f"[recon error] Invalid nc format '{nc}', expected host:port")

    return "\n\n---\n\n".join(parts)
