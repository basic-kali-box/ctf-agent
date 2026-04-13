#!/usr/bin/env python3
"""
Forensics Multi-Tool Runner — CTF Template

Systematically applies common forensics tools and reports any findings.
Covers: strings, binwalk, exiftool, steghide, stegsolve patterns, zsteg,
foremost, file carving, PCAP analysis, zip/archive cracking.
"""
import subprocess
import sys
from pathlib import Path


def run(cmd: str, timeout: int = 20) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return "(timed out)"
    except Exception as e:
        return f"(error: {e})"


def check(output: str) -> bool:
    """Returns True if output looks interesting."""
    if not output or output in ("(timed out)", "(no output)"):
        return False
    keywords = ["flag", "ctf{", "htb{", "pico", "key", "secret", "password",
                 "hidden", "embed", "base64", "hex", "found", "extracted"]
    return any(k in output.lower() for k in keywords)


def section(title: str, output: str):
    border = "─" * 60
    print(f"\n{border}")
    print(f"  {title}")
    print(border)
    if check(output):
        print(f"  ⚡ INTERESTING:\n{output[:1000]}")
    else:
        print(f"  (nothing notable: {output[:100]}...)" if len(output) > 100 else f"  {output}")


def analyze_file(path: str):
    p = Path(path)
    if not p.exists():
        print(f"[!] File not found: {path}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  FORENSICS ANALYSIS: {p.name}")
    print(f"{'='*60}")

    file_type = run(f"file {path}")
    size = p.stat().st_size
    print(f"  Type: {file_type}")
    print(f"  Size: {size} bytes")

    # ── Universal ───────────────────────────────────────────────────────
    section("strings (flag-like)", run(
        f"strings -a {path} | grep -iE 'flag|ctf{{|htb{{|pico|key=|secret' | head -30"
    ))
    section("strings (base64-like)", run(
        f"strings -a {path} | grep -E '^[A-Za-z0-9+/]{{20,}}=*$' | head -10"
    ))
    section("exiftool", run(f"exiftool {path} 2>/dev/null | head -40"))
    section("binwalk",  run(f"binwalk {path} 2>/dev/null | head -30"))

    ft = file_type.lower()

    # ── Image ────────────────────────────────────────────────────────────
    if any(x in ft for x in ["png", "jpeg", "jpg", "gif", "bmp", "tiff", "image"]):
        section("steghide (empty password)", run(
            f"steghide extract -sf {path} -p '' -f 2>&1"
        ))
        section("zsteg (LSB stego)", run(f"zsteg {path} 2>/dev/null | head -20"))
        section("binwalk extract", run(
            f"binwalk -e --directory /tmp/binwalk_out {path} 2>/dev/null && "
            f"find /tmp/binwalk_out -type f | head -20"
        ))
        # Check trailing data
        section("trailing data", run(
            f"python3 -c \""
            f"import struct; d=open('{path}','rb').read(); "
            f"print('Trailing:', d[-200:].hex())\""
        ))

    # ── PCAP ─────────────────────────────────────────────────────────────
    elif "pcap" in ft or p.suffix.lower() in [".pcap", ".pcapng"]:
        section("tshark protocol hierarchy", run(
            f"tshark -r {path} -q -z io,phs 2>/dev/null | head -30"
        ))
        section("HTTP URIs", run(
            f"tshark -r {path} -Y 'http.request' -T fields "
            f"-e http.host -e http.request.uri 2>/dev/null | head -30"
        ))
        section("Follow HTTP stream 0", run(
            f"tshark -r {path} -q -z follow,http,ascii,0 2>/dev/null | head -50"
        ))
        section("DNS queries", run(
            f"tshark -r {path} -Y dns -T fields -e dns.qry.name 2>/dev/null | head -30"
        ))
        section("Extract files (tshark)", run(
            f"tshark -r {path} --export-objects http,/tmp/pcap_http 2>/dev/null && "
            f"ls /tmp/pcap_http 2>/dev/null | head -20"
        ))
        section("strings for flag", run(
            f"strings -a {path} | grep -iE 'flag|ctf{{|key' | head -20"
        ))

    # ── Archive ───────────────────────────────────────────────────────────
    elif any(x in ft for x in ["zip", "gzip", "tar", "7-zip", "bzip"]):
        section("unzip listing", run(f"unzip -l {path} 2>/dev/null | head -30"))
        section("foremost carve", run(
            f"foremost -i {path} -o /tmp/foremost_out 2>/dev/null && "
            f"find /tmp/foremost_out -type f 2>/dev/null | head -20"
        ))

    # ── ELF binary ────────────────────────────────────────────────────────
    elif "elf" in ft:
        section("strings interesting", run(
            f"strings -a {path} | grep -iE 'flag|key|pass|secret|win|correct' | head -30"
        ))
        section("radare2 info", run(f"r2 -q -c 'iI;is' {path} 2>/dev/null | head -30"))

    print(f"\n{'='*60}")
    print("  Analysis complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 forensics_multitool.py <file>")
        sys.exit(1)
    analyze_file(sys.argv[1])
