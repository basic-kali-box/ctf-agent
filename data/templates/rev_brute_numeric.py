#!/usr/bin/env python3
"""
Brute-force a numeric code submitted to a binary via stdin.

Use when you see format strings like '%06u', '%04d', '%08u' — they reveal
the code is a zero-padded integer of a known width.  1M candidates runs in
seconds.  Adjust the variables below and run:

    python3 rev_brute_numeric.py

For ARM/MIPS binaries extracted from an initramfs:
    BINARY  = "/path/to/initrd/challenge/vault_app"
    QEMU    = "qemu-arm -L /path/to/initrd"   # set to "" for native
    MENU_SEQ maps menu option → numeric code → final response
"""

import subprocess
import sys

# ── configure ────────────────────────────────────────────────────────────────
BINARY   = "./target"           # path to binary
QEMU     = ""                   # e.g. "qemu-arm -L ./initrd" for ARM, "" for native
DIGITS   = 6                    # width from format string, e.g. '%06u' → 6
START    = 0
END      = 10 ** DIGITS         # exclusive upper bound
STEP     = 1

# Input sent to the binary before the numeric code (menu selections, etc.)
# Each entry is a line; the code is appended last.
# Example: binary shows menu "1=deposit 2=token 3=quit", choose 2 first:
PRE_INPUT  = ["2"]              # lines sent before the code (empty list if code is first input)

# String that indicates success (case-sensitive substring match on stdout)
SUCCESS_STR = "Correct"
# String that indicates failure — if seen, skip faster
FAIL_STR    = "Incorrect"

TIMEOUT  = 3                    # seconds per attempt
VERBOSE  = 100_000              # print progress every N attempts
# ─────────────────────────────────────────────────────────────────────────────


def run(code: int) -> str:
    code_str = str(code).zfill(DIGITS)
    lines = PRE_INPUT + [code_str, ""]
    stdin_data = "\n".join(lines).encode()

    cmd = f"{QEMU} {BINARY}".strip()
    try:
        result = subprocess.run(
            cmd, shell=True,
            input=stdin_data,
            capture_output=True,
            timeout=TIMEOUT,
        )
        return (result.stdout + result.stderr).decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return ""


def main():
    print(f"[*] Brute-forcing {DIGITS}-digit codes {START}..{END-1} against {BINARY}")
    if QEMU:
        print(f"[*] Running under: {QEMU}")

    for code in range(START, END, STEP):
        if code % VERBOSE == 0:
            pct = 100 * code / (END - START)
            print(f"    {code:>{DIGITS}} / {END-1}  ({pct:.1f}%)", end="\r", flush=True)

        output = run(code)
        if SUCCESS_STR in output:
            print(f"\n[+] FOUND! code = {str(code).zfill(DIGITS)}")
            print(f"[+] Output:\n{output}")
            sys.exit(0)

    print(f"\n[-] No valid code found in range {START}..{END-1}")


if __name__ == "__main__":
    main()
