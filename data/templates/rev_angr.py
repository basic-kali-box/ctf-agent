#!/usr/bin/env python3
"""
angr Symbolic Execution — CTF Template (rev/pwn)

Automatically finds inputs that reach a target function/address.
Extremely powerful for crackme binaries, custom checksum reversals,
CTF binaries that just print "Correct!" or "Wrong!".

ARM/MIPS note: angr supports non-native architectures natively — no qemu needed.
For an ARM binary extracted from an initramfs, just point BINARY at the ELF file.
If auto-detection fails, add: main_opts={'arch': 'ARM'} to angr.Project().

Usage:
  python3 angr_solve.py
  (adjust BINARY, FIND_ADDR, AVOID_ADDR below)
"""
import angr
import claripy

# ── configure ────────────────────────────────────────────────────────────────
BINARY    = "./chall"        # path to the target binary
FLAG_LEN  = 40               # expected flag length (bytes); adjust

# Addresses or strings to find/avoid (use IDA/ghidra/r2 to find these)
# Option A: find by string in output
FIND_STR  = b"Correct"       # angr will find paths that print this
AVOID_STR = b"Wrong"         # angr will avoid paths that print this

# Option B: find by address (comment out the string version if using this)
# FIND_ADDR  = 0x401234       # address of "Correct" print / success code
# AVOID_ADDR = 0x401A00       # address of "Wrong" / exit(-1)

# Input via stdin? If via argv, change to claripy.BVS args below.
INPUT_VIA_STDIN = True
# ─────────────────────────────────────────────────────────────────────────────


def solve_with_stdin():
    """Symbolic stdin: works for most CTF crackmes that read from stdin."""
    project = angr.Project(BINARY, auto_load_libs=False)

    # Create symbolic stdin buffer
    flag_chars = claripy.BVS("flag", FLAG_LEN * 8)
    stdin = angr.SimFile("/dev/stdin", content=flag_chars, size=FLAG_LEN)

    state = project.factory.full_init_state(
        stdin=stdin,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # Constrain to printable ASCII
    for i in range(FLAG_LEN):
        byte = flag_chars.get_byte(i)
        state.solver.add(byte >= 0x20, byte <= 0x7e)

    sim = project.factory.simulation_manager(state)

    # Run with string-based find/avoid (easier than manual addresses)
    sim.explore(
        find=lambda s: FIND_STR in s.posix.dumps(1),
        avoid=lambda s: AVOID_STR in s.posix.dumps(1),
    )

    if sim.found:
        found_state = sim.found[0]
        flag = found_state.solver.eval(flag_chars, cast_to=bytes)
        print("[+] FLAG:", flag)
        print("[+] As string:", flag.decode("utf-8", errors="replace"))
        return flag
    else:
        print("[-] No solution found")
        if sim.deadended:
            print(f"    Deadended: {len(sim.deadended)} states (try adjusting addresses)")
        return None


def solve_with_argv():
    """Symbolic argv[1]: works for binaries like ./crackme <flag>."""
    project = angr.Project(BINARY, auto_load_libs=False)
    flag = claripy.BVS("flag", FLAG_LEN * 8)
    argv = [project.filename.encode(), flag]

    state = project.factory.entry_state(
        args=argv,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )
    for i in range(FLAG_LEN):
        b = flag.get_byte(i)
        state.solver.add(b >= 0x20, b <= 0x7e)

    sim = project.factory.simulation_manager(state)
    sim.explore(
        find=lambda s: FIND_STR in s.posix.dumps(1),
        avoid=lambda s: AVOID_STR in s.posix.dumps(1),
    )

    if sim.found:
        result = sim.found[0].solver.eval(flag, cast_to=bytes)
        print("[+] FLAG:", result)
        return result
    print("[-] No solution")
    return None


if __name__ == "__main__":
    if INPUT_VIA_STDIN:
        solve_with_stdin()
    else:
        solve_with_argv()
