#!/usr/bin/env python3
"""
Z3 SMT Solver — CTF Template
Solves constraint satisfaction problems: crypto, rev, misc.

Common patterns:
  - Verify: find input X such that check(X) == True
  - Crypto: recover key/message from XOR/add/mul constraints
  - Rev: crack a custom hash/check function symbolically
"""
from z3 import *

# ── configure ──────────────────────────────────────────────────────────────
# Example: find a flag of N bytes satisfying constraints
FLAG_LEN = 20   # adjust to challenge

# Define symbolic variables: one BitVec per byte
flag = [BitVec(f"c{i}", 8) for i in range(FLAG_LEN)]
s = Solver()

# ── add constraints ────────────────────────────────────────────────────────
# Printable ASCII constraint (always add these)
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# Example: flag[0] + flag[1] == 0x8d and flag[2] ^ flag[3] == 0x05
# s.add(flag[0] + flag[1] == 0x8d)
# s.add(flag[2] ^ flag[3] == 0x05)

# Example: reproduce a custom checksum
# total = Sum(flag)   # BitVec addition
# s.add(total == 0x1234)

# ── solve ──────────────────────────────────────────────────────────────────
if s.check() == sat:
    model = s.model()
    result = bytes(model[c].as_long() for c in flag)
    print("[+] Solution found:", result)
    print("[+] As string:", result.decode("utf-8", errors="replace"))
else:
    print("[-] No solution — constraints are unsatisfiable")
    print("    Hint: check your constraints for typos, try AllDifferent=False")
