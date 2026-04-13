"""
Per-category ordered technique trees.
Used as fallback when RAG retrieval finds nothing relevant.
The agent can call get_attack_tree(category) to get a prioritized checklist.

v3 — Expanded with advanced heap, kernel, IO_FILE, race conditions, ROP synthesis.
"""

TREES: dict[str, list[str]] = {
    "web": [
        "1. Recon: curl headers, robots.txt, /sitemap.xml, source code comments",
        "2. Auth: try default creds (admin/admin, admin/password)",
        "3. SQLi: test ' and 1=1-- in every input field; run sqlmap --level=3",
        "4. JWT: decode token; check alg=none; try RS256→HS256 confusion with public key",
        "5. SSTI: inject {{7*7}} in every template field; target Jinja2/Twig/Freemarker",
        "6. LFI/Path traversal: ../../../etc/passwd in file params",
        "7. SSRF: point URL params to internal 169.254.169.254 or localhost",
        "8. XSS: <script>alert(1)</script> — look for stored vs reflected",
        "9. Deserialization: check Content-Type for pickle/java serial/PHP serial",
        "10. IDOR: enumerate IDs in API endpoints, change user_id param",
        "11. Race condition: parallel requests on sensitive endpoints",
        "12. XXE: inject XML entity in SOAP/XML endpoints",
    ],
    "crypto": [
        "1. Identify cipher: entropy, character set, block size, key hints",
        "2. Classical: try Caesar/ROT13, Vigenere (index of coincidence), Bacon",
        "3. Base encodings: base64, base32, base58, hex — check for nested encoding",
        "4. RSA small e: e=3 or e=5 → cube root attack (get_template crypto_rsa)",
        "5. RSA two ciphertexts same n, RELATED plaintexts (m2 = m1>>8, m2=m1-k, etc.) → Franklin-Reiter related message attack (get_template crypto_franklin_reiter). Search 'franklin reiter related message polynomial gcd'.",
        "6. RSA two ciphertexts same n, SAME e, DIFFERENT plaintexts → common modulus attack",
        "7. RSA large e (close to n) → Wiener continued fractions (get_template crypto_rsa wiener_attack)",
        "8. RSA: try factordb.com with the modulus n",
        "9. AES-ECB: look for repeated blocks → block boundary oracle",
        "10. AES-CBC: bit-flip attack if you control ciphertext",
        "11. Padding oracle: repeated requests with different padding",
        "12. Hash: MD5 length extension (hashpumpy), rainbow table (crackstation.net)",
        "13. XOR: single-byte XOR → frequency analysis; multi-byte → Kasiski",
        "14. PRNG: check if seed is time-based or predictable",
    ],
    "pwn": [
        # ── Phase 1: Reconnaissance ──────────────────────────────────────────
        "1. checksec: identify protections (NX, PIE, Canary, RELRO, ASLR)",
        "2. file ./binary: arch (32/64-bit), stripped, statically/dynamically linked",
        "3. strings ./binary: look for win function, /bin/sh, flag path, system, execve",
        "4. Run normally: understand input/output behaviour, identify vuln surface",
        "5. Run under ltrace/strace: spot strcmp, memcmp, read/write calls",

        # ── Phase 2: Classic Stack ────────────────────────────────────────────
        "6. No canary + overflow → find offset with cyclic pattern (cyclic_offset), then:",
        "   6a. Win function present → direct ret2win with ROP gadget",
        "   6b. No win function, no NX → shellcode injection at controlled buffer",
        "   6c. NX enabled → ret2libc: leak puts/printf GOT, compute libc base, system('/bin/sh')",
        "   6d. Full RELRO + PIE → leak .text base via format-string or partial overwrite",
        "7. Canary present → leak canary first:",
        "   7a. Format string: %p×N leak, identify canary position on stack",
        "   7b. Off-by-one: overwrite LSB of canary-adjacent value",
        "   7c. Use-after-free / info-leak to read canary from TLS tcb_self",

        # ── Phase 3: Format String (advanced) ────────────────────────────────
        "8. Format string vulnerability:",
        "   8a. Stage 1 — leak addresses: %p×N to dump stack, find PIE/libc/canary",
        "   8b. Stage 2 — arbitrary write: %Nc%N$n to overwrite GOT/return-addr",
        "   8c. Blind write: use %hhn (1-byte writes) to write shellcode byte-by-byte",
        "   8d. ret2linker: overwrite _dl_fini pointer in link_map to hijack control on exit",
        "   8e. Overwrite __malloc_hook / __free_hook (glibc <2.34) → one_gadget",

        # ── Phase 4: ROP Chains ───────────────────────────────────────────────
        "9. ROP chain construction (NX + no one_gadget):",
        "   9a. Find gadgets: find_gadget('pop rdi; ret'), find_gadget('pop rsi; ret'), find_gadget('ret')",
        "   9b. Stack alignment: add bare 'ret' gadget before system() if MOVAPS crash (Ubuntu ≥18.04)",
        "   9c. Ret2plt: call puts@plt(puts@got) → leak → compute libc base → call system",
        "   9d. ret2csu: use __libc_csu_init gadgets for 64-bit 3-arg ROP when pop rdx absent → see step 25",
        "   9e. SROP: sigreturn-oriented programming — single syscall controls all regs → see step 24",
        "   9f. ret2syscall: build execve('/bin/sh',NULL,NULL) with syscall gadget (rax=0x3b)",

        # ── Phase 5: Heap Exploitation ────────────────────────────────────────
        "10. Heap vulnerability identification:",
        "    10a. UAF (Use-After-Free): pointer still accessible after free → tcache/fastbin reuse",
        "    10b. Double-free: free same chunk twice → tcache poisoning (glibc 2.28+: needs key bypass)",
        "    10c. Heap overflow: overwrite next-chunk header → unsorted bin / large bin attack",
        "    10d. Off-by-null (off-by-one with '\\0'): shrink prev_size → consolidation attack",

        "11. Tcache poisoning (glibc 2.27–2.31, no key):",
        "    → free chunk A; free chunk B overlapping A; write target-addr into A's fd",
        "    → malloc×2 returns &target → overwrite __free_hook or __malloc_hook",

        "12. Tcache key bypass (glibc 2.32–2.35):",
        "    → tcache_entry.key = tcache_ptr; must XOR fd with (heap_base >> 12)",
        "    → leak heap base first via UAF read on first tcache chunk (fd = heap_addr)",
        "    → safe_link: fd_enc = fd ^ (ptr >> 12); reconstruct with known heap addr",

        "13. House of Botcake (glibc 2.29+, double-free protection bypass):",
        "    → consolidate chunk via unsorted bin, then double-free into tcache",
        "    → overlapping chunk allows fd corruption without triggering key check",

        "14. House of Tangerine (glibc 2.35+, no hooks, tcache):",
        "    → abuse tcache_perthread_struct: overwrite counts[] or entries[] directly",
        "    → requires heap write primitive; gives arbitrary-alloc anywhere",

        "15. House of Force (old glibc, top-chunk size overwrite):",
        "    → overwrite wilderness/top-chunk size → -1 (0xffffffff...)",
        "    → next malloc(offset_to_target) places top-chunk at target-2*SIZE_SZ",

        "16. House of Lore / smallbin corruption:",
        "    → requires two pointers to corrupted chunk; manipulate bk in smallbin",

        "17. Unsorted bin attack (glibc <2.30):",
        "    → overwrite bk of unsorted chunk → write &target-0x10 → triggers write",
        "    → use to overwrite global_max_fast → all sizes become fastbins",

        "18. Largebin attack (glibc 2.30+):",
        "    → overwrite bk_nextsize of large chunk → arbitrary write on next consolidation",
        "    → use to corrupt mp_.tcache_bins or _IO_list_all pointer",

        # ── Phase 6: IO_FILE Exploitation ────────────────────────────────────
        "19. _IO_FILE exploitation (no hooks available, glibc 2.34+):",
        "    19a. Corrupt _IO_list_all → fake FILE struct → FSOP (File Structure Oriented Programming)",
        "    19b. _IO_FILE vtable hijack: overwrite vtable ptr in FILE struct → arbitrary call on fclose/fflush",
        "    19c. house of apple: _IO_wfile_overflow path → call __io_buf_base with controlled args",
        "    19d. house of emma: abuse _IO_cookie_file / _IO_cookie_jumps vtable",
        "    19e. FSOP via _IO_str_overflow: fake FILE with buf_base=target, buf_end=target+size",
        "    19f. Trigger: fclose(), exit() (calls _IO_cleanup), or abort() will walk _IO_list_all",

        # ── Phase 7: Kernel Exploitation ─────────────────────────────────────
        "20. Kernel challenge indicators: /dev/X device, mmap of /proc, setuid binary, kernel module .ko",
        "21. Kernel heap (slab) exploitation:",
        "    21a. pipe_buffer UAF: alloc pipe, trigger UAF on pipe_buffer → arbitrary ops via pipe_buf_operations",
        "    21b. msg_msg spray: use msgsnd/msgrcv to spray kernel heap with controlled data",
        "    21c. seq_file / tty_struct: arbitrary read/write via corrupted ops pointer",
        "    21d. physmap spray: spray user-space pages mapped at kernel addresses (needs SMEP=off)",

        "22. Kernel KASLR/SMEP/KPTI bypass:",
        "    22a. /proc/kallsyms or /proc/modules (if readable) → leak kernel base",
        "    22b. dmesg (if accessible) → kernel text addresses in crash logs",
        "    22c. KPTI bypass: use trampoline at entry_SYSCALL_64+offset (swapgs_restore_regs_and_return_to_usermode)",
        "    22d. SMEP/SMAP bypass: kernel ROP chain (no user-space code/data) → ret2usr via sigreturn",
        "    22e. modprobe_path overwrite → trigger with unknown binary → executes as root",

        "23. Kernel ROP chain template:",
        "    → commit_creds(prepare_kernel_cred(0)) → set uid=0",
        "    → KPTI trampoline → swapgs → iretq back to user-space shell",
        "    → use kernel gadgets only (no user-space addresses while in ring-0)",

        # ── Phase 8: Advanced ROP Techniques ──────────────────────────────────
        "24. SROP (Sigreturn-Oriented Programming) — only needs 'syscall; ret' gadget:",
        "    → set rax=0xf via write(1,buf,15) return value or 'pop rax; ret'",
        "    → SigreturnFrame() from pwntools: set rip=syscall_gadget, rdi=/bin/sh, rax=0x3b",
        "    → get_template('pwn_srop') for complete implementation",
        "25. ret2csu — universal 3-arg ROP when pop rdx is absent:",
        "    → __libc_csu_init gadget set: rbx=0, rbp=1, r12=&got_fn, r13=rdi, r14=rsi, r15=rdx",
        "    → csu_call: mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]",
        "    → get_template('pwn_ret2csu') for complete implementation",

        # ── Phase 9: Advanced / Cutting-Edge ──────────────────────────────────
        "26. Integer overflow: check bounds on size params, signed/unsigned wrap, alloca overflow",
        "27. Race condition (user-space): TOCTOU on file ops; pthread_create exploit window",
        "    → use userfaultfd or mmap tricks to pause kernel mid-copy",
        "    → fasttrap / key_replenish timing for precise single-instruction windows",
        "    → get_template('pwn_race_condition') for toctou_symlink + parallel_requests",
        "28. V8 / browser engine: OOB read/write → addrOf + fakeObj primitives",
        "    → exploit via ArrayBuffer backing store pointer → arbitrary R/W → JIT shellcode",
        "29. SMM exploitation (UEFI): SmmS3ResumeState hijacking, MMIO handler overwrite",
        "30. musl libc (non-glibc target):",
        "    30a. Identify: ldd binary shows 'musl' or /lib/ld-musl-x86_64.so",
        "    30b. atexit hijacking: __funcs_on_exit singly-linked list → overwrite fn pointer",
        "    30c. No tcache/fastbins: overflow directly into chunk header to corrupt free-list",
        "    30d. No hooks (__malloc_hook/__free_hook never existed in musl)",
        "31. mimalloc (modern libraries/binaries): segment-based allocator",
        "    → overflow into segment metadata → corrupt free-list → arbitrary write",
    ],
    "rev": [
        "1. file ./binary: type, arch, stripped",
        "2. ARM/MIPS/non-native arch: extract rootfs/initramfs first (binwalk or cpio); "
           "run binary under qemu-arm -L <rootfs> ./binary for dynamic analysis; "
           "angr handles ARM natively — no qemu needed for symbolic execution.",
        "3. strings -a ./binary | grep -i flag — check for plaintext flag",
        "4. strings -a ./binary | grep -E '%[0-9]+[duf]|%[0-9]+s' — find format strings that "
           "reveal input type and length. '%06u' = 6-digit number → brute-force 0..999999 "
           "(get_template rev_brute_numeric). '%20s' = 20-char string → angr or dict attack.",
        "5. ltrace ./binary (native) OR strace (ARM under qemu): watch strcmp/memcmp for plaintext leaks",
        "6. Open in Ghidra: find main, locate string comparisons or success path",
        "7. GDB dynamic analysis: set breakpoints at strcmp/memcmp, dump registers",
        "8. Anti-debug: check for ptrace calls, timing checks — patch them out",
        "9. Symbolic execution: angr works on x86, x86_64, ARM, MIPS — use rev_angr template; "
           "for ARM set arch='ARM' in main_opts if needed.",
        "10. Small numeric keyspace (≤ 10^7): always brute-force first — it's faster than reversing "
            "(get_template rev_brute_numeric). One million iterations takes <10 seconds.",
        "11. Packing/obfuscation: detect UPX (upx -d), check for self-modifying code",
        "12. VM/interpreter: look for dispatch loops, custom opcode handlers",
        "13. .NET/Java/Python: decompile with dnSpy / jadx / uncompyle6",
        "14. Algorithm identification: look for magic constants (AES S-box, SHA round constants)",
    ],
    "forensics": [
        "1. file ./artifact: identify true file type regardless of extension",
        "2. exiftool ./artifact: metadata, GPS, author, software, timestamps",
        "3. strings -a ./artifact | grep -i 'flag\\|ctf\\|htb\\|pico'",
        "4. binwalk -e ./artifact: extract embedded files and filesystems",
        "5. PNG/JPG: zsteg ./image (LSB), steghide extract -sf ./image",
        "6. Stegsolve / bit-plane analysis on images",
        "7. PCAP: tshark -r ./file.pcap -Y 'http' | grep flag; follow TCP streams",
        "8. Memory dump: volatility3 -f dump.raw windows.pslist then filescan",
        "9. Deleted files: photorec, foremost for carved files",
        "10. Audio: Audacity spectrogram view; DTMF decode; morse decode",
        "11. ZIP/archive: check for password, known-plaintext attack (pkcrack)",
        "12. Disk image: mount and check $Recycle.Bin, shadow copies, slack space",
    ],
    "misc": [
        "1. Encoding: base64/32/58/85, hex, URL, HTML entity, morse, binary",
        "2. Try CyberChef magic operation on the input",
        "3. QR code / barcode: zbarimg, online decoders",
        "4. OSINT: reverse image search, username search (sherlock), WHOIS, Shodan",
        "5. Pyjail / bash jail: check builtins, import restrictions; try __import__, exec",
        "6. Scripting: read the problem carefully — it may just be a math/logic puzzle",
        "7. Network: pcap with unusual protocol → decode manually or find Wireshark dissector",
    ],
    "blockchain": [
        "1. Read contract source/ABI: `cast interface <addr> --rpc-url <rpc>` or read provided .sol",
        "2. Check all public/external state: `cast call <addr> 'owner()' ...`; `cast storage <addr> 0`",
        "3. Read private storage slots: `cast storage <addr> <slot>` — Solidity lays out sequentially",
        "4. Look for missing access control: public/external functions without onlyOwner/modifier",
        "5. Reentrancy: external call before state update → write attack contract with malicious fallback",
        "6. Integer overflow (Solidity <0.8): underflow uint to max, overflow to 0",
        "7. tx.origin phishing: contract checks tx.origin==owner → deploy middleman contract",
        "8. Weak randomness: blockhash/block.timestamp used as RNG → predict or manipulate",
        "9. Delegatecall storage collision: proxy delegates to impl → storage slot 0 overlaps owner",
        "10. Selfdestruct / forced ETH: forcibly send ETH to break balance==0 checks",
        "11. Flash loan: borrow → exploit price oracle → profit → repay in one atomic tx",
        "12. Signature replay: check if nonce+chainId is included in signed message; if not, replay",
        "13. Uninitialized proxy: `cast storage <proxy> 0x360894a13ba1a3210667c828492db98dca3e2076635130ab13be3f` (EIP-1967)",
        "14. CREATE2 address prediction: compute keccak256(0xff ++ deployer ++ salt ++ bytecode_hash)",
    ],
    "android": [
        "1. Decompile APK: android_analyze action=decompile → Java source in <apk>_jadx/sources/",
        "2. Parse manifest: android_analyze action=manifest → check exported=true, debuggable=true",
        "3. List permissions: android_analyze action=permissions → spot dangerous permissions",
        "4. Dump strings: android_analyze action=strings → scan for hardcoded secrets/flags",
        "5. Search source: android_analyze action=search query='flag|secret|key|CTF|password'",
        "6. Check BuildConfig: find API keys, debug flags, base URLs in generated BuildConfig.java",
        "7. Trace flag check: find validate()/check() method → follow logic → replicate in Python",
        "8. Crypto reversal: note algorithm+key+IV from source → implement decryption in Python",
        "9. Exported components: launch with `adb shell am start -n <pkg>/<activity>` — may skip auth",
        "10. Content providers: `adb shell content query --uri content://<authority>/table`",
        "11. SQLite DBs: `adb pull /data/data/<pkg>/databases/*.db` (needs root/debuggable APK)",
        "12. Shared prefs: `adb pull /data/data/<pkg>/shared_prefs/*.xml`",
        "13. Native (.so): `strings lib/*.so | grep -i flag` — keys often in .rodata",
        "14. Dynamic with frida: `frida -U -l hook.js <pkg>` to intercept crypto calls",
        "15. Certificate pinning bypass: use objection (`objection -g <pkg> explore`) or patch smali",
    ],
}

# ── Heap quick-reference (injected with get_attack_tree('pwn')) ──────────────

HEAP_QUICK_REF = """
## Heap Exploitation Quick Reference

### glibc Version Detection
```bash
ldd --version         # glibc version
strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C Library"
```

### tcache_entry structure (glibc 2.28+)
```c
typedef struct tcache_entry {
    struct tcache_entry *next;   // fd — obfuscated with PROTECT_PTR in 2.32+
    struct tcache_perthread_struct *key;  // points to tcache for double-free detection
} tcache_entry;
// PROTECT_PTR: enc = real_ptr ^ (slot_addr >> 12)
// Deobfuscate: real_ptr = enc ^ (slot_addr >> 12)
```

### _IO_FILE offsets (glibc 2.35, x86_64)
```
+0x00  _flags
+0x08  _IO_read_ptr
+0x10  _IO_read_end
+0x18  _IO_read_base
+0x20  _IO_write_base    ← control RDI/RSI in _IO_str_overflow
+0x28  _IO_write_ptr
+0x38  _IO_buf_base
+0x40  _IO_buf_end
+0xd8  vtable            ← overwrite to _IO_str_jumps for FSOP
+0xe0  _mode
```

### One-gadget constraints (typical)
```
# Check: one_gadget /lib/x86_64-linux-gnu/libc.so.6
# Common constraints: [rsp+0x30] == NULL, r12 == NULL, rdi == NULL
# If no constraint met: set rsp+0x30 = NULL via ROP before gadget
```

### KPTI Trampoline (kernel ≥4.15)
```asm
; swapgs_restore_regs_and_return_to_usermode trampoline
; Address: ksymtab entry or: ffffffff81200f10 (varies per build)
; Replaces:  swapgs; iretq
; Place on ROP stack: [trampoline] [0] [0] [user_rip] [user_cs] [user_rflags] [user_rsp] [user_ss]
```
"""


def get_attack_tree(category: str) -> str:
    """Return the technique checklist for a category as a formatted string."""
    category = category.lower().strip()
    tree = TREES.get(category)
    if not tree:
        available = ", ".join(TREES.keys())
        return f"Unknown category '{category}'. Available: {available}"

    lines = [f"## Attack Tree — {category.upper()}", ""]
    lines += tree

    # Append heap quick-reference for pwn
    if category == "pwn":
        lines.append(HEAP_QUICK_REF)

    lines += [
        "",
        "Work through these in order. Call note_failure() for each that doesn't apply or fails.",
        "Call search_writeups() with specific technique keywords once you know which path you're on.",
    ]
    return "\n".join(lines)
