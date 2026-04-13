#!/usr/bin/env bash
# Forensics first-look checklist — run against any artifact
# Usage: bash forensics_recon.sh ./suspicious_file

FILE="$1"
[ -z "$FILE" ] && { echo "Usage: $0 <file>"; exit 1; }

sep() { echo; echo "=== $* ==="; }

sep "file type"
file "$FILE"

sep "size"
wc -c "$FILE"

sep "exiftool metadata"
exiftool "$FILE" 2>/dev/null | head -40

sep "strings — flag patterns"
strings -a "$FILE" | grep -iE 'flag|ctf|htb|pico|key|secret|pass' | head -30

sep "strings — all (head 60)"
strings -a "$FILE" | head -60

sep "binwalk — embedded files"
binwalk "$FILE" | head -30

sep "hexdump head"
xxd "$FILE" | head -30

sep "xxd tail (last 20 lines)"
xxd "$FILE" | tail -20

# PNG-specific
if file "$FILE" | grep -qi png; then
    sep "zsteg LSB check"
    zsteg "$FILE" 2>/dev/null | head -20
    sep "pngcheck"
    pngcheck "$FILE" 2>/dev/null
fi

# PCAP-specific
if file "$FILE" | grep -qi pcap; then
    sep "tshark protocol hierarchy"
    tshark -r "$FILE" -q -z io,phs 2>/dev/null
    sep "tshark HTTP URIs"
    tshark -r "$FILE" -Y http -T fields -e http.request.full_uri 2>/dev/null | head -20
    sep "tshark DNS queries"
    tshark -r "$FILE" -Y dns -T fields -e dns.qry.name 2>/dev/null | head -20
    sep "tshark flag search in payload"
    tshark -r "$FILE" -T fields -e data.text 2>/dev/null | grep -iE 'flag|ctf|htb|pico' | head -10
fi

# ZIP/archive
if file "$FILE" | grep -qiE 'zip|gzip|bzip|tar|7-zip'; then
    sep "archive contents"
    unzip -l "$FILE" 2>/dev/null || tar -tvf "$FILE" 2>/dev/null
fi

sep "done"
