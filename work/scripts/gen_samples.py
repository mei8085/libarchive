#!/usr/bin/env python3
"""
Craft raw tar/PAX samples with byte-level control.

Each generator writes one file into work/samples and prints its layout.
All samples are self-contained byte strings; no system tar is trusted to
build the malicious parts.
"""
import os
import sys

OUT = "/srv/fb2/mei8085/0070-libarchive-5-c88eda7f/work/samples"


# ---------------------------------------------------------------- primitives

def octal_field(value, width):
    """Traditional NUL-terminated octal numeric field."""
    return ("%0*o" % (width - 1, value)).encode() + b"\x00"


def ustar_header(name, size, typeflag=b"0", magic=b"ustar\x0000",
                 mode=0o644, extra=None):
    """Build a 512-byte ustar header with a correct checksum."""
    if isinstance(name, str):
        name = name.encode()
    h = bytearray(512)
    h[0:100] = name.ljust(100, b"\x00")
    h[100:108] = octal_field(mode, 8)
    h[108:116] = octal_field(0, 8)      # uid
    h[116:124] = octal_field(0, 8)      # gid
    h[124:136] = octal_field(size, 12)
    h[136:148] = octal_field(0, 12)     # mtime
    h[148:156] = b"        "            # checksum placeholder (spaces)
    h[156:157] = typeflag
    h[157:257] = b"".ljust(100, b"\x00")  # linkname
    h[257:265] = magic                  # "ustar\0" + "00"
    h[265:297] = b"".ljust(32, b"\x00")  # uname
    h[297:329] = b"".ljust(32, b"\x00")  # gname
    h[329:337] = octal_field(0, 8)      # devmajor
    h[337:345] = octal_field(0, 8)      # devminor
    if extra is not None:
        for off, data in extra.items():
            h[off:off + len(data)] = data
    chksum = sum(h)
    h[148:156] = ("%06o\x00 " % chksum).encode()
    assert len(h) == 512
    return bytes(h)


def pad512(data):
    r = len(data) % 512
    return data + (b"\x00" * ((512 - r) % 512))


def pax_record(key, value, declared_len=None):
    """
    A well-formed record is:  "%d %s=%s\n" % (len(whole), key, value).
    declared_len lets us lie about the length while keeping real bytes.
    """
    if isinstance(key, str):
        key = key.encode()
    if isinstance(value, str):
        value = value.encode()
    if declared_len is None:
        body = b" %s=%s\n" % (key, value)
        s = str(len(body) + 1)            # one-digit length guess
        while True:                       # fixed point per POSIX algorithm
            whole = s.encode() + body
            if len(whole) == int(s):
                return whole
            s = str(len(whole))
    return ("%d" % declared_len).encode() + b" %s=%s\n" % (key, value)


def pax_header(records_bytes, hdr_name=b"PaxHeader/0000000000"):
    """A type 'x' header whose ustar size is len(records_bytes)."""
    return ustar_header(hdr_name, len(records_bytes), typeflag=b"x")


def write_sample(fname, blob):
    path = os.path.join(OUT, fname)
    with open(path, "wb") as f:
        f.write(blob)
    print("wrote %-34s %8d bytes" % (fname, len(blob)))
    return path


def two_zero_blocks():
    return b"\x00" * 1024


# ------------------------------------------------------------------ samples

def s01_len_shorter():
    """
    Declared record length SHORTER than actual bytes.
    Real record: "21 path=AAAAAAAAAA\\n" (21 bytes).
    Declared 15 -> parser consumes only 15 bytes; the 6 leftover bytes
    ("AAAA\\n") then become the next 'record' start inside the same body.
    Body size stays truthful (512), so we can observe the mis-sync.
    """
    real = b"20 path=AAAAAAAAAAA\n"   # 2+1+5+11+1 = 20 bytes, truthful
    assert len(real) == 20
    rec = b"14" + real[2:]            # same bytes, lie says 14
    assert len(rec) == 20             # leftover 6 bytes: "AAAAA\n"
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("real_file.txt", 5) + pad512(b"hello")
    blob += two_zero_blocks()
    return write_sample("s01_pax_len_shorter.tar", blob), rec


def s02_len_longer():
    """
    Declared length LONGER than actual record (and longer than body):
    declared 60 for a 19-byte record inside a 512-byte pax body.
    Check: does the parser jump across the body boundary?
    """
    rec = pax_record("path", "BBBBBBBB", declared_len=60)
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("after_pax.txt", 3) + pad512(b"abc")
    blob += two_zero_blocks()
    return write_sample("s02_pax_len_longer.tar", blob), rec


def s03_line_overflow():
    """
    Attribute length > max_parsed_line_length (99,999,999).
    Body is only 512 bytes; parser must reject without allocating/reading
    ~100MB.
    """
    rec = pax_record("path", "x", declared_len=100_000_000)
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("victim.txt", 2) + pad512(b"zz")
    blob += two_zero_blocks()
    return write_sample("s03_pax_line_overflow.tar", blob), rec


def s04_pax_size_huge():
    """
    pax 'size' numeric value beyond entry_limit (2^60), inside an x body.
    ustar header of the real entry claims size 0.
    """
    rec = pax_record("size", "9999999999999999999")  # ~1e19 > 2^60
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("huge.txt", 0) + two_zero_blocks()
    return write_sample("s04_pax_size_huge.tar", blob), rec


def s05_pax_size_negative():
    """Negative pax size (numeric, allowed syntax but illegal value)."""
    rec = pax_record("size", "-5")
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("neg.txt", 0) + two_zero_blocks()
    return write_sample("s05_pax_size_negative.tar", blob), rec


def s06_size_conflict_pax_bigger():
    """
    Allowed-by-spec override: ustar says 3, pax size says 8.
    Body contains 8 bytes so the correct parser consumes all 8.
    """
    rec = pax_record("size", "8")
    body = pad512(rec)
    data = b"DATA1234"             # exactly 8 bytes
    blob = pax_header(rec) + body
    blob += ustar_header("conflict_big.txt", 3) + pad512(data)
    # A second entry placed right after the 8-byte body tests boundary.
    blob += ustar_header("second.txt", 2) + pad512(b"qq")
    blob += two_zero_blocks()
    return write_sample("s06_size_conflict_pax_bigger.tar", blob), rec


def s07_size_conflict_pax_smaller():
    """
    ustar says 8, pax size says 3. Body holds 8 bytes + padding.
    Correct behavior per POSIX: consume 3; remaining 5 bytes are
    'dead' space up to the ustar-declared padded block; next header
    location depends on which size drives consumption.
    """
    rec = pax_record("size", "3")
    body = pad512(rec)
    data = b"ABCDEFGH"
    blob = pax_header(rec) + body
    # ustar size=8 -> its padding is 504; next header at +512
    blob += ustar_header("conflict_small.txt", 8) + pad512(data)
    blob += ustar_header("after_small.txt", 1) + pad512(b"w")
    blob += two_zero_blocks()
    return write_sample("s07_size_conflict_pax_smaller.tar", blob), rec


def s08_len_swallows_next_header():
    """
    pax body = 2 records. First declared length is big enough to run
    past its own record INTO the second record region (but stays < body).
    Tests whether record 2's bytes get hidden/skipped.
    """
    r1 = pax_record("path", "first_name", declared_len=40)  # real ~22
    r2 = pax_record("size", "1")                            # real 11
    recs = r1 + r2
    body = pad512(recs)
    blob = pax_header(recs) + body
    blob += ustar_header("entry.txt", 1) + pad512(b"X")
    blob += two_zero_blocks()
    return write_sample("s08_len_swallows_record.tar", blob), recs


def s09_empty_name():
    """Malformed record: no '=' / empty name within declared length."""
    rec = b"10 =\n"            # length 5, but declared 10
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("x.txt", 1) + pad512(b"q")
    blob += two_zero_blocks()
    return write_sample("s09_empty_name.tar", blob), rec


def s10_truncated_at_eof():
    """
    x header says body is 512 bytes, but archive ends after 100 body
    bytes -> truncated stream must produce FATAL, never a fake entry.
    """
    rec = pax_record("path", "trunc")
    # x header truthfully claims a 512-byte body, but stream ends early.
    h = ustar_header(b"PaxHeader/trunc", 512, typeflag=b"x")
    blob = h + rec + b"\x00" * (100 - len(rec))
    return write_sample("s10_truncated_eof.tar", blob), rec


def s11_oversized_ext_body():
    """
    ustar size of the x entry: 2 GiB (> 1 GiB sanity limit, < entry_limit).
    Archive ends right after the header: parser must consume/skip and
    refuse, not attempt a 2 GiB allocation.
    """
    big = 2 * 1024 * 1024 * 1024
    h = ustar_header(b"PaxHeader/big", big, typeflag=b"x")
    blob = h  # no body bytes at all
    return write_sample("s11_ext_2gib.tar", blob), None


def s12_valid_compat():
    """
    Fully standards-conformant PAX archive: long UTF-8 path + size
    override + mtime float, two regular entries. Compatibility oracle.
    """
    longname = "dir/" + ("e" * 120) + "/file-\xc3\xa9\xc3\xa8.txt"
    recs = pax_record("path", longname) + pax_record("size", "5") + \
           pax_record("mtime", "1700000000.123456789")
    body = pad512(recs)
    blob = pax_header(recs) + body
    blob += ustar_header("PaxHeader/file", 5) + pad512(b"pax!!")
    recs2 = pax_record("path", "second/normal.txt")
    body2 = pad512(recs2)
    blob += pax_header(recs2, b"PaxHeader/0000000001") + body2
    blob += ustar_header("PaxHeader/file2", 7) + pad512(b"second!")
    blob += two_zero_blocks()
    return write_sample("s12_valid_compat.tar", blob), recs


def s13_duplicate_size():
    """Two size records: 3 then 9. Which wins, and is the boundary kept?"""
    r1 = pax_record("size", "3")
    r2 = pax_record("size", "9")
    recs = r1 + r2
    body = pad512(recs)
    data = b"123456789"
    blob = pax_header(recs) + body
    blob += ustar_header("dup.txt", 3) + pad512(data)
    blob += ustar_header("after_dup.txt", 1) + pad512(b"z")
    blob += two_zero_blocks()
    return write_sample("s13_duplicate_size.tar", blob), recs


def s14_non_numeric_size():
    """size value with trailing garbage -> parser number handling."""
    rec = pax_record("size", "4abc")
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("garbage.txt", 4) + pad512(b"abcd")
    blob += two_zero_blocks()
    return write_sample("s14_non_numeric_size.tar", blob), rec


def s15_hidden_entry_attempt():
    """
    ustar size of main entry = 0, pax size = 512. Body region of 512
    bytes actually contains a full forged ustar header ('forged.txt').
    If pax size is honored for consumption, the forged header is eaten
    as data; if the boundary is mis-managed it may surface as an entry.
    """
    forged = ustar_header("forged.txt", 4) + pad512(b"evil")
    assert len(forged) == 1024          # forged header + its padded body
    rec = pax_record("size", "1024")
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("carrier.txt", 0) + forged
    blob += ustar_header("legit_after.txt", 1) + pad512(b"l")
    blob += two_zero_blocks()
    return write_sample("s15_hidden_entry.tar", blob), rec


def main():
    os.makedirs(OUT, exist_ok=True)
    funcs = [v for k, v in sorted(globals().items())
             if k.startswith("s") and callable(v)]
    for fn in funcs:
        fn()


if __name__ == "__main__":
    main()
