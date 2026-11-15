#!/usr/bin/env python3
"""Focused follow-up probes derived from the code review."""
import os
import sys
sys.path.insert(0, "/srv/fb2/mei8085/0070-libarchive-5-c88eda7f/work/scripts")
from gen_samples import (ustar_header, pax_record, pax_header, pad512,
                         two_zero_blocks, OUT)


def s16_good_then_bad():
    """
    Record 1 is a VALID path override; record 2 has a declared length
    that exceeds the body. Does the valid path survive and get applied
    to the ustar entry after the WARN?
    """
    r1 = pax_record("path", "attacker_controlled_name.txt")
    r2 = pax_record("size", "1", declared_len=999)
    recs = r1 + r2
    body = pad512(recs)
    blob = pax_header(recs) + body
    blob += ustar_header("innocent.txt", 4) + pad512(b"data")
    blob += two_zero_blocks()
    p = os.path.join(OUT, "s16_good_then_bad.tar")
    open(p, "wb").write(blob)
    print("wrote", p, len(blob), "r1=%r r2=%r" % (r1, r2))


def s17_bad_then_good():
    """Malformed first record, valid second record: is the second ever parsed?"""
    r1 = pax_record("path", "ignored_name.txt", declared_len=999)
    r2 = pax_record("size", "2")
    recs = r1 + r2
    body = pad512(recs)
    blob = pax_header(recs) + body
    blob += ustar_header("real.txt", 2) + pad512(b"ok")
    blob += two_zero_blocks()
    p = os.path.join(OUT, "s17_bad_then_good.tar")
    open(p, "wb").write(blob)
    print("wrote", p, len(blob))


def s18_value_len_underflow():
    """
    Declared length exactly covers "len name=" but leaves no room for
    value or newline:  e.g. '8 path=X' where the true bytes are longer.
    Look for value_length underflow (size_t wrap) in the parser.
    """
    real = pax_record("path", "zzz")        # e.g. 12 bytes
    n = len((" path=").encode()) + len(b"8")  # prologue length
    rec = str(n).encode() + real[len(str(n)):]
    body = pad512(rec)
    blob = pax_header(rec) + body
    blob += ustar_header("u.txt", 1) + pad512(b"x")
    blob += two_zero_blocks()
    p = os.path.join(OUT, "s18_value_underflow.tar")
    open(p, "wb").write(blob)
    print("wrote", p, len(blob), "rec=%r" % rec)


def s19_size_attr_mismatch_framing():
    """
    Correct framing but pax size=3 while the ustar body is 8 bytes AND
    no padding reconciliation exists: place next header at ustar's
    expected position (512) vs pax-driven position; a parser using the
    pax size only for data but ustar size for skipping must still align.
    """
    rec = pax_record("size", "3")
    body = pad512(rec)
    # ustar size 3 -> padded body 512; next header lands at a clean block.
    blob = pax_header(rec) + body
    blob += ustar_header("a.txt", 3) + pad512(b"abc")
    blob += ustar_header("b.txt", 1) + pad512(b"z")
    blob += two_zero_blocks()
    p = os.path.join(OUT, "s19_framing_ok.tar")
    open(p, "wb").write(blob)
    print("wrote", p, len(blob))


if __name__ == "__main__":
    s16_good_then_bad()
    s17_bad_then_good()
    s18_value_len_underflow()
    s19_size_attr_mismatch_framing()
