#!/usr/bin/env python3
"""
Boundary-desync probes: pax size vs ustar size crossing 512-block edges.
The on-disk framing is laid out according to the ustar size (the value
physically in the header). If a parser drives consumption purely from
the pax size, the two boundaries diverge here.
"""
import os
import sys
sys.path.insert(0, "/srv/fb2/mei8085/0070-libarchive-5-c88eda7f/work/scripts")
from gen_samples import (ustar_header, pax_record, pax_header, pad512,
                         two_zero_blocks, OUT)


def s22_pax_zero_ustar_513():
    """
    ustar size=513 -> physical body region = 1024 bytes (513 data + 511 pad).
    pax size=0     -> a pax-trusting parser consumes 0 data + 0 padding.
    First 512 bytes of the physical region hold a FORGED ustar header
    with a valid checksum. Then a real trailing entry.
    """
    forged_hdr = ustar_header("forged_spurious.txt", 4)
    data = forged_hdr + b"X"                    # 513 physical data bytes
    assert len(data) == 513
    body_region = pad512(data)                  # -> 1024 bytes on disk
    assert len(body_region) == 1024

    rec = pax_record("size", "0")
    xbody = pad512(rec)
    blob = pax_header(rec) + xbody
    blob += ustar_header("carrier.txt", 513) + body_region
    blob += ustar_header("tail_real.txt", 2) + pad512(b"zz")
    blob += two_zero_blocks()
    p = os.path.join(OUT, "s22_desync_pax0_ustar513.tar")
    open(p, "wb").write(blob)
    print("wrote", p, len(blob))


def s23_pax_big_ustar_zero():
    """
    ustar size=0   -> physical body region absent.
    pax size=1024  -> pax-trusting parser consumes the following 1024
    bytes (which contain a real header + body) as if they were data,
    hiding the real entry.
    """
    rec = pax_record("size", "1024")
    xbody = pad512(rec)
    hidden = ustar_header("hidden_real.txt", 4) + pad512(b"seed")  # 1024 B
    assert len(hidden) == 1024
    blob = pax_header(rec) + xbody
    blob += ustar_header("swallower.txt", 0) + hidden
    blob += ustar_header("after.txt", 1) + pad512(b"q")
    blob += two_zero_blocks()
    p = os.path.join(OUT, "s23_desync_pax1024_ustar0.tar")
    open(p, "wb").write(blob)
    print("wrote", p, len(blob))


def s24_pax1_ustar512():
    """Milder desync: ustar 512 (one full block), pax 1."""
    rec = pax_record("size", "1")
    xbody = pad512(rec)
    forged = ustar_header("forged_mild.txt", 1)
    region = pad512(forged + b"X" * (512 - len(forged)))  # exactly 512 bytes
    blob = pax_header(rec) + xbody
    blob += ustar_header("mild_carrier.txt", 512) + region
    blob += ustar_header("mild_tail.txt", 1) + pad512(b"t")
    blob += two_zero_blocks()
    p = os.path.join(OUT, "s24_desync_pax1_ustar512.tar")
    open(p, "wb").write(blob)
    print("wrote", p, len(blob))


if __name__ == "__main__":
    s22_pax_zero_ustar_513()
    s23_pax_big_ustar_zero()
    s24_pax1_ustar512()
