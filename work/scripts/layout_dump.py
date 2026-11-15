#!/usr/bin/env python3
"""Emit a compact byte-layout description for each crafted sample."""
import os
import glob

SAMP = "/srv/fb2/mei8085/0070-libarchive-5-c88eda7f/work/samples"


def octal(b, off, n):
    s = b[off:off + n].strip(b"\x00 ")
    try:
        return int(s, 8) if s else 0
    except ValueError:
        return None


def describe(path):
    b = open(path, "rb").read()
    out = ["file=%s (%d bytes)" % (os.path.basename(path), len(b))]
    off = 0
    idx = 0
    while off + 512 <= len(b):
        block = b[off:off + 512]
        if block == b"\x00" * 512:
            out.append("  +%-8d NULL block (end marker)" % off)
            off += 512
            idx += 1
            continue
        name = block[0:100].rstrip(b"\x00").decode("latin1")
        size = octal(block, 124, 12)
        tf = chr(block[156])
        magic = block[257:263]
        body_end = off + 512 + (size or 0)
        pad = (512 - (size or 0) % 512) % 512
        nxt = body_end + pad
        out.append("  +%-8d hdr[%d] type=%r name=%-22r ustar_size=%s magic=%r"
                   % (off, idx, tf, name[:22], size, magic))
        if size:
            out.append("  +%-8d   body (%d B) -> block end +%d"
                       % (off + 512, size, nxt))
            # peek pax records
            if tf in ("x", "g", "X"):
                p = off + 512
                end = min(p + min(size, 400), len(b))
                seg = b[p:end].split(b"\n")
                for rec in seg[:4]:
                    if rec:
                        out.append("             rec: %r" % rec[:60])
        off = nxt
        idx += 1
        if idx > 12:
            out.append("  ...")
            break
    return "\n".join(out)


for p in sorted(glob.glob(os.path.join(SAMP, "s*.tar"))):
    print(describe(p))
    print()
