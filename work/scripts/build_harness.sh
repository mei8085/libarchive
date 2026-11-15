#!/bin/bash
# Build two harness variants against the locally built libarchive.
set -e
ROOT=/srv/fb2/mei8085/0070-libarchive-5-c88eda7f
BUILD=$ROOT/work/build
OUT=$ROOT/work/scripts

cc -g -O0 -I"$ROOT/libarchive" \
   "$OUT/tar_harness.c" \
   "$BUILD/libarchive/libarchive.a" \
   -lz -lbz2 -llzma -lzstd -llz4 -lcrypto -lacl -lext2fs -lc \
   -o "$OUT/harness" 2>/dev/null || \
cc -g -O0 -I"$ROOT/libarchive" \
   "$OUT/tar_harness.c" \
   "$BUILD/libarchive/libarchive.a" \
   -lz -lbz2 -llzma -lcrypto -lc \
   -o "$OUT/harness"

# Sanitizer build for out-of-bounds / UB detection on the same inputs.
cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
   -I"$ROOT/libarchive" \
   "$OUT/tar_harness.c" \
   "$BUILD/libarchive/libarchive.a" \
   -lz -lbz2 -llzma -lcrypto -lc \
   -o "$OUT/harness_asan"

echo built:
ls -la "$OUT/harness" "$OUT/harness_asan"
