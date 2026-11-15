/*-
 * Copyright (c) 2026 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "test.h"

/* The shared limit enforced by every symlink-capable format reader. */
#define SYMLINK_TARGET_MAX (1024 * 1024)

/*
 * Cross-format symlink target validation for the ZIP reader: a malformed
 * symlink target must fail only that entry with ARCHIVE_FAILED, must not
 * deliver a target, and must not disturb the following entries.  Covered
 * here: an embedded NUL byte, an empty target, an over-long stored target,
 * a target that inflates past the shared 1 MiB limit (a decompression
 * bomb), and a compressed stream that ends before the target is complete.
 * Legitimate targets, stored or deflated, must be delivered byte-for-byte
 * unchanged.
 *
 * The archives are built in memory so that targets containing NUL bytes
 * can be represented exactly.  Every case is exercised with both small
 * and large read blocks, and with both the streaming and the seeking
 * reader, so that chunked decompression and buffer boundaries are covered.
 */

struct zbuf {
	unsigned char *d;
	size_t len;
	size_t cap;
};

static void
zb_put(struct zbuf *b, const void *p, size_t n)
{
	if (b->len + n > b->cap) {
		size_t newcap = b->cap == 0 ? 4096 : b->cap;
		while (newcap < b->len + n)
			newcap *= 2;
		b->d = realloc(b->d, newcap);
		assert(b->d != NULL);
		b->cap = newcap;
	}
	memcpy(b->d + b->len, p, n);
	b->len += n;
}

static void
zb_put16(struct zbuf *b, unsigned v)
{
	unsigned char p[2];
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
	zb_put(b, p, 2);
}

static void
zb_put32(struct zbuf *b, uint32_t v)
{
	unsigned char p[4];
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
	p[2] = (unsigned char)((v >> 16) & 0xff);
	p[3] = (unsigned char)((v >> 24) & 0xff);
	zb_put(b, p, 4);
}

struct zipent {
	const char *name;
	uint32_t mode;		/* Unix mode, in external attributes */
	unsigned compression;	/* 0 = stored, 8 = deflated */
	int length_at_end;	/* sizes only in the data descriptor */
	const void *data;	/* (possibly compressed) entry body */
	size_t csize;		/* compressed size */
	size_t usize;		/* uncompressed size */
	uint32_t crc;		/* CRC32 of the uncompressed data */
	size_t local_offset;
};

/*
 * Write a local file header with an experimental 'xl' extra field
 * carrying the Unix mode, so that the streaming reader recognizes a
 * symlink, followed by the entry body.
 */
static void
zip_add_local(struct zbuf *b, struct zipent *e)
{
	unsigned char xl[11];
	size_t namelen = strlen(e->name);

	e->local_offset = b->len;
	zb_put(b, "PK\003\004", 4);
	zb_put16(b, 20);			/* version needed */
	/* Bit 3 ("streaming"): sizes follow the body in a data descriptor
	 * and must therefore be zero in the local header. */
	zb_put16(b, e->length_at_end ? 8 : 0);
	zb_put16(b, e->compression);
	zb_put16(b, 0);				/* mod time */
	zb_put16(b, 0);				/* mod date */
	zb_put32(b, e->length_at_end ? 0 : e->crc);
	zb_put32(b, e->length_at_end ? 0 : (uint32_t)e->csize);
	zb_put32(b, e->length_at_end ? 0 : (uint32_t)e->usize);
	zb_put16(b, (unsigned)namelen);
	zb_put16(b, (unsigned)sizeof(xl));
	zb_put(b, e->name, namelen);
	xl[0] = 0x78; xl[1] = 0x6c;		/* tag 0x6c78 */
	xl[2] = 7; xl[3] = 0;			/* body size */
	xl[4] = 0x05;				/* bitmap: fields 1 and 4 */
	xl[5] = 20; xl[6] = 3;			/* version made by: Unix */
	/* external file attributes, little-endian (mode << 16) */
	xl[7] = 0;
	xl[8] = 0;
	xl[9] = (unsigned char)(e->mode & 0xff);
	xl[10] = (unsigned char)((e->mode >> 8) & 0xff);
	zb_put(b, xl, sizeof(xl));
	zb_put(b, e->data, e->csize);
	if (e->length_at_end) {
		/* Data descriptor with the real sizes. */
		zb_put(b, "PK\007\010", 4);
		zb_put32(b, e->crc);
		zb_put32(b, (uint32_t)e->csize);
		zb_put32(b, (uint32_t)e->usize);
	}
}

static void
zip_add_central(struct zbuf *cd, struct zipent *e)
{
	size_t namelen = strlen(e->name);

	zb_put(cd, "PK\001\002", 4);
	zb_put16(cd, (3 << 8) | 20);		/* version made by: Unix */
	zb_put16(cd, 20);			/* version needed */
	zb_put16(cd, e->length_at_end ? 8 : 0);	/* flags */
	zb_put16(cd, e->compression);
	zb_put16(cd, 0);			/* mod time */
	zb_put16(cd, 0);			/* mod date */
	zb_put32(cd, e->crc);
	zb_put32(cd, (uint32_t)e->csize);
	zb_put32(cd, (uint32_t)e->usize);
	zb_put16(cd, (unsigned)namelen);
	zb_put16(cd, 0);			/* extra length */
	zb_put16(cd, 0);			/* comment length */
	zb_put16(cd, 0);			/* disk number */
	zb_put16(cd, 0);			/* internal attributes */
	zb_put32(cd, e->mode << 16);		/* external attributes */
	zb_put32(cd, (uint32_t)e->local_offset);
	zb_put(cd, e->name, namelen);
}

static void
zip_assemble(struct zbuf *b, struct zipent *entries, int n)
{
	struct zbuf cd = { NULL, 0, 0 };
	size_t cd_offset;
	int i;

	for (i = 0; i < n; i++) {
		zip_add_local(b, &entries[i]);
		zip_add_central(&cd, &entries[i]);
	}
	cd_offset = b->len;
	zb_put(b, cd.d, cd.len);
	zb_put(b, "PK\005\006", 4);
	zb_put16(b, 0);				/* disk number */
	zb_put16(b, 0);				/* central dir disk */
	zb_put16(b, (unsigned)n);		/* entries on this disk */
	zb_put16(b, (unsigned)n);		/* entries total */
	zb_put32(b, (uint32_t)cd.len);
	zb_put32(b, (uint32_t)cd_offset);
	zb_put16(b, 0);				/* comment length */
	free(cd.d);
}

/* Raw deflate stream for "target-file". */
static const unsigned char deflate_target_file[] = {
	0x2b,0x49,0x2c,0x4a,0x4f,0x2d,0xd1,0x4d,0xcb,0xcc,0x49,0x05,
	0x00,
};

/* Raw deflate stream for "ab\0cdef": inflates to a target with an
 * embedded NUL byte. */
static const unsigned char deflate_nul[] = {
	0x4b,0x4c,0x62,0x48,0x4e,0x49,0x4d,0x03,0x00,
};

/* Raw deflate stream truncated to 7 of its 13 bytes; the complete
 * target cannot be produced. */
static const unsigned char deflate_truncated[] = {
	0x2b,0x49,0x2c,0x4a,0x4f,0x2d,0xd1,
};

/* Raw deflate stream for 1048577 'A' bytes (1034 bytes compressed): it
 * inflates one byte past the shared symlink target limit, so it must be
 * rejected as a decompression bomb rather than silently truncated. */
static const unsigned char deflate_bomb[] = {
	0xed,0xc1,0x31,0x01,0x00,0x00,0x00,0xc2,0xa0,0x6c,0xeb,0x5f,
	0xca,0x10,0xbe,0x40,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x9c,0x06,
};

/* Verify a malformed entry failed and delivered no target. */
static void
assert_rejected(struct archive *a, struct archive_entry *ae,
    const char *name, const char *reason)
{
	const char *err;

	(void)ae;
	assert(archive_entry_symlink(ae) == NULL);
	err = archive_error_string(a);
	failure("%s: error should mention %s: %s", name, reason,
	    err != NULL ? err : "(null)");
	assert(err != NULL && strstr(err, reason) != NULL);
}

/* Stored targets: valid, embedded NUL, empty, over-long. */
static void
verify_stored(const unsigned char *img, size_t imgsize, int seekable,
    size_t block)
{
	static const char good_target[] = "target-file";
	static const char second_data[] = "hello world";
	struct archive_entry *ae;
	struct archive *a;
	char buff[32];

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_zip(a));
	if (seekable)
		assertEqualIntA(a, ARCHIVE_OK,
		    read_open_memory_seek(a, img, imgsize, block));
	else
		assertEqualIntA(a, ARCHIVE_OK,
		    read_open_memory(a, img, imgsize, block));

	/* A valid target is delivered byte-for-byte. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("good", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));
	assertEqualString(good_target, archive_entry_symlink(ae));

	/* Embedded NUL byte. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("bad-nul", archive_entry_pathname(ae));
	assert_rejected(a, ae, "bad-nul", "embedded NUL");

	/* Empty target. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("bad-empty", archive_entry_pathname(ae));
	assert_rejected(a, ae, "bad-empty", "empty");

	/* Over-long target. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("bad-long", archive_entry_pathname(ae));
	assert_rejected(a, ae, "bad-long", "too long");

	/* The entry after the malformed ones reads cleanly. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("second", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(sizeof(second_data) - 1,
	    (int)archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, second_data, sizeof(second_data) - 1);
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/* Deflated targets: valid, embedded NUL, truncated stream, bomb. */
static void
verify_deflated(const unsigned char *img, size_t imgsize, int seekable,
    size_t block)
{
	static const char zlink_target[] = "target-file";
	static const char tail_data[] = "hello";
	struct archive_entry *ae;
	struct archive *a;
	char buff[32];

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_zip(a));
	if (seekable)
		assertEqualIntA(a, ARCHIVE_OK,
		    read_open_memory_seek(a, img, imgsize, block));
	else
		assertEqualIntA(a, ARCHIVE_OK,
		    read_open_memory(a, img, imgsize, block));

	/* A valid compressed target is delivered unchanged. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("zlink", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));
	assertEqualString(zlink_target, archive_entry_symlink(ae));

	/* An embedded NUL survives decompression and is rejected. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("znul", archive_entry_pathname(ae));
	assert_rejected(a, ae, "znul", "embedded NUL");

	/* A stream that ends before the target is complete. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("zshort", archive_entry_pathname(ae));
	assert_rejected(a, ae, "zshort", "truncated");

	/* A decompression bomb. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("zbomb", archive_entry_pathname(ae));
	assert_rejected(a, ae, "zbomb", "too long");

	/* Following entries are unaffected. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("tail", archive_entry_pathname(ae));
	assertEqualInt(sizeof(tail_data) - 1,
	    (int)archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, tail_data, sizeof(tail_data) - 1);
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/* Length-at-end targets: the size is only known after the data
 * descriptor, so the target is assembled from the data blocks. */
static void
verify_length_at_end(const unsigned char *img, size_t imgsize, int seekable,
    size_t block)
{
	static const char lae_target[] = "target-file";
	static const char tail_data[] = "hello";
	struct archive_entry *ae;
	struct archive *a;
	char buff[32];

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_zip(a));
	if (seekable)
		assertEqualIntA(a, ARCHIVE_OK,
		    read_open_memory_seek(a, img, imgsize, block));
	else
		assertEqualIntA(a, ARCHIVE_OK,
		    read_open_memory(a, img, imgsize, block));

	/* A valid length-at-end target is delivered unchanged. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("laegood", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));
	assertEqualString(lae_target, archive_entry_symlink(ae));

	/* A length-at-end target that is too long. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("laelong", archive_entry_pathname(ae));
	assert_rejected(a, ae, "laelong", "too long");

	/* Following entries are unaffected. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("laetail", archive_entry_pathname(ae));
	assertEqualInt(sizeof(tail_data) - 1,
	    (int)archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, tail_data, sizeof(tail_data) - 1);
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_zip_malformed_symlink)
{
	static const char good_target[] = "target-file";
	static const char bad_nul_target[] = { 'a', 'b', 'c', '\0',
	    'd', 'e', 'f' };
	static const char second_data[] = "hello world";
	static const size_t blocks[] = { 7, 4096 };
	char *long_target;
	struct zbuf b = { NULL, 0, 0 };
	struct zbuf zb = { NULL, 0, 0 };
	struct zipent entries[5];
	struct zipent zentries[5];
	size_t bi;
	int i;

	/* An over-long stored target: one byte past the shared limit. */
	long_target = malloc(SYMLINK_TARGET_MAX + 1);
	assert(long_target != NULL);
	memset(long_target, 'A', SYMLINK_TARGET_MAX + 1);

	memset(entries, 0, sizeof(entries));
	i = 0;
	entries[i].name = "good";
	entries[i].mode = 0120777;
	entries[i].data = good_target;
	entries[i].csize = entries[i].usize = sizeof(good_target) - 1;
	entries[i].crc = (uint32_t)bitcrc32(0, good_target,
	    sizeof(good_target) - 1);
	i++;
	entries[i].name = "bad-nul";
	entries[i].mode = 0120777;
	entries[i].data = bad_nul_target;
	entries[i].csize = entries[i].usize = sizeof(bad_nul_target);
	entries[i].crc = (uint32_t)bitcrc32(0, bad_nul_target,
	    sizeof(bad_nul_target));
	i++;
	entries[i].name = "bad-empty";
	entries[i].mode = 0120777;
	entries[i].data = "";
	entries[i].csize = entries[i].usize = 0;
	entries[i].crc = (uint32_t)bitcrc32(0, NULL, 0);
	i++;
	entries[i].name = "bad-long";
	entries[i].mode = 0120777;
	entries[i].data = long_target;
	entries[i].csize = entries[i].usize = SYMLINK_TARGET_MAX + 1;
	entries[i].crc = (uint32_t)bitcrc32(0, long_target,
	    SYMLINK_TARGET_MAX + 1);
	i++;
	entries[i].name = "second";
	entries[i].mode = 0100644;
	entries[i].data = second_data;
	entries[i].csize = entries[i].usize = sizeof(second_data) - 1;
	entries[i].crc = (uint32_t)bitcrc32(0, second_data,
	    sizeof(second_data) - 1);
	i++;

	zip_assemble(&b, entries, i);

	for (bi = 0; bi < sizeof(blocks) / sizeof(blocks[0]); bi++) {
		verify_stored(b.d, b.len, 0, blocks[bi]);
		verify_stored(b.d, b.len, 1, blocks[bi]);
	}

	free(b.d);

	/* Deflated symlink targets. */
	if (archive_zlib_version() == NULL) {
		skipping("zlib not available on this platform");
		return;
	}

	memset(zentries, 0, sizeof(zentries));
	i = 0;
	zentries[i].name = "zlink";
	zentries[i].mode = 0120777;
	zentries[i].compression = 8;
	zentries[i].data = deflate_target_file;
	zentries[i].csize = sizeof(deflate_target_file);
	zentries[i].usize = sizeof(good_target) - 1;
	zentries[i].crc = (uint32_t)bitcrc32(0, good_target,
	    sizeof(good_target) - 1);
	i++;
	zentries[i].name = "znul";
	zentries[i].mode = 0120777;
	zentries[i].compression = 8;
	zentries[i].data = deflate_nul;
	zentries[i].csize = sizeof(deflate_nul);
	zentries[i].usize = sizeof(bad_nul_target);
	zentries[i].crc = (uint32_t)bitcrc32(0, bad_nul_target,
	    sizeof(bad_nul_target));
	i++;
	zentries[i].name = "zshort";
	zentries[i].mode = 0120777;
	zentries[i].compression = 8;
	zentries[i].data = deflate_truncated;
	zentries[i].csize = sizeof(deflate_truncated);
	zentries[i].usize = sizeof(good_target) - 1;
	zentries[i].crc = (uint32_t)bitcrc32(0, good_target,
	    sizeof(good_target) - 1);
	i++;
	zentries[i].name = "zbomb";
	zentries[i].mode = 0120777;
	zentries[i].compression = 8;
	zentries[i].data = deflate_bomb;
	zentries[i].csize = sizeof(deflate_bomb);
	zentries[i].usize = SYMLINK_TARGET_MAX + 1;
	zentries[i].crc = 0;
	i++;
	zentries[i].name = "tail";
	zentries[i].mode = 0100644;
	zentries[i].data = "hello";
	zentries[i].csize = zentries[i].usize = 5;
	zentries[i].crc = (uint32_t)bitcrc32(0, "hello", 5);
	i++;

	zip_assemble(&zb, zentries, i);

	for (bi = 0; bi < sizeof(blocks) / sizeof(blocks[0]); bi++) {
		verify_deflated(zb.d, zb.len, 0, blocks[bi]);
		verify_deflated(zb.d, zb.len, 1, blocks[bi]);
	}

	free(zb.d);

	/* Length-at-end symlink targets (data descriptor mode). */
	{
		struct zbuf lb = { NULL, 0, 0 };
		struct zipent lentries[3];

		memset(lentries, 0, sizeof(lentries));
		i = 0;
		lentries[i].name = "laegood";
		lentries[i].mode = 0120777;
		lentries[i].length_at_end = 1;
		lentries[i].data = good_target;
		lentries[i].csize = lentries[i].usize =
		    sizeof(good_target) - 1;
		lentries[i].crc = (uint32_t)bitcrc32(0, good_target,
		    sizeof(good_target) - 1);
		i++;
		lentries[i].name = "laelong";
		lentries[i].mode = 0120777;
		lentries[i].length_at_end = 1;
		lentries[i].data = long_target;
		lentries[i].csize = lentries[i].usize =
		    SYMLINK_TARGET_MAX + 1;
		lentries[i].crc = (uint32_t)bitcrc32(0, long_target,
		    SYMLINK_TARGET_MAX + 1);
		i++;
		lentries[i].name = "laetail";
		lentries[i].mode = 0100644;
		lentries[i].length_at_end = 1;
		lentries[i].data = "hello";
		lentries[i].csize = lentries[i].usize = 5;
		lentries[i].crc = (uint32_t)bitcrc32(0, "hello", 5);
		i++;

		zip_assemble(&lb, lentries, i);
		for (bi = 0; bi < sizeof(blocks) / sizeof(blocks[0]); bi++) {
			verify_length_at_end(lb.d, lb.len, 0, blocks[bi]);
			verify_length_at_end(lb.d, lb.len, 1, blocks[bi]);
		}
		free(lb.d);
	}

	free(long_target);
}
