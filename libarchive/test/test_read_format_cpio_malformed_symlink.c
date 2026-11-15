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
 * Cross-format symlink target validation for the cpio reader: a malformed
 * symlink target (embedded NUL byte, empty, or over the shared 1 MiB
 * limit) must fail only that entry with ARCHIVE_FAILED, must not deliver
 * a target, and must not disturb the reading of subsequent entries.  A
 * legitimate target must be delivered byte-for-byte unchanged.
 *
 * The archive is built in memory (newc format) so that targets containing
 * NUL bytes can be represented exactly, and every case is read with a
 * tiny block size so that the read-ahead buffer boundary is exercised.
 */

struct cbuf {
	char *d;
	size_t len;
	size_t cap;
};

static void
cb_put(struct cbuf *b, const void *p, size_t n)
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

/* Append one newc entry: header, NUL-terminated name with padding, then
 * the entry body with padding. */
static void
cb_add_entry(struct cbuf *b, const char *name, unsigned mode,
    const void *data, size_t size)
{
	char header[111];
	size_t namesize = strlen(name) + 1;
	size_t pad;
	int hlen;

	hlen = snprintf(header, sizeof(header),
	    "070701"	/* magic */
	    "%08x"	/* c_ino */
	    "%08x"	/* c_mode */
	    "%08x"	/* c_uid */
	    "%08x"	/* c_gid */
	    "%08x"	/* c_nlink */
	    "%08x"	/* c_mtime */
	    "%08x"	/* c_filesize */
	    "%08x"	/* c_devmajor */
	    "%08x"	/* c_devminor */
	    "%08x"	/* c_rdevmajor */
	    "%08x"	/* c_rdevminor */
	    "%08x"	/* c_namesize */
	    "%08x",	/* c_check */
	    1, mode, 0, 0, 1, 0, (unsigned)size, 0, 0, 0, 0,
	    (unsigned)namesize, 0);
	assertEqualInt(110, hlen);
	cb_put(b, header, 110);
	cb_put(b, name, namesize);
	/* Pad header + name to a multiple of 4 bytes. */
	pad = (4 - ((110 + namesize) & 3)) & 3;
	cb_put(b, "\0\0\0", pad);
	if (size > 0)
		cb_put(b, data, size);
	/* Pad file data to a multiple of 4 bytes. */
	pad = (4 - (size & 3)) & 3;
	cb_put(b, "\0\0\0", pad);
}

DEFINE_TEST(test_read_format_cpio_malformed_symlink)
{
	static const char good_target[] = "target-file";
	static const char bad_nul_target[] = { 'a', 'b', 'c', '\0',
	    'd', 'e', 'f' };
	static const char second_data[] = "hello world";
	struct archive_entry *ae;
	struct archive *a;
	struct cbuf b = { NULL, 0, 0 };
	char *long_target;
	char buff[32];
	const char *err;

	/* An over-long symlink target: one byte past the shared limit. */
	long_target = malloc(SYMLINK_TARGET_MAX + 1);
	assert(long_target != NULL);
	memset(long_target, 'A', SYMLINK_TARGET_MAX + 1);

	cb_add_entry(&b, "good", 0120777, good_target,
	    sizeof(good_target) - 1);
	cb_add_entry(&b, "bad-nul", 0120777, bad_nul_target,
	    sizeof(bad_nul_target));
	cb_add_entry(&b, "bad-empty", 0120777, NULL, 0);
	cb_add_entry(&b, "bad-long", 0120777, long_target,
	    SYMLINK_TARGET_MAX + 1);
	cb_add_entry(&b, "second", 0100644, second_data,
	    sizeof(second_data) - 1);
	cb_add_entry(&b, "TRAILER!!!", 0, NULL, 0);

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_cpio(a));
	/* A small block size exercises the read-ahead buffer boundary. */
	assertEqualIntA(a, ARCHIVE_OK,
	    read_open_memory(a, b.d, b.len, 13));

	/* A valid target is delivered byte-for-byte. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("good", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));
	assertEqualString(good_target, archive_entry_symlink(ae));

	/* Embedded NUL byte: entry fails, no target is delivered. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("bad-nul", archive_entry_pathname(ae));
	assert(archive_entry_symlink(ae) == NULL);
	err = archive_error_string(a);
	failure("error should mention the embedded NUL byte: %s",
	    err != NULL ? err : "(null)");
	assert(err != NULL && strstr(err, "embedded NUL") != NULL);

	/* Empty target: entry fails. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("bad-empty", archive_entry_pathname(ae));
	assert(archive_entry_symlink(ae) == NULL);
	err = archive_error_string(a);
	failure("error should mention the empty target: %s",
	    err != NULL ? err : "(null)");
	assert(err != NULL && strstr(err, "empty") != NULL);

	/* Over-long target: entry fails. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualString("bad-long", archive_entry_pathname(ae));
	assert(archive_entry_symlink(ae) == NULL);
	err = archive_error_string(a);
	failure("error should mention the excessive length: %s",
	    err != NULL ? err : "(null)");
	assert(err != NULL && strstr(err, "too long") != NULL);

	/* The entry after the malformed ones reads cleanly. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("second", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(sizeof(second_data) - 1,
	    (int)archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, second_data, sizeof(second_data) - 1);

	/* The trailer still ends the archive. */
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	free(b.d);
	free(long_target);
}
