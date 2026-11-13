/*-
 * Copyright (c) 2026 The libarchive authors.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Verify the controlled format fallback: when more than one format
 * bids on a stream and the winning format fails to read the first
 * entry, the runner-up format gets exactly one retry, and only if
 * the stream can still be rewound to where the failed attempt began.
 *
 * The test archives below all start with the 8-byte ar signature
 * "!<arch>\n" (so ar bids 64 and wins) while their first 512 bytes
 * also form a valid old-style tar header (so tar bids 48+2=50 and
 * becomes the runner-up).  The ar member header that would follow
 * the signature is deliberately malformed, so the ar reader always
 * fails on the first entry.
 */

#include "test.h"

/*
 * Fill 512 bytes with a valid old-style (v7) tar header for a
 * regular file.  When ustar_magic is non-zero, a POSIX ustar
 * magic/version is included as well.
 */
static void
make_tar_header(unsigned char *h, const char *name, unsigned long size,
    char typeflag, int ustar_magic)
{
	unsigned int sum;
	int i;

	memset(h, 0, 512);
	strncpy((char *)h + 0, name, 100);		/* name */
	snprintf((char *)h + 100, 8, "%07o", 0644);	/* mode */
	snprintf((char *)h + 108, 8, "%07o", 0);	/* uid */
	snprintf((char *)h + 116, 8, "%07o", 0);	/* gid */
	snprintf((char *)h + 124, 12, "%011lo", size);	/* size */
	snprintf((char *)h + 136, 12, "%011lo", (unsigned long)0); /* mtime */
	memset(h + 148, ' ', 8);			/* checksum placeholder */
	h[156] = typeflag;				/* typeflag */
	if (ustar_magic) {
		memcpy(h + 257, "ustar\0", 6);
		memcpy(h + 263, "00", 2);
	}
	sum = 0;
	for (i = 0; i < 512; i++)
		sum += h[i];
	snprintf((char *)h + 148, 7, "%06o", sum);
	h[154] = '\0';
	h[155] = ' ';
}

/*
 * Archive that is simultaneously:
 *  - an ar archive (starts with "!<arch>\n") whose first member
 *    header is malformed (ar fails to read the first entry), and
 *  - an old-style tar archive with one 4-byte entry named
 *    "!<arch>\n" followed by the usual zero blocks.
 */
static void
make_ambiguous_archive(unsigned char *buff, size_t *len)
{
	memset(buff, 0, 2048);
	make_tar_header(buff, "!<arch>\n", 4, '0', 0);
	memcpy(buff + 512, "data", 4);
	*len = 2048;
}

DEFINE_TEST(test_read_format_fallback_succeeds)
{
	unsigned char buff[2048];
	size_t len;
	struct archive *a;
	struct archive_entry *ae;
	char data[16];

	make_ambiguous_archive(buff, &len);

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_memory(a, buff, len));

	/*
	 * ar wins the bidding but cannot parse the first entry; the
	 * reader must fall back to tar, which parses it cleanly.
	 */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualInt(ARCHIVE_FORMAT_TAR, archive_format(a));
	assertEqualString("!<arch>\n", archive_entry_pathname(ae));
	assertEqualInt(4, archive_entry_size(ae));

	assertEqualInt(4, archive_read_data(a, data, 4));
	assertEqualMem(data, "data", 4);

	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_free(a));
}

/*
 * Minimal streaming reader without a seek callback: once the ar
 * reader has consumed input, the failed attempt cannot be undone,
 * so no fallback may happen.
 */
struct streaming {
	const unsigned char *data;
	size_t size;
	size_t pos;
};

static la_ssize_t
streaming_read(struct archive *a, void *client_data, const void **block)
{
	struct streaming *s = (struct streaming *)client_data;
	size_t remain = s->size - s->pos;
	size_t chunk = remain > 1024 ? 1024 : remain;

	(void)a; /* UNUSED */
	*block = s->data + s->pos;
	s->pos += chunk;
	return (chunk);
}

DEFINE_TEST(test_read_format_fallback_requires_rewind)
{
	unsigned char buff[2048];
	size_t len;
	struct streaming s;
	struct archive *a;
	struct archive_entry *ae;

	make_ambiguous_archive(buff, &len);
	s.data = buff;
	s.size = len;
	s.pos = 0;

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open(a, &s, NULL, streaming_read, NULL));

	/*
	 * The ar reader consumed input that this non-seekable stream
	 * cannot return to, so the failure must stand.
	 */
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assert(strstr(archive_error_string(a),
	    "Incorrect file header signature") != NULL);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_fallback_rejects_corruption)
{
	unsigned char buff[2048];
	size_t len;
	struct archive *a;
	struct archive_entry *ae;

	make_ambiguous_archive(buff, &len);
	/* Break the tar header checksum: tar no longer bids at all. */
	buff[148] = '8';

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_memory(a, buff, len));

	/*
	 * A damaged header must not be laundered into a successful
	 * read via the fallback: with no credible runner-up, the
	 * original failure is reported.
	 */
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assert(strstr(archive_error_string(a),
	    "Incorrect file header signature") != NULL);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_fallback_failure_restores_error)
{
	unsigned char buff[1024];
	struct archive *a;
	struct archive_entry *ae;

	/*
	 * Ambiguous ar/tar input where the tar fallback also fails:
	 * the tar entry is a pax extended header declaring 4096
	 * bytes of metadata that the archive does not contain.
	 */
	memset(buff, 0, sizeof(buff));
	make_tar_header(buff, "!<arch>\n", 4096, 'x', 0);

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_memory(a, buff, sizeof(buff)));

	/*
	 * Both formats reject the stream.  The reported error must be
	 * the original one from the winning (ar) format, not the
	 * fallback's truncated-input complaint.
	 */
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assert(strstr(archive_error_string(a),
	    "Incorrect file header signature") != NULL);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_fallback_not_after_exposed_entry)
{
	unsigned char buff[712];
	struct archive *a;
	struct archive_entry *ae;

	/*
	 * A valid ustar archive (tar bids highest) whose first entry
	 * is named "!<arch>\n" (so ar also bids and becomes the
	 * runner-up).  The archive is truncated in the middle of the
	 * second header.
	 */
	memset(buff, 0, sizeof(buff));
	make_tar_header(buff, "!<arch>\n", 0, '0', 1);
	memcpy(buff + 512, "partial-header", 14);

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_memory(a, buff, sizeof(buff)));

	/* The first entry is exposed as tar. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("!<arch>\n", archive_entry_pathname(ae));

	/*
	 * The second header is truncated.  Because an entry has
	 * already been exposed, the format choice is final: no
	 * fallback to ar may be attempted.
	 */
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_free(a));
}
