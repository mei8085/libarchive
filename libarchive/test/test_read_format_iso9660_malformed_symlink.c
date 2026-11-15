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
 * Cross-format symlink target validation for the ISO9660 reader.  A
 * malformed Rock Ridge symlink target must fail only that entry with
 * ARCHIVE_FAILED, must not deliver a target, and must not disturb the
 * reading of the other entries.  Legitimate targets must be delivered
 * byte-for-byte unchanged.
 *
 * Cases: an embedded NUL byte inside an "SL" component, a target longer
 * than the shared 1 MiB limit, and an "SL" record that claims to continue
 * in a record that never arrives.
 *
 * Images are produced with libarchive's own ISO9660 writer (Rock Ridge is
 * enabled by default) and then patched; this keeps the fixture compact
 * while still exercising the real Rock Ridge parser.
 */

static const char iso_target[] = "iso-symlink-target-XYZ";
static const char second_data[] = "hello world";

/* Build an image with one symlink ("link") and one regular file
 * ("second").  'target' may be NULL to use iso_target. */
static void
make_iso(unsigned char *buff, size_t buffsize, size_t *used,
    const char *target)
{
	struct archive *a;
	struct archive_entry *ae;

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_set_format_iso9660(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, used));

	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "link");
	archive_entry_set_mode(ae, AE_IFLNK | 0777);
	archive_entry_set_symlink(ae, target != NULL ? target : iso_target);
	archive_entry_set_size(ae, 0);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);

	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "second");
	archive_entry_set_mode(ae, AE_IFREG | 0644);
	archive_entry_set_size(ae, sizeof(second_data) - 1);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	assertEqualInt(sizeof(second_data) - 1,
	    (int)archive_write_data(a, second_data, sizeof(second_data) - 1));
	archive_entry_free(ae);

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualInt(ARCHIVE_OK, archive_write_free(a));
}

/* Locate the first occurrence of 'needle' in 'haystack'. */
static unsigned char *
find_bytes(unsigned char *haystack, size_t haystack_len,
    const char *needle, size_t needle_len)
{
	size_t i;

	for (i = 0; i + needle_len <= haystack_len; i++) {
		if (memcmp(haystack + i, needle, needle_len) == 0)
			return (haystack + i);
	}
	return (NULL);
}

/* Locate the "SL" System Use Entry whose component data contains
 * 'target', and return a pointer to the record start. */
static unsigned char *
find_sl_record(unsigned char *img, size_t imgsize, const char *target,
    size_t target_len)
{
	unsigned char *p;
	size_t i = 0;

	p = find_bytes(img, imgsize, target, target_len);
	if (p == NULL)
		return (NULL);
	/* Walk backwards to the nearest 'SL' signature within 64 bytes. */
	while (i < 64 && p - i >= img + 2) {
		if (p[-i - 2] == 'S' && p[-i - 1] == 'L')
			return (p - i - 2);
		i++;
	}
	return (NULL);
}

/* Read the image and record what happened to each entry. */
static void
read_iso(const unsigned char *img, size_t imgsize,
    int *link_result, char *link_target, size_t link_target_size,
    int *second_result)
{
	struct archive_entry *ae;
	struct archive *a;
	char buff[32];
	int r;

	*link_result = *second_result = -1;
	if (link_target_size > 0)
		link_target[0] = '\0';

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_iso9660(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    read_open_memory(a, img, imgsize, 512));

	for (;;) {
		r = archive_read_next_header(a, &ae);
		if (r == ARCHIVE_EOF)
			break;
		if (r == ARCHIVE_FATAL) {
			failure("unexpected fatal error: %s",
			    archive_error_string(a));
			assert(0);
			break;
		}
		if (strcmp(archive_entry_pathname(ae), "link") == 0) {
			*link_result = r;
			if (r == ARCHIVE_OK || r == ARCHIVE_WARN) {
				const char *s = archive_entry_symlink(ae);
				assert(s != NULL);
				if (s != NULL) {
					assert(strlen(s) < link_target_size);
					strcpy(link_target, s);
				}
			} else {
				assert(archive_entry_symlink(ae) == NULL);
			}
		} else if (strcmp(archive_entry_pathname(ae), "second") == 0) {
			*second_result = r;
			assertEqualInt(sizeof(second_data) - 1,
			    (int)archive_read_data(a, buff, sizeof(buff)));
			assertEqualMem(buff, second_data,
			    sizeof(second_data) - 1);
		}
	}

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_iso9660_malformed_symlink)
{
	unsigned char *img;
	size_t imgsize = 4 * 1024 * 1024;
	size_t used = 0;
	int link_result, second_result;
	char link_target[64];
	unsigned char *p;
	char *long_target;

	assert((img = malloc(imgsize)) != NULL);

	/* A valid image: the target comes back unchanged. */
	make_iso(img, imgsize, &used, NULL);
	read_iso(img, used, &link_result, link_target,
	    sizeof(link_target), &second_result);
	assertEqualInt(ARCHIVE_OK, link_result);
	assertEqualString(iso_target, link_target);
	assertEqualInt(sizeof(iso_target) - 1, (int)strlen(link_target));
	assertEqualInt(ARCHIVE_OK, second_result);

	/* Patch a NUL byte into the middle of the SL component data: the
	 * entry must now fail individually. */
	p = find_bytes(img, used, iso_target, sizeof(iso_target) - 1);
	failure("could not locate the symlink target in the ISO image");
	assert(p != NULL);
	if (p != NULL) {
		p[5] = '\0';
		read_iso(img, used, &link_result, link_target,
		    sizeof(link_target), &second_result);
		assertEqualInt(ARCHIVE_FAILED, link_result);
		assertEqualInt(ARCHIVE_OK, second_result);
	}

	/* Mark the terminal SL record as continuing; the continuation
	 * never arrives, so the target is truncated. */
	make_iso(img, imgsize, &used, NULL);
	p = find_sl_record(img, used, iso_target, sizeof(iso_target) - 1);
	failure("could not locate the SL record in the ISO image");
	assert(p != NULL);
	if (p != NULL) {
		/* p[0..1] = "SL", p[2] = length, p[3] = version,
		 * p[4] = flags (0 = last record), p[5] = first component
		 * flag.  Set both to "continues". */
		p[4] = 1;
		p[5] |= 0x01;
		read_iso(img, used, &link_result, link_target,
		    sizeof(link_target), &second_result);
		assertEqualInt(ARCHIVE_FAILED, link_result);
		assertEqualInt(ARCHIVE_OK, second_result);
	}

	/* A target one byte past the shared limit must be rejected. */
	/* NUL-terminated for the writer API; the target itself is
	 * one byte longer than the shared limit. */
	long_target = malloc(SYMLINK_TARGET_MAX + 2);
	assert(long_target != NULL);
	memset(long_target, 'A', SYMLINK_TARGET_MAX + 1);
	long_target[SYMLINK_TARGET_MAX + 1] = '\0';
	make_iso(img, imgsize, &used, long_target);
	read_iso(img, used, &link_result, link_target,
	    sizeof(link_target), &second_result);
	assertEqualInt(ARCHIVE_FAILED, link_result);
	assertEqualInt(ARCHIVE_OK, second_result);
	free(long_target);

	free(img);
}
