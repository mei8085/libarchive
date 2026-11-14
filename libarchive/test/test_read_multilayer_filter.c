/*-
 * Copyright (c) 2026
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

/*
 * Resource handling for multi-layer (nested) compression filter
 * chains.  Every layer that fails while being probed, initialized or
 * decoded must tear its own resources down exactly once, and a failure
 * in one layer must terminate the read instead of leaving a half-dead
 * chain that keeps being read.  Independently reopened archives must
 * not inherit any state from the failed one.
 */

static const char *test_payload = "multi-layer filter payload\n";

/*
 * Build a ustar archive wrapped in "gzip_layers" gzip streams.
 * Returns the number of bytes written, or 0 on failure.
 */
static size_t
build_nested_gzip(char *buff, size_t buffsize, int gzip_layers)
{
	struct archive *w;
	struct archive_entry *ae;
	size_t used = 0;
	int i;

	assert((w = archive_write_new()) != NULL);
	assertEqualIntA(w, ARCHIVE_OK,
	    archive_write_set_format_ustar(w));
	for (i = 0; i < gzip_layers; i++) {
		if (archive_write_add_filter_gzip(w) != ARCHIVE_OK) {
			skipping("gzip writing not supported");
			assertEqualInt(ARCHIVE_OK, archive_write_free(w));
			return (0);
		}
	}
	assertEqualIntA(w, ARCHIVE_OK,
	    archive_write_open_memory(w, buff, buffsize, &used));
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "nested.txt");
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_size(ae, strlen(test_payload));
	assertEqualIntA(w, ARCHIVE_OK, archive_write_header(w, ae));
	assertEqualIntA(w, (int)strlen(test_payload),
	    archive_write_data(w, test_payload, strlen(test_payload)));
	archive_entry_free(ae);
	assertEqualIntA(w, ARCHIVE_OK, archive_write_close(w));
	assertEqualInt(ARCHIVE_OK, archive_write_free(w));
	return (used);
}

/*
 * Fully drain one independent read handle over the given buffer and
 * release it again.  Whatever the (damaged) input does, the handle
 * must come down cleanly: every established layer is closed exactly
 * once and no read reaches a layer that was already torn down.  The
 * return value merely reports whether a complete payload came out.
 */
static int
drain_handle(const char *tag, const char *buff, size_t size)
{
	struct archive *a;
	struct archive_entry *ae;
	char out[256];
	ssize_t n;
	size_t total = 0;
	int r, decoded = 0;

	(void)tag; /* Used in failure() messages below. */
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));

	r = archive_read_open_memory(a, buff, size);
	if (r != ARCHIVE_OK) {
		failure("%s: open failure without error message", tag);
		assert(NULL != archive_error_string(a));
		/* Closing a failed chain must not touch any resource twice. */
		assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
		/* A second close is a harmless no-op. */
		assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
		assertEqualInt(ARCHIVE_OK, archive_read_free(a));
		return (0);
	}

	while ((r = archive_read_next_header(a, &ae)) == ARCHIVE_OK) {
		while ((n = archive_read_data(a, out, sizeof(out))) > 0) {
			if (total < sizeof(out))
				total += (size_t)n;
		}
		if (n < 0) {
			failure("%s: data failure without error message", tag);
			assert(NULL != archive_error_string(a));
			break;
		}
	}
	if (r == ARCHIVE_EOF) {
		decoded = (total == strlen(test_payload) &&
		    memcmp(out, test_payload, strlen(test_payload)) == 0);
	}

	/* Whether or not decoding failed, teardown stays balanced. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
	return (decoded);
}

/*
 * Read a (possibly damaged) archive with a fresh, independent handle
 * and verify the outcome.  A successful read must return the exact
 * payload; a failed read must leave an error string behind.
 */
static void
read_nested(const char *tag, const char *buff, size_t size, int expect_ok)
{
	int decoded = drain_handle(tag, buff, size);

	if (expect_ok) {
		failure("%s: valid input was not decoded unchanged", tag);
		assertEqualInt(1, decoded);
	} else {
		failure("%s: damaged input was unexpectedly accepted", tag);
		assertEqualInt(0, decoded);
	}
}

/*
 * A legal, moderately deep gzip chain must be decoded unchanged.
 */
DEFINE_TEST(test_read_multilayer_filter_valid)
{
	char *buff;
	size_t buffsize, used;
	struct archive *a;

	if (archive_zlib_version() == NULL) {
		skipping("zlib not available");
		return;
	}

	buffsize = (size_t)1 << 20;
	assert((buff = malloc(buffsize)) != NULL);
	used = build_nested_gzip(buff, buffsize, 6);
	if (used == 0) {
		free(buff);
		return;
	}

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_memory(a, buff, used));
	/* Six gzip filters plus the client none filter. */
	assertEqualInt(7, archive_filter_count(a));
	assertEqualInt(ARCHIVE_FILTER_GZIP,
	    archive_filter_code(a, 0));
	assertEqualInt(ARCHIVE_FILTER_NONE,
	    archive_filter_code(a, archive_filter_count(a) - 1));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	/* The decoded entry content and order must be unchanged. */
	read_nested("valid", buff, used, 1);
	free(buff);
}

/*
 * A mixed gzip/xz chain exercises the unified teardown across two
 * different filter implementations at the same time.
 */
DEFINE_TEST(test_read_multilayer_filter_mixed_gzip_xz)
{
	char *buff, *damaged;
	size_t buffsize, used;
	struct archive *w;
	struct archive_entry *ae;
	struct archive *a;
	int i;

	if (archive_zlib_version() == NULL) {
		skipping("zlib not available");
		return;
	}
	if (archive_liblzma_version() == NULL) {
		skipping("liblzma not available");
		return;
	}

	buffsize = (size_t)1 << 20;
	assert((buff = malloc(buffsize)) != NULL);
	assert((damaged = malloc(buffsize)) != NULL);

	/* Outer gzip layers around an inner xz layer. */
	used = 0;
	assert((w = archive_write_new()) != NULL);
	assertEqualIntA(w, ARCHIVE_OK, archive_write_set_format_ustar(w));
	assertEqualIntA(w, ARCHIVE_OK, archive_write_add_filter_xz(w));
	for (i = 0; i < 3; i++)
		assertEqualIntA(w, ARCHIVE_OK,
		    archive_write_add_filter_gzip(w));
	assertEqualIntA(w, ARCHIVE_OK,
	    archive_write_open_memory(w, buff, buffsize, &used));
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "nested.txt");
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_size(ae, strlen(test_payload));
	assertEqualIntA(w, ARCHIVE_OK, archive_write_header(w, ae));
	assertEqualIntA(w, (int)strlen(test_payload),
	    archive_write_data(w, test_payload, strlen(test_payload)));
	archive_entry_free(ae);
	assertEqualIntA(w, ARCHIVE_OK, archive_write_close(w));
	assertEqualInt(ARCHIVE_OK, archive_write_free(w));

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_memory(a, buff, used));
	/* Three gzip, one xz and the client none filter.  Read-side
	 * index 0 is the innermost decoder (xz), increasing indices walk
	 * outwards toward the client none filter. */
	assertEqualInt(5, archive_filter_count(a));
	assertEqualInt(ARCHIVE_FILTER_XZ, archive_filter_code(a, 0));
	assertEqualInt(ARCHIVE_FILTER_GZIP, archive_filter_code(a, 3));
	assertEqualInt(ARCHIVE_FILTER_NONE, archive_filter_code(a, 4));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	read_nested("mixed-valid", buff, used, 1);

	/* Damage every byte: teardown must stay balanced across both
	 * filter types, and a following intact read must still work. */
	for (i = 0; i < (int)used; i++) {
		memcpy(damaged, buff, used);
		damaged[i] ^= 0xFF;
		(void)drain_handle("mixed-fuzz", damaged, used);
	}
	read_nested("mixed-reopen", buff, used, 1);

	free(buff);
	free(damaged);
}

/*
 * Chains deeper than MAX_NUMBER_FILTERS must be rejected while the
 * chain is still being probed instead of growing without bound.
 */
DEFINE_TEST(test_read_multilayer_filter_too_deep)
{
	char *buff;
	size_t buffsize, used;
	struct archive *a;
	int r;

	if (archive_zlib_version() == NULL) {
		skipping("zlib not available");
		return;
	}

	buffsize = (size_t)1 << 20;
	assert((buff = malloc(buffsize)) != NULL);
	used = build_nested_gzip(buff, buffsize, 26);
	if (used == 0) {
		free(buff);
		return;
	}

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	r = archive_read_open_memory(a, buff, used);
	assertEqualInt(ARCHIVE_FATAL, r);
	failure("bounded rejection must explain itself");
	assert(NULL != archive_error_string(a));
	/* The chain was torn down during the failed open. */
	assertEqualInt(0, archive_filter_count(a));
	/* Releasing the failed handle must not free anything twice. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
	free(buff);
}

/*
 * A malformed layer (truncation or corruption) terminates the read,
 * and a subsequently opened, independent archive still works: no
 * filter state is inherited from the failed handle.
 */
DEFINE_TEST(test_read_multilayer_filter_failure_isolation)
{
	char *buff, *damaged;
	size_t buffsize, used;
	int i;

	if (archive_zlib_version() == NULL) {
		skipping("zlib not available");
		return;
	}

	buffsize = (size_t)1 << 20;
	assert((buff = malloc(buffsize)) != NULL);
	assert((damaged = malloc(buffsize)) != NULL);
	used = build_nested_gzip(buff, buffsize, 5);
	if (used == 0) {
		free(buff);
		free(damaged);
		return;
	}

	/* Truncated stream: the innermost layers cannot be completed. */
	memcpy(damaged, buff, used);
	read_nested("truncated", damaged, used - 24, 0);

	/* Corrupt a byte in the middle of the compressed payload: the
	 * output can no longer match even if the decoder itself does not
	 * flag the byte. */
	memcpy(damaged, buff, used);
	damaged[used / 2] ^= 0xA5;
	read_nested("corrupted", damaged, used, 0);

	/* Damage every single byte offset in turn.  Whether a particular
	 * flip is fatal, changes the output or is in an ignored header
	 * field, each attempt must fail cleanly (or decode correctly) and
	 * leave the next attempt completely unaffected. */
	for (i = 0; i < (int)used; i++) {
		memcpy(damaged, buff, used);
		damaged[i] ^= 0xFF;
		(void)drain_handle("byte-fuzz", damaged, used);
	}

	/* A brand new handle over the intact data is fully independent:
	 * it never inherits filter state from any failed handle above. */
	for (i = 0; i < 3; i++)
		read_nested("reopen", buff, used, 1);

	free(buff);
	free(damaged);
}
