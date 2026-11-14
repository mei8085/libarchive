/*-
 * Copyright (c) 2026 The libarchive Project
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
 * Integration tests for secure extraction of untrusted archives.
 *
 * Unlike the unit-style test_write_disk_secure* tests, which feed
 * hand-built entries directly to archive_write_disk, these tests build
 * complete archives (tar, cpio, zip) in memory, read them back through
 * archive_read and extract them into a sandbox directory with the
 * ARCHIVE_EXTRACT_SECURE_* options enabled.  This exercises the full
 * path from on-disk archive format to filesystem, verifying that:
 *
 *  - entries with absolute paths or ".." components that would escape
 *    the extraction directory are rejected and pre-existing files
 *    outside the sandbox are left untouched;
 *  - a symlink written by an earlier entry cannot be abused by a later
 *    entry to write outside the sandbox, and neither can a hardlink
 *    whose target lies outside;
 *  - legitimate relative paths, in-sandbox symlinks/hardlinks and
 *    path spellings that normalize to the same in-sandbox location
 *    are all extracted normally;
 *  - extraction of valid entries continues after hostile entries
 *    have been rejected.
 */

#define UMASK 022

/* Format selectors for the entry table below. */
#define FMT_TAR		0x01
#define FMT_CPIO	0x02
#define FMT_ZIP		0x04
#define FMT_ALL		(FMT_TAR | FMT_CPIO | FMT_ZIP)
#define FMT_TAR_CPIO	(FMT_TAR | FMT_CPIO)

struct payload_entry {
	int formats;		/* formats this entry is written to */
	int filetype;		/* AE_IFDIR / AE_IFREG / AE_IFLNK */
	const char *pathname;	/* NULL: use the computed absolute path */
	const char *target;	/* symlink or hardlink target, or NULL */
	const char *data;	/* regular file contents, or NULL */
	int expect;		/* expected archive_write_header() result */
	long ino;		/* cpio hardlink group, 0 = not grouped */
};

/*
 * The archive payload, in archive order.  A single table is used for
 * all three formats; entries tagged with a format subset are skipped
 * for the other formats (zip cannot represent hardlinks).
 *
 * Note on the cpio hardlink entries: cpio has no linkname field, so a
 * hardlink can only name another archive member via a shared
 * (dev, ino) pair.  The evil hardlink "evilhard.txt" is therefore
 * preceded by a member literally named "../outside/victim.txt" in the
 * same inode group; that member is itself a ".." escape and is
 * rejected, and the reader then resolves "evilhard.txt" as a hardlink
 * to the outside name, which must also be rejected.
 */
static const struct payload_entry entries[] = {
	/* Legitimate content inside the sandbox. */
	{ FMT_ALL, AE_IFDIR, "legit", NULL, NULL, ARCHIVE_OK, 0 },
	{ FMT_ALL, AE_IFREG, "legit/hello.txt", NULL, "hello\n",
	    ARCHIVE_OK, 100 },
	/*
	 * Equivalent spellings of in-sandbox paths: the '.' components
	 * normalize away, so these must be accepted exactly like the
	 * plain form "legit/dot.txt" / "legit/lead.txt".
	 */
	{ FMT_ALL, AE_IFREG, "legit/./dot.txt", NULL, "dot\n",
	    ARCHIVE_OK, 0 },
	{ FMT_ALL, AE_IFREG, "./legit/lead.txt", NULL, "lead\n",
	    ARCHIVE_OK, 0 },
	/* A symlink whose target stays inside the sandbox is fine. */
	{ FMT_ALL, AE_IFLNK, "legit/inner_link", "hello.txt", NULL,
	    ARCHIVE_OK, 0 },
	/* A hardlink to a file inside the sandbox is fine. */
	{ FMT_TAR_CPIO, AE_IFREG, "legit/hard.txt", "legit/hello.txt",
	    NULL, ARCHIVE_OK, 100 },
	/* An absolute path outside the sandbox: rejected. */
	{ FMT_ALL, AE_IFREG, NULL, NULL, "ABS-EVIL\n",
	    ARCHIVE_FAILED, 0 },
	/* A ".." component escaping the sandbox: rejected. */
	{ FMT_ALL, AE_IFREG, "../escape1.txt", NULL, "ESC1\n",
	    ARCHIVE_FAILED, 0 },
	/*
	 * The same escape spelled with a detour into the sandbox; it
	 * normalizes to "../escape2.txt" and must get the same verdict
	 * as the plain form above.
	 */
	{ FMT_ALL, AE_IFREG, "legit/../../escape2.txt", NULL, "ESC2\n",
	    ARCHIVE_FAILED, 0 },
	/*
	 * cpio only: first half of the evil hardlink group (see the
	 * comment above the table).  Rejected as a ".." escape.
	 */
	{ FMT_CPIO, AE_IFREG, "../outside/victim.txt", NULL, NULL,
	    ARCHIVE_FAILED, 200 },
	/*
	 * A symlink pointing outside the sandbox may itself be
	 * created (its target is not validated at creation time) ...
	 */
	{ FMT_ALL, AE_IFLNK, "evillink", "../outside", NULL,
	    ARCHIVE_OK, 0 },
	/*
	 * ... but a later entry must not be allowed to borrow that
	 * link to write outside the sandbox.
	 */
	{ FMT_ALL, AE_IFREG, "evillink/payload.txt", NULL, "PAYLOAD\n",
	    ARCHIVE_FAILED, 0 },
	/* A hardlink whose target escapes the sandbox: rejected. */
	{ FMT_TAR_CPIO, AE_IFREG, "evilhard.txt", "../outside/victim.txt",
	    NULL, ARCHIVE_FAILED, 200 },
	/*
	 * After all of the rejections above, ordinary entries must
	 * still be extracted, inside the sandbox.
	 */
	{ FMT_ALL, AE_IFREG, "legit/after.txt", NULL, "after\n",
	    ARCHIVE_OK, 0 },
};

/*
 * Write the payload entries for the given format into a memory buffer.
 * Returns the buffer (caller frees) and its used size.
 */
static void
build_archive(int format, const char *abs_evil_path,
    void **out_buff, size_t *out_used)
{
	struct archive *a;
	struct archive_entry *ae;
	size_t i;

	*out_buff = malloc(256 * 1024);
	assert(*out_buff != NULL);

	assert((a = archive_write_new()) != NULL);
	switch (format) {
	case FMT_TAR:
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_write_set_format_pax_restricted(a));
		break;
	case FMT_CPIO:
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_write_set_format_cpio_newc(a));
		break;
	case FMT_ZIP:
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_write_set_format_zip(a));
		break;
	default:
		assert(0);
	}
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, *out_buff, 256 * 1024, out_used));

	for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
		const struct payload_entry *e = &entries[i];
		const char *pathname;

		if (!(e->formats & format))
			continue;
		pathname = e->pathname != NULL ? e->pathname : abs_evil_path;

		assert((ae = archive_entry_new()) != NULL);
		archive_entry_copy_pathname(ae, pathname);
		archive_entry_set_mode(ae,
		    e->filetype | (e->filetype == AE_IFDIR ? 0755 : 0644));
		if (e->filetype == AE_IFLNK) {
			archive_entry_copy_symlink(ae, e->target);
		} else if (e->target != NULL) {
			archive_entry_copy_hardlink(ae, e->target);
		}
		/* The cpio writer requires an explicit size on every
		 * entry, so set one unconditionally. */
		archive_entry_set_size(ae,
		    e->data != NULL ? (int64_t)strlen(e->data) : 0);
		if (e->ino != 0) {
			/* Group hardlinked members for cpio. */
			archive_entry_set_ino64(ae, e->ino);
			archive_entry_set_nlink(ae, 2);
		}
		assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
		if (e->data != NULL)
			assertEqualInt((int)strlen(e->data),
			    (int)archive_write_data(a, e->data,
				strlen(e->data)));
		archive_entry_free(ae);
	}
	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualInt(ARCHIVE_OK, archive_write_free(a));
}

/*
 * Read the in-memory archive back and extract it with all secure
 * options enabled, checking each entry against its table expectation.
 */
static void
extract_archive(int format, const void *buff, size_t used,
    const char *abs_evil_path)
{
	struct archive *in, *out;
	struct archive_entry *ae;
	size_t i;
	int r;

	assert((in = archive_read_new()) != NULL);
	switch (format) {
	case FMT_TAR:
		assertEqualIntA(in, ARCHIVE_OK,
		    archive_read_support_format_tar(in));
		break;
	case FMT_CPIO:
		assertEqualIntA(in, ARCHIVE_OK,
		    archive_read_support_format_cpio(in));
		break;
	case FMT_ZIP:
		assertEqualIntA(in, ARCHIVE_OK,
		    archive_read_support_format_zip(in));
		break;
	default:
		assert(0);
	}
	assert((out = archive_write_disk_new()) != NULL);
	archive_write_disk_set_options(out,
	    ARCHIVE_EXTRACT_SECURE_SYMLINKS |
	    ARCHIVE_EXTRACT_SECURE_NODOTDOT |
	    ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS);

	assertEqualIntA(in, ARCHIVE_OK,
	    archive_read_open_memory(in, buff, used));

	for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
		const struct payload_entry *e = &entries[i];
		const char *expected_path;

		if (!(e->formats & format))
			continue;
		expected_path =
		    e->pathname != NULL ? e->pathname : abs_evil_path;

		assertEqualIntA(in, ARCHIVE_OK,
		    archive_read_next_header(in, &ae));

		/* The reader must hand us the entry we wrote. */
		if (e->filetype == AE_IFDIR) {
			/* Writers may store dirs with a trailing slash. */
			size_t l = strlen(expected_path);
			assert(archive_entry_pathname(ae) != NULL);
			if (strncmp(expected_path, archive_entry_pathname(ae),
				l) != 0 ||
			    (archive_entry_pathname(ae)[l] != '\0' &&
				strcmp(archive_entry_pathname(ae) + l,
				    "/") != 0)) {
				failure("Dir entry should be stored as '%s/'"
				    " but was '%s'", expected_path,
				    archive_entry_pathname(ae));
				assert(0);
			}
		} else {
			assertEqualString(expected_path,
			    archive_entry_pathname(ae));
		}
		if (e->filetype == AE_IFLNK)
			assertEqualString(e->target,
			    archive_entry_symlink(ae));
		else if (e->target != NULL)
			assertEqualString(e->target,
			    archive_entry_hardlink(ae));

		failure("Entry '%s' should %s be extracted",
		    expected_path,
		    e->expect == ARCHIVE_OK ? "be" : "not");
		r = archive_write_header(out, ae);
		assertEqualInt(e->expect, r);
		if (r == ARCHIVE_OK && e->data != NULL)
			assertEqualInt((int)strlen(e->data),
			    (int)archive_write_data(out, e->data,
				strlen(e->data)));
		archive_write_finish_entry(out);
	}
	assertEqualIntA(in, ARCHIVE_EOF, archive_read_next_header(in, &ae));

	assertEqualIntA(in, ARCHIVE_OK, archive_read_close(in));
	assertEqualInt(ARCHIVE_OK, archive_read_free(in));
	archive_write_close(out);
	assertEqualInt(ARCHIVE_OK, archive_write_free(out));
}

static void
run_extraction_test(int format)
{
	void *buff;
	size_t used;
#ifdef PATH_MAX
	char abs_evil[PATH_MAX * 2];
#else
	char abs_evil[2048];
#endif

	if (!canSymlink()) {
		skipping("Can't test symlinks on this filesystem");
		return;
	}

	/* Start with a known umask. */
	assertUmask(UMASK);

	/*
	 * A directory outside the sandbox holding a pre-existing file
	 * that the archive will try to modify through various paths.
	 */
	assertMakeDir("outside", 0755);
	assertMakeFile("outside/victim.txt", 0644, "original\n");

	/* An absolute path pointing outside the future sandbox. */
	assert(snprintf(abs_evil, sizeof(abs_evil),
	    "%s/outside/abs_evil.txt", testworkdir) > 0);

	build_archive(format, abs_evil, &buff, &used);

	/* The sandbox we extract into. */
	assertMakeDir("extract", 0755);
	assertChdir("extract");
	extract_archive(format, buff, used, abs_evil);
	assertChdir("..");
	free(buff);

	/*
	 * Nothing may have escaped the sandbox: the pre-existing file
	 * is untouched and no new files appeared outside it.
	 */
	assertTextFileContents("original\n", "outside/victim.txt");
	assertFileNotExists("outside/abs_evil.txt");
	assertFileNotExists("outside/payload.txt");
	assertFileNotExists("escape1.txt");
	assertFileNotExists("escape2.txt");
	assertFileNotExists("extract/evilhard.txt");

	/* Legitimate content was restored inside the sandbox. */
	assertIsDir("extract/legit", -1);
	assertTextFileContents("hello\n", "extract/legit/hello.txt");
	assertTextFileContents("dot\n", "extract/legit/dot.txt");
	assertTextFileContents("lead\n", "extract/legit/lead.txt");
	assertIsSymlink("extract/legit/inner_link", "hello.txt", 0);
	if (format != FMT_ZIP) {
		assertIsHardlink("extract/legit/hello.txt",
		    "extract/legit/hard.txt");
		assertTextFileContents("hello\n", "extract/legit/hard.txt");
	}
	/* The outside-pointing symlink itself was created ... */
	assertIsSymlink("extract/evillink", "../outside", 1);
	/* ... but nothing was written through it (checked above). */
	assertTextFileContents("after\n", "extract/legit/after.txt");
}

DEFINE_TEST(test_write_disk_secure_extraction_tar)
{
	run_extraction_test(FMT_TAR);
}

DEFINE_TEST(test_write_disk_secure_extraction_cpio)
{
	run_extraction_test(FMT_CPIO);
}

DEFINE_TEST(test_write_disk_secure_extraction_zip)
{
	run_extraction_test(FMT_ZIP);
}
