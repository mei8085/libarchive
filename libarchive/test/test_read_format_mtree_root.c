/*-
 * Copyright (c) 2026 mei8085
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
 * The mtree reader confines every pathname it reports to a content root.
 * These tests exercise that boundary through the same public entry
 * points a caller would use: ordinary relative names, ".." entries,
 * absolute names, symbolic link targets, duplicate lines, non-canonical
 * separators, an empty root option and the reset between manifests.
 */

/* Build a reader over an in-memory specification with the given options. */
static struct archive *
open_spec(const char *options, const void *data, size_t size)
{
	struct archive *a;

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_mtree(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	if (options != NULL)
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_set_options(a, options));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_memory(a, data, size));
	return (a);
}

/*
 * A legal manifest produces directories, files and links with the
 * metadata given in the manifest, and the paths are reported relative
 * to the content root.
 */
DEFINE_TEST(test_read_format_mtree_root_legal_entries)
{
	static const char spec[] =
	    "#mtree\n"
	    "dir type=dir mode=0750 uid=1000 gid=1000 "
	    "time=1234567890.5\n"
	    "dir/file type=file mode=0640 size=4 "
	    "time=1234567890.5\n"
	    "dir/link type=link link=file mode=0777\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec("mtree:root=.", spec, sizeof(spec) - 1);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir", archive_entry_pathname(ae));
	assertEqualInt(AE_IFDIR, archive_entry_filetype(ae));
	assertEqualInt(AE_IFDIR | 0750, archive_entry_mode(ae));
	assertEqualInt(1000, archive_entry_uid(ae));
	assertEqualInt(1000, archive_entry_gid(ae));
	assertEqualInt(1234567890, archive_entry_mtime(ae));
	assertEqualInt(5, archive_entry_mtime_nsec(ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir/file", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(AE_IFREG | 0640, archive_entry_mode(ae));
	assertEqualInt(4, archive_entry_size(ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir/link", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));
	assertEqualString("file", archive_entry_symlink(ae));

	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualInt(3, archive_file_count(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/* A ".." entry that climbs above the root is rejected with a diagnostic. */
DEFINE_TEST(test_read_format_mtree_root_dotdot_escape)
{
	static const char spec[] =
	    "#mtree\n"
	    "..\n"
	    "file type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assert(strstr(archive_error_string(a), "content root") != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * A relative name whose components cancel out past the root ("a/../../x")
 * is rejected; a name that stays inside remains accepted.
 */
DEFINE_TEST(test_read_format_mtree_root_relative_escape)
{
	static const char spec[] =
	    "#mtree\n"
	    "a/../../x type=file\n"
	    "y type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);

	/* The manifest continues; the next entry is still usable. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("y", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/* Non-canonical separators must not hide an escape. */
DEFINE_TEST(test_read_format_mtree_root_separator_escape)
{
	static const char spec[] =
	    "#mtree\n"
	    "a//..//..//x type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * An absolute name is rejected unless the root is absolute and contains it.
 * The leading slash is written as an octal escape, because a raw leading
 * '/' makes the line a special command in mtree syntax.
 */
DEFINE_TEST(test_read_format_mtree_root_absolute_name)
{
	static const char spec[] =
	    "#mtree\n"
	    "\\057etc/passwd type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	/* A relative root cannot contain an absolute specification name. */
	a = open_spec("mtree:root=.", spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(strstr(archive_error_string(a), "content root") != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	/* An absolute root that does contain the name accepts it. */
	a = open_spec("mtree:root=/etc", spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("/etc/passwd", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	/* An absolute root that does not contain it rejects it. */
	a = open_spec("mtree:root=/usr", spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/* A symbolic link target that leaves the root is rejected. */
DEFINE_TEST(test_read_format_mtree_root_symlink_escape)
{
	static const char spec[] =
	    "#mtree\n"
	    "dir type=dir\n"
	    "dir/inside type=link link=../dir/target\n"
	    "dir/outside type=link link=../../etc/passwd\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir", archive_entry_pathname(ae));

	/* The target stays inside the root. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir/inside", archive_entry_pathname(ae));
	assertEqualString("../dir/target", archive_entry_symlink(ae));

	/* The target climbs above the root. */
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(strstr(archive_error_string(a), "content root") != NULL);

	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * Duplicate lines for the same full path go through the same boundary
 * rule, whether the escape appears on the first or on a later line.
 */
DEFINE_TEST(test_read_format_mtree_root_duplicate_entries)
{
	static const char spec[] =
	    "#mtree\n"
	    "a/../../x type=file mode=0644\n"
	    "a/../../x type=file mode=0600\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * An empty root option must not widen the boundary.  An escape is still
 * rejected after "mtree:root=" resets the configured root.
 */
DEFINE_TEST(test_read_format_mtree_root_empty_option)
{
	static const char spec[] =
	    "#mtree\n"
	    "a/../../x type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec("mtree:root=", spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	a = open_spec("mtree:!root", spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * After a manifest fails to parse, the handle stays failed and the state
 * it left behind is gone.  A fresh handle starts from a clean root
 * context and can read a valid manifest again.
 */
DEFINE_TEST(test_read_format_mtree_root_reset_after_failure)
{
	static const char good[] =
	    "#mtree\n"
	    "dir type=dir\n"
	    ". type=file\n";
	static const char bad[] =
	    "#mtree\n"
	    "a type=file\n"
	    "\x01\n";
	struct archive_entry *ae;
	struct archive *a;

	/* A broken manifest is a hard parse error. */
	a = open_spec(NULL, bad, sizeof(bad) - 1);
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));
	/* The failure is sticky: no half-parsed entry is ever exposed. */
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	/*
	 * A valid manifest that names the root directory "." and then
	 * uses a relative entry resolves that entry against the root,
	 * not against whatever a previous manifest had left behind.
	 */
	a = open_spec(NULL, good, sizeof(good) - 1);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString(".", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * The boundary is evaluated after unescaping, so an encoded slash or
 * dot-dot cannot smuggle an escape past the check.
 */
DEFINE_TEST(test_read_format_mtree_root_escaped_escape)
{
	/* "a\057..\057..\057x" is "a/../../x" after unescaping. */
	static const char spec[] =
	    "#mtree\n"
	    "a\\057..\\057..\\057x type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/* An empty manifest is legal and yields no entries. */
DEFINE_TEST(test_read_format_mtree_root_empty_manifest)
{
	static const char spec[] = "#mtree\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualInt(0, archive_file_count(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * A name whose unescaped form embeds a NUL cannot be satisfied: the NUL
 * would hide the rest of the text from the boundary check, so the entry
 * is rejected with a diagnostic instead of being silently truncated.
 */
DEFINE_TEST(test_read_format_mtree_root_embedded_nul)
{
	/* "a\000/../../x": a NUL escape splits the visible name. */
	static const char spec[] =
	    "#mtree\n"
	    "a\\000/../../x type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * A link target that embeds a NUL is also rejected, and the rejection is
 * diagnosable: the invisible tail must not be treated as omitted.
 */
DEFINE_TEST(test_read_format_mtree_root_embedded_nul_link)
{
	static const char spec[] =
	    "#mtree\n"
	    "l type=link link=ok\\000/../../etc/passwd\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);
	assertEqualIntA(a, ARCHIVE_FAILED, archive_read_next_header(a, &ae));
	assert(archive_error_string(a) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * With checkfs the root also anchors the backing files: the entry's
 * metadata is read from <root>/<relative path>, and a backing symbolic
 * link that points out of the root is rejected rather than followed.
 */
DEFINE_TEST(test_read_format_mtree_root_checkfs)
{
	static const char spec[] =
	    "#mtree\n"
	    "sub type=dir\n"
	    "sub/file type=file\n"
	    "sub/badlink type=link\n"
	    "sub/escape type=file\n";
	struct archive_entry *ae;
	struct archive *a;
	char buff[16];

	/* Build an on-disk tree under a dedicated root directory. */
	assertMakeDir("croot", 0755);
	assertMakeDir("croot/sub", 0755);
	assertMakeFile("croot/sub/file", 0644, "payload");
	/* A real object outside the root, so the link below is not dangling. */
	assertMakeFile("outside", 0644, "secret");
	if (canSymlink()) {
		assertMakeSymlink("croot/sub/escape", "../../outside", 0);
	}

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_mtree(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_set_options(a, "mtree:checkfs,mtree:root=croot"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_memory(a, spec, sizeof(spec) - 1));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("sub", archive_entry_pathname(ae));
	assertEqualInt(AE_IFDIR, archive_entry_filetype(ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("sub/file", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(7, archive_entry_size(ae));
	assertEqualIntA(a, 7, archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem("payload", buff, 7);

	/*
	 * A declared symlink is only lstat()ed, so its (in-root) name is
	 * accepted even though a backing link of the same name points out
	 * of the root; the reader never follows it.
	 */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("sub/badlink", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));

	if (canSymlink()) {
		/*
		 * A declared file whose backing object is a link that
		 * leaves the root must be rejected, not opened.
		 */
		assertEqualIntA(a, ARCHIVE_FAILED,
		    archive_read_next_header(a, &ae));
		assert(archive_error_string(a) != NULL);
		assert(strstr(archive_error_string(a), "content root") != NULL);
	} else {
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_next_header(a, &ae));
	}
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * A broken manifest leaves no half-built state behind, and the failure
 * is sticky so a partially parsed entry list is never exposed.  A fresh
 * reader then parses the next manifest from a clean root context.
 */
DEFINE_TEST(test_read_format_mtree_root_no_state_leak)
{
	static const char bad[] =
	    "#mtree\n"
	    "dir type=dir\n"
	    "dir/sub type=file\n"
	    "\x01 broken\n";
	static const char good[] =
	    "#mtree\n"
	    "leaf type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	/*
	 * The whole manifest is parsed before any entry is reported, so
	 * a bad line fails the manifest outright.
	 */
	a = open_spec(NULL, bad, sizeof(bad) - 1);
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));
	/* Sticky: no half-parsed entry is ever exposed on a retry. */
	assertEqualIntA(a, ARCHIVE_FATAL, archive_read_next_header(a, &ae));
	assert(archive_entry_pathname(ae) == NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	/* A fresh reader starts from an empty root context. */
	a = open_spec(NULL, good, sizeof(good) - 1);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("leaf", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/*
 * A rejected ".." that would leave the root must not disturb the
 * following entries: the reader keeps resolving from the root context.
 */
DEFINE_TEST(test_read_format_mtree_root_reject_keeps_context)
{
	static const char spec[] =
	    "#mtree\n"
	    "keep type=dir\n"
	    "keep/file type=file\n"
	    "..\n"
	    "keep/after type=file\n";
	struct archive_entry *ae;
	struct archive *a;

	a = open_spec(NULL, spec, sizeof(spec) - 1);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("keep", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("keep/file", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("keep/after", archive_entry_pathname(ae));
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}
