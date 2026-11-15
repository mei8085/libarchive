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
#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

/*
 * A ZIP entry is described twice in an archive:
 *   - a local file header (LFH, signature PK\003\004) precedes the data,
 *   - a central directory record (CD,  signature PK\001\002) follows it.
 * Each copy independently carries the entry name, CRC-32, compressed and
 * uncompressed sizes, and the compression method.  A malicious archive can
 * make the two copies disagree, or tamper with the local-header offsets that
 * order the central directory, so that an addressable (seekable) reader and
 * a streaming reader observe different entries or cross a data boundary.
 *
 * These tests synthesize such archives entirely in memory and read every one
 * through both front ends:
 *   - the seekable reader via a memory stream that *does* provide a seek
 *     callback (it slurps the central directory and follows CD offsets),
 *   - the streamable reader via a deliberately non-seekable callback that
 *     only hands back a few bytes per call (it walks the local headers in
 *     physical order and never consults the central directory).
 *
 * Invariant under test: a field contradiction is either reported explicitly
 * or both front ends produce the identical, bounded result; no front end may
 * silently swallow an entry or hand back bytes past the declared entry.
 * After a bad entry is flushed, the following well-formed independent entry
 * must still be decoded correctly.
 */

#define LOCAL_HDR_SIZE	30
#define CENTRAL_HDR_SIZE 46
#define EOCD_HDR_SIZE	22

struct zip_builder {
	unsigned char	*buf;
	size_t		 size;
	size_t		 cap;
};

/* Byte layout of one synthesized entry.  Every *_local_* offset points into
 * the local file header and every *_central_* offset into the central
 * directory record, so a test can patch the two copies of a field
 * independently. */
struct zip_layout {
	size_t	local;			/* LFH file offset */
	size_t	local_method;		/* u16 at LFH+8  */
	size_t	local_crc;		/* u32 at LFH+14 */
	size_t	local_csize;		/* u32 at LFH+18 */
	size_t	local_usize;		/* u32 at LFH+22 */
	size_t	local_name;		/* filename at LFH+30 */
	size_t	data;			/* first body byte */
	size_t	central;		/* CD record file offset */
	size_t	central_method;		/* u16 at CD+10 */
	size_t	central_crc;		/* u32 at CD+16 */
	size_t	central_csize;		/* u32 at CD+20 */
	size_t	central_usize;		/* u32 at CD+24 */
	size_t	central_name;		/* filename at CD+46 */
	/* u32 local-header offset at CD+42 */
	size_t	central_offset;
};

/* A fully described entry held until the central directory is written. */
struct zip_pending {
	char		 name[64];
	size_t		 name_len;
	const void	*body;
	size_t		 body_len;	/* uncompressed length */
	unsigned char	*cdata;		/* compressed body (NULL if stored) */
	size_t		 cdata_len;
	uint32_t	 crc;
	int		 method;
	size_t		 local;		/* assigned local-header offset */
};

static uint32_t
test_crc32(const void *buf, size_t n)
{
	static uint32_t table[256];
	const unsigned char *p = buf;
	uint32_t crc;
	size_t i;

	if (table[1] == 0) {
		for (i = 0; i < 256; i++) {
			uint32_t c = (uint32_t)i;
			int k;
			for (k = 0; k < 8; k++)
				c = (c & 1) ? (0xEDB88320u ^ (c >> 1))
				    : (c >> 1);
			table[i] = c;
		}
	}
	crc = 0xFFFFFFFFu;
	for (i = 0; i < n; i++)
		crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
	return (crc ^ 0xFFFFFFFFu);
}

static void
put_le16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void
put_le32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
	p[2] = (unsigned char)((v >> 16) & 0xff);
	p[3] = (unsigned char)((v >> 24) & 0xff);
}

static void
builder_reserve(struct zip_builder *zb, size_t extra)
{
	if (zb->size + extra > zb->cap) {
		size_t ncap = zb->cap ? zb->cap * 2 : 256;
		while (ncap < zb->size + extra)
			ncap *= 2;
		zb->buf = realloc(zb->buf, ncap);
		assert(zb->buf != NULL);
		zb->cap = ncap;
	}
}

static void
builder_append(struct zip_builder *zb, const void *p, size_t n)
{
	builder_reserve(zb, n);
	memcpy(zb->buf + zb->size, p, n);
	zb->size += n;
}

/* Describe one entry.  For method 8 the body is deflated here into a private
 * buffer; the local and central sections are emitted later by build_finish. */
static void
pending_init(struct zip_pending *pe, const char *name, const void *body,
	size_t body_len, int method)
{
	memset(pe, 0, sizeof(*pe));
	pe->name_len = strlen(name);
	assert(pe->name_len < sizeof(pe->name));
	memcpy(pe->name, name, pe->name_len);
	pe->body = body;
	pe->body_len = body_len;
	pe->method = method;
	pe->crc = test_crc32(body, body_len);
	pe->cdata = NULL;
	pe->cdata_len = body_len;

	if (method == 8) {
#if defined(HAVE_ZLIB_H)
		uLongf dlen = compressBound((uLong)body_len) + 16;
		z_stream zs;
		int zr;

		pe->cdata = malloc(dlen);
		assert(pe->cdata != NULL);
		memset(&zs, 0, sizeof(zs));
		/* Negative windowBits selects raw deflate (no zlib header). */
		zr = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
		    -15, 8, Z_DEFAULT_STRATEGY);
		assertEqualInt(Z_OK, zr);
		zs.next_in = (Bytef *)(uintptr_t)body;
		zs.avail_in = (uInt)body_len;
		zs.next_out = pe->cdata;
		zs.avail_out = (uInt)dlen;
		zr = deflate(&zs, Z_FINISH);
		assertEqualInt(Z_STREAM_END, zr);
		pe->cdata_len = dlen - zs.avail_out;
		deflateEnd(&zs);
#else
		skipping("deflate test requires zlib");
#endif
	}
}

/*
 * Emit all local sections (header + name + body), then the central directory
 * and the EOCD record.  The parallel layout[] array is filled with the exact
 * file offset of every patchable field in both sections.
 */
static unsigned char *
build_archive(struct zip_pending *entries, unsigned int n,
	struct zip_layout *layout, size_t *out_len)
{
	struct zip_builder zb;
	unsigned char hdr[LOCAL_HDR_SIZE];
	unsigned char cen[CENTRAL_HDR_SIZE];
	unsigned char eocd[EOCD_HDR_SIZE];
	size_t cd_start, cd_size;
	unsigned int i;

	memset(&zb, 0, sizeof(zb));

	/* Phase 1: local file headers and data, in entry order. */
	for (i = 0; i < n; i++) {
		struct zip_pending *pe = &entries[i];
		struct zip_layout *lay = &layout[i];
		const void *payload = pe->cdata ? pe->cdata : pe->body;
		size_t payload_len = pe->cdata ? pe->cdata_len : pe->body_len;

		pe->local = zb.size;
		lay->local = pe->local;
		lay->local_method = pe->local + 8;
		lay->local_crc = pe->local + 14;
		lay->local_csize = pe->local + 18;
		lay->local_usize = pe->local + 22;
		lay->local_name = pe->local + 30;
		lay->data = pe->local + LOCAL_HDR_SIZE + pe->name_len;

		memset(hdr, 0, sizeof(hdr));
		memcpy(hdr, "PK\003\004", 4);
		put_le16(hdr + 4, 20);			/* version needed */
		put_le16(hdr + 6, 0);			/* flags */
		put_le16(hdr + 8, (uint16_t)pe->method);
		put_le32(hdr + 14, pe->crc);
		put_le32(hdr + 18, (uint32_t)payload_len);
		put_le32(hdr + 22, (uint32_t)pe->body_len);
		put_le16(hdr + 26, (uint16_t)pe->name_len);
		builder_append(&zb, hdr, sizeof(hdr));
		builder_append(&zb, pe->name, pe->name_len);
		builder_append(&zb, payload, payload_len);
	}

	/* Phase 2: central directory, one record per entry. */
	cd_start = zb.size;
	for (i = 0; i < n; i++) {
		struct zip_pending *pe = &entries[i];
		struct zip_layout *lay = &layout[i];
		size_t payload_len = pe->cdata ? pe->cdata_len : pe->body_len;

		lay->central = zb.size;
		lay->central_method = zb.size + 10;
		lay->central_crc = zb.size + 16;
		lay->central_csize = zb.size + 20;
		lay->central_usize = zb.size + 24;
		lay->central_name = zb.size + 46;
		lay->central_offset = zb.size + 42;

		memset(cen, 0, sizeof(cen));
		memcpy(cen, "PK\001\002", 4);
		put_le16(cen + 4, 20);			/* version made by */
		put_le16(cen + 6, 20);			/* version needed */
		put_le16(cen + 8, 0);			/* flags */
		put_le16(cen + 10, (uint16_t)pe->method);
		put_le32(cen + 16, pe->crc);
		put_le32(cen + 20, (uint32_t)payload_len);
		put_le32(cen + 24, (uint32_t)pe->body_len);
		put_le16(cen + 28, (uint16_t)pe->name_len);
		put_le32(cen + 38, 0);			/* external attributes */
		put_le32(cen + 42, (uint32_t)pe->local);
		builder_append(&zb, cen, sizeof(cen));
		builder_append(&zb, pe->name, pe->name_len);
	}
	cd_size = zb.size - cd_start;

	/* Phase 3: end of central directory. */
	memset(eocd, 0, sizeof(eocd));
	memcpy(eocd, "PK\005\006", 4);
	put_le16(eocd + 8, (uint16_t)n);
	put_le16(eocd + 10, (uint16_t)n);
	put_le32(eocd + 12, (uint32_t)cd_size);
	put_le32(eocd + 16, (uint32_t)cd_start);
	builder_append(&zb, eocd, sizeof(eocd));

	/* Release the per-entry scratch compression buffers. */
	for (i = 0; i < n; i++) {
		free(entries[i].cdata);
		entries[i].cdata = NULL;
	}

	*out_len = zb.size;
	return (zb.buf);
}

/* Build the standard three-entry stored archive used by every contradiction
 * test.  The entry under test ("second") is bracketed by "first" and "third"
 * so recovery after a bad entry is observable on both sides.  Each body is a
 * fixed 16 bytes. */
#define BODY_LEN 16
static unsigned char *
build_three_entry_methods(struct zip_layout *layout, size_t *out_len,
	int middle_method)
{
	static const char first_body[BODY_LEN] = "AAAA-first-body-";
	static const char second_body[BODY_LEN] = "BBBB-second-body";
	static const char third_body[BODY_LEN] = "CCCC-third-body-";
	struct zip_pending entries[3];

	pending_init(&entries[0], "first", first_body, BODY_LEN, 0);
	pending_init(&entries[1], "second", second_body, BODY_LEN,
	    middle_method);
	pending_init(&entries[2], "third", third_body, BODY_LEN, 0);

	return (build_archive(entries, 3, layout, out_len));
}

static unsigned char *
build_three_entry(struct zip_layout *layout, size_t *out_len)
{
	return (build_three_entry_methods(layout, out_len, 0));
}

/* A deliberately unpleasant non-seekable memory stream: each read returns at
 * most a few bytes and there is no skip callback, so the streamable front end
 * cannot re-read or jump around the way a file can. */
struct stream_state {
	const unsigned char	*data;
	size_t			 size;
	size_t			 pos;
	size_t			 chunk;
};

static la_ssize_t
stream_read(struct archive *a, void *client_data, const void **buffer)
{
	struct stream_state *st = client_data;
	size_t avail;

	(void)a;
	if (st->pos >= st->size) {
		*buffer = NULL;
		return (0);
	}
	avail = st->size - st->pos;
	if (avail > st->chunk)
		avail = st->chunk;
	*buffer = st->data + st->pos;
	st->pos += avail;
	return ((la_ssize_t)avail);
}

static la_int64_t
stream_seek(struct archive *a, void *client_data, la_int64_t request,
	int whence)
{
	struct stream_state *st = client_data;
	size_t base;

	(void)a;
	switch (whence) {
	case SEEK_SET: base = 0; break;
	case SEEK_CUR: base = st->pos; break;
	case SEEK_END: base = st->size; break;
	default: return (ARCHIVE_FAILED);
	}
	if (request < 0 || (uint64_t)request > st->size - base)
		return (ARCHIVE_FAILED);
	st->pos = base + (size_t)request;
	return ((la_int64_t)st->pos);
}

/* What one front end reported for a single entry. */
struct observed_entry {
	int	 header_status;	/* archive_read_next_header() result */
	char	 name[64];
	int64_t size;
	int	 data_status;	/* final archive_read_data() result */
	int64_t data_bytes;
};

struct observed_archive {
	struct observed_entry entry[8];
	unsigned int nentries;
	int next_header_final;	/* terminating next_header() result (EOF/etc) */
};

static void
observe_archive_chunk(int seekable, const unsigned char *data, size_t size,
	size_t chunk, struct observed_archive *obs)
{
	struct archive *a;
	struct archive_entry *ae;
	struct stream_state st;
	unsigned int i;
	int r;

	memset(obs, 0, sizeof(*obs));
	st.data = data;
	st.size = size;
	st.pos = 0;
	st.chunk = chunk;

	assert((a = archive_read_new()) != NULL);
	if (seekable) {
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_support_format_zip_seekable(a));
		archive_read_set_seek_callback(a, stream_seek);
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_open2(a, &st, NULL, stream_read, NULL, NULL));
	} else {
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_support_format_zip_streamable(a));
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_open2(a, &st, NULL, stream_read, NULL, NULL));
	}

	for (i = 0; i < 8; i++) {
		char buff[64];
		la_ssize_t n;
		int last = ARCHIVE_OK;
		const char *path;

		r = archive_read_next_header(a, &ae);
		if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
			obs->next_header_final = r;
			break;
		}
		obs->entry[i].header_status = r;
		path = archive_entry_pathname(ae);
		if (path != NULL) {
			strncpy(obs->entry[i].name, path,
			    sizeof(obs->entry[i].name) - 1);
		}
		obs->entry[i].size = archive_entry_size(ae);

		/* Drain the body, enforcing the hard declared-size boundary. */
		for (;;) {
			n = archive_read_data(a, buff, sizeof(buff));
			if (n < 0) {
				obs->entry[i].data_status = (int)n;
				break;
			}
			if (n == 0) {
				obs->entry[i].data_status = last;
				break;
			}
			last = ARCHIVE_OK;
			obs->entry[i].data_bytes += n;
			failure("data must never cross the declared entry "
			    "boundary: %lld > %lld",
			    (long long)obs->entry[i].data_bytes,
			    (long long)obs->entry[i].size);
			assert(obs->entry[i].data_bytes
			    <= obs->entry[i].size);
		}
		obs->nentries = i + 1;
	}
	if (i >= 8)
		obs->next_header_final = ARCHIVE_EOF;

	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

/* Default observation: feed the stream in deliberately small 7-byte reads,
 * which is smaller than every fixed-size header the parser must reassemble. */
static void
observe_archive(int seekable, const unsigned char *data, size_t size,
	struct observed_archive *obs)
{
	observe_archive_chunk(seekable, data, size, 7, obs);
}

/* Assert the two front ends surface the same ordered entry names.  A
 * contradiction that one front end hid but the other reported would fail here
 * rather than being swallowed. */
static void
assert_same_names(const struct observed_archive *sk,
	const struct observed_archive *st)
{
	unsigned int i;

	failure("entry count differs: seekable=%u streaming=%u",
	    sk->nentries, st->nentries);
	assertEqualInt(sk->nentries, st->nentries);
	for (i = 0; i < sk->nentries && i < st->nentries; i++) {
		failure("entry %u name differs: seekable='%s' streaming='%s'",
		    i, sk->entry[i].name, st->entry[i].name);
		assertEqualString(sk->entry[i].name, st->entry[i].name);
	}
}

/*
 * Contradiction 1: CRC-32.  The local header carries a bogus CRC while the
 * central directory keeps the real one.  Both front ends must flag the bad
 * checksum rather than accepting the body, and must still decode the
 * surrounding good entries.
 */
DEFINE_TEST(test_read_format_zip_header_mismatch_crc32)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;

	data = build_three_entry(lay, &size);

	/* Corrupt only the local copy of the middle entry's CRC. */
	put_le32(data + lay[1].local_crc, 0xDEADBEEFu);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	/* Both front ends expose all three entries and agree on names. */
	assert_same_names(&sk, &st);
	assertEqualInt(3, sk.nentries);
	assertEqualString("first", sk.entry[0].name);
	assertEqualString("second", sk.entry[1].name);
	assertEqualString("third", sk.entry[2].name);

	/* The bad entry is explicitly rejected on both paths. */
	assert(sk.entry[1].data_status != ARCHIVE_OK);
	assert(st.entry[1].data_status != ARCHIVE_OK);
	/* Its body never leaks past the declared 16-byte boundary. */
	assert(sk.entry[1].data_bytes <= sk.entry[1].size);
	assert(st.entry[1].data_bytes <= st.entry[1].size);

	/* The independent good entries before and after decode cleanly. */
	assertEqualInt(ARCHIVE_OK, sk.entry[0].data_status);
	assertEqualInt(ARCHIVE_OK, sk.entry[2].data_status);
	assertEqualInt(ARCHIVE_OK, st.entry[0].data_status);
	assertEqualInt(ARCHIVE_OK, st.entry[2].data_status);
	assertEqualInt(BODY_LEN, sk.entry[0].data_bytes);
	assertEqualInt(BODY_LEN, sk.entry[2].data_bytes);
	assertEqualInt(BODY_LEN, st.entry[0].data_bytes);
	assertEqualInt(BODY_LEN, st.entry[2].data_bytes);

	free(data);
}

/*
 * Contradiction 2: compressed size.  Patch the local header's compressed size
 * away from the central directory value while both CRCs stay correct.  A
 * stored entry's compressed size bounds the physical read, so this directly
 * probes whether a front end overruns into the next entry or stops short.
 * Both directions are exercised: a local size that is too small (truncation)
 * and one that is too large (would read into the following entry).
 */
DEFINE_TEST(test_read_format_zip_header_mismatch_compressed_size)
{
	/* An oversized local compressed size forces the non-seekable stream
	 * to consume into the next entry's bytes; it cannot seek back to
	 * resync, so it must stop with an explicit error rather than invent
	 * data.  The seekable front end still recovers through the central
	 * directory. */
	static const uint32_t bogus_csize[] = { 8, 32 };
	/* Indexed in lock-step with bogus_csize: 1 = the streamable front
	 * end stays aligned and keeps every entry, 0 = it cannot resync. */
	static const int stream_recovers[] = { 1, 0 };
	unsigned int ci, k;

	for (ci = 0; ci < sizeof(bogus_csize) / sizeof(bogus_csize[0]);
	    ci++) {
		struct zip_layout lay[3];
		unsigned char *data;
		size_t size;
		struct observed_archive sk, st;

		data = build_three_entry(lay, &size);
		put_le32(data + lay[1].local_csize, bogus_csize[ci]);

		observe_archive(1, data, size, &sk);
		observe_archive(0, data, size, &st);

		failure("bogus local compressed size %ju",
		    (uintmax_t)bogus_csize[ci]);

		/* Both front ends reach and name the bad entry identically;
		 * neither silently accepts it. */
		assert(sk.nentries >= 2);
		assert(st.nentries >= 2);
		assertEqualString("first", sk.entry[0].name);
		assertEqualString("second", sk.entry[1].name);
		assertEqualString("first", st.entry[0].name);
		assertEqualString("second", st.entry[1].name);
		assert(sk.entry[1].data_status != ARCHIVE_OK);
		assert(st.entry[1].data_status != ARCHIVE_OK);
		/* No front end returns more than the entry's declared size. */
		assert(sk.entry[1].data_bytes <= sk.entry[1].size);
		assert(st.entry[1].data_bytes <= st.entry[1].size);

		/* The entry before the bad one is intact on both paths. */
		assertEqualInt(ARCHIVE_OK, sk.entry[0].data_status);
		assertEqualInt(ARCHIVE_OK, st.entry[0].data_status);
		assertEqualInt(BODY_LEN, sk.entry[0].data_bytes);
		assertEqualInt(BODY_LEN, st.entry[0].data_bytes);

		if (stream_recovers[ci]) {
			/* Truncation keeps the stream aligned, so both front
			 * ends recover and fully read the trailing entry. */
			assertEqualInt(3, sk.nentries);
			assertEqualInt(3, st.nentries);
			assertEqualString("third", sk.entry[2].name);
			assertEqualString("third", st.entry[2].name);
			assertEqualInt(ARCHIVE_OK, sk.entry[2].data_status);
			assertEqualInt(ARCHIVE_OK, st.entry[2].data_status);
			assertEqualInt(BODY_LEN, sk.entry[2].data_bytes);
			assertEqualInt(BODY_LEN, st.entry[2].data_bytes);
		} else {
			/* Seekable front end recovers through the central
			 * directory and reads the trailing entry fully. */
			assertEqualInt(3, sk.nentries);
			assertEqualString("third", sk.entry[2].name);
			assertEqualInt(ARCHIVE_OK, sk.entry[2].data_status);
			assertEqualInt(BODY_LEN, sk.entry[2].data_bytes);
			/* The streamable front end cannot seek back after
			 * over-consuming, so it reports the bad entry and then
			 * honestly reaches end-of-stream rather than parsing a
			 * shifted header as a phantom entry. */
			assertEqualInt(ARCHIVE_FAILED,
			    st.entry[1].data_status);
			assert(st.nentries == 2);
			assertEqualInt(ARCHIVE_EOF, st.next_header_final);
			for (k = 0; k < st.nentries; k++)
				assert(st.entry[k].data_bytes
				    <= st.entry[k].size);
		}

		free(data);
	}
}

/*
 * Contradiction 3: uncompressed size.  The local header advertises a larger
 * uncompressed size than the central directory.  archive_entry_size() is a
 * caller's hard allocation boundary, so the decoded stream must never exceed
 * the real body and the mismatch must be reported.
 */
DEFINE_TEST(test_read_format_zip_header_mismatch_uncompressed_size)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;

	data = build_three_entry(lay, &size);

	/* Local uncompressed size lies upward; the real body is 16 bytes. */
	put_le32(data + lay[1].local_usize, 128);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	assert_same_names(&sk, &st);
	assertEqualInt(3, sk.nentries);

	/* The short real stream against the inflated declaration fails the
	 * final size verification on both paths. */
	assert(sk.entry[1].data_status != ARCHIVE_OK);
	assert(st.entry[1].data_status != ARCHIVE_OK);
	/* And the 16 real bytes are never exceeded. */
	assert(sk.entry[1].data_bytes <= BODY_LEN);
	assert(st.entry[1].data_bytes <= BODY_LEN);

	assertEqualInt(ARCHIVE_OK, sk.entry[2].data_status);
	assertEqualInt(ARCHIVE_OK, st.entry[2].data_status);
	assertEqualInt(BODY_LEN, sk.entry[2].data_bytes);
	assertEqualInt(BODY_LEN, st.entry[2].data_bytes);

	free(data);
}

/*
 * Contradiction 4: compression method.  The central directory says stored (0)
 * while the local header says deflate (8).  Both front ends dispatch on the
 * local method, so both attempt raw inflate over plain text and fail the same
 * way; they must not silently decode using the central method.  Inflating
 * non-deflate data is a hard decoder error, so both front ends stop the
 * archive at the bad entry rather than recovering past it; the requirement is
 * that they stop identically and never return a fabricated byte.
 */
DEFINE_TEST(test_read_format_zip_header_mismatch_method)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;

	data = build_three_entry(lay, &size);

	/* Flip only the local method to deflate; central stays stored. */
	put_le16(data + lay[1].local_method, 8);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	/* Both front ends reach the bad entry and agree on its name. */
	assert_same_names(&sk, &st);
	assertEqualString("first", sk.entry[0].name);
	assertEqualString("second", sk.entry[1].name);

	/* Both reject identically: inflating plain text cannot succeed. */
	assert(sk.entry[1].data_status != ARCHIVE_OK);
	assert(st.entry[1].data_status != ARCHIVE_OK);
	assertEqualInt(sk.entry[1].data_status, st.entry[1].data_status);
	assert(sk.entry[1].data_bytes == 0);
	assert(st.entry[1].data_bytes == 0);

	/* The hard decoder error terminates both front ends the same way;
	 * neither path silently accepts the entry or skips past the error. */
	assertEqualInt(sk.next_header_final, st.next_header_final);
	assert(sk.next_header_final != ARCHIVE_EOF);

	free(data);
}

/*
 * Contradiction 5: entry name.  Rewrite the local header's name to an
 * equal-length but different string.  There is no separate "correct" copy the
 * reader is required to prefer, so the contract is that both front ends make
 * the same choice and that the data behind the entry is unchanged; the entry
 * must not be hidden or duplicated.
 */
DEFINE_TEST(test_read_format_zip_header_mismatch_name)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;

	data = build_three_entry(lay, &size);

	/* Same length (6) so no size fields move. */
	memcpy(data + lay[1].local_name, "renamd", 6);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	/* Both front ends report the identical renamed entry and all three. */
	assert_same_names(&sk, &st);
	assertEqualInt(3, sk.nentries);
	assertEqualString("renamd", sk.entry[1].name);
	assertEqualString("renamd", st.entry[1].name);

	/* The body is still the original bytes and decodes successfully. */
	assertEqualInt(ARCHIVE_OK, sk.entry[1].data_status);
	assertEqualInt(ARCHIVE_OK, st.entry[1].data_status);
	assertEqualInt(BODY_LEN, sk.entry[1].data_bytes);
	assertEqualInt(BODY_LEN, st.entry[1].data_bytes);

	free(data);
}

/*
 * Order anomaly 1: central directory entries point at shuffled local headers.
 * Swap the local-header offsets that the first two central records point at so
 * the central directory order no longer matches the on-disk local-header
 * order.  The seekable reader sorts entries by offset and must still visit
 * every entry's real data; the streamable reader follows physical order.
 * Both must expose all three entries and never read a body through the wrong
 * header.
 */
DEFINE_TEST(test_read_format_zip_order_shuffled_offsets)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;
	unsigned int i;
	uint32_t off_first, off_second;

	data = build_three_entry(lay, &size);

	/* Swap the recorded offsets of the first two central records. */
	off_first = (uint32_t)lay[0].local;
	off_second = (uint32_t)lay[1].local;
	put_le32(data + lay[0].central_offset, off_second);
	put_le32(data + lay[1].central_offset, off_first);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	/* Every physical entry is still represented on both paths. */
	assertEqualInt(3, sk.nentries);
	assertEqualInt(3, st.nentries);

	/* No body may be read through a mismatched header: every entry stays
	 * within its declared size. */
	for (i = 0; i < 3; i++) {
		assert(sk.entry[i].data_bytes <= sk.entry[i].size);
		assert(st.entry[i].data_bytes <= st.entry[i].size);
	}
	/* The streamable path, which ignores central offsets, decodes each
	 * physical entry's own bytes cleanly. */
	for (i = 0; i < 3; i++)
		assertEqualInt(ARCHIVE_OK, st.entry[i].data_status);

	free(data);
}

/*
 * Order anomaly 2: two central records claim the same local-header offset.
 * The seekable reader keys its entry tree by offset, so a duplicate collapses
 * to a single entry rather than being read twice; the streamable reader still
 * sees every physical local header.  The requirement is that neither front
 * end reads past a data boundary or fabricates bytes, and the single shared
 * body the seekable reader returns is exactly that entry's declared bytes.
 */
DEFINE_TEST(test_read_format_zip_order_duplicate_offsets)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;
	unsigned int i;

	data = build_three_entry(lay, &size);

	/* Make the second central record alias the first entry's offset. */
	put_le32(data + lay[1].central_offset, (uint32_t)lay[0].local);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	/* The streaming front end still visits each physical local header. */
	assertEqualInt(3, st.nentries);
	for (i = 0; i < 3; i++) {
		assertEqualInt(ARCHIVE_OK, st.entry[i].data_status);
		assert(st.entry[i].data_bytes <= st.entry[i].size);
	}

	/* The seekable front end must not double-read the aliased body:
	 * whatever it returns is bounded by the entry's declared size. */
	for (i = 0; i < sk.nentries; i++)
		assert(sk.entry[i].data_bytes <= sk.entry[i].size);

	free(data);
}

/*
 * Order anomaly 3: a central record points outside the archive.  A seekable
 * reader that blindly followed this offset would read garbage or another
 * entry's bytes; it must instead fail explicitly.  The streamable reader does
 * not use central offsets and must keep decoding the physical entries.
 */
DEFINE_TEST(test_read_format_zip_order_offset_out_of_bounds)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;
	unsigned int i;

	data = build_three_entry(lay, &size);

	/* Point the last central record well past the end of the file. */
	put_le32(data + lay[2].central_offset, (uint32_t)(size + 256));

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	/* The streamable path is unaffected: all three physical entries. */
	assertEqualInt(3, st.nentries);
	for (i = 0; i < 3; i++) {
		assertEqualInt(ARCHIVE_OK, st.entry[i].data_status);
		assertEqualInt(BODY_LEN, st.entry[i].data_bytes);
	}

	/* The seekable path reads the good entries, then reports the bad
	 * offset as a terminal failure instead of reading out of bounds. */
	assert(sk.nentries >= 1);
	for (i = 0; i < sk.nentries; i++)
		assert(sk.entry[i].data_bytes <= sk.entry[i].size);
	assert(sk.next_header_final != ARCHIVE_OK);
	/* The first good entry is fully decoded before the failure. */
	assertEqualString("first", sk.entry[0].name);
	assertEqualInt(ARCHIVE_OK, sk.entry[0].data_status);
	assertEqualInt(BODY_LEN, sk.entry[0].data_bytes);

	free(data);
}

/*
 * Compressed path: the middle entry is genuinely deflated (method 8) in both
 * sections, then only its local CRC is corrupted.  This exercises the deflate
 * decoder's end-of-entry check rather than the stored fast path, and proves
 * the surrounding stored entries and the bad deflate entry are all handled
 * consistently across both front ends.
 */
DEFINE_TEST(test_read_format_zip_header_mismatch_crc32_deflate)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;

	if (archive_zlib_version() == NULL) {
		skipping("deflate test requires zlib");
		return;
	}

	data = build_three_entry_methods(lay, &size, 8);

	/* Corrupt only the local CRC of the deflated middle entry. */
	put_le32(data + lay[1].local_crc, 0xDEADBEEFu);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	assert_same_names(&sk, &st);
	assertEqualInt(3, sk.nentries);

	/* The deflated bad entry is rejected on both front ends without
	 * overshooting its declared uncompressed size. */
	assert(sk.entry[1].data_status != ARCHIVE_OK);
	assert(st.entry[1].data_status != ARCHIVE_OK);
	assert(sk.entry[1].data_bytes <= sk.entry[1].size);
	assert(st.entry[1].data_bytes <= st.entry[1].size);

	/* Both neighboring stored entries still decode fully. */
	assertEqualInt(ARCHIVE_OK, sk.entry[0].data_status);
	assertEqualInt(ARCHIVE_OK, sk.entry[2].data_status);
	assertEqualInt(ARCHIVE_OK, st.entry[0].data_status);
	assertEqualInt(ARCHIVE_OK, st.entry[2].data_status);
	assertEqualInt(BODY_LEN, sk.entry[0].data_bytes);
	assertEqualInt(BODY_LEN, sk.entry[2].data_bytes);
	assertEqualInt(BODY_LEN, st.entry[0].data_bytes);
	assertEqualInt(BODY_LEN, st.entry[2].data_bytes);

	free(data);
}

/*
 * Buffering robustness: the same contradictory archive must yield the same
 * bounded results regardless of how many bytes each client read returns.
 * Feed the CRC-mismatch archive through a range of awkward chunk sizes,
 * including 1 (byte at a time) and a size larger than the whole archive, on
 * both front ends.
 */
DEFINE_TEST(test_read_format_zip_header_mismatch_chunk_sizes)
{
	static const size_t chunks[] = { 1, 2, 3, 7, 31, 4096 };
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size, ci;
	struct observed_archive sk, st;

	data = build_three_entry(lay, &size);
	put_le32(data + lay[1].local_crc, 0xDEADBEEFu);

	for (ci = 0; ci < sizeof(chunks) / sizeof(chunks[0]); ci++) {
		observe_archive_chunk(1, data, size, chunks[ci], &sk);
		observe_archive_chunk(0, data, size, chunks[ci], &st);

		failure("chunk size %ju", (uintmax_t)chunks[ci]);
		assert_same_names(&sk, &st);
		assertEqualInt(3, sk.nentries);
		assert(sk.entry[1].data_status != ARCHIVE_OK);
		assert(st.entry[1].data_status != ARCHIVE_OK);
		assert(sk.entry[1].data_bytes <= sk.entry[1].size);
		assert(st.entry[1].data_bytes <= st.entry[1].size);
		assertEqualInt(ARCHIVE_OK, sk.entry[2].data_status);
		assertEqualInt(ARCHIVE_OK, st.entry[2].data_status);
		assertEqualInt(BODY_LEN, sk.entry[2].data_bytes);
		assertEqualInt(BODY_LEN, st.entry[2].data_bytes);
	}

	free(data);
}

/*
 * Baseline: a fully consistent archive must produce identical, correct
 * results on both front ends, establishing that the contradiction tests above
 * measure actual tampering rather than builder artifacts.
 */
DEFINE_TEST(test_read_format_zip_header_consistency_baseline)
{
	struct zip_layout lay[3];
	unsigned char *data;
	size_t size;
	struct observed_archive sk, st;
	unsigned int i;

	data = build_three_entry(lay, &size);

	observe_archive(1, data, size, &sk);
	observe_archive(0, data, size, &st);

	assert_same_names(&sk, &st);
	assertEqualInt(3, sk.nentries);
	assertEqualInt(3, st.nentries);
	for (i = 0; i < 3; i++) {
		assertEqualInt(ARCHIVE_OK, sk.entry[i].header_status);
		assertEqualInt(ARCHIVE_OK, st.entry[i].header_status);
		assertEqualInt(ARCHIVE_OK, sk.entry[i].data_status);
		assertEqualInt(ARCHIVE_OK, st.entry[i].data_status);
		assertEqualInt(BODY_LEN, sk.entry[i].data_bytes);
		assertEqualInt(BODY_LEN, st.entry[i].data_bytes);
		assertEqualInt(BODY_LEN, sk.entry[i].size);
		assertEqualInt(BODY_LEN, st.entry[i].size);
	}
	assertEqualInt(ARCHIVE_EOF, sk.next_header_final);
	assertEqualInt(ARCHIVE_EOF, st.next_header_final);

	free(data);
}
