/*
 * Tar parsing harness: feeds a file to libarchive from memory and
 * reports every entry, the stream position at each step, body bytes
 * actually delivered, and the exact status/error at each stage.
 *
 * Build: see build_harness.sh
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <archive.h>
#include <archive_entry.h>

static const char *code_name(int r)
{
	switch (r) {
	case ARCHIVE_EOF:    return "EOF";
	case ARCHIVE_OK:     return "OK";
	case ARCHIVE_RETRY:  return "RETRY";
	case ARCHIVE_WARN:   return "WARN";
	case ARCHIVE_FAILED:return "FAILED";
	case ARCHIVE_FATAL:  return "FATAL";
	default:             return "?";
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s file.tar\n", argv[0]);
		return 2;
	}
	FILE *f = fopen(argv[1], "rb");
	if (f == NULL) { perror("fopen"); return 2; }
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
	unsigned char *buf = malloc((size_t)fsize);
	if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
		perror("fread"); return 2;
	}
	fclose(f);
	printf("== file=%s size=%ld ==\n", argv[1], fsize);

	struct archive *a = archive_read_new();
	archive_read_support_format_tar(a);
	int rc = archive_read_open_memory(a, buf, (size_t)fsize);
	printf("open_memory -> %s\n", code_name(rc));

	int idx = 0;
	for (;;) {
		struct archive_entry *ae = NULL;
		la_int64_t pos_before = archive_filter_bytes(a, -1);
		rc = archive_read_next_header(a, &ae);
		la_int64_t pos_after_hdr = archive_filter_bytes(a, -1);
		printf("[%d] next_header: %s (pos %lld -> %lld)", idx,
		    code_name(rc), (long long)pos_before,
		    (long long)pos_after_hdr);
		if (rc == ARCHIVE_EOF) {
			printf("\n");
			break;
		}
		const char *err = archive_error_string(a);
		if (err != NULL)
			printf(" err=\"%s\"", err);
		if (ae != NULL && rc != ARCHIVE_FATAL) {
			const char *p = archive_entry_pathname(ae);
			printf(" path='%s' size=%lld type='%c'",
			    p ? p : "(null)",
			    (long long)archive_entry_size(ae),
			    archive_entry_filetype(ae) ?
			        (char)archive_entry_filetype(ae) : '?');
		}
		printf("\n");
		if (rc == ARCHIVE_RETRY) {
			/* Transient framing error; the parser resynced one
			 * block but no entry is available. Loop for the next
			 * header instead of requesting body data. */
			printf("    -> RETRY: resyncing to next header\n");
			idx++;
			continue;
		}
		if (rc < ARCHIVE_WARN) {
			/* FATAL/FAILED: no entry is usable */
			printf("    -> terminal error, stopping\n");
			break;
		}

		/* Drain the body exactly the way a consumer would. */
		const void *chunk;
		size_t n;
		la_int64_t off;
		long long total = 0;
		int body_calls = 0;
		for (;;) {
			la_int64_t p0 = archive_filter_bytes(a, -1);
			int br = archive_read_data_block(a, &chunk, &n, &off);
			la_int64_t p1 = archive_filter_bytes(a, -1);
			body_calls++;
			if (br == ARCHIVE_EOF) {
				printf("    data_block #%d: EOF (pos %lld -> %lld) total=%lld\n",
				    body_calls, (long long)p0, (long long)p1, total);
				break;
			}
			if (br < ARCHIVE_WARN) {
				printf("    data_block #%d: %s (pos %lld -> %lld) n=%zu off=%lld total=%lld err=\"%s\"\n",
				    body_calls, code_name(br),
				    (long long)p0, (long long)p1, n,
				    (long long)off, total,
				    archive_error_string(a) ?
				        archive_error_string(a) : "");
				break;
			}
			if (br == ARCHIVE_WARN)
				printf("    data_block #%d: WARN (pos %lld -> %lld) n=%zu err=\"%s\"\n",
				    body_calls, (long long)p0,
				    (long long)p1, n,
				    archive_error_string(a) ?
				        archive_error_string(a) : "");
			total += (long long)n;
		}
		printf("    body delivered=%lld bytes, pos now=%lld\n",
		    total, (long long)archive_filter_bytes(a, -1));
		idx++;
	}
	la_int64_t final_pos = archive_filter_bytes(a, -1);
	printf("close -> %s, final consumed pos=%lld of %ld (unconsumed=%ld)\n",
	    code_name(archive_read_close(a)), (long long)final_pos, fsize,
	    fsize - (long)final_pos);
	archive_read_free(a);
	free(buf);
	return 0;
}
