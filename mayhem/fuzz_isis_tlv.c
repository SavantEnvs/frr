// libFuzzer harness for the IS-IS TLV codec. Same pipeline as tests/isisd/test_fuzz_isis_tlv.c
// (unpack -> format -> copy -> pack -> re-unpack -> fragment), fed from the fuzzer's bytes.
#include <zebra.h>

#include "memory.h"
#include "sbuf.h"
#include "stream.h"
#include "frrevent.h"

#include "isisd/isis_circuit.h"
#include "isisd/isis_tlvs.h"

#define TEST_STREAM_SIZE 1500

static int comp_line(const void *p1, const void *p2)
{
	return strcmp(*(char *const *)p1, *(char *const *)p2);
}

static char *sortlines(char *in)
{
	size_t line_count = 1;
	size_t rv_len = strlen(in) + 1;
	size_t rv_pos = 0;
	char *rv = XMALLOC(MTYPE_TMP, rv_len);

	for (char *c = in; *c; c++) {
		if (*c == '\n')
			line_count++;
	}

	if (line_count == 1) {
		memcpy(rv, in, rv_len);
		return rv;
	}

	char **lines = XCALLOC(MTYPE_TMP, sizeof(char *) * line_count);
	char *saveptr = NULL;
	size_t i = 0;

	for (char *line = strtok_r(in, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
		lines[i++] = line;
		assert(i <= line_count);
	}

	line_count = i;
	qsort(lines, line_count, sizeof(char *), comp_line);

	for (i = 0; i < line_count; i++) {
		int printf_rv = snprintf(rv + rv_pos, rv_len - rv_pos, "%s\n", lines[i]);

		assert(printf_rv >= 0);
		rv_pos += printf_rv;
	}

	XFREE(MTYPE_TMP, lines);
	return rv;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > TEST_STREAM_SIZE)
		return -1;

	struct stream *s = stream_new(TEST_STREAM_SIZE);

	stream_put(s, data, size);
	stream_set_getp(s, 0);

	struct isis_tlvs *tlvs;
	const char *log;
	int rv = isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log);

	if (rv) {
		isis_free_tlvs(tlvs);
		stream_free(s);
		return -1;
	}

	const char *s_tlvs = isis_format_tlvs(tlvs, NULL);

	(void)s_tlvs;

	struct isis_item *orig_auth = tlvs->isis_auth.head;

	tlvs->isis_auth.head = NULL;
	s_tlvs = isis_format_tlvs(tlvs, NULL);
	struct isis_tlvs *tlv_copy = isis_copy_tlvs(tlvs);

	tlvs->isis_auth.head = orig_auth;
	isis_free_tlvs(tlvs);

	struct stream *s2 = stream_new(TEST_STREAM_SIZE);

	assert(!isis_pack_tlvs(tlv_copy, s2, (size_t)-1, false, false));

	stream_set_getp(s2, 0);
	rv = isis_unpack_tlvs(STREAM_READABLE(s2), s2, &tlvs, &log);
	assert(!rv);

	char *orig_tlvs = XSTRDUP(MTYPE_TMP, s_tlvs);

	s_tlvs = isis_format_tlvs(tlvs, NULL);
	assert(!strcmp(orig_tlvs, s_tlvs));

	isis_free_tlvs(tlv_copy);
	stream_free(s);
	stream_free(s2);

	struct list *fragments = isis_fragment_tlvs(tlvs, 550);

	isis_free_tlvs(tlvs);
	if (!fragments) {
		XFREE(MTYPE_TMP, orig_tlvs);
		return 0;
	}

	s = stream_new(550);

	struct sbuf fragment_format;

	sbuf_init(&fragment_format, NULL, 0);

	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(fragments, node, tlvs)) {
		stream_reset(s);
		assert(!isis_pack_tlvs(tlvs, s, (size_t)-1, false, false));
		sbuf_push(&fragment_format, 0, "%s", isis_format_tlvs(tlvs, NULL));
		isis_free_tlvs(tlvs);
	}
	list_delete(&fragments);
	stream_free(s);

	char *fragment_content = sortlines((char *)sbuf_buf(&fragment_format));

	sbuf_free(&fragment_format);
	char *orig_tlv_content = sortlines(orig_tlvs);

	XFREE(MTYPE_TMP, orig_tlvs);
	assert(!strcmp(fragment_content, orig_tlv_content));

	XFREE(MTYPE_TMP, fragment_content);
	XFREE(MTYPE_TMP, orig_tlv_content);

	return 0;
}
