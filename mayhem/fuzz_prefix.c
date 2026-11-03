// libFuzzer harness for FRR's text-to-address parsers in lib/ (prefix, MAC, sockunion, ASN, netmask).
// First byte selects the parser; the rest is the NUL-terminated input string. Successful parses are
// checked for a print/re-parse round trip.
#include <zebra.h>

#include "prefix.h"
#include "sockunion.h"
#include "asn.h"

#define MAX_INPUT 256

static void check_prefix_roundtrip(const struct prefix *p)
{
	char buf[PREFIX_STRLEN];
	struct prefix q;

	if (p->family != AF_INET && p->family != AF_INET6)
		return;
	assert(prefix2str(p, buf, sizeof(buf)) == buf);
	assert(str2prefix(buf, &q));
	assert(prefix_same(p, &q));
	assert(prefix_cmp(p, &q) == 0);
	assert(prefix_match(&q, p));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1 || size > MAX_INPUT)
		return -1;

	char str[MAX_INPUT + 1];

	memcpy(str, data + 1, size - 1);
	str[size - 1] = '\0';

	switch (data[0] % 8) {
	case 0: {
		struct prefix p, masked;

		if (!str2prefix(str, &p))
			return -1;
		check_prefix_roundtrip(&p);
		prefix_copy(&masked, &p);
		apply_mask(&masked);
		(void)prefix_hash_key(&masked);
		break;
	}
	case 1: {
		struct prefix_ipv4 p;

		if (!str2prefix_ipv4(str, &p))
			return -1;
		apply_mask_ipv4(&p);
		check_prefix_roundtrip((struct prefix *)&p);
		break;
	}
	case 2: {
		struct prefix_ipv6 p;

		if (!str2prefix_ipv6(str, &p))
			return -1;
		apply_mask_ipv6(&p);
		check_prefix_roundtrip((struct prefix *)&p);
		break;
	}
	case 3: {
		struct prefix_eth p;

		if (!str2prefix_eth(str, &p))
			return -1;
		break;
	}
	case 4: {
		struct ethaddr mac, mac2;
		char buf[ETHER_ADDR_STRLEN];

		if (!prefix_str2mac(str, &mac))
			return -1;
		prefix_mac2str(&mac, buf, sizeof(buf));
		assert(prefix_str2mac(buf, &mac2));
		assert(!memcmp(&mac, &mac2, sizeof(mac)));
		break;
	}
	case 5: {
		union sockunion su, su2;
		char buf[SU_ADDRSTRLEN];

		memset(&su, 0, sizeof(su));
		if (str2sockunion(str, &su))
			return -1;
		sockunion2str(&su, buf, sizeof(buf));
		memset(&su2, 0, sizeof(su2));
		assert(!str2sockunion(buf, &su2));
		assert(sockunion_cmp(&su, &su2) == 0);
		break;
	}
	case 6: {
		as_t asn;
		bool found = false;

		if (!asn_str2asn(str, &asn))
			return -1;
		(void)asn_asn2asplain(asn);
		(void)asn_str2asn_parse(str, &asn, &found);
		(void)asn_str2asn_match(str);
		break;
	}
	case 7: {
		char out[PREFIX_STRLEN];
		char *mask = strchr(str, '\n');

		if (!mask)
			return -1;
		*mask++ = '\0';
		if (!netmask_str2prefix_str(str, mask, out, sizeof(out)))
			return -1;
		(void)str2family(str);
		break;
	}
	}
	return 0;
}
