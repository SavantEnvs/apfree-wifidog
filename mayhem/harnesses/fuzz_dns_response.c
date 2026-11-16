/* Feeds one DNS response to the portal DNS snooper, the same way a ring-buffer event from the
 * br-lan TC monitor does (handle_portal_dns_event). The snooper parses the question and answer
 * records and records resolved A/AAAA addresses under the configured wildcard trusted domains. */
#include "../../src/dns_snoop.c"

static const char kWildcards[] = "*.example.com,.test,example.org,*.com";

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	config_init();
	debugconf.debuglevel = 0;
	debugconf.log_stderr = 0;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* handle_portal_dns_event drops pkt_len == 0 or > MAX_DNS_PAYLOAD_LEN; the BPF producer
	 * never emits a longer payload */
	if (size == 0 || size > MAX_DNS_PAYLOAD_LEN)
		return -1;

	struct raw_dns_data ev;
	memset(&ev, 0, sizeof(ev));
	ev.pkt_len = (uint32_t)size;
	ev.ip_version = 4;
	memcpy(ev.dns_payload, data, size);

	parse_trusted_wildcard_domain_string(kWildcards);
	handle_portal_dns_event(NULL, &ev, sizeof(ev));
	clear_trusted_wildcard_domains();
	return 0;
}
