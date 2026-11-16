/* Drives the list parsers behind wdctl commands and config-file values: trusted/wildcard domain
 * lists, domain:ip pairs, trusted IP lists, trusted/untrusted MAC lists and popular servers.
 * The input is a script: each '\n'-separated line is one command (first byte selects it, the rest
 * is its argument), so add-then-delete sequences are exercised. All lists are emptied afterwards,
 * so one input's result never depends on an earlier one. */
#include "../../src/conf.c"

enum { OP_USER_DOMAIN, OP_WILDCARD, OP_DEL_USER_DOMAIN, OP_DEL_WILDCARD, OP_DOMAIN_IP_USER,
       OP_DOMAIN_IP_INNER, OP_IPLIST_ADD, OP_IPLIST_DEL, OP_TMAC_ADD, OP_TMAC_DEL, OP_UMAC_ADD,
       OP_UMAC_DEL, OP_POPULAR, OP_RESOLVED, OP_COUNT };

static void reset_lists(void)
{
	free_domain_trusted_list(config.domains_trusted);
	config.domains_trusted = NULL;
	free_domain_trusted_list(config.inner_domains_trusted);
	config.inner_domains_trusted = NULL;
	free_domain_trusted_list(config.wildcard_domains_trusted);
	config.wildcard_domains_trusted = NULL;
	free_popular_servers_list(config.popular_servers);
	config.popular_servers = NULL;
	clear_trusted_mac_list();
	clear_untrusted_mac_list();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	config_init();
	debugconf.debuglevel = 0;
	debugconf.log_stderr = 0;
	return 0;
}

static void run_command(unsigned op, char *arg)
{
	switch (op % OP_COUNT) {
	case OP_USER_DOMAIN: parse_user_trusted_domain_string(arg); break;
	case OP_WILDCARD: parse_trusted_wildcard_domain_string(arg); break;
	case OP_DEL_USER_DOMAIN: parse_del_trusted_domain_string(arg); break;
	case OP_DEL_WILDCARD: parse_del_trusted_wildcard_domain_string(arg); break;
	case OP_DOMAIN_IP_USER: add_domain_ip_pair(arg, USER_TRUSTED_DOMAIN); break;
	case OP_DOMAIN_IP_INNER: add_domain_ip_pair(arg, INNER_TRUSTED_DOMAIN); break;
	case OP_IPLIST_ADD: add_trusted_ip_list(arg); break;
	case OP_IPLIST_DEL: del_trusted_ip_list(arg); break;
	case OP_TMAC_ADD: parse_trusted_mac_list(arg); break;
	case OP_TMAC_DEL: parse_del_trusted_mac_list(arg); break;
	case OP_UMAC_ADD: parse_untrusted_mac_list(arg); break;
	case OP_UMAC_DEL: parse_del_untrusted_mac_list(arg); break;
	case OP_POPULAR: parse_popular_servers(arg); break;
	case OP_RESOLVED: {
		char *ip = strchr(arg, '=');
		if (ip) {
			*ip++ = '\0';
			add_wildcard_resolved_ip(arg, ip);
		}
		break;
	}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf = malloc(size + 1);
	char *line, *next;

	if (!buf)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	for (line = buf; line; line = next) {
		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';
		if (*line)
			run_command((unsigned char)line[0], line + 1);
	}

	reset_lists();
	free(buf);
	return 0;
}
